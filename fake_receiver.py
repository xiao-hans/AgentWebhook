#!/usr/bin/env python3
"""Loopback fake Hermes receiver for synthetic verification only.

Verifies the wire contract on 127.0.0.1: HMAC-SHA256 signature, payload field
allow-list, event type, and event_id dedup (claim semantics). Mode injects
failures so tests can exercise retry / auth-block / redirect-refusal without
touching real services.

Modes:
  ok       -> 202 {"accepted": true, "deduped": false} on first sight of an event_id
              200 {"accepted": true, "deduped": true} on repeats
  500      -> one 500, then ok              (retry + stable event_id)
  badsig   -> always 401                    (4xx -> blocked, never auto-accepted)
  redirect -> one 302, then ok              (client must refuse redirects)

Single-threaded server: handlers run sequentially, so plain sets/ints are safe.
One JSON line per request in <root>/requests.jsonl; the log records only the
four payload fields' identities, never session content.
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

ALLOWED_FIELDS = {"schema_version", "task_id", "event_id", "status"}
STATUSES = {"report_ready", "stopped_unfinished", "failed", "stalled"}


def verify_signature(header, body, secret):
    if not header or not header.startswith("sha256="):
        return False
    want = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header, want)


class Receiver:
    def __init__(self, root, mode, secret):
        self.root = root
        self.mode = mode
        self.secret = secret
        self.seen = set()
        self.faults_used = 0
        self.requests = 0
        try:
            os.makedirs(root, exist_ok=True)
        except OSError as e:
            raise SystemExit(f"fake_receiver: cannot create log dir {root}: {e}") from e
        self.log_path = os.path.join(root, "requests.jsonl")

    def handle(self, headers, body):
        """Return (status_code, response_dict)."""
        payload = None
        if not verify_signature(headers.get("X-Hub-Signature-256", ""), body, self.secret):
            code, resp = 400, {"accepted": False, "reason": "bad_signature"}
        elif headers.get("X-Event-Type") != "agent_task_handoff":
            code, resp = 400, {"accepted": False, "reason": "bad_event_type"}
        else:
            try:
                parsed = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                parsed = None
            if not isinstance(parsed, dict):
                code, resp = 400, {"accepted": False, "reason": "body_not_object"}
            else:
                payload = parsed
                code, resp = self._route(payload)
        self.requests += 1
        rec = {"code": code, "resp": resp, "request_id": headers.get("X-Request-ID"),
               "event_id": (payload or {}).get("event_id")}
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=True, sort_keys=True) + "\n")
        except OSError as e:
            print(f"fake_receiver: log write failed: {e}", file=sys.stderr)
        return code, resp

    def _route(self, payload):
        extra = set(payload) - ALLOWED_FIELDS
        if extra:
            return 400, {"accepted": False, "reason": "payload_fields_not_allowed"}
        if set(payload) != ALLOWED_FIELDS:
            return 400, {"accepted": False, "reason": "payload_fields_missing"}
        if payload["status"] not in STATUSES:
            return 400, {"accepted": False, "reason": "bad_status"}
        if not isinstance(payload["event_id"], str) or not payload["event_id"]:
            return 400, {"accepted": False, "reason": "bad_event_id"}
        if self.mode == "badsig":
            return 401, {"accepted": False, "reason": "auth_rejected"}
        if self.mode in ("500", "redirect") and self.faults_used < 1:
            self.faults_used += 1
            if self.mode == "500":
                return 500, {"accepted": False, "reason": "temporary"}
            return 302, {"accepted": False, "reason": "redirect"}
        eid = payload["event_id"]
        if eid in self.seen:
            return 200, {"accepted": True, "deduped": True}
        self.seen.add(eid)
        return 202, {"accepted": True, "deduped": False, "synthetic_ack_only": True}


class Handler(BaseHTTPRequestHandler):
    receiver: Receiver  # set by serve() before the server starts

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        code, resp = self.receiver.handle(self.headers, body)
        data = json.dumps(resp, ensure_ascii=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if code == 302:
            self.send_header("Location", "http://127.0.0.1:1/refused")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):  # noqa: A002 - BaseHTTPRequestHandler signature
        pass


def serve(receiver, host, port, max_requests=0):
    Handler.receiver = receiver
    httpd = HTTPServer((host, port), Handler)
    if max_requests:
        def watchdog():
            deadline = time.time() + 120
            while time.time() < deadline:
                if receiver.requests >= max_requests:
                    break
                time.sleep(0.05)
            threading.Thread(target=httpd.shutdown, daemon=True).start()
        threading.Thread(target=watchdog, daemon=True).start()
    print(f"fake_receiver listening http://{host}:{port}/ mode={receiver.mode}", flush=True)
    httpd.serve_forever()
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                   "tmp", "fake"))
    ap.add_argument("--mode", default="ok", choices=["ok", "500", "badsig", "redirect"])
    ap.add_argument("--secret-file", required=True, help="synthetic key file; never a real credential")
    ap.add_argument("--max-requests", type=int, default=0)
    args = ap.parse_args()
    try:
        with open(os.path.realpath(args.secret_file), "rb") as f:
            secret = f.read().strip()
    except OSError as e:
        raise SystemExit(f"fake_receiver: cannot read secret file: {e}") from e
    return serve(Receiver(args.root, args.mode, secret), args.host, args.port,
                 args.max_requests)


if __name__ == "__main__":
    sys.exit(main())
