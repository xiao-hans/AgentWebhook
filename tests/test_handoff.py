#!/usr/bin/env python3
"""Synthetic verification for the pi -> Hermes webhook handoff (handoff.py).

Standard library only. No engineering project is touched: every session file,
root and secret is synthetic and lives under tmp/. The HTTP receiver is
fake_receiver.py bound to 127.0.0.1. No real credential is read: the HMAC secret
is generated into a throwaway file under tmp/.

Run: python tests/test_handoff.py            (prints PASS/FAIL per section)
     python -m pytest -q tests/test_handoff.py

Covered (per IMPLEMENTATION-BRIEF.md):
  task_id / path / URL validation, register + allow-root, strict JSONL parsing,
  half-line, no event during a tool call, handoff/compaction summary,
  stopReason length/error, PID-alive report, verifiable PID exit, liveness unknown,
  stable event_id + duplicate tick, cap/backlog, resend retry + backoff,
  5xx/4xx/redirect, loopback-only + proxy bypass, signed envelope,
  webhook response contract (real Hermes 202 status/delivery_id shape, correlation,
    refusal-status/accepted:false vetoes, duplicate termination,
    ignored/filtered/unparseable/mismatch rejections),
  receipt size cap, claim/ack dedup, delivered != accepted, stalled,
  end-to-end synthetic webhook, cron-safe exit codes,
  claude stream-json compatibility (dual-source dispatch, session_id entry check,
    trusted result verdict, foreign-record rejection).
"""

import contextlib
import hashlib
import hmac
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

import fake_receiver  # noqa: E402
import handoff as H  # noqa: E402  (real module, not a copy)

PY = sys.executable
TMP = os.path.join(PROJECT, "tmp")
NOW = 1793400000  # fixed clock for deterministic retries/backoff
FAILURES = []
NONCE = f"{int(time.time())}-{os.getpid()}"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
        return True
    print(f"  FAIL {name} {detail}")
    FAILURES.append(f"{name} {detail}")
    return False


def scenario(tag):
    """Fresh scratch root with a synthetic session file inside it."""
    root = os.path.join(TMP, f"it-{tag}-{NONCE}")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root, exist_ok=True)
    return root, os.path.join(root, "session.jsonl")


def write_session(path, records):
    with open(path, "wb") as f:
        for r in records:
            f.write(r if isinstance(r, bytes) else (json.dumps(r, ensure_ascii=True) + "\n").encode())


def append_lines(path, lines):
    with open(path, "ab") as f:
        for ln in lines:
            f.write(ln if isinstance(ln, bytes) else (ln + "\n").encode())


def rec(role, content, stop=None, ts=None):
    msg = {"role": role, "content": content}
    if stop:
        msg["stopReason"] = stop
    return {"type": "message", "timestamp": ts or 1793000000000, "message": msg}


def tool_block(name="bash"):
    return {"type": "toolCall", "name": name, "arguments": {}}


def as_root(path):
    """Windows keeps 8.3 and long-form spellings of the same file apart."""
    return os.path.realpath(path)


def cli(args, root):
    """Call handoff.main() in-process: validation must exit 2 with a message,
    not a traceback, and without spawning an interpreter per assertion.
    argparse writes usage/errors to stderr, so both streams are captured."""
    buf, ebuf = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(buf), redirect_stderr(ebuf):
            code = H.main(["--root", root, *args])
    except SystemExit as e:  # main() itself never raises; keep the suite alive anyway
        code = e.code if isinstance(e.code, int) else 2
    return code or 0, buf.getvalue() + ebuf.getvalue()


def reg(root, session, tid="task-a", extra=()):
    args = ["register", "--task-id", tid, "--session-path", session,
            "--workdir", PROJECT, "--goal", "合成验收目标", "--next-phase", "phase-1",
            *extra]
    return cli(args, root)


def tick(root, args=()):
    return cli(["tick", "--secret-file", os.path.join(TMP, f"secret-{NONCE}.txt"), *args], root)


def fresh_state(root):
    return H.load_state(root, "x")


def task_reg_at(root, tid):
    return H.load_registry(root)["tasks"][tid]["registered_at"]


def secret_file():
    path = os.path.join(TMP, f"secret-{NONCE}.txt")
    with open(path, "w", encoding="ascii") as f:
        f.write("synthetic-secret\n")
    return path


def events_in(root):
    return H.load_events(root)


def first_event(root):
    evs = list(events_in(root).values())
    assert len(evs) == 1, f"expected 1 event, got {[e['status'] for e in evs]}"
    return evs[0]


def stub_server(handler, host="127.0.0.1"):
    """Return (url, httpd, thread) for a one-shot loopback stub."""
    httpd = HTTPServer((host, 0), handler)
    srv = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    srv.start()
    return f"http://{host}:{httpd.server_address[1]}/", httpd, srv


class RecordingHandler(BaseHTTPRequestHandler):
    hits = []
    mode = "ok"
    secret = b""
    # mode == "json202" sends RESP_CODE with RESP_BODY verbatim: a synthetic receiver that
    # answers with the shape a contract test needs, e.g. the real Hermes 202 webhook body
    resp_code = 202
    resp_body = b"{}"

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        # capture the HTTPMessage, not a dict copy: urllib sends name.title() spellings
        # ("X-Github-Event", "X-Request-Id"), so a case-sensitive dict lookup misses them
        RecordingHandler.hits.append((self.headers, body))
        mode = RecordingHandler.mode
        if mode == "5xx":
            self.send_response(503)
            self.end_headers()
            return
        if mode == "4xx":
            self.send_response(401)
            self.end_headers()
            return
        if mode == "json202":
            self.send_response(RecordingHandler.resp_code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(RecordingHandler.resp_body)
            return
        if mode == "badsig":
            self.send_response(401)
            self.end_headers()
            RecordingHandler.mode = "ok"
            return
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/refused")
            self.end_headers()
            return
        # default "ok": the pre-existing accepted:true shape, still accepted
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"accepted":true}')

    def log_message(self, format, *args):  # noqa: A002 - match BaseHTTPRequestHandler signature
        return


def start_response_stub(code, body):
    """Stub that answers POST with exactly `code` and `body` (str or bytes).

    Synthetic receiver for response-contract tests: every body is authored here, never
    captured from a real system."""
    RecordingHandler.hits = []
    RecordingHandler.mode = "json202"
    RecordingHandler.resp_code = code
    RecordingHandler.resp_body = body.encode() if isinstance(body, str) else body
    return stub_server(RecordingHandler)


def contract_send(sf, body, code=202, tag="x"):
    """register -> tick --no-send -> one `send` against a stub answering (code, body).

    `body` may be a callable taking the pending event_id, so a fixture can echo the id
    this run actually sent. Returns (root, event_id, event_after, rc, stdout, hits)."""
    root, session = scenario(f"resp-{tag}")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    reg(root, session, extra=("--synthetic",))
    tick(root, ["--no-send"])
    eid = first_event(root)["event_id"]
    payload = body(eid) if callable(body) else body
    url, httpd, srv = start_response_stub(code, payload)
    rc, out = cli(["send", "--url", url, "--secret-file", sf], root)
    ev = first_event(root)
    hits = len(RecordingHandler.hits)
    httpd.shutdown()
    srv.join(timeout=2)
    RecordingHandler.mode = "ok"
    return root, eid, ev, rc, out, hits


def start_stub(mode="ok"):
    RecordingHandler.hits = []
    RecordingHandler.mode = mode
    return stub_server(RecordingHandler)


# ---------------------------------------------------------------------------
# 0. environment: real python, stdlib only
# ---------------------------------------------------------------------------
def t00_env():
    print("\n### 0. environment")
    v = sys.version_info
    check("python >= 3.11", (v.major, v.minor) >= (3, 11), f"{v.major}.{v.minor}")
    check("pid_exists(os.getpid()) is True", H.pid_exists(os.getpid()) is True)
    gone = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(0)"])
    gone.wait()
    check("pid_exists(exited pid) is False", H.pid_exists(gone.pid) is False, str(gone.pid))
    check("pid_exists(None) is None (unknown)", H.pid_exists(None) is None)


# ---------------------------------------------------------------------------
# 1. validation: task_id, paths, URLs, receipts
# ---------------------------------------------------------------------------
def t01_validation():
    print("\n### 1. validation: task_id / path / loopback URL")
    for good in ("a", "task-1", "mcp-hermes_partial.2", "A1", "a.b", "x" * 64):
        check(f"task_id accepted: {good[:14]}", H.validate_task_id(good) == good)
    for bad in ("", "..", "a..b", "a/b", "a\\b", ".hidden", "-lead", "a b", "tašk",
                "x" * 65, "_lead"):
        try:
            H.validate_task_id(bad)
        except ValueError:
            check(f"task_id rejected: {bad[:14]!r}", True)
        else:
            check(f"task_id rejected: {bad[:14]!r}", False, "accepted, should raise")

    for ok in ("http://127.0.0.1:8644/webhook", "http://localhost:8644/hooks/x",
               "https://127.0.0.1/webhook"):
        check(f"loopback url ok: {ok}", H.validate_loopback_url(ok) == ok)
    for bad in ("http://evil.example.com/", "http://10.0.0.5:8644/", "http://[::1]:8644/",
                "file:///c:/windows/win.ini", "http://127.0.0.1@evil.example.com/",
                "ftp://127.0.0.1/", "", "http://192.168.1.1/", "http://0.0.0.0/",
                "https://sub.example.com/", "not-a-url"):
        try:
            H.validate_loopback_url(bad)
        except ValueError:
            check(f"url rejected: {bad[:22]!r}", True)
        else:
            check(f"url rejected: {bad[:22]!r}", False, "accepted, should raise")

    # CLI surface: bad task_id and escaping session path must exit 2 with a message
    root, session = scenario("validate-cli")
    write_session(session, [rec("assistant", "x", stop="stop")])
    code, out = cli(["register", "--task-id", "bad id!", "--session-path", session,
                     "--workdir", PROJECT, "--goal", "合成验收目标"], root)
    check("register bad task_id -> rc2", code == 2, f"rc={code} out={out[:80]!r}")
    check("no traceback for bad task_id", "Traceback" not in out, out[:120])
    check("error names task_id", "task_id" in out, out[:120])
    escape = os.path.join(TMP, "nope", "..", "it-validate-cli", "session.jsonl")
    code, out = cli(["register", "--task-id", "t", "--session-path", escape,
                     "--workdir", PROJECT, "--goal", "合成验收目标"], root)
    check("register path with '..' -> rc2", code == 2, out[:120])
    check("'..' rejected by name", "'..' segments" in out, out[:160])
    outside = os.path.abspath(os.path.join(os.environ.get("SYSTEMROOT", "C:/Windows"),
                                           "tasks", "Handoff-Outside.txt"))
    code, out = cli(["register", "--task-id", "t2", "--session-path", outside,
                     "--workdir", PROJECT, "--goal", "合成验收目标"], root)
    check("register non-existent session file -> rc2", code == 2, out[:160])
    check("reports not-an-existing-file", "not an existing file" in out, out[:160])

    # --allow-root containment: register validates that the session path IS an
    # existing file (handoff.py:220-223), so the fixture must create it first.
    # --allow-root then covers BOTH the session path and the workdir
    # (handoff.py:1173-1175), so a positive fixture must place every registered path
    # inside the approved root instead of widening the root to fit outside paths.
    root2, session2 = scenario("allowroot")
    write_session(session2, [rec("assistant", "x", stop="stop")])
    real_session = as_root(session2)
    code, out = cli(["register", "--task-id", "t", "--session-path", real_session,
                     "--workdir", as_root(TMP), "--goal", "合成验收目标",
                     "--allow-root", as_root(TMP)], root2)
    check("session under --allow-root ok", code == 0, out[:160])
    # the guard itself: a workdir outside the approved root is refused with rc2
    code, out = cli(["register", "--task-id", "t3", "--session-path", real_session,
                     "--workdir", PROJECT, "--goal", "合成验收目标",
                     "--allow-root", as_root(TMP)], root2)
    check("workdir outside --allow-root -> rc2", code == 2, out[:160])
    check("rejection names workdir + allowed roots",
          "workdir resolves outside allowed roots" in out, out[:200])
    code, out = cli(["tick"], root2)
    check("tick under allowed root ran", code == 0, out[:120])

    # clean guard refuses the live default root
    code, out = cli(["clean", "--root", as_root(H.default_root())], TMP)
    check("clean refuses live default root", code == 2 and "refusing" in out, out[:120])


# ---------------------------------------------------------------------------
# 2. registration + first report
# ---------------------------------------------------------------------------
def t02_register_report():
    print("\n### 2. register + tick: report with live PID -> report_ready, never auto-accepted")
    root, session = scenario("report-ready")
    write_session(session, [
        rec("user", "do the work"),
        rec("assistant", [tool_block("bash")]),
        {"type": "toolResult", "message": {"role": "toolResult", "content": "ok"}},
        rec("assistant", "phase A complete, tests green, webhook not yet deployed", stop="stop"),
    ])
    me = os.getpid()
    code, out = reg(root, session, extra=["--pid", str(me)])
    check("register rc0", code == 0, out[:160])
    check("register echoes task_id", '"task_id"' in out, out[:160])
    code, out = reg(root, session)
    check("duplicate register -> rc2 + says --force", code == 2 and "--force" in out, out[:160])
    code, out = tick(root, ["--verbose-send"])
    check("tick rc0 without receiver configured", code == 0, out[:200])
    check("tick reports the event", "EVENT report_ready" in out, out[:200])
    ev = first_event(root)
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("event status report_ready", ev["status"] == "report_ready", str(ev["status"]))
    check("reason is stopReason=stop", ev["reason"] == "final assistant report (stopReason=stop)",
          ev["reason"])
    check("PID-alive report is informational", ev["state"] == "pending", str(ev["state"]))
    check("nothing auto-accepted", "accepted" not in json.dumps(ev), str(ev)[:200])
    check("no verdict yet", ev.get("verdict") is None)
    check("offset advanced to file size", st["offset"] == os.path.getsize(session),
          f"{st['offset']} vs {os.path.getsize(session)}")
    check("line_seq counted", st["line_seq"] == 4, str(st["line_seq"]))
    check("tool_open closed by toolResult", st["tool_open"] is False, str(st["tool_open"]))
    check("pid_status true", st["pid_status"] is True, str(st["pid_status"]))
    check("tool timeline kept", st["last_tool"]["tool"] == "bash", str(st["last_tool"]))
    recp = H.read_json(ev["receipt_path"], {})
    for key, want in (("event_id", ev["event_id"]), ("task_id", "task-a"),
                      ("status", "report_ready"), ("pid_status", True), ("pid", me),
                      ("synthetic", False), ("lines_seen", 4), ("bad_lines", 0)):
        check(f"receipt.{key}", recp.get(key) == want, f"{recp.get(key)!r} != {want!r}")
    check("receipt carries task context goal/next_phases/workdir",
          recp.get("goal") == "合成验收目标" and recp.get("next_phases") == ["phase-1"]
          and recp.get("workdir"), str(recp)[:200])
    check("receipt has bounded final text", "phase A complete" in recp.get("final_text", ""),
          str(recp.get("final_text"))[:80])
    check("receipt has no session path", "session_path" not in recp, str(list(recp))[:200])
    check("receipt has no credentials/secret", "secret" not in json.dumps(recp).lower())
    check("receipt has no tool arguments", "arguments" not in json.dumps(recp), str(recp)[:200])

    # tick again with no new bytes: no new event, send still pending, state unchanged
    before = json.dumps(first_event(root), sort_keys=True)
    code, out = tick(root, ["--no-send"])
    check("second tick rc0", code == 0, out[:120])
    check("second tick emits no event", "EVENT" not in out, out[:200])
    check("second tick did not create a duplicate", "duplicate" not in out, out[:200])
    check("terminal task is skipped on later ticks", out.strip() == "", out[:200])
    check("state unchanged after duplicate tick",
          json.dumps(first_event(root), sort_keys=True) == before)
    check("still exactly 1 event", len(events_in(root)) == 1, str(len(events_in(root))))

    # idempotent across --force full rescan (stable event_id)
    code, out = cli(["tick", "--force"], root)
    check("forced rescan rc0", code == 0, out[:160])
    check("forced rescan did NOT duplicate the event", "duplicate" in out, out[:200])
    check("still 1 event after rescan", len(events_in(root)) == 1, str(events_in(root)))

    # status readback
    code, out = cli(["status", "--json"], root)
    doc = json.loads(out)
    task = doc["task-a"]
    check("status --json exposes task/state/events",
          {"task", "state", "events"} <= set(task), str(list(task)))
    check("status shows the unaccepted event", task["events"][0]["state"] == "pending",
          str(task["events"][0]))
    check("status says delivered!=accepted via state field",
          task["events"][0]["state"] != "accepted")


# ---------------------------------------------------------------------------
# 3. classification rules (no false positives)
# ---------------------------------------------------------------------------
def t03_classification():
    print("\n### 3. classification: tool-in-flight, summary, length/error, garbage")
    # (a) last record is a toolCall -> NO event even though the process is dead
    root, session = scenario("tool-open")
    write_session(session, [
        rec("assistant", "working"),
        rec("assistant", [tool_block("write")]),
    ])
    pid = subprocess.Popen([PY, "-c", "import time; time.sleep(0.1)"])
    pid.wait()
    code, out = reg(root, session, extra=["--pid", str(pid.pid), "--synthetic"])
    check("register with dead pid + --synthetic rc0", code == 0, out[:200])
    code, out = tick(root, ["--no-send"])
    check("no event while a tool call is unresolved", "EVENT" not in out, out[:240])
    check("no failed event from liveness during tool call", "failed" not in out, out[:240])
    st = H.read_json(H.p_state(root, "task-a"), {}) or {}
    check("state remembers the open tool", st["tool_open"] is True, str(st))
    check("last_tool recorded", st["last_tool"]["tool"] == "write", str(st["last_tool"]))

    # (b) handoff/compaction summary text -> stopped_unfinished, never report_ready
    root, session = scenario("summary")
    write_session(session, [rec("assistant", "上下文交接摘要：任务已完成大部分", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    code, out = tick(root, ["--no-send"])
    ev = first_event(root)
    check("summary -> stopped_unfinished", ev["status"] == "stopped_unfinished", str(ev["status"]))
    check("summary reason says not accepted", "not an accepted result" in ev["reason"], ev["reason"])
    check("summary event is synthetic", ev["synthetic"] is True)
    for probe in ("上下文交接摘要", "压缩摘要", "上下文交接", "Context-Handoff Summary",
                  "Compaction summary", "handoff summary"):
        check(f"classify summary: {probe[:18]}", H.classify_final_text(probe) == "summary")
    for probe in ("已实现 handoff.py，测试通过", "All tests pass, see README",
                  "交付完成，结果如下", "上下文已处理完毕"):
        check(f"classify report: {probe[:18]}", H.classify_final_text(probe) == "report", probe)

    # (c) stopReason length / error: length is unfinished, error is a failed run
    for stop, want, mention in (("length", "stopped_unfinished", "output incomplete"),
                                 ("error", "failed", "the run failed")):
        root, session = scenario(f"stop-{stop}")
        write_session(session, [rec("assistant", "half a sentence", stop=stop)])
        cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
             "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
        tick(root, ["--no-send"])
        ev = first_event(root)
        check(f"stopReason {stop} -> {want}", ev["status"] == want, str(ev["status"]))
        check(f"stopReason {stop} reason mentions {mention}",
              mention in ev["reason"], ev["reason"])
        check(f"stopReason {stop} is informational only", ev["state"] == "pending")

    # (d) garbage and foreign records: counted, never fatal, no event
    root, session = scenario("garbage")
    write_session(session, [
        b'{"this": "is not a pi message"}\n',
        b'not json at all\n',
        b'\xff\xfe bad bytes\n',
        rec("system", "role not tracked"),
    ])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标"], root)
    code, out = tick(root, ["--no-send"])
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("garbage tick rc0", code == 0, out[:160])
    check("no event from garbage", "EVENT" not in out, out[:200])
    check("bad_lines counted", st["bad_lines"] == 4, str(st["bad_lines"]))
    check("line_seq unchanged for untracked roles", st["line_seq"] == 0, str(st["line_seq"]))

    # (e) half-line: a truncated final record stays unconsumed until the newline lands
    root, session = scenario("half-line")
    write_session(session, [rec("user", "start")])
    final = json.dumps(rec("assistant", "final report text", stop="stop"), ensure_ascii=True)
    with open(session, "ab") as f:
        f.write(final[:18].encode())  # partial line, no newline
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标"], root)
    code, out = tick(root, ["--no-send"])
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("half-line: no event", "EVENT" not in out, out[:200])
    check("half-line: offset did not consume the tail",
          st["offset"] == len(json.dumps(rec("user", "start"), ensure_ascii=True)) + 1,
          str(st["offset"]))
    check("half-line: bad_lines stayed 0", st["bad_lines"] == 0, str(st["bad_lines"]))
    check("half-line: pending_size remembered",
          st["pending_size"] == os.path.getsize(session), str(st["pending_size"]))
    # complete the line and tick again
    append_lines(session, [final[18:]])
    code, out = tick(root, ["--no-send"])
    check("completed half-line -> report_ready", "EVENT report_ready" in out, out[:200])
    check("completed half-line consumed", "backlog" not in out, out[:200])

    # (f) final record with NO trailing newline and no verifiable process exit:
    #     size stability is not proof the writer finished, so the tail is never consumed
    root, session = scenario("no-newline-tail")
    tail = json.dumps(rec("assistant", "tail without newline", stop="stop"),
                      ensure_ascii=True).encode()
    with open(session, "wb") as f:
        f.write(tail)  # must exist before register: validate_session_path rejects it
    code, out = cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
                     "--workdir", PROJECT, "--goal", "合成验收目标"], root)
    check("tail w/o newline: register rc0", code == 0, f"rc={code} out={out[:160]!r}")
    code, out = tick(root, ["--no-send"])
    check("tail w/o newline: 1st tick holds it", "EVENT" not in out, out[:200])
    code, out = tick(root, ["--no-send"])
    st = H.read_json(H.p_state(root, "task-a"), {})
    # the half line really is unconsumed: cursor parked at 0, the whole tail pending
    check("tail w/o newline stays unconsumed without verifiable exit",
          "EVENT" not in out and st["offset"] == 0 and st["bad_lines"] == 0
          and st["pending_size"] == len(tail) == os.path.getsize(session),
          f"{out[:160]} {st}")


# ---------------------------------------------------------------------------
# 4. process-exit classification (verifiable only)
# ---------------------------------------------------------------------------
def t04_pid_exit():
    print("\n### 4. verifiable process exit")
    # (a) dead PID, last record is final text -> report_ready (no rescan needed)
    root, session = scenario("pid-dead-final")
    write_session(session, [rec("assistant", "phase B done", stop="stop")])
    gone = subprocess.Popen([PY, "-c", "import sys; sys.exit(0)"])
    gone.wait()
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--pid", str(gone.pid), "--synthetic"], root)
    code, out = tick(root, ["--no-send"])
    check("dead pid w/ final report rc0", code == 0, out[:160])
    ev = first_event(root)
    check("dead pid final -> exactly 1 event", len(events_in(root)) == 1, str(events_in(root)))
    check("dead pid final keeps report_ready", ev["status"] == "report_ready", str(ev["status"]))
    check("pid_status false in state", H.read_json(H.p_state(root, "task-a"), {})["pid_status"]
          is False)

    # (b) dead PID, no final report -> stopped_unfinished, not failed
    root, session = scenario("pid-dead-no-report")
    write_session(session, [rec("user", "开始执行任务")])
    gone = subprocess.Popen([PY, "-c", "import sys; sys.exit(0)"])
    gone.wait()
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--pid", str(gone.pid), "--synthetic"], root)
    code, out = tick(root, ["--no-send"])
    check("exit-without-report event emitted", "EVENT stopped_unfinished" in out, out[:240])
    ev = first_event(root)
    check("reason mentions exit", "without a final assistant report" in ev["reason"], ev["reason"])
    check("status stopped_unfinished (not failed)", ev["status"] == "stopped_unfinished",
          str(ev["status"]))
    check("no event claims a project outcome",
          all(w not in json.dumps(ev, ensure_ascii=False)
              for w in ("项目完成", "任务成功", "accepted")), str(ev)[:240])

    # (c) dead PID with zero readable records -> stalled (no session records)
    root, session = scenario("pid-dead-silent")
    with open(session, "wb"):
        pass
    gone = subprocess.Popen([PY, "-c", "import sys; sys.exit(0)"])
    gone.wait()
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--pid", str(gone.pid), "--synthetic"], root)
    code, out = tick(root, ["--no-send"])
    check("silent dead pid -> stalled", "EVENT stalled" in out, out[:240])
    sev = first_event(root)
    # the reason text lives on the event; tick only prints "EVENT stalled <id> (pid exit)"
    # (handoff.py:802-808), so asserting the wording against stdout was the wrong surface
    check("stalled reason names the no-record condition",
          sev["status"] == "stalled" and "before any session record" in sev["reason"],
          sev["reason"])
    check("stalled is terminal for the scan", len(events_in(root)) == 1)

    # (d) unverifiable liveness: pid absent -> nothing terminal
    root, session = scenario("liveness-unknown")
    write_session(session, [rec("assistant", [tool_block("bash")])])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    code, out = tick(root, ["--no-send"])
    check("live tool call without pid: no event", "EVENT" not in out, out[:200])
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("pid_status is null (unknown)", st["pid_status"] is None, str(st["pid_status"]))

    # (e) stopReason=error is the only automatic producer of 'failed'
    root, session = scenario("inject-failed")
    write_session(session, [rec("assistant", "boom", stop="error")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    tick(root, ["--no-send"])
    check("stopReason error -> failed", first_event(root)["status"] == "failed",
          str(first_event(root)["status"]))
    check("failed is informational only", first_event(root)["state"] == "pending",
          str(first_event(root)["state"]))
    check("failed survives a write/read round trip",
          first_event(root)["status"] == "failed", str(first_event(root)["status"]))
    check("status readback shows failed", "failed" in cli(["status"], root)[1],
          cli(["status"], root)[1][:200])


# ---------------------------------------------------------------------------
# 5. caps, backlog, stall detection
# ---------------------------------------------------------------------------
def t05_caps_and_stall():
    print("\n### 5. per-tick caps, backlog, receipt size cap, stall")
    # (a) byte cap: a huge session is consumed in bounded slices
    root, session = scenario("backlog")
    big = [{"type": "message", "timestamp": 1,
            "message": {"role": "user", "content": "x" * 400}} for _ in range(40)]
    write_session(session, big)
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标"], root)
    code, out = tick(root, ["--no-send", "--max-bytes", "2000"])
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("capped tick reports backlog", "backlog remains" in out, out[:200])
    check("capped tick consumed <= max-bytes", st["offset"] <= 2000, str(st["offset"]))
    check("capped tick emitted no event", "EVENT" not in out, out[:200])
    seen_first = st["offset"]
    code, out = tick(root, ["--no-send", "--max-bytes", "2000"])
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("second capped tick advanced further", st["offset"] > seen_first,
          f"{st['offset']} > {seen_first}")
    # drain fully: the last record is not a report, so still no event
    for _ in range(30):
        tick(root, ["--no-send"])
        if H.read_json(H.p_state(root, "task-a"), {})["offset"] == os.path.getsize(session):
            break
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("backlog drains to EOF", st["offset"] == os.path.getsize(session), str(st["offset"]))
    check("no event for a user-only session", len(events_in(root)) == 0, str(events_in(root)))
    check("line_seq matches records", st["line_seq"] == 40, str(st["line_seq"]))

    # (b) record cap
    root, session = scenario("record-cap")
    write_session(session, [rec("user", f"line {i}") for i in range(10)])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标"], root)
    env = dict(os.environ, AGENT_HANDOFF_MAX_RECORDS="3")
    code, out = cli_with(env, ["tick", "--no-send"], root)
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("record cap reported", "record cap" in out, out[:200])
    check("record cap limited lines", st["line_seq"] == 3, str(st["line_seq"]))

    # (c) receipt size cap: long final text + huge timeline is bounded, still valid JSON
    root, session = scenario("receipt-cap")
    records = []
    for i in range(80):
        records.append(rec("assistant", [tool_block(f"tool{i}")]))
        records.append({"type": "toolResult", "message": {"role": "toolResult", "content": "ok"}})
    records.append(rec("assistant", "结论：" + ("很长的报告正文 " * 3000), stop="stop"))
    write_session(session, records)
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标"], root)
    tick(root, ["--no-send"])
    ev = first_event(root)
    size = os.path.getsize(ev["receipt_path"])
    check("receipt <= 64 KiB", size <= H.MAX_RECEIPT_BYTES, f"{size} bytes")
    recp = H.read_json(ev["receipt_path"], None)
    check("receipt is valid JSON", isinstance(recp, dict), str(type(recp)))
    if not isinstance(recp, dict):
        recp = {}
    check("receipt kept timeline", len(recp["tool_timeline"]) > 0, str(len(recp["tool_timeline"])))
    check("timeline capped at 50", len(recp["tool_timeline"]) <= H.MAX_TIMELINE,
          str(len(recp["tool_timeline"])))
    check("final text capped at 8000", len(recp["final_text"]) <= H.MAX_FINAL_CHARS,
          str(len(recp["final_text"])))
    # receipt_overflow_trim is only set by the SECOND reduction, taken when the
    # serialized body still passes 64 KiB (handoff.py:569-575, 595-600). The body here
    # fits (checked above), so the proof of body trimming is final_text_truncated.
    check("final text truncation recorded", recp.get("final_text_truncated") is True,
          str(recp.get("final_text_truncated")))
    check("no second reduction needed at this size", "receipt_overflow_trim" not in recp,
          str(recp.get("receipt_overflow_trim")))
    check("event stores receipt_bytes", ev["receipt_bytes"] == size,
          f"{ev['receipt_bytes']} vs {size}")
    check("receipt holds no raw session dump",
          "content" not in json.dumps(recp), str(list(recp))[:200])

    # (c2) true second-stage 64 KiB overflow: goal + 4 next_phases at the 2000-char cap
    # keep the serialized receipt above MAX_RECEIPT_BYTES even AFTER build_receipt's
    # first trim (final_text->1000, timeline->10), which is the only path that sets
    # receipt_overflow_trim (handoff.py:569-575); create_event then drops final_text
    # entirely (595-600) so the written body returns under the cap.
    root, session = scenario("receipt-overflow")
    records = []
    for i in range(80):
        records.append(rec("assistant", [tool_block(f"tool{i}")]))
        records.append({"type": "toolResult", "message": {"role": "toolResult", "content": "ok"}})
    records.append(rec("assistant", "结论：" + ("很长的报告正文 " * 3000), stop="stop"))
    write_session(session, records)
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "目标" * 1000, "--synthetic",
         *[x for _ in range(4) for x in ("--next-phase", "阶段" * 1000)]], root)
    tick(root, ["--no-send"])
    ev = first_event(root)
    size = os.path.getsize(ev["receipt_path"])
    recp = H.read_json(ev["receipt_path"], {})
    check("overflow fixture still bounded by 64 KiB", size <= H.MAX_RECEIPT_BYTES,
          f"{size} bytes")
    check("second-stage overflow flag really set", recp.get("receipt_overflow_trim") is True,
          str(recp.get("receipt_overflow_trim")))
    check("overflow drops final text and flags truncation",
          recp.get("final_text") == "" and recp.get("final_text_truncated") is True,
          str(((recp.get("final_text") or "")[:40], recp.get("final_text_truncated"))))
    check("event stores overflow receipt size", ev["receipt_bytes"] == size,
          f"{ev['receipt_bytes']} vs {size}")

    # (e) over-limit record: skipped bytes are recorded and the verdict is honest
    root, session = scenario("over-limit")
    big = json.dumps(rec("assistant", "y" * 300_000, stop="stop"), ensure_ascii=True).encode() + b"\n"
    with open(session, "wb") as f:
        f.write(big)
    gone = subprocess.Popen([PY, "-c", "import sys; sys.exit(0)"])
    gone.wait()
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--pid", str(gone.pid),
         "--synthetic"], root)
    # A 300 KB record cannot be swallowed by one 2048-byte window: read_incremental
    # advances whole windows per tick and discards them unread (handoff.py:497-503).
    # Drain it with a bounded tick count at the SAME budget - no inflation.
    bound = 2048
    max_ticks = (len(big) + bound - 1) // bound + 2
    prev, ticks, violations, early = 0, 0, [], None
    while ticks < max_ticks:
        code, out = tick(root, ["--no-send", "--max-bytes", str(bound)])
        ticks += 1
        st = H.read_json(H.p_state(root, "task-a"), {})
        if code != 0:
            violations.append(("rc", code, out[:120]))
            break
        advance = st["offset"] - prev
        if not 0 < advance <= bound:
            violations.append((prev, st["offset"]))
        prev = st["offset"]
        if prev < len(big) and ("EVENT" in out or events_in(root)):
            early = (ticks, prev, out[:120])
        if prev >= len(big):
            break
    check("each over-limit tick advanced within the read budget", not violations,
          str(violations[:3]))
    check("over-limit backlog drained in bounded ticks", prev == len(big),
          f"offset={prev} after {ticks} ticks of {bound}B")
    check("no terminal verdict before the backlog drained", early is None, str(early))
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("over-limit skipped bytes persisted", st.get("skipped_bytes", 0) >= len(big) - bound,
          str(st.get("skipped_bytes")))
    check("over-limit flag persisted", st.get("over_limit") is True, str(st)[:200])
    check("cursor still advances over the huge record", st["offset"] == len(big), str(st["offset"]))
    code, out = tick(root, ["--no-send", "--max-bytes", str(bound)])
    check("later over-limit tick does not duplicate the verdict", len(events_in(root)) == 1,
          str(len(events_in(root))))
    ev = first_event(root)
    check("over-limit verdict is stopped_unfinished", ev["status"] == "stopped_unfinished",
          str(ev["status"]))
    check("over-limit reason names the limit",
          "over-limit" in ev["reason"] and "skipped" in ev["reason"], ev["reason"])
    check("over-limit never claims no-record", "before any session record" not in ev["reason"],
          ev["reason"])

    # (f) stall detection is time-based, and does not invent a final status
    root, session = scenario("stall")
    write_session(session, [rec("user", "thinking...")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    st = H.read_json(H.p_state(root, "task-a"), {})
    st["last_activity_at"] = NOW - 10_000_000  # ancient synthetic clock
    H.write_json_atomic(H.p_state(root, "task-a"), st)
    code, out = cli(["tick", "--no-send"], root)
    check("stalled event emitted", "EVENT stalled" in out, out[:240])
    check("stalled mentions the idle window", "idle" in out, out[:240])
    evs = list(events_in(root).values())
    stalled = [e for e in evs if e["status"] == "stalled"]
    check("exactly one stalled event", len(stalled) == 1, str([e["status"] for e in evs]))
    check("stalled event id is stable",  # fp=stall:<registered_at>:<offset> binds the id to this run
          stalled[0]["event_id"] == H.make_event_id(
              "task-a", "stalled", stalled[0]["reason"],
              "stall:{}:{}".format(task_reg_at(root, "task-a"), H.load_state(root, "task-a")["offset"])))
    # another stalled tick must not duplicate
    st = H.read_json(H.p_state(root, "task-a"), {})
    st["last_activity_at"] = NOW - 10_000_000
    H.write_json_atomic(H.p_state(root, "task-a"), st)
    code, out = cli(["tick", "--no-send"], root)
    check("second stalled tick dedups", len(events_in(root)) == 1, str(events_in(root)))
    check("stalled is not a report_ready/failed claim",
          stalled[0]["status"] not in ("report_ready", "failed"))


# ---------------------------------------------------------------------------
# 6. outbox: persistence, retries, signatures, redirect, loopback-only
# ---------------------------------------------------------------------------
def t06_outbox():
    print("\n### 6. outbox persistence, retry/backoff, envelope, redirect, proxy")
    sf = secret_file()

    # (a) no receiver configured -> events persist, rc 0, nothing sent
    root, session = scenario("no-url")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    code, out = tick(root, ["--no-send"])
    ev = first_event(root)
    # the no-receiver path is tick's own send phase: no --url, no $AGENT_HANDOFF_URL
    env = dict.fromkeys(("AGENT_HANDOFF_URL", "AGENT_HANDOFF_SECRET_FILE"), "")
    code, out = cli_with(env, ["tick"], root)
    check("send without url rc0", code == 0, out[:160])
    check("send without url keeps pending", "stay pending" in out or "nothing pending" in out,
          out[:200])
    check("event persisted on disk", os.path.isfile(H.p_event(root, ev["event_id"])))
    check("journal recorded create", "created" in _readtext(H.p_journal(root)))

    # (b) connection refused -> pending + backoff + identical event_id on retry
    root, session = scenario("refused")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    tick(root, ["--no-send"])
    ev = first_event(root)
    dead_port = _free_port()
    code, out = cli(["send", "--url", f"http://127.0.0.1:{dead_port}/hook",
                     "--secret-file", sf], root)
    ev1 = first_event(root)
    check("transport failure keeps rc0", code == 0, out[:160])
    check("transport failure stays pending", ev1["state"] == "pending", str(ev1["state"]))
    check("attempts counted", ev1["attempts"] == 1, str(ev1["attempts"]))
    check("event_id unchanged after failure", ev1["event_id"] == ev["event_id"])
    check("backoff scheduled", ev1["next_retry_at"] > ev1["created_at"],
          f"{ev1['next_retry_at']} vs {ev1['created_at']}")
    check("history records the error", ev1["history"][-1].get("error"), str(ev1["history"]))
    check("retry not scheduled before backoff elapses",
          cli(["send", "--url", f"http://127.0.0.1:{dead_port}/hook", "--secret-file", sf],
              root)[0] == 0)
    check("second attempt counted", first_event(root)["attempts"] == 1,
          "backoff window must gate the retry: " + str(first_event(root)["attempts"]))
    j = _readtext(H.p_journal(root))
    check("journal logged retry_scheduled", "retry_scheduled" in j, j[:200])

    # max attempts -> blocked
    evs = events_in(root)
    e = evs[ev["event_id"]]
    e["attempts"] = e["max_attempts"] - 1
    e["next_retry_at"] = 0
    H.save_event(root, e, "manual")
    code, out = cli(["send", "--url", f"http://127.0.0.1:{dead_port}/hook",
                     "--secret-file", sf], root)
    e2 = first_event(root)
    check("max attempts -> blocked", e2["state"] == "blocked", str(e2["state"]))
    check("blocked reason recorded", e2.get("reason_blocked") == "max attempts exceeded",
          str(e2)[:200])

    # (c) 5xx -> retry, then 2xx -> delivered, same event_id throughout
    root, session = scenario("flaky")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    tick(root, ["--no-send"])
    ev = first_event(root)
    url, httpd, srv = start_stub("5xx")
    code, out = cli(["send", "--url", url, "--secret-file", sf], root)
    check("5xx keeps pending", first_event(root)["state"] == "pending", out[:200])
    check("5xx attempt counted", first_event(root)["attempts"] == 1)
    first_id = first_event(root)["event_id"]
    e = first_event(root)
    e["next_retry_at"] = 0
    H.save_event(root, e, "manual")
    RecordingHandler.mode = "ok"
    code, out = cli(["send", "--url", url, "--secret-file", sf], root)
    e2 = first_event(root)
    httpd.shutdown()
    srv.join(timeout=2)
    check("retry after 5xx reaches delivered", e2["state"] == "delivered", out[:200])
    check("event_id stable across retry", e2["event_id"] == first_id == ev["event_id"])
    check("delivered_at recorded", isinstance(e2.get("delivered_at"), int))
    hdrs, body = RecordingHandler.hits[-1]
    payload = json.loads(body)
    check("payload has exactly the 4 allowed fields",
          set(payload) == {"schema_version", "task_id", "event_id", "status"}, str(payload))
    check("payload carries no body/paths/credentials",
          not any(k in body.decode(errors="replace") for k in
                  ("session", "receipt", "secret", "goal", "final_text")), body[:200])
    want = "sha256=" + hmac.new(_readtext(sf).strip().encode(), body, hashlib.sha256).hexdigest()
    check("X-Hub-Signature-256 matches HMAC-SHA256(body)",
          hdrs.get("X-Hub-Signature-256") == want, str(hdrs.get("X-Hub-Signature-256"))[:40])
    check("X-Event-Type is agent_task_handoff", hdrs.get("X-Event-Type") == "agent_task_handoff")
    check("X-GitHub-Event also carries the event type",
          hdrs.get("X-GitHub-Event") == "agent_task_handoff", str(hdrs.get("X-GitHub-Event")))
    check("X-Request-ID stable", hdrs.get("X-Request-ID") == f"agent-handoff-{ev['event_id']}",
          str(hdrs.get("X-Request-ID")))
    req_ids = {h0.get("X-Request-ID") for h0, _ in RecordingHandler.hits}
    check("retry reuses the same X-Request-ID", len(req_ids) == 1, str(req_ids))
    check("Content-Type json", hdrs.get("Content-Type") == "application/json")

    # (d) bad signature -> 401 -> blocked, no bypass, no further retry
    root, session = scenario("badsig")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    tick(root, ["--no-send"])
    url, httpd, srv = start_stub("badsig")
    code, out = cli(["send", "--url", url, "--secret-file", sf], root)
    e = first_event(root)
    check("4xx -> blocked", e["state"] == "blocked", str(e["state"]))
    check("4xx reason carries code", e.get("reason_blocked") == "http 401", str(e)[:200])
    e["next_retry_at"] = 0
    H.save_event(root, e, "manual")
    code, out = cli(["send", "--url", url, "--secret-file", sf], root)
    check("blocked event is not retried", first_event(root)["state"] == "blocked",
          str(first_event(root)))
    httpd.shutdown()
    srv.join(timeout=2)

    # (e) 3xx redirect -> refused
    root, session = scenario("redirect")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    tick(root, ["--no-send"])
    url, httpd, srv = start_stub("redirect")
    code, out = cli(["send", "--url", url, "--secret-file", sf], root)
    e = first_event(root)
    check("redirect refused -> blocked", e["state"] == "blocked", out[:200])
    check("redirect reason recorded", "redirect rejected" in e.get("reason_blocked", ""),
          str(e)[:200])
    check("stub received exactly one request (no follow)", len(RecordingHandler.hits) == 1,
          str(len(RecordingHandler.hits)))
    httpd.shutdown()
    srv.join(timeout=2)

    # (f) non-loopback URL -> refused before any network call
    root, session = scenario("non-loopback")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    tick(root, ["--no-send"])
    code, out = cli(["send", "--url", "http://evil.example.com/hook", "--secret-file", sf], root)
    check("non-loopback url rc2", code == 2, out[:160])
    check("non-loopback refused by name", "only loopback receivers allowed" in out, out[:160])
    check("non-loopback send left event pending", first_event(root)["state"] == "pending")
    check("no secret leaked to stdout", "synthetic-secret" not in out, out[:160])

    # (g) env proxy must not intercept loopback
    root, session = scenario("proxy-bypass")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    tick(root, ["--no-send"])
    url, httpd, srv = start_stub("ok")
    host, port = url.split("//")[1].split("/")[0].split(":")
    proxy = f"http://{host}:{_free_port()}"  # a port with nothing listening
    env = dict(os.environ, HTTP_PROXY=proxy, http_proxy=proxy, HTTPS_PROXY=proxy,
               https_proxy=proxy, NO_PROXY="", no_proxy="")
    code, out = cli_with(env, ["send", "--url", url, "--secret-file", sf], root)
    e = first_event(root)
    httpd.shutdown()
    srv.join(timeout=2)
    check("loopback delivered despite env proxy", e["state"] == "delivered",
          f"{out[:160]} proxy={proxy}")
    check("event did not route through the proxy", "timed out" not in str(e)[:400], str(e)[:300])

    # (h) tick sends inline when configured
    root, session = scenario("tick-send")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    url, httpd, srv = start_stub("ok")
    code, out = cli(["tick", "--url", url, "--secret-file", sf, "--verbose-send"], root)
    httpd.shutdown()
    srv.join(timeout=2)
    check("tick --url delivers", "delivered" in out, out[:240])
    check("tick created and sent one event", first_event(root)["state"] == "delivered")


# ---------------------------------------------------------------------------
# 6b. webhook response contract: real Hermes 202 shape, correlation, rejection
# ---------------------------------------------------------------------------
_REAL_HERMES = ('{"status":"accepted","route":"agent-task-handoff",'
                '"cron_job":"cron-example","event":"agent_task_handoff",')


def t06b_webhook_response_contract():
    print("\n### 6b. webhook response contract: accepted needs a correlated verdict")
    sf = secret_file()
    eid = "evt-" + "ab" * 10  # synthetic id, same shape as make_event_id output
    classify = H.classify_response

    # --- pure classification of the CURRENT real Hermes 202 body (no accepted flag) ---
    body_real = json.loads(_REAL_HERMES + f'"delivery_id":"{eid}"}}')
    kind, detail = classify(body_real, json.dumps(body_real).encode(), eid)
    check("real Hermes 202 body -> accepted", kind == "accepted", str((kind, detail)))
    check("real-shape acceptance carries no warning detail", detail == "", str(detail))
    # the X-Request-ID spelling we send is accepted too
    kind, _ = classify({"status": "accepted", "request_id": f"agent-handoff-{eid}"}, b"", eid)
    check("accepted via agent-handoff-<event_id> request id", kind == "accepted")
    # a numeric delivery id is still the same identifier
    kind, _ = classify({"status": "accepted", "event_id": 7}, b"", "7")
    check("accepted via integer event_id match", kind == "accepted")

    # --- shapes that must NEVER be accepted (2xx says nothing on its own) ---
    neg = [
        # route/cron_job/event name the routing, not THIS delivery: correlation missing
        ("status accepted without a delivery id", {"status": "accepted"}),
        ("real body minus delivery_id", json.loads(_REAL_HERMES.rstrip(",") + "}")),
        ("delivery_id of another delivery", {"status": "accepted",
                                             "delivery_id": "evt-" + "cd" * 10}),
        ("blank delivery id", {"status": "accepted", "delivery_id": "  "}),
        ("null delivery id", {"status": "accepted", "delivery_id": None}),
        ("non-string status", {"status": 7}),
        ("status queued is not accepted", {"status": "queued", "delivery_id": eid}),
        ("empty object", {}),
        ("duplicate without any id", {"status": "duplicate"}),
        ("deduped marker without any id", {"accepted": False, "deduped": True}),
        ("duplicate names another delivery", {"status": "duplicate", "delivery_id": "req-9"}),
        # explicit refusals veto every acceptance shape, incl. the legacy ones
        ("status rejected with a job_id", {"status": "rejected", "job_id": "job-9"}),
        ("status failed with accepted:true", {"status": "failed", "accepted": True}),
        ("status error with correlated id", {"status": "error", "delivery_id": eid}),
        ("status blocked with correlated id", {"status": "blocked", "delivery_id": eid}),
        ("status denied", {"status": "denied", "job_id": "job-9"}),
        ("status Refused is case/space normalised", {"status": "Refused ",
                                                     "accepted": True}),
        ("accepted:false with job_id", {"accepted": False, "job_id": "job-9"}),
        # an echoed delivery id that is not this event's rejects even a legacy verdict
        ("accepted:true with mismatched id (id vetoes)",
         {"accepted": True, "delivery_id": "evt-" + "ef" * 10}),
        ("job_id with mismatched id", {"job_id": "job-1",
                                       "delivery_id": "evt-" + "ef" * 10}),
        # this event's id AND a foreign id in one body: ambiguous answer, proves nothing
        ("conflicting delivery ids in one body",
         {"status": "accepted", "delivery_id": eid, "request_id": "req-9"}),
    ]
    for name, obj in neg:
        raw = json.dumps(obj).encode()
        kind, detail = classify(obj, raw, eid)
        check(f"reject: {name}", kind == "rejected" and "not delivered" in detail,
              str((kind, detail)))
    kind, detail = classify([{"accepted": True}], b"x", eid)
    check("reject: json array body", kind == "rejected", str((kind, detail)))
    kind, detail = classify(None, b"not json at all", eid)
    check("reject: unparseable body", kind == "rejected" and "verifiable" in detail,
          str((kind, detail)))
    kind, detail = classify(None, b"x" * H.MAX_RESPONSE_BYTES, eid)
    check("reject: oversized body", kind == "rejected" and "oversized" in detail,
          str((kind, detail)))
    for st in ("ignored", "filtered", "Ignored"):
        kind, detail = classify({"status": st}, b"", eid)
        check(f"ignored/filtered stays its own kind: {st}",
              kind == "ignored" and "not delivered" in detail, str((kind, detail)))

    # --- kept pre-existing acceptance shapes (minimal compatibility) ---
    for name, obj in (("accepted:true", {"accepted": True}),
                      ("legacy job_id (REPAIR-BRIEF.md:9)", {"job_id": "job-1"}),
                      ("real body with both id spellings of this event",
                       {"status": "accepted", "delivery_id": eid,
                        "request_id": f"agent-handoff-{eid}"}),
                      ("synthetic double duplicate (accepted:true + deduped)",
                       {"accepted": True, "deduped": True, "synthetic_ack_only": True})):
        kind, detail = classify(obj, b"", eid)
        check(f"accept: {name}", kind == "accepted", str((kind, detail)))
    # a refusal detail names the veto, so cron output says why the event stayed pending
    kind, detail = classify({"status": "rejected", "job_id": "job-9"}, b"", eid)
    check("refusal status names the veto", "explicit refusal status" in detail,
          str((kind, detail)))
    kind, detail = classify({"status": "accepted", "delivery_id": eid,
                             "request_id": "req-9"}, b"", eid)
    check("conflicting-id rejection names the foreign id", "req-9" in detail,
          str((kind, detail)))
    # falsy handles / no marker at all are not an acceptance: they fall through to the
    # normal rules and stay unverified
    for name, obj in (("empty job_id", {"job_id": ""}), ("null job_id", {"job_id": None}),
                      ("false job_id", {"job_id": False}), ("falsy status", {"status": ""})):
        kind, detail = classify(obj, b"", eid)
        check(f"reject: {name}", kind == "rejected", str((kind, detail)))

    # --- end-to-end through the real send path (loopback stub, synthetic bodies) ---
    root, _eid1, ev1, rc, out, hits = contract_send(
        sf, lambda e: _REAL_HERMES + f'"delivery_id":"{e}"}}', tag="real-202")
    check("real Hermes body delivers over the wire", rc == 0 and ev1["state"] == "delivered",
          f"{out[:160]} state={ev1['state']}")
    check("delivered_at recorded", isinstance(ev1.get("delivered_at"), int), str(ev1)[:200])
    check("receiver saw exactly one request", hits == 1, str(hits))
    # a delivered event is never re-sent: no endless retry against a healthy receiver
    rc, out = cli(["send", "--url", "http://127.0.0.1:1/x", "--secret-file", sf], root)
    check("delivered event is not retried", first_event(root)["attempts"] == 1, str(out)[:160])
    # receiver-side acceptance is NOT a task verdict
    check("webhook acceptance left verdict empty", not first_event(root).get("verdict"),
          str(first_event(root))[:200])

    _, _, ev2, _, out2, _ = contract_send(
        sf, '{"status":"accepted","route":"agent-task-handoff"}', tag="no-corr")
    check("uncorrelated accepted stays pending", ev2["state"] == "pending", str(ev2)[:200])
    check("pending detail says not delivered", "not delivered" in out2, out2[:200])
    check("pending schedules a retry", ev2["next_retry_at"] > ev2["updated_at"],
          f"{ev2['next_retry_at']} vs {ev2['updated_at']}")

    _, _, ev3, _, out3, _ = contract_send(
        sf, '{"status":"accepted","delivery_id":"evt-' + 'cd' * 10 + '"}', tag="wrong-corr")
    check("mismatched delivery id stays pending", ev3["state"] == "pending", str(ev3)[:200])
    check("mismatch names both sides", "correlation mismatch" in out3, out3[:220])

    # the defect Hermes read back: a refusal that still carries a job_id must NOT deliver
    _, _, ev3b, _, out3b, _ = contract_send(
        sf, '{"status":"rejected","job_id":"job-9"}', tag="refusal-veto")
    check("status rejected + job_id stays pending", ev3b["state"] == "pending",
          str(ev3b)[:200])
    check("refusal veto named in detail", "explicit refusal status" in out3b, out3b[:220])

    _, _, ev4, _, _, _ = contract_send(sf, '{"status":"ignored"}', tag="ignored")
    check("ignored response stays pending", ev4["state"] == "pending", str(ev4)[:200])
    _, _, ev5, _, out5, _ = contract_send(sf, 'y', tag="unparseable")
    check("unparseable 202 stays pending", ev5["state"] == "pending", str(ev5)[:200])
    check("unparseable detail recorded", "not a verifiable acceptance" in out5, out5[:200])
    # 204: an HTTP success with no body is NOT acceptance
    _, _, ev6, _, _, _ = contract_send(sf, "", code=204, tag="no-content")
    check("204 without body stays pending", ev6["state"] == "pending", str(ev6)[:200])

    # duplicate answers terminate the retry loop, without claiming business completion
    # shape 1: the synthetic test double's duplicate: accepted:true + deduped:true
    _, _, ev7, _, out7, _ = contract_send(
        sf, '{"accepted":true,"deduped":true,"synthetic_ack_only":true}',
        code=200, tag="dup-terminates")
    check("dedup response ends retrying (delivered)", ev7["state"] == "delivered",
          f"{str(ev7)[:200]} {out7[:160]}")
    check("duplicate acceptance did not set a verdict", not ev7.get("verdict"), str(ev7)[:200])
    # shape 2: a bare duplicate marker that names THIS delivery
    _, _, ev8, _, _, _ = contract_send(
        sf, lambda e: f'{{"status":"duplicate","delivery_id":"{e}"}}', tag="dup-correlated")
    check("correlated duplicate ends retrying", ev8["state"] == "delivered", str(ev8)[:200])
    note = ev8["history"][-1].get("note", "")
    check("duplicate acceptance carries a not-a-verdict note",
          "already holds" in note and "not a task verdict" in note, str(note)[:200])
    check("correlated duplicate left no verdict", not ev8.get("verdict"), str(ev8)[:200])
    # shape 3: a duplicate marker with nothing to correlate it -> still unverified
    _, _, ev9, _, _, _ = contract_send(sf, '{"status":"duplicate"}', tag="dup-uncorr")
    check("uncorrelated duplicate stays pending", ev9["state"] == "pending", str(ev9)[:200])


# ---------------------------------------------------------------------------
# 7. fake receiver contract
# ---------------------------------------------------------------------------
def t07_fake_receiver():
    print("\n### 7. fake_receiver contract (Hermes test double)")
    root = os.path.join(TMP, f"fr-{NONCE}")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root, exist_ok=True)
    sf = secret_file()
    with open(sf, "rb") as f:
        secret = f.read().strip()
    body = json.dumps({"schema_version": 1, "task_id": "task-a",
                       "event_id": "evt-abc", "status": "report_ready"},
                      ensure_ascii=True).encode()
    good = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    r = fake_receiver.Receiver(root, "ok", secret)
    code, resp = r.handle({"X-Hub-Signature-256": good, "X-Event-Type": "agent_task_handoff"}, body)
    check("valid signed event -> 202", code == 202, str((code, resp)))
    check("first sight is accepted, not deduped",
          resp["accepted"] is True and resp["deduped"] is False, str(resp))
    check("ack is synthetic-only", resp["synthetic_ack_only"] is True, str(resp))
    check("receiver request counter", r.requests == 1, str(r.requests))
    code2, resp2 = r.handle({"X-Hub-Signature-256": good, "X-Event-Type": "agent_task_handoff"}, body)
    check("duplicate event_id -> 200", code2 == 200, str((code2, resp2)))
    check("duplicate is not dispatched again", resp2["accepted"] is True
          and resp2["deduped"] is True, str(resp2))
    code3, resp3 = r.handle({"X-Hub-Signature-256": "sha256=" + "0" * 64,
                             "X-Event-Type": "agent_task_handoff"}, body)
    check("bad signature -> 400", code3 == 400, str((code3, resp3)))
    check("bad signature reason", resp3.get("reason") == "bad_signature", str(resp3))
    r2 = fake_receiver.Receiver(root, "badsig", secret)
    code4, _ = r2.handle({"X-Hub-Signature-256": good, "X-Event-Type": "agent_task_handoff"}, body)
    check("badsig mode rejects a valid signature", code4 == 401, str(code4))
    r3 = fake_receiver.Receiver(root, "500", secret)
    code5, _ = r3.handle({"X-Hub-Signature-256": good, "X-Event-Type": "agent_task_handoff"}, body)
    code6, _ = r3.handle({"X-Hub-Signature-256": good, "X-Event-Type": "agent_task_handoff"}, body)
    check("fault injection: one 500 then success", (code5, code6) == (500, 202),
          str((code5, code6)))
    r4 = fake_receiver.Receiver(root, "redirect", secret)
    code7, resp7 = r4.handle({"X-Hub-Signature-256": good,
                              "X-Event-Type": "agent_task_handoff"}, body)
    # redirect mode: the RESP body carries no Location (the HTTP header does, added by
    # the server handler); assert the documented 302 + refusal reason
    check("redirect fault: one 302", code7 == 302
          and resp7.get("reason") == "redirect", str(resp7))
    code8, resp8 = r4.handle({"X-Hub-Signature-256": good,
                              "X-Event-Type": "agent_task_handoff"}, body)
    check("redirect fault is one-shot, then accepted", (code8, resp8["deduped"]) == (202, False),
          str((code8, resp8)))
    # payload contract enforcement
    for extra, reason in ((b'{"schema_version":1,"task_id":"t","event_id":"e",'
                           b'"status":"report_ready","body":"leak"}', "payload_fields_not_allowed"),
                          (b'{"schema_version":1,"task_id":"t","event_id":"e"}',
                           "payload_fields_missing"),
                          (b'{"schema_version":1,"task_id":"t","event_id":"e",'
                           b'"status":"accepted"}', "bad_status"),
                          # fake_receiver.py:91-92 rejects only a non-string or empty
                          # event_id, so "bogus" is a perfectly legal id for it
                          (b'{"schema_version":1,"task_id":"t","event_id":"",'
                           b'"status":"report_ready"}', "bad_event_id"),
                          (b'{"schema_version":1,"task_id":"t","event_id":123,'
                           b'"status":"report_ready"}', "bad_event_id")):
        sig = "sha256=" + hmac.new(secret, extra, hashlib.sha256).hexdigest()
        rc, rp = fake_receiver.Receiver(root, "ok", secret).handle(
            {"X-Hub-Signature-256": sig, "X-Event-Type": "agent_task_handoff"}, extra)
        check(f"receiver rejects {reason}", rc == 400 and rp.get("reason") == reason,
              str((rc, rp)))
    rc, rp = fake_receiver.Receiver(root, "ok", secret).handle(
        {"X-Hub-Signature-256": good, "X-Event-Type": "other"}, body)
    check("receiver rejects wrong event type", rc == 400
          and rp.get("reason") == "bad_event_type", str((rc, rp)))
    rc, rp = fake_receiver.Receiver(root, "ok", secret).handle({"X-Event-Type": "agent_task_handoff"}, body)
    check("receiver rejects a missing signature header",
          rc == 400 and rp.get("reason") == "bad_signature", str((rc, rp)))
    loglines = []
    with open(r.log_path, encoding="utf-8") as lf:
        for x in lf:
            if x.strip():
                loglines.append(json.loads(x))
    check("requests.jsonl records only the 4 identity fields",
          loglines and all(set(rec) == {"code", "resp", "request_id", "event_id"}
                           for rec in loglines), str(loglines[:1]))


# ---------------------------------------------------------------------------
# 8. ack protocol: claim + verdict, delivered != accepted
# ---------------------------------------------------------------------------
def t08_ack():
    print("\n### 8. ack protocol: atomic claim, dedup, delivered != accepted")
    root, session = scenario("ack")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    sf = secret_file()
    url, httpd, srv = start_stub("ok")
    cli(["tick", "--url", url, "--secret-file", sf], root)
    httpd.shutdown()
    srv.join(timeout=2)
    ev = first_event(root)
    eid = ev["event_id"]
    check("stub delivered the event first", ev["state"] == "delivered", str(ev["state"]))
    code, out = cli(["claim", eid, "--claimer", "hermes"], root)
    doc = json.loads(out)
    check("claim ok + claimed", doc["ok"] is True and doc["result"] == "claimed", out[:200])
    check("claim reports synthetic mode", doc["synthetic"] is True, out[:200])
    code, out = cli(["claim", eid, "--claimer", "another-worker"], root)
    doc2 = json.loads(out)
    check("duplicate claim -> already_claimed", doc2["result"] == "already_claimed", out[:200])
    check("duplicate claim keeps first claimed_at",
          doc2["first_claimed_at"] == doc["claimed_at"], str(doc2))
    check("claim marker on disk", os.path.isfile(H.p_claim(root, eid)))
    code, out = cli(["claim", "evt-doesnotexist0000000", "--claimer", "x"], root)
    check("claim unknown event -> ok:false + rc1", code == 1, out[:160])
    check("claim unknown says unknown_event", "unknown_event" in out, out[:160])

    # ack requires a claim
    code, out = cli(["ack", eid, "--verdict", "accepted", "--claimer", "hermes",
                     "--note", "合成验收：只做测试回执，不触发工程动作"], root)
    echo = json.loads(out)
    cur = first_event(root)
    # cmd_ack echoes the event's real state read inside the lock (handoff.py:1145-1165).
    # The claim above already owns the marker, so already_claimed is the correct echo;
    # what must never appear is a hardcoded "processing" standing in for the state.
    check("ack echoes the real event state, not a fake processing",
          code == 0 and echo["state"] == cur["state"] == "delivered"
          and echo["verdict"] == "accepted" and "processing" not in out, out[:200])
    check("ack echoes a real claim result", echo["claim"] in ("claimed", "already_claimed"),
          str(echo["claim"]))
    acks = [json.loads(x) for x in _readtext(H.p_acks(root)).splitlines() if x.strip()]
    check("acks.jsonl recorded", acks and acks[-1]["event_id"] == eid, str(acks)[:200])
    check("ack verdict stored", acks[-1]["verdict"] == "accepted", str(acks[-1]))
    check("ack note kept", "不触发工程动作" in json.dumps(acks[-1], ensure_ascii=False),
          str(acks[-1])[:200])
    check("delivered does not imply accepted", first_event(root)["verdict"] == "accepted")
    code, out = cli(["status"], root)
    check("status shows the verdict", "verdict=accepted" in out, out[:300])
    check("status still reports delivered (not accepted)", "state=delivered" in out, out[:300])

    # verdict validation is argparse's choices (rc2); unknown event goes rc1
    code, out = cli(["ack", eid, "--verdict", "done", "--claimer", "h"], root)
    check("bad verdict -> rc2", code == 2, out[:160])
    check("bad verdict rejected by argparse choices", "invalid choice" in out, out[:160])
    code, out = cli(["ack", "evt-unknown0000000000000", "--verdict", "accepted"], root)
    check("ack unknown event -> rc1", code == 1, out[:160])

    # empty/partial marker recovery re-claims exactly once, then dedups. The marker is a
    # crash artifact of a REAL outbox event: claim_event looks the event up first
    # (handoff.py:1078-1085), so an invented id can only ever return unknown_event.
    root2, session2 = scenario("marker-recovery")
    write_session(session2, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session2),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root2)
    cli(["tick", "--no-send"], root2)
    eid2 = first_event(root2)["event_id"]
    H._atomic_write(H.p_claim(root2, eid2), b"")
    code, out = cli(["claim", eid2, "--claimer", "r1"], root2)
    doc = json.loads(out)
    check("empty marker re-claims with dispatch", code == 0 and doc["result"] == "claimed"
          and doc["dispatch"] is True, out[:200])
    marker = H.read_json(H.p_claim(root2, eid2), {})
    check("recovered marker records the first claimer",
          marker.get("claimer") == "r1" and marker.get("recovered_empty_marker") is True,
          str(marker)[:200])
    code, out = cli(["claim", eid2, "--claimer", "r2"], root2)
    doc = json.loads(out)
    # already_claimed always carries dispatch:false (handoff.py:1117) - the field is
    # present and false, never omitted, so the dedup proof is `is False`.
    check("recovered marker then dedups (rc3)", code == 3
          and doc["result"] == "already_claimed" and doc["dispatch"] is False, out[:200])

    # blocked verdict path (real project not completed)
    root, session = scenario("ack-blocked")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    cli(["tick", "--no-send"], root)
    eid = first_event(root)["event_id"]
    code, out = cli(["claim", eid, "--claimer", "hermes"], root)
    check("claim of undelivered event works", json.loads(out)["result"] == "claimed", out[:160])
    code, out = cli(["ack", eid, "--verdict", "blocked", "--note", "等待真实部署验收"], root)
    check("blocked verdict accepted", code == 0, out[:160])
    check("blocked stored in status", "verdict=blocked" in cli(["status"], root)[1],
          cli(["status"], root)[1][:300])

    # ack-pending lists open items for the receiver
    root, session = scenario("ack-pending")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    cli(["tick", "--no-send"], root)
    code, out = cli(["ack-pending"], root)
    pend = json.loads(out.strip().splitlines()[0])
    check("ack-pending returns the open event", pend["event_id"] == first_event(root)["event_id"],
          out[:200])
    check("ack-pending includes claim state", "claimed" in pend, str(pend))
    eid = pend["event_id"]
    cli(["claim", eid, "--claimer", "hermes"], root)
    code, out = cli(["ack-pending"], root)
    pend2 = json.loads(out.strip().splitlines()[0])
    check("ack-pending reflects the claim", pend2["claimed"] is True, str(pend2))
    cli(["ack", eid, "--verdict", "accepted"], root)
    code, out = cli(["ack-pending"], root)
    check("acked event leaves the pending list", "nothing" in out.lower() or
          eid not in out, out[:200])


# ---------------------------------------------------------------------------
# 9. end-to-end synthetic webhook over loopback
# ---------------------------------------------------------------------------
def t09_end_to_end():
    print("\n### 9. end-to-end: real handoff.py sender -> fake_receiver over 127.0.0.1")
    sf = secret_file()
    root, session = scenario("e2e")
    write_session(session, [
        rec("user", "实现 webhook 交接器"),
        rec("assistant", [tool_block("read")]),
        {"type": "toolResult", "message": {"role": "toolResult", "content": "ok"}},
        rec("assistant", "handoff.py 与 fake_receiver.py 已落盘，合成验证覆盖全部分类", stop="stop"),
    ])
    fr_root = os.path.join(TMP, f"e2e-receiver-{NONCE}")
    shutil.rmtree(fr_root, ignore_errors=True)
    os.makedirs(fr_root, exist_ok=True)
    with open(sf, "rb") as f:
        secret = f.read().strip()
    recv = fake_receiver.Receiver(fr_root, "ok", secret)
    port = _free_port()
    httpd = HTTPServer(("127.0.0.1", port), _make_receiver_handler(recv))
    srv = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.02},
                           daemon=True)
    srv.start()
    url = f"http://127.0.0.1:{port}/hook"
    code, out = cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
                     "--workdir", PROJECT, "--synthetic", "--allow-root", os.path.dirname(PROJECT),
                     "--goal", "mcp-handoff-e2e", "--next-phase", "真实部署验收"], root)
    check("e2e register rc0", code == 0, out[:160])
    code, out = cli(["tick", "--url", url, "--secret-file", sf, "--verbose-send"], root)
    check("e2e tick rc0", code == 0, out[:240])
    check("e2e delivered", "delivered" in out, out[:300])
    ev = first_event(root)
    check("e2e event delivered", ev["state"] == "delivered", str(ev["state"]))
    check("e2e still not accepted", "verdict" not in ev or not ev.get("verdict"), str(ev)[:200])
    reqs = [json.loads(x) for x in _readtext(recv.log_path).splitlines() if x.strip()]
    check("receiver logged exactly 1 request", len(reqs) == 1, str(reqs))
    check("receiver logged 202", reqs and reqs[0]["code"] == 202, str(reqs[:1]))
    check("receiver saw the same event_id", reqs[0]["event_id"] == ev["event_id"], str(reqs[0]))
    check("receiver did not receive any session body/path",
          all(set(json.loads(x)) <= {"at", "code", "resp", "request_id", "event_id"}
              for x in _readtext(recv.log_path).splitlines() if x.strip()))
    httpd.shutdown()
    srv.join(timeout=2)

    # receiver side: claim + ack through the CLI (Hermes' role), dedup check
    eid = ev["event_id"]
    code, out = cli(["claim", eid, "--claimer", "hermes"], root)
    check("e2e claim once", json.loads(out)["result"] == "claimed", out[:160])
    code, out = cli(["claim", eid, "--claimer", "hermes"], root)
    check("e2e duplicate claim not dispatched", json.loads(out)["result"] == "already_claimed",
          out[:160])
    code, out = cli(["ack", eid, "--verdict", "accepted", "--claimer", "hermes",
                     "--note", "合成测试回执：只确认收到，不代表工程完成"], root)
    check("e2e ack stored", code == 0, out[:160])
    code, out = cli(["status", "--json"], root)
    doc = json.loads(out)
    got = doc["task-a"]["events"][0]
    check("e2e status shows delivered + accepted verdict",
          got["state"] == "delivered" and got["verdict"] == "accepted", str(got))

    # re-emit for the same task_id after --force rescan: dedup by stable event_id
    code, out = cli(["tick", "--force", "--no-send"], root)
    check("e2e rescan did not duplicate", len(events_in(root)) == 1, str(events_in(root)))
    check("e2e rescan logged duplicate", "duplicate" in out, out[:200])


# ---------------------------------------------------------------------------
# 10. cron-safety: exit codes + real subprocess invocation
# ---------------------------------------------------------------------------
def t10_cron_safety():
    print("\n### 10. cron safety: subprocess exit codes and no-traceback errors")
    root, session = scenario("cron")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])

    def run(args, expect_rc):
        # this sandbox forbids CreatePipe: capture via file handles, never pipes
        outp = os.path.join(TMP, f"cron-out-{NONCE}.txt")
        errp = os.path.join(TMP, f"cron-err-{NONCE}.txt")
        with open(outp, "wb") as fo, open(errp, "wb") as fe:
            res = subprocess.run([PY, os.path.join(PROJECT, "handoff.py"), "--root", root, *args],
                                 stdout=fo, stderr=fe, timeout=60)
        out, err = _readtext(outp), _readtext(errp)
        cp = SimpleNamespace(returncode=res.returncode, stdout=out, stderr=err)
        check(f"subprocess {' '.join(args[:2])} rc={expect_rc}", cp.returncode == expect_rc,
              f"rc={cp.returncode} out={cp.stdout[:120]!r} err={cp.stderr[:200]!r}")
        check(f"no traceback for {' '.join(args[:2])}", "Traceback" not in cp.stderr
              and "Traceback" not in cp.stdout, cp.stderr[:200])
        return cp

    cp = run(["register", "--task-id", "task-a", "--session-path", as_root(session),
              "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], 0)
    check("register stdout json", '"task_id"' in cp.stdout, cp.stdout[:120])
    run(["tick", "--no-send"], 0)
    run(["status"], 0)
    run(["send", "--url", "http://evil.example.com/", "--secret-file", secret_file()], 2)
    run(["claim", "evt-notfound00000000000", "--claimer", "x"], 1)
    run(["ack", first_event(root)["event_id"], "--verdict", "nope"], 2)
    run(["unregister", "--task-id", "nope"], 1)
    run(["unregister", "--task-id", "task-a"], 0)
    check("unregistered task is gone", "task-a" not in cli(["status"], root)[1],
          cli(["status"], root)[1][:120])
    code, out = cli(["tick", "--no-send"], root)
    check("tick with empty registry rc0", code == 0, out[:120])


# ---------------------------------------------------------------------------
# 11. cleanup (this tool never installs Windows cron jobs)
# ---------------------------------------------------------------------------
def t11_cleanup():
    print("\n### 11. scratch cleanup")
    root, session = scenario("to-clean")
    write_session(session, [rec("assistant", "x", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标"], root)
    code, out = cli(["clean", "--root", as_root(root)], TMP)
    check("clean rc0", code == 0, out[:160])
    check("clean removed the scratch root", not os.path.exists(root), out[:160])
    code, out = cli(["clean", "--root", "relative/path"], TMP)
    check("clean refuses a relative root", code == 2, out[:160])
    code, out = cli(["clean", "--root", as_root(os.path.join(TMP, "definitely-missing"))], TMP)
    check("clean on a missing dir rc0", code == 0, out[:160])
    check("clean of a missing dir did not create it", not os.path.isdir(os.path.join(TMP, "definitely-missing")),
          "main() must not mkdir a root that clean then reports as cleaned")
    try:
        cp = _run_nopipes(["schtasks", "/query", "/tn", "PiHandoff"])
        check("no Windows scheduled task was created by this tool",
              cp["rc"] != 0 or "PiHandoff" not in cp["out"], cp["out"][:160])
    except OSError as e:
        # environment cannot run schtasks at all: report the skip honestly, never a fake ok
        print(f"  SKIP schtasks check unavailable in this sandbox: {e}")


# ---------------------------------------------------------------------------
# 12. claude stream-json compatibility
# ---------------------------------------------------------------------------
CL_SID = "cd93ad7e-0959-44c5-8385-e1913ac2d18a"
OTHER_SID = "11111111-2222-4333-8444-555555555555"


def crec(role, content, stop=None, sid=CL_SID):
    """One claude stream-json frame wrapping an Anthropic API message."""
    msg = {"role": role, "content": content}
    if stop:
        msg["stop_reason"] = stop
    return {"type": role, "message": msg, "session_id": sid, "uuid": "u-" + role,
            "timestamp": "2026-10-31T00:00:00.000Z"}


def ctool_block(name="Bash"):
    return {"type": "tool_use", "id": "toolu_1", "name": name, "input": {"command": "true"}}


def cresult(subtype="success", is_error=False, text: "str | None" = "所有改动已落盘",
            sid=CL_SID):
    # `text=None` builds a result record WITHOUT a result field: that is the
    # "finished but nothing to report" shape the judge must catch (t12 (e)).
    rec = {"type": "result", "subtype": subtype, "is_error": is_error,
           "stop_reason": "end_turn", "session_id": sid, "num_turns": 4,
           "duration_ms": 1234, "total_cost_usd": 0.5, "permission_denials": [],
           "terminal_reason": "completed"}
    if text is not None:
        rec["result"] = text
    return rec


def gone_pid():
    """A pid the OS confirms exited: the only exit evidence scan_task accepts."""
    p = subprocess.Popen([PY, "-c", "import sys; sys.exit(0)"])
    p.wait()
    return str(p.pid)


def reg_claude(root, session, sid=CL_SID, extra=(), tid="task-a"):
    args = ["register", "--task-id", tid, "--session-path", as_root(session),
            "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic",
            "--source", "claude"]
    if sid is not None:
        args += ["--session-id", sid]
    return cli([*args, *extra], root)


def t12_claude_compat():
    print("\n### 12. claude stream-json: only a trusted result record can end a task")

    # (a) registration contract: claude needs a format-valid session_id, pi keeps none
    root, session = scenario("c-register")
    write_session(session, [crec("assistant", "wip")])
    code, out = cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
                     "--workdir", PROJECT, "--goal", "g", "--source", "claude"], root)
    check("claude register without --session-id -> rc2", code == 2, out[:160])
    code, out = reg_claude(root, session, sid="short")
    check("claude register with a malformed session_id -> rc2", code == 2, out[:160])
    code, out = reg_claude(root, session)
    check("claude register with a session_id -> rc0", code == 0, out[:160])
    check("register echoes the source", '"source"' in out and "claude" in out, out[:220])
    check("register echoes the session_id", CL_SID in out, out[:220])
    task = H.load_registry(root)["tasks"]["task-a"]
    check("registry keeps source + session_id",
          task["source"] == "claude" and task["session_id"] == CL_SID, str(task)[:220])
    code, out = cli(["register", "--task-id", "task-pi", "--session-path", as_root(session),
                     "--workdir", PROJECT, "--goal", "g"], root)
    check("pi register rc0", code == 0, out[:160])
    check("pi register echoes source pi", '"source"' in out and "pi" in out, out[:220])
    check("pi register echoes no session_id", "session_id" not in out, out[:220])
    ptask = H.load_registry(root)["tasks"]["task-pi"]
    check("pi task defaults to source pi", ptask["source"] == "pi", str(ptask)[:220])
    check("pi task stores no session_id key", "session_id" not in ptask, str(ptask)[:220])

    # (b) assistant/tool/user/system frames are activity: never an event
    root, session = scenario("c-activity")
    write_session(session, [
        {"type": "system", "subtype": "init", "session_id": CL_SID, "model": "claude-fable-5"},
        crec("user", "开始执行任务"),
        crec("assistant", [ctool_block("Bash")]),
        crec("user", [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}]),
        crec("assistant", "report ready, nothing left to do", stop="end_turn"),
    ])
    code, out = reg_claude(root, session, extra=["--pid", str(os.getpid())])
    check("claude register with a live pid rc0", code == 0, out[:160])
    code, out = tick(root, ["--no-send"])
    check("activity frames produce no event", "EVENT" not in out, out[:220])
    check("nothing stored for activity", not events_in(root), str(events_in(root))[:220])
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("system frame is liveness not content (bad_lines)", st["bad_lines"] == 1,
          str(st["bad_lines"]))
    check("activity records are counted", st["line_seq"] == 4, str(st["line_seq"]))

    # (c) one trusted success result -> report_ready, 4-field payload, never re-reported
    sf = secret_file()
    root, session = scenario("c-success")
    write_session(session, [crec("assistant", "working"),
                            cresult(text="全部改动已落盘：handoff.py、tests、报告")])
    code, out = reg_claude(root, session, extra=["--pid", gone_pid()])
    check("claude success register rc0", code == 0, out[:160])
    code, out = tick(root, ["--no-send"])
    check("trusted success result -> report_ready", "EVENT report_ready" in out, out[:240])
    ev = first_event(root)
    check("claude report reason names the result record",
          ev["reason"] == "claude result subtype=success with a final report", ev["reason"])
    check("report_ready is not acceptance", ev["state"] == "pending" and not ev.get("verdict"),
          str(ev)[:220])
    recp = H.read_json(ev["receipt_path"], {})
    check("claude receipt carries the result text",
          "全部改动已落盘" in recp.get("final_text", ""), str(recp.get("final_text"))[:80])
    check("claude receipt records the untrusted counter",
          recp.get("untrusted_records") == 0, str(recp.get("untrusted_records")))
    code, out = tick(root, ["--no-send"])
    check("a second tick stays silent", "EVENT" not in out, out[:220])
    check("still exactly one event", len(events_in(root)) == 1, str(events_in(root))[:220])
    url, httpd, srv = start_stub("ok")
    code, out = cli(["send", "--url", url, "--secret-file", sf], root)
    httpd.shutdown()
    srv.join(timeout=2)
    payload = json.loads(RecordingHandler.hits[-1][1])
    check("claude payload carries only the 4 allowed fields",
          set(payload) == {"schema_version", "task_id", "event_id", "status"}, str(payload)[:220])
    check("claude payload status is the report", payload["status"] == "report_ready",
          str(payload)[:220])

    # (d) is_error / error subtype -> failed naming both fields
    for subtype, is_err in (("error_during_execution", True), ("success", True),
                            ("error_max_budget_usd", False)):
        root, session = scenario("c-failed-" + subtype)
        write_session(session, [crec("assistant", "partial"),
                                cresult(subtype=subtype, is_error=is_err, text="boom")])
        reg_claude(root, session, extra=["--pid", gone_pid()])
        code, out = tick(root, ["--no-send"])
        check("subtype={} is_error={} -> failed".format(subtype, is_err),
              "EVENT failed" in out, out[:240])
        ev = first_event(root)
        check("failed names the subtype", subtype in ev["reason"], ev["reason"])
        check("failed names is_error", "is_error=" in ev["reason"], ev["reason"])
        check("failed never claims acceptance", "not an accepted result" in ev["reason"],
              ev["reason"])

    # (e) a result that only looks finished -> stopped_unfinished, never report_ready
    cases = (
        ("unknown_kind", False, "text", "subtype=unknown_kind is not a trustworthy success"),
        ("success", False, None, "carried no result text"),
        ("success", False, "上下文交接摘要：已完成 A、B，剩余 C", "handoff/compaction summary"),
    )
    for subtype, is_err, text, want in cases:
        root, session = scenario("c-unfinished-" + subtype)
        write_session(session, [cresult(subtype=subtype, is_error=is_err, text=text)])
        reg_claude(root, session, extra=["--pid", gone_pid()])
        code, out = tick(root, ["--no-send"])
        evs = events_in(root)
        check("subtype={} text={} -> exactly one event".format(subtype, str(text)[:8]),
              len(evs) == 1, str(evs)[:220])
        ev = first_event(root)
        check("subtype={} -> stopped_unfinished".format(subtype),
              ev["status"] == "stopped_unfinished", str(ev["status"]))
        check("reason says: " + want[:28], want in ev["reason"], ev["reason"])

    # (f) session_id trust: a missing or foreign id is never evidence, even a success
    root, session = scenario("c-untrusted")
    foreign = cresult(subtype="success", text="另一个会话的成功报告", sid=OTHER_SID)
    nosid = cresult(subtype="success", text="没有 session_id 的成功报告")
    nosid.pop("session_id")
    write_session(session, [cresult(subtype="success", text="本会话的真实报告"),
                            crec("assistant", "still working", sid=OTHER_SID),
                            foreign, nosid])
    # registered against a session_id this log never carries: nothing may be trusted
    code, out = reg_claude(root, session, sid="eeeeeeee-0000-4000-8000-000000000000",
                           extra=["--pid", gone_pid()])
    check("unrelated session_id register rc0", code == 0, out[:160])
    code, out = tick(root, ["--no-send"])
    ev = first_event(root)
    check("no trusted result -> stopped_unfinished", ev["status"] == "stopped_unfinished",
          str(ev["status"]))
    check("exit reason says no trustworthy result record",
          "without a trustworthy result record" in ev["reason"], ev["reason"])
    check("exit reason counts every untrusted record",
          "4 record(s) were seen with a missing or foreign session_id" in ev["reason"],
          ev["reason"])
    check("an untrusted success is never reported as success",
          ev["status"] != "report_ready", str(ev["status"]))
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("state keeps the untrusted count", st["untrusted_records"] == 4, str(st)[:220])

    root, session = scenario("c-trusted-after-foreign")
    write_session(session, [cresult(subtype="success", text="冒名报告", sid=OTHER_SID),
                            cresult(text="真正属于本会话的报告")])
    reg_claude(root, session, extra=["--pid", gone_pid()])
    code, out = tick(root, ["--no-send"])
    check("a trusted result after a foreign one still reports",
          "EVENT report_ready" in out, out[:240])
    check("only one event despite the foreign result", len(events_in(root)) == 1,
          str(events_in(root))[:220])

    # (g) a result still mid-write is deferred, then judged once the line closes
    root, session = scenario("c-halfline")
    line = json.dumps(cresult(text="完整报告内容"), ensure_ascii=True) + "\n"
    half = line[: len(line) // 2]
    with open(session, "wb") as f:
        f.write((json.dumps(crec("assistant", "working"), ensure_ascii=True) + "\n").encode())
        f.write(half.encode())
    code, out = reg_claude(root, session, extra=["--pid", str(os.getpid())])
    check("half-line register rc0", code == 0, out[:160])
    code, out = tick(root, ["--no-send"])
    check("a half-written result line yields no event", "EVENT" not in out, out[:220])
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("the partial tail is held, not consumed", st["pending_size"], str(st)[:220])
    with open(session, "ab") as f:
        f.write(line[len(half):].encode())
    code, out = tick(root, ["--no-send"])
    check("the completed line reports", "EVENT report_ready" in out, out[:220])
    check("the half-line path stored one event", len(events_in(root)) == 1,
          str(events_in(root))[:220])

    # (h) a record larger than the read bound is skipped honestly: no success claim
    root, session = scenario("c-overlimit")
    with open(session, "wb") as f:
        f.write((json.dumps(crec("assistant", "x" * 6000), ensure_ascii=True) + "\n").encode())
        f.write((json.dumps(crec("assistant", "y" * 20), ensure_ascii=True) + "\n").encode())
    reg_claude(root, session, extra=["--pid", gone_pid()])
    size = os.path.getsize(session)
    for _ in range(60):
        tick(root, ["--no-send", "--max-bytes", "300"])
        if events_in(root) or H.read_json(H.p_state(root, "task-a"), {})["offset"] >= size:
            break
    code, out = tick(root, ["--no-send", "--max-bytes", "300"])
    ev = first_event(root)
    check("an over-limit claude run never reports success",
          ev["status"] == "stopped_unfinished", str(ev["status"]))
    check("the reason names the unreadable record", "over-limit" in ev["reason"], ev["reason"])
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("skipped bytes are recorded", st["over_limit"] is True and st["skipped_bytes"] > 0,
          str(st)[:220])

    # (i) no trustworthy result inside the stall window -> stalled, still rescannable
    root, session = scenario("c-stall")
    write_session(session, [crec("assistant", "thinking", stop="tool_use")])
    reg_claude(root, session, extra=["--pid", str(os.getpid())])
    code, out = cli_with({"AGENT_HANDOFF_STALL_SECONDS": "0"}, ["tick", "--no-send"], root)
    check("idle claude run -> stalled", "EVENT stalled" in out, out[:240])
    sev = first_event(root)
    check("stalled reason says no readable result record",
          "no readable claude result record" in sev["reason"], sev["reason"])
    check("stalled is not a verdict", sev["state"] == "pending", str(sev["state"]))
    check("stalled does not close the task",
          not H.load_registry(root)["tasks"]["task-a"].get("terminal_event_id"),
          str(H.load_registry(root)["tasks"]["task-a"])[:200])
    code, out = cli_with({"AGENT_HANDOFF_STALL_SECONDS": "0"}, ["tick", "--no-send"], root)
    check("the same stall is not reported twice", "EVENT" not in out, out[:220])
    append_lines(session, [json.dumps(cresult(text="迟到的完整报告"), ensure_ascii=True)])
    code, out = tick(root, ["--no-send"])
    check("a result that lands after a stall still reports",
          "EVENT report_ready" in out, out[:220])

    # (j) pi behaviour is untouched: same parser, same reason, no claude-only fields
    root, session = scenario("c-pi-compat")
    write_session(session, [rec("user", "do the work"),
                            rec("assistant", [tool_block("bash")]),
                            {"type": "toolResult",
                             "message": {"role": "toolResult", "content": "ok"}},
                            rec("assistant", "阶段 A 完成，测试通过", stop="stop")])
    code, out = cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
                     "--workdir", PROJECT, "--goal", "合成验收目标",
                     "--pid", str(os.getpid())], root)
    check("pi register rc0", code == 0, out[:160])
    code, out = tick(root, ["--no-send"])
    check("pi stopReason=stop still reports", "EVENT report_ready" in out, out[:220])
    ev = first_event(root)
    check("pi reason unchanged", ev["reason"] == "final assistant report (stopReason=stop)",
          ev["reason"])
    recp = H.read_json(ev["receipt_path"], {})
    check("pi receipt has no claude-only fields", "untrusted_records" not in recp,
          str(sorted(recp))[:300])

    # a claude result record read as pi is just an unparsable line
    root, session = scenario("c-claude-as-pi")
    write_session(session, [cresult(text="claude result 当作 pi 行")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "g", "--pid", str(os.getpid())], root)
    code, out = tick(root, ["--no-send"])
    check("a claude result parsed as pi is not a record", "EVENT" not in out, out[:220])
    st = H.read_json(H.p_state(root, "task-a"), {})
    check("it lands as a bad pi line", st["bad_lines"] == 1 and st["line_seq"] == 0,
          str(st)[:220])


# ---------------------------------------------------------------------------
# 13. renamed settings: an old PI_HANDOFF_* name fails fast and is never mapped
# ---------------------------------------------------------------------------
@contextlib.contextmanager
def _env(**overrides):
    """Set keys for one call, then put the process env back exactly as it was.

    The empty string means "remove it": a deployment that exports
    AGENT_HANDOFF_URL="" must resolve as unset, and a test must be able to say so.
    """
    saved = {}
    try:
        for name, value in overrides.items():
            saved[name] = os.environ.get(name)
            if value == "":
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _router_module():
    """Load the dispatcher script as a module: it is a file, not an import path."""
    import importlib.util

    path = os.path.join(PROJECT, "scripts", "agent_handoff_router.py")
    spec = importlib.util.spec_from_file_location("rename_guard_router", path)
    if spec is None or spec.loader is None:  # pragma: no cover - the file is in the repo
        raise RuntimeError(f"cannot load the router module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def t13_renamed_settings():
    print("\n### 13. renamed settings: old names fail fast, new names only")
    root, session = scenario("rename-guard")
    write_session(session, [rec("assistant", "报告已就绪", stop="stop")])
    cli(["register", "--task-id", "task-a", "--session-path", as_root(session),
         "--workdir", PROJECT, "--goal", "合成验收目标", "--synthetic"], root)
    cli(["tick", "--no-send"], root)

    # (a) one old name, no new twin: the run stops and points at the new
    # spelling. The list walked is H.ENV_KEYS itself, so a renamed key cannot
    # leave the sample files, the fail-fast and the code out of sync.
    for new in H.ENV_KEYS:
        old = "PI_" + new[len("AGENT_"):]
        with _env(**{old: "synthetic-legacy-value", "AGENT_HANDOFF_CONFIG": ""}):
            code, out = cli(["status"], root)
        check(f"{old} alone exits non-zero", code != 0, f"rc={code} {out[:160]!r}")
        check(f"{old} error names {new}", new in out, out[:200])
        check(f"{old} error says the name was renamed", "renamed" in out, out[:200])
    check("every key in the list is a renamed AGENT_ setting",
          all(k.startswith("AGENT_HANDOFF_") for k in H.ENV_KEYS)
          and len(H.ENV_KEYS) == 15, str(H.ENV_KEYS)[:220])

    # (a2) the shipped samples cover exactly that list, so code and docs cannot
    # drift apart: every key but the pointer itself, and nothing extra.
    documented = set(H.ENV_KEYS) - {"AGENT_HANDOFF_CONFIG"}
    for name, pattern in (("config.example.toml", "AGENT_HANDOFF_"),
                          (".env.example", "AGENT_HANDOFF_")):
        with open(os.path.join(PROJECT, name), encoding="utf-8") as f:
            text = f.read()
        found = set()
        for line in text.splitlines():
            stripped = line.strip()
            head = stripped.split("=")[0].strip()
            if head.startswith("export "):
                head = head[len("export "):].strip()
            if head in set(H.ENV_KEYS):
                found.add(head)
        check(f"{name} documents every setting",
              documented <= found, str(sorted(documented - found)))
        check(f"{name} documents nothing extra", found <= set(H.ENV_KEYS),
              str(sorted(found - set(H.ENV_KEYS))))
        check(f"{name} mentions the key prefix", pattern in text, name)

    # (b) the old data root is never used as a data root: nothing lands in that dir
    legacy_root = os.path.join(TMP, f"legacy-root-{NONCE}")
    shutil.rmtree(legacy_root, ignore_errors=True)
    with _env(PI_HANDOFF_ROOT=legacy_root, AGENT_HANDOFF_CONFIG=""):
        out_buf, err_buf = io.StringIO(), io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = H.main(["status"]) or 0
    check("a stale PI_HANDOFF_ROOT is refused, not honoured", code != 0, f"rc={code}")
    check("no registry was created under the old root",
          not os.path.exists(H.p_registry(legacy_root)), legacy_root)

    # (c) a send with only the old URL configured must not go out at all
    sf = secret_file()
    with _env(PI_HANDOFF_URL="http://127.0.0.1:1/webhooks/agent-task-handoff",
              AGENT_HANDOFF_CONFIG=""):
        code, out = cli_with({"AGENT_HANDOFF_SECRET_FILE": sf}, ["tick"], root)
    check("PI_HANDOFF_URL alone does not send", code != 0, f"rc={code} {out[:160]!r}")
    check("nothing was delivered under the old name", not first_event(root).get("verdict"),
          str(first_event(root))[:200])

    # (d) both spellings set: the guard stays quiet and only the new value is read
    with _env(PI_HANDOFF_STALL_SECONDS="1", AGENT_HANDOFF_STALL_SECONDS="99",
              AGENT_HANDOFF_CONFIG=""):
        check("a resolved twin silences the guard", H.legacy_env_offenders() == [],
              str(H.legacy_env_offenders()))
        check("the new value wins, the old one is not mapped",
              H.setting("AGENT_HANDOFF_STALL_SECONDS") == "99",
              str(H.setting("AGENT_HANDOFF_STALL_SECONDS")))

    # (e) the config file is held to the same rule as the environment
    cfg = os.path.join(TMP, f"legacy-config-{NONCE}.toml")
    with open(cfg, "w", encoding="ascii") as f:
        f.write('pi_handoff_max_attempts = 5\n')
    H._CONFIG_CACHE.pop(os.path.realpath(cfg), None)
    with _env(AGENT_HANDOFF_CONFIG=cfg):
        offenders = H.legacy_env_offenders()
        check("a legacy key in the config file is an offender too",
              offenders == [("PI_HANDOFF_MAX_ATTEMPTS", "AGENT_HANDOFF_MAX_ATTEMPTS")],
              str(offenders))
        code, out = cli_with({}, ["status"], root)
        check("the config file cannot smuggle an old name through", code != 0,
              f"rc={code} {out[:160]!r}")
    os.remove(cfg)

    # (f) the dispatcher refuses an old name and never probes a machine path
    R = _router_module()
    with _env(PI_HANDOFF_DATA_ROOT="synthetic-legacy-data", PI_HANDOFF_HERMES_BIN="x",
              AGENT_HANDOFF_CONFIG="", AGENT_HANDOFF_DATA_ROOT="", AGENT_HANDOFF_SCRIPT=""):
        errors = R.configuration_errors()
        text = "\n".join(errors)
        check("the router names the replacement for each old key",
              "AGENT_HANDOFF_DATA_ROOT" in text and "AGENT_HANDOFF_HERMES_BIN" in text, text[:300])
        summary = R.run_router()
        check("the router stops as misconfigured, not as delivered",
              summary.get("result") == "misconfigured" and summary.get("ok") is False,
              str(summary)[:220])
    with _env(AGENT_HANDOFF_CONFIG="", AGENT_HANDOFF_DATA_ROOT="", AGENT_HANDOFF_SCRIPT="",
              PI_HANDOFF_DATA_ROOT="", PI_HANDOFF_HERMES_BIN=""):
        missing = "\n".join(R.configuration_errors())
        check("an unconfigured router reports the missing key, not a default path",
              "AGENT_HANDOFF_DATA_ROOT" in missing and "AGENT_HANDOFF_SCRIPT" in missing,
              missing[:300])
        check("no Hermes candidate list survives", not hasattr(R, "DEFAULT_HERMES_PYTHON_CANDIDATES"),
              str(sorted(n for n in dir(R) if "CANDIDATE" in n)))
        check("no machine default survives", not hasattr(R, "DEFAULT_DATA_ROOT")
              and not hasattr(R, "DEFAULT_HANDOFF_PY") and not hasattr(R, "DEFAULT_HERMES_BIN"),
              str([n for n in dir(R) if n.startswith("DEFAULT_")]))

    # (g) a clean environment with only new names resolves and runs
    with _env(AGENT_HANDOFF_CONFIG="", AGENT_HANDOFF_ROOT="", AGENT_HANDOFF_URL="",
              AGENT_HANDOFF_SECRET_FILE="", PI_HANDOFF_URL="", PI_HANDOFF_ROOT="",
              AGENT_HANDOFF_MAX_ATTEMPTS="7"):
        check("new names alone run cleanly without a guard line",
              H.legacy_env_offenders() == [], str(H.legacy_env_offenders())[:220])
        check("the new name is what a setting reads",
              H.setting("AGENT_HANDOFF_MAX_ATTEMPTS") == "7",
              str(H.setting("AGENT_HANDOFF_MAX_ATTEMPTS")))
        code, out = cli(["status"], root)
        check("a new-name-only run still works", code == 0, f"rc={code} {out[:160]!r}")


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------
def cli_with(env, args, root):
    buf, ebuf = io.StringIO(), io.StringIO()
    old = dict(os.environ)
    os.environ.update(env)
    try:
        with redirect_stdout(buf), redirect_stderr(ebuf):
            code = H.main(["--root", root, *args]) or 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 2
    finally:
        os.environ.clear()
        os.environ.update(old)
    return code, buf.getvalue() + ebuf.getvalue()


def _make_receiver_handler(receiver):
    class Bound(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n)
            # pass the case-insensitive HTTPMessage through: fake_receiver reads
            # X-Hub-Signature-256 / X-Event-Type / X-Request-ID as sent by handoff.py:946-953,
            # whose wire spelling is title-cased by urllib
            code, resp = receiver.handle(self.headers, body)
            payload = json.dumps(resp, ensure_ascii=True).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            # Receiver.handle() already counts the request and appends the
            # requests.jsonl line; `requests` is an int, never a list

        def log_message(self, format, *args):  # noqa: A002 - match base signature
            return

    return Bound


def _free_port():
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _readtext(path):
    with open(path, "rb") as f:
        return f.read().decode("utf-8", "replace")


def _run_nopipes(argv):
    """Run a short external command with file-handle capture (no CreatePipe)."""
    outp = os.path.join(TMP, f"cmd-out-{NONCE}-{abs(hash(tuple(argv))) % 100000}.txt")
    errp = os.path.join(TMP, f"cmd-err-{NONCE}-{abs(hash(tuple(argv))) % 100000}.txt")
    try:
        with open(outp, "wb") as fo, open(errp, "wb") as fe:
            rc = subprocess.call(argv, stdout=fo, stderr=fe, timeout=30)
        return {"rc": rc, "out": _readtext(outp), "err": _readtext(errp)}
    finally:
        for p in (outp, errp):
            with contextlib.suppress(OSError):
                os.remove(p)


ALL = [t00_env, t01_validation, t02_register_report, t03_classification, t04_pid_exit,
       t05_caps_and_stall, t06_outbox, t06b_webhook_response_contract, t07_fake_receiver,
       t08_ack, t09_end_to_end, t10_cron_safety, t11_cleanup, t12_claude_compat,
       t13_renamed_settings]


def main():
    os.makedirs(TMP, exist_ok=True)
    for fn in ALL:
        try:
            fn()
        except Exception as e:  # noqa: BLE001 - report, keep going
            import traceback
            print(f"  ERROR in {fn.__name__}: {e.__class__.__name__}: {e}")
            traceback.print_exc()
            FAILURES.append(f"{fn.__name__} crashed: {e}")
    print("\n" + "=" * 72)
    if FAILURES:
        print(f"FAIL: {len(FAILURES)} problem(s)")
        for f in FAILURES:
            print("  - " + str(f)[:300])
        return 1
    print(f"PASS: all synthetic checks green ({NONCE})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
