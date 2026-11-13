#!/usr/bin/env python3
"""Offline unit tests for the Phase 2 webhook hardening (Gaps 1-5).

Synthetic data only. Every state root is a fresh tempdir under ``tmp/``; HTTP is
mocked at ``urllib.request.build_opener`` (so no socket is ever created), process
liveness at ``handoff.pid_exists``, and the router's subprocess seam is replaced by
a fake ``run`` that executes handoff.py IN-PROCESS against the same temp root and
cans every Hermes send/mirror call. The live ``data/`` tree is never touched.

Run: python -m unittest discover -s tests -p test_webhook_hardening.py -v
"""

import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)

import handoff as H  # noqa: E402

# The router is a script, not an installed package: load it from its real path so
# this test exercises the file the cron job actually runs.
_ROUTER_PATH = os.path.join(PROJECT, "scripts", "agent_handoff_router.py")
_router_spec = importlib.util.spec_from_file_location("agent_handoff_router", _ROUTER_PATH)
if _router_spec is None or _router_spec.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot load the router module from {_ROUTER_PATH}")
R = importlib.util.module_from_spec(_router_spec)
sys.modules["agent_handoff_router"] = R
_router_spec.loader.exec_module(R)

LOOPBACK = "http://127.0.0.1:19999/handoff"
VERIFY_LOOPBACK = "http://127.0.0.1:19999/verify"
SECRET_FILE = os.path.join(PROJECT, "tmp", "unit-webhook-secret-not-read")
TG_TARGET = "telegram:-1001234567890:27"
LOCAL_TARGET = "local:abcd1234efgh"
DEAD_PID = 999999


class BaseCase(unittest.TestCase):
    """Temp root + mocked HTTP/secret/env; subclasses add their own seam patches."""

    def setUp(self):
        scratch = os.path.join(PROJECT, "tmp")
        os.makedirs(scratch, exist_ok=True)
        temp = tempfile.TemporaryDirectory(prefix="hardening-", dir=scratch)
        self.addCleanup(temp.cleanup)
        self.root = temp.name
        self.workdir = os.path.join(self.root, "workdir")
        os.makedirs(self.workdir)

        self.opener = mock.MagicMock()
        response = self.opener.open.return_value.__enter__.return_value
        response.getcode.return_value = 202
        response.read.return_value = b'{"accepted":true}'
        patcher = mock.patch.object(H.urllib.request, "build_opener",
                                    return_value=self.opener)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(H, "load_secret", return_value=b"synthetic-unit-secret")
        patcher.start()
        self.addCleanup(patcher.stop)
        # a deployment environment must never leak into a unit run
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        for key in ("AGENT_HANDOFF_URL", "AGENT_HANDOFF_SECRET_FILE",
                    "AGENT_HANDOFF_VERIFY_URL", "AGENT_HANDOFF_ROOT"):
            os.environ.pop(key, None)

    # -- cli helpers -------------------------------------------------------
    def cli(self, *args):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            try:
                code = H.main(["--root", self.root, *args])
            except SystemExit as e:  # argparse exits, handoff.py returns codes
                code = e.code
        return code, output.getvalue()

    def jcli(self, *args):
        """(rc, last-json-object) for commands that answer with one JSON line.

        A command that prints no JSON yields {} rather than None, so a missing
        contract field fails on the assertion instead of on a subscript.
        """
        rc, output = self.cli(*args)
        for line in reversed(output.strip().splitlines()):
            try:
                data = json.loads(line)
            except ValueError:
                continue
            return rc, data if isinstance(data, dict) else {}
        return rc, {}

    def register(self, tid, source="cursor", target=TG_TARGET, extra=()):
        args = ["register", "--task-id", tid, "--workdir", self.workdir,
                "--goal", "hardening goal", "--source", source]
        if target:
            args += ["--origin-target", target]
        args += list(extra)
        return self.cli(*args)

    def task(self, tid):
        return H.load_registry(self.root)["tasks"][tid]

    def receipt(self, tid, key="session_path"):
        return self.task(tid)[key]

    def write_receipt(self, tid, text, key="session_path"):
        """Leave a receipt the way a compliant executor would, for this task's mode.

        Every mode keeps its own contract (Spec §2.5): a bare sentence is no longer a
        completion claim, so the helper has to satisfy the same checks the scanner does.
        """
        task = self.task(tid)
        mode = task.get("receipt_mode") or "json"
        success = task.get("exit_code_success") or 0
        low = task.get("min_report_chars") or 200
        body = text if len(text) >= low else text + "\n" + "x" * (low - len(text))
        now = int(time.time())
        if mode == "marker":
            fp = hashlib.sha256(body.encode("utf-8")).hexdigest()
            payload = f"exit={success}\nreport_fp={fp}\n"
        elif mode == "exitcode":
            artifact = task.get("report_path")
            if artifact is None:
                artifact = os.path.join(os.path.dirname(task["session_path"]), "artifact.txt")
            os.makedirs(os.path.dirname(artifact), exist_ok=True)
            with open(artifact, "w", encoding="utf-8") as f:
                f.write(body)
            payload = json.dumps({"exit_code": success, "artifact": artifact,
                                  "finished_at": now})
        else:
            payload = json.dumps({
                "schema_version": 1, "task_id": tid, "exit_code": success,
                "status": "report_ready", "report_text": body,
                "report_fp": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                "finished_at": now})
        return self.write_raw_receipt(tid, payload, key)

    def write_raw_receipt(self, tid, payload, key="session_path"):
        """Write a receipt file byte-for-byte: the entry point for rejection scenarios."""
        path = self.task(tid)[key]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(payload)
        return path

    def bad_receipts(self, tid):
        return H.load_state(self.root, tid).get("bad_receipts", 0)

    def receipt_of(self, tid, **overrides):
        """A complete json receipt body with the given fields replaced/removed (None)."""
        task = self.task(tid)
        low = task.get("min_report_chars") or 200
        text = overrides.pop("report_text", "done\n" + "y" * low)
        fp = overrides.pop("report_fp", None)
        body = {"schema_version": 1, "task_id": tid, "exit_code": 0,
                "status": "report_ready", "report_text": text,
                "report_fp": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "finished_at": int(time.time())}
        if fp is not None:
            body["report_fp"] = fp
        for key, val in overrides.items():
            if val is None:
                body.pop(key, None)
            else:
                body[key] = val
        return json.dumps(body)

    def tick(self, tid):
        rc, output = self.cli("tick", "--task", tid, "--no-send")
        self.assertEqual(rc, 0, output)
        return output

    def events(self):
        return H.load_events(self.root)

    def events_for(self, tid):
        return [e for e in self.events().values() if e["task_id"] == tid]

    def only_event(self, tid):
        found = [e for e in self.events().values() if e["task_id"] == tid]
        self.assertEqual(len(found), 1, f"expected one event for {tid}: {found}")
        return found[0]

    def patch_event(self, eid, **fields):
        ev = self.events()[eid]
        ev.update(fields)
        # an explicit updated_at is part of the scenario (age tests), not noise
        fields.setdefault("updated_at", int(time.time()))
        ev["updated_at"] = fields["updated_at"]
        H.write_json_atomic(H.p_event(self.root, eid), ev)
        return ev

    def verify_doc(self, eid) -> dict:
        return self.doc(H.p_verify(self.root, eid))

    def doc(self, path) -> dict:
        """The JSON object at path; {} when it is absent (never None)."""
        data = H.read_json(path, None)
        return data if isinstance(data, dict) else {}

    def open_verify(self, eid):
        """Walk the script channel's real order: claim, dispatch, then queue the review.

        Nothing else creates outbox/verify/<eid>.json (Spec §1.5), so a test that needs a
        queue doc has to go through the same two calls the router makes.
        """
        rc, out = self.jcli("claim", eid, "--claimer", "hermes-webhook", "--lease-seconds", "300")
        self.assertEqual(rc, 0, out)
        self.assertTrue(out["dispatch"])
        rc, out = self.jcli("verify-open", eid)
        self.assertEqual(rc, 0, out)
        return out

class VerifyChannelTests(BaseCase):
    """Gap 1: the script channel opens the verify queue, the verifier alone judges it.

    Rewritten for Major 1/2: create_event no longer queues a doc; only `verify-open`
    does, and only after the script channel holds the claim. A verify POST is closed
    only by a correlated acceptance, and a queue item stops at its attempt budget.
    """

    def _lines(self, path):
        if not os.path.isfile(path):
            return []
        with open(path, encoding="utf-8") as f:
            return [json.loads(x) for x in f if x.strip()]

    def _open_doc(self, eid):
        """Queue the doc exactly the way production does: claim, then verify-open."""
        rc, out = self.jcli("claim", eid, "--claimer", "hermes-webhook",
                            "--lease-seconds", "300")
        self.assertEqual(rc, 0, out)
        self.assertTrue(out["dispatch"], out)
        rc, out = self.jcli("verify-open", eid)
        self.assertEqual(rc, 0, out)
        self.assertEqual(out["result"], "opened", out)
        return out

    def _delivery_id(self, index=-1):
        req = self.opener.open.call_args_list[index].args[0]
        for name, value in req.header_items():
            if name.lower() == "x-github-delivery":
                return value
        return None

    def _echo_accept(self):
        """Accept the event only when the receiver echoes the id we sent (Major 2)."""
        def _read(*_args, **_kwargs):
            return json.dumps({"status": "accepted",
                               "delivery_id": self._delivery_id()}).encode()
        self.opener.open.return_value.__enter__.return_value.read.side_effect = _read

    def _respond(self, payload):
        reader = self.opener.open.return_value.__enter__.return_value
        reader.read.side_effect = None
        reader.read.return_value = payload

    def _verify_posts(self):
        return len([c for c in self.opener.open.call_args_list
                    if c.args[0].full_url == VERIFY_LOOPBACK])

    def test_tick_queues_no_doc_and_verify_open_after_claim_does(self):
        self.register("g1-real", extra=("--next-phase", "phase3"))
        self.write_receipt("g1-real", "task done\n")
        self.tick("g1-real")
        ev = self.only_event("g1-real")
        self.assertEqual(ev["status"], "report_ready")
        self.assertEqual(self.verify_doc(ev["event_id"]), {},
                         "create_event must not queue a verification (Major 1)")
        self.assertEqual(H.list_verify_queue(self.root), [])

        self._open_doc(ev["event_id"])
        doc = self.verify_doc(ev["event_id"])
        self.assertEqual(doc["task_id"], "g1-real")
        self.assertEqual(doc["status"], "report_ready")
        # the verifier reads the archived receipt, the same artifact the event names
        self.assertEqual(doc["receipt_path"], ev["receipt_path"])
        self.assertTrue(os.path.isfile(doc["receipt_path"]))
        self.assertEqual(doc["next_phases"], ["phase3"])
        self.assertEqual(doc["origin_target"], TG_TARGET)
        self.assertIs(doc["synthetic"], False)
        self.assertEqual(doc["claim_state"], "claimed_by_script")
        self.assertEqual(doc["route_state"], "ready")
        self.assertEqual(doc["notify_state"], "pending",
                         "notify_state mirrors the delivery side, not the claim")
        self.assertEqual(doc["verify_state"], "queued")
        self.assertEqual(len(H.list_verify_queue(self.root)), 1)

    def test_verify_open_refuses_before_the_scripts_own_claim(self):
        self.register("g1-noc")
        self.write_receipt("g1-noc", "report\n")
        self.tick("g1-noc")
        eid = self.only_event("g1-noc")["event_id"]
        rc, out = self.jcli("verify-open", eid)
        self.assertEqual(rc, 3, out)
        self.assertEqual(out["result"], "not_claimed_by_script")
        self.assertEqual(self.verify_doc(eid), {},
                         "a refusal must not leave a queue doc behind")

    def test_verify_open_refuses_a_synthetic_drill(self):
        self.register("g1-syn", extra=("--synthetic",))
        self.write_receipt("g1-syn", "synthetic drill\n")
        self.tick("g1-syn")
        eid = self.only_event("g1-syn")["event_id"]
        self.assertTrue(self.only_event("g1-syn")["synthetic"])
        rc, out = self.jcli("verify-open", eid)
        self.assertEqual(rc, 2, out)
        self.assertEqual(out["result"], "synthetic_not_queued")
        self.assertEqual(self.verify_doc(eid), {},
                         "a synthetic drill must never reach the verify Agent")
        self.assertEqual(H.list_verify_queue(self.root), [])

    def test_verify_open_refuses_a_blocked_route(self):
        self.register("g1-route")
        self.write_receipt("g1-route", "report\n")
        self.tick("g1-route")
        eid = self.only_event("g1-route")["event_id"]
        # a hand-edited registry with no origin target: the notification channel
        # never really told anyone, so a verifier would be chasing nothing
        reg = H.load_registry(self.root)
        reg["tasks"]["g1-route"]["origin_target"] = None
        H.write_json_atomic(H.p_registry(self.root), reg)
        rc, out = self.jcli("claim", eid, "--claimer", "hermes-webhook",
                            "--lease-seconds", "300")
        self.assertEqual(rc, 0, out)
        rc, out = self.jcli("verify-open", eid)
        self.assertEqual(rc, 2, out)
        self.assertEqual(out["result"], "route_not_ready")
        self.assertEqual(self.verify_doc(eid), {})

    def test_verify_open_is_idempotent_and_keeps_progress(self):
        self.register("g1-twice")
        self.write_receipt("g1-twice", "report\n")
        self.tick("g1-twice")
        eid = self.only_event("g1-twice")["event_id"]
        self._open_doc(eid)
        self._echo_accept()
        rc, _ = self.cli("send", "--url", LOOPBACK, "--secret-file", SECRET_FILE,
                         "--verify-url", VERIFY_LOOPBACK)
        self.assertEqual(rc, 0)
        first = self.verify_doc(eid)
        rc, out = self.jcli("verify-open", eid)
        self.assertEqual(rc, 0, out)
        self.assertEqual(out["result"], "already_opened", out)
        after = self.verify_doc(eid)
        self.assertEqual(after["verify_state"], "sent",
                         "re-opening must not erase the delivery progress")
        self.assertEqual(after["attempts"], first["attempts"])
        self.assertEqual(after["sent_at"], first["sent_at"])

    def test_send_with_verify_url_marks_sent_once_and_is_idempotent(self):
        self.register("g1-send")
        self.write_receipt("g1-send", "report\n")
        self.tick("g1-send")
        eid = self.only_event("g1-send")["event_id"]
        self._open_doc(eid)
        self._echo_accept()

        rc, _ = self.cli("send", "--url", LOOPBACK, "--secret-file", SECRET_FILE,
                         "--verify-url", VERIFY_LOOPBACK)
        self.assertEqual(rc, 0)
        doc = self.verify_doc(eid)
        self.assertEqual(doc["verify_state"], "sent")
        self.assertTrue(doc["sent_at"])
        self.assertEqual(doc["attempts"], 1)
        self.assertEqual(self._verify_posts(), 1)

        rc, _ = self.cli("send", "--url", LOOPBACK, "--secret-file", SECRET_FILE,
                         "--verify-url", VERIFY_LOOPBACK)
        self.assertEqual(rc, 0)
        self.assertEqual(self.verify_doc(eid)["attempts"], 1,
                         "a sent queue doc must not be re-posted")
        self.assertEqual(self._verify_posts(), 1)

    def test_verify_send_rotates_the_delivery_id_and_demands_correlation(self):
        self.register("g1-rot")
        self.write_receipt("g1-rot", "report\n")
        self.tick("g1-rot")
        eid = self.only_event("g1-rot")["event_id"]
        self._open_doc(eid)
        # a 2xx that says "ignored" must NOT close the queue item (Major 2)
        self._respond(b'{"status":"ignored","reason":"filtered by the receiver"}')
        rc, _ = self.cli("send", "--url", LOOPBACK, "--secret-file", SECRET_FILE,
                         "--verify-url", VERIFY_LOOPBACK)
        self.assertEqual(rc, 0)
        doc = self.verify_doc(eid)
        self.assertEqual(doc["attempts"], 1)
        self.assertNotEqual(doc.get("verify_state"), "sent",
                            "an ignored 2xx must not be recorded as delivered")
        self.assertEqual(self._delivery_id(), f"verify-{eid}")

        rc, _ = self.cli("send", "--url", LOOPBACK, "--secret-file", SECRET_FILE,
                         "--verify-url", VERIFY_LOOPBACK)
        self.assertEqual(rc, 0)
        self.assertEqual(self._delivery_id(), f"verify-{eid}-a1",
                         "a retry must carry a fresh id so the receiver re-fires")
        # and now the receiver actually accepts it
        self._echo_accept()
        rc, _ = self.cli("send", "--url", LOOPBACK, "--secret-file", SECRET_FILE,
                         "--verify-url", VERIFY_LOOPBACK)
        self.assertEqual(rc, 0)
        doc = self.verify_doc(eid)
        self.assertEqual(doc["verify_state"], "sent")
        self.assertEqual(doc["attempts"], 3)
        self.assertEqual(self._verify_posts(), 3)

    def test_verify_send_stops_at_the_attempt_budget(self):
        self.register("g1-cap")
        self.write_receipt("g1-cap", "report\n")
        self.tick("g1-cap")
        eid = self.only_event("g1-cap")["event_id"]
        self._open_doc(eid)
        path = H.p_verify(self.root, eid)
        doc = self.verify_doc(eid)
        doc["max_attempts"] = 2
        H.write_json_atomic(path, doc)
        self._respond(b'{"status":"ignored"}')
        for _ in range(2):
            self.cli("send", "--url", LOOPBACK, "--secret-file", SECRET_FILE,
                     "--verify-url", VERIFY_LOOPBACK)
        doc = self.verify_doc(eid)
        self.assertEqual(doc["attempts"], 2)
        self.assertEqual(doc["verify_state"], "failed",
                         "an exhausted verify budget must be recorded, not retried forever")
        self.assertTrue(doc["last_error"])
        self.assertEqual(self._verify_posts(), 2)

        rc, _ = self.cli("send", "--url", LOOPBACK, "--secret-file", SECRET_FILE,
                         "--verify-url", VERIFY_LOOPBACK)
        self.assertEqual(rc, 0)
        self.assertEqual(self._verify_posts(), 2,
                         "a failed queue item leaves the queue (Major 2)")

    def test_verify_posts_never_touch_the_router_webhook_url(self):
        self.register("g1-urls")
        self.write_receipt("g1-urls", "report\n")
        self.tick("g1-urls")
        eid = self.only_event("g1-urls")["event_id"]
        self._open_doc(eid)
        self._echo_accept()
        self.cli("send", "--url", LOOPBACK, "--secret-file", SECRET_FILE,
                 "--verify-url", VERIFY_LOOPBACK)
        urls = sorted({call.args[0].full_url for call in self.opener.open.call_args_list})
        self.assertEqual(urls, sorted([LOOPBACK, VERIFY_LOOPBACK]))

    def test_verify_claim_is_atomic_then_rejects_duplicate(self):
        self.register("g1-claim")
        self.write_receipt("g1-claim", "report\n")
        self.tick("g1-claim")
        eid = self.only_event("g1-claim")["event_id"]
        self._open_doc(eid)

        rc, out = self.jcli("verify-claim", eid, "--claimer", "verifier-a",
                            "--lease-seconds", "300")
        self.assertEqual(rc, 0)
        self.assertTrue(out["dispatch"])
        self.assertEqual(out["verify"]["event_id"], eid)

        rc, out = self.jcli("verify-claim", eid, "--claimer", "verifier-b",
                            "--lease-seconds", "300")
        self.assertEqual(rc, 3, "a duplicate verify claim must never dispatch twice")
        self.assertFalse(out["dispatch"])
        self.assertEqual(out["result"], "already_claimed")

    def test_verify_claim_lease_takeover_needs_expired_lease_and_dead_pid(self):
        self.register("g1-lease")
        self.write_receipt("g1-lease", "report\n")
        self.tick("g1-lease")
        eid = self.only_event("g1-lease")["event_id"]
        self._open_doc(eid)
        self.jcli("verify-claim", eid, "--claimer", "verifier-a", "--lease-seconds", "300")
        marker = H.p_verify_claim(self.root, eid)
        doc = self.doc(marker)
        doc["lease_expires_at"] = 1

        with mock.patch.object(H, "pid_exists", return_value=True):
            rc, _ = self.jcli("verify-claim", eid, "--claimer", "thief-alive")
            self.assertEqual(rc, 3, "an expired lease with a live pid is still owned")

        doc["claimer_pid"] = DEAD_PID
        H.write_json_atomic(marker, doc)
        with mock.patch.object(H, "pid_exists", return_value=False):
            rc, out = self.jcli("verify-claim", eid, "--claimer", "thief-dead")
        self.assertEqual(rc, 0)
        self.assertTrue(out["recovered"])
        self.assertEqual(out["prev_claimer"], "verifier-a")

    def test_verify_claim_unknown_event_is_rc1(self):
        rc, out = self.jcli("verify-claim", "nope1234", "--claimer", "x")
        self.assertEqual(rc, 1)
        self.assertEqual(out["result"], "unknown_event")

    def test_verify_claim_after_a_recorded_verdict_is_refused(self):
        self.register("g1-done")
        self.write_receipt("g1-done", "report\n")
        self.tick("g1-done")
        eid = self.only_event("g1-done")["event_id"]
        self._open_doc(eid)
        self.assertEqual(self.jcli("verify-ack", eid, "--verdict", "accepted")[0], 0)
        rc, out = self.jcli("verify-claim", eid, "--claimer", "late-comer")
        self.assertEqual(rc, 3, out)
        self.assertEqual(out["result"], "already_verified",
                         "the ledger outlives the doc: never re-dispatch a judged event")

    def test_verify_show_reads_the_queue_without_creating_anything(self):
        self.register("g1-show")
        self.write_receipt("g1-show", "report\n")
        self.tick("g1-show")
        eid = self.only_event("g1-show")["event_id"]
        rc, out = self.jcli("verify-show", eid)
        self.assertEqual(rc, 3, out)
        self.assertEqual(out["result"], "not_queued")
        self.assertEqual(self.verify_doc(eid), {},
                         "a read must never rebuild a doc the script channel refused")

        self._open_doc(eid)
        rc, out = self.jcli("verify-show", eid)
        self.assertEqual(rc, 0, out)
        self.assertEqual(out["verify"]["event_id"], eid)
        self.assertEqual(out["verify"]["claim_state"], "claimed_by_script")

    def test_verify_ack_writes_verify_ledger_without_touching_router_verdict(self):
        self.register("g1-ack")
        self.write_receipt("g1-ack", "report\n")
        self.tick("g1-ack")
        eid = self.only_event("g1-ack")["event_id"]
        self._open_doc(eid)
        # the router side records its own verdict first (delivery succeeded, work not
        # judged); the verify ledger is a separate book and must not rewrite it (I3)
        rc, _ = self.cli("ack", eid, "--verdict", "blocked", "--note", "等待独立验收",
                         "--claimer", "hermes-webhook")
        self.assertEqual(rc, 0)
        self.assertEqual(self.verify_doc(eid)["notify_state"], "blocked",
                         "the doc mirrors the notification side for operators only")

        rc, out = self.jcli("verify-ack", eid, "--verdict", "accepted",
                            "--note", "产物已核对", "--claimer", "verifier-a")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out["queue_doc"], "closed", out)
        self.assertEqual(self.events()[eid]["verdict"], "blocked",
                         "verify-ack must never rewrite the router verdict")
        router_ledger = self._lines(H.p_acks(self.root))
        self.assertEqual(len(router_ledger), 1)
        self.assertEqual(router_ledger[0]["verdict"], "blocked")
        verify_ledger = self._lines(H.p_verify_acks(self.root))
        self.assertEqual(len(verify_ledger), 1)
        self.assertEqual(verify_ledger[0]["verdict"], "accepted")
        self.assertEqual(verify_ledger[0]["claimer"], "verifier-a")
        self.assertEqual(self.verify_doc(eid), {},
                         "an acked doc leaves the queue; the ledger is the record (Minor 3)")
        self.assertEqual(H.list_verify_queue(self.root), [])

    def test_verify_ack_refuses_second_verdict_and_bad_verdict(self):
        self.register("g1-once")
        self.write_receipt("g1-once", "report\n")
        self.tick("g1-once")
        eid = self.only_event("g1-once")["event_id"]
        self._open_doc(eid)
        self.assertEqual(self.jcli("verify-ack", eid, "--verdict", "accepted")[0], 0)
        rc, _ = self.cli("verify-ack", eid, "--verdict", "blocked")
        self.assertEqual(rc, 2, "a verify verdict is final")
        rc, _ = self.cli("verify-ack", eid, "--verdict", "maybe")
        self.assertEqual(rc, 2)

    def test_verify_ack_on_a_missing_doc_reports_the_ledger(self):
        self.register("g1-gone")
        self.write_receipt("g1-gone", "report\n")
        self.tick("g1-gone")
        eid = self.only_event("g1-gone")["event_id"]
        self._open_doc(eid)
        os.remove(H.p_verify(self.root, eid))
        rc, out = self.jcli("verify-ack", eid, "--verdict", "accepted")
        self.assertEqual(rc, 3, out)
        self.assertEqual(out["result"], "not_queued",
                         "without the script channel's dispatch there is nothing to judge")
        self.assertEqual(self._lines(H.p_verify_acks(self.root)), [])

    def test_verify_clear_drops_unacked_and_keeps_verdicted(self):
        ids = []
        for tid in ("g1-clr-a", "g1-clr-b"):
            self.register(tid)
            self.write_receipt(tid, "report\n")
            self.tick(tid)
            eid = self.only_event(tid)["event_id"]
            ids.append(eid)
            self._open_doc(eid)
        self.assertEqual(self.jcli("verify-ack", ids[0], "--verdict", "accepted",
                                   "--note", "已核对")[0], 0)
        # a doc that still carries a verdict (written before this rework) is a record
        stale = dict(self.verify_doc(ids[1]))
        stale.update({"event_id": ids[0], "task_id": "g1-clr-a",
                      "verdict": "accepted", "verify_state": "acked"})
        H.write_json_atomic(H.p_verify(self.root, ids[0]), stale)

        rc, out = self.jcli("verify-clear", "--reason", "清理未验收积压")
        self.assertEqual(rc, 0)
        self.assertEqual(out["event_ids"], [ids[1]])
        self.assertEqual(out["skipped_verdicted"], [ids[0]])
        self.assertEqual(self.verify_doc(ids[1]), {})
        self.assertTrue(self.verify_doc(ids[0]),
                        "a reviewed doc is the record of that review: never drop it")

    def test_verify_clear_requires_reason_and_is_idempotent(self):
        rc, _ = self.cli("verify-clear")
        self.assertEqual(rc, 2)
        rc, out = self.jcli("verify-clear", "--reason", "nothing queued yet")
        self.assertEqual(rc, 0)
        self.assertEqual(out["cleared"], 0)
        self.assertEqual(out["absent"], [])

class MultiAgentSourceTests(BaseCase):
    """Gap 2: more agent sources, three receipt modes, and Fix B's name contract."""

    def test_cursor_codex_dsh_have_default_agent_names(self):
        for tid, source, name in (("g2-cursor", "cursor", "Cursor Agent"),
                                  ("g2-codex", "codex", "Codex"),
                                  ("g2-dsh", "dsh", "DSH")):
            rc, out = self.register(tid, source)
            self.assertEqual(rc, 0, out)
            self.assertEqual(self.task(tid)["agent_name"], name)

    def test_receipt_and_exit_require_explicit_agent_name(self):
        for source in ("receipt", "exit"):
            rc, out = self.register(f"g2-{source}", source)
            self.assertEqual(rc, 2, f"--source {source} must not guess a display name")
            self.assertIn("--agent-name is required", out)
            self.assertNotIn(f"g2-{source}", H.load_registry(self.root)["tasks"])

            rc, out = self.cli("register", "--task-id", f"g2-{source}",
                               "--workdir", self.workdir, "--goal", "g",
                               "--source", source, "--agent-name", "Manual Runner",
                               "--origin-target", TG_TARGET)
            self.assertEqual(rc, 0, out)
            self.assertEqual(self.task(f"g2-{source}")["agent_name"], "Manual Runner")

    def test_marker_mode_ready_and_stalled(self):
        self.register("g2-mark", extra=("--receipt-mode", "marker"))
        self.tick("g2-mark")
        self.assertEqual(self.events(), {}, "no marker, no pid: nothing to report yet")

        self.write_receipt("g2-mark", "all done\n")
        self.tick("g2-mark")
        self.assertEqual(self.only_event("g2-mark")["status"], "report_ready")

        # a dead pid that never wrote its marker is a stall, not a silent drop
        self.register("g2-dead", "cursor", extra=("--receipt-mode", "marker",
                                                 "--pid", str(DEAD_PID)))
        with mock.patch.object(H, "pid_exists", return_value=False):
            self.tick("g2-dead")
        ev = self.only_event("g2-dead")
        self.assertEqual(ev["status"], "stalled")
        self.assertIn("without marker file", ev["reason"])

    def test_marker_mode_rejects_thin_claims(self):
        # Spec §2.6: a marker is only a completion claim once it names an exit code AND a
        # report fingerprint; anything shorter is rejected, never a terminal event.
        self.register("g2-mark-thin", extra=("--receipt-mode", "marker"))
        bad = {
            "bare sentence": "all done\n",
            "exit line only": "exit=0\n",
            "empty report_fp": "exit=0\nreport_fp=\n",
            "report_fp is not a digest": "exit=0\nreport_fp=deadbeef\n",
            "exit line is not an int": "exit=ok\nreport_fp=" + "0" * 64 + "\n",
        }
        for label, payload in bad.items():
            with self.subTest(case=label):
                self.write_raw_receipt("g2-mark-thin", payload)
                self.tick("g2-mark-thin")
                self.assertEqual(self.events(), {}, f"{label} must not create an event")
        self.assertEqual(self.bad_receipts("g2-mark-thin"), len(bad))

        # the rejected task stays eligible: the corrected marker is still believed
        self.write_receipt("g2-mark-thin", "all done\n")
        self.tick("g2-mark-thin")
        self.assertEqual(self.only_event("g2-mark-thin")["status"], "report_ready")

    def test_register_defaults_to_json_mode(self):
        self.register("g2-default")
        self.assertEqual(self.task("g2-default")["receipt_mode"], "json")
        self.assertTrue(self.receipt("g2-default").endswith(
            os.path.join("receipt-source", "receipt.json")), self.receipt("g2-default"))

    def test_receipt_family_rejects_session_id(self):
        rc, out = self.register("g2-sid", extra=("--session-id", "abcd1234efgh"))
        self.assertEqual(rc, 2, out)
        self.assertIn("--session-id is not valid", out)
        self.assertNotIn("g2-sid", H.load_registry(self.root)["tasks"])

    def test_min_report_chars_is_configurable_and_bounded(self):
        self.register("g2-low", extra=("--receipt-mode", "json",
                                      "--min-report-chars", "50"))
        self.assertEqual(self.task("g2-low")["min_report_chars"], 50)
        self.write_raw_receipt("g2-low", self.receipt_of("g2-low", report_text="x" * 60))
        self.tick("g2-low")
        self.assertEqual(self.only_event("g2-low")["status"], "report_ready")

        rc, out = self.register("g2-bounds", extra=("--min-report-chars", "10"))
        self.assertEqual(rc, 2, out)
        self.assertIn("--min-report-chars", out)

    def test_json_mode_valid_and_failed_and_malformed(self):
        self.register("g2-json-ok", "codex", extra=("--receipt-mode", "json"))
        self.write_raw_receipt("g2-json-ok", self.receipt_of("g2-json-ok", summary="shipped"))
        self.tick("g2-json-ok")
        self.assertEqual(self.only_event("g2-json-ok")["status"], "report_ready")

        self.register("g2-json-bad", "codex", extra=("--receipt-mode", "json"))
        self.write_raw_receipt("g2-json-bad", self.receipt_of(
            "g2-json-bad", status="failed", exit_code=3, report_text="", reason="tests red"))
        self.tick("g2-json-bad")
        ev = self.only_event("g2-json-bad")
        self.assertEqual(ev["status"], "failed")
        self.assertIn("tests red", ev["reason"])

        # a malformed receipt is NO LONGER a terminal `failed` verdict: it is rejected, the
        # task stays open, and the corrected receipt still produces the real event. No pid:
        # the stall detector needs one, so this tick can only answer with the rejection.
        self.register("g2-json-malformed", "codex", extra=("--receipt-mode", "json"))
        self.write_raw_receipt("g2-json-malformed", "{not json")
        self.tick("g2-json-malformed")
        self.assertEqual(self.events_for("g2-json-malformed"), [],
                         "an unreadable receipt is not a verdict")
        self.assertEqual(self.bad_receipts("g2-json-malformed"), 1)
        self.write_raw_receipt("g2-json-malformed",
                               self.receipt_of("g2-json-malformed", report_text="fixed\n" + "z" * 220))
        self.tick("g2-json-malformed")
        self.assertEqual(self.only_event("g2-json-malformed")["status"], "report_ready")

        self.register("g2-json-partial", "codex",
                      extra=("--receipt-mode", "json", "--pid", str(os.getpid())))
        self.write_raw_receipt("g2-json-partial", '{"task_id": "g2-json-partial", ')
        with mock.patch.object(H, "pid_exists", return_value=True):
            self.tick("g2-json-partial")
        self.assertEqual(self.events_for("g2-json-partial"), [],
                         "partial json while the agent still runs is not a verdict")
        self.assertEqual(self.bad_receipts("g2-json-partial"), 0,
                         "a wait is not a rejection")

    def test_json_mode_matrix_rejects_thin_claims(self):
        # Every row here is a receipt that looks finished but cannot be believed; none of
        # them may create an event (Spec §2.6, reviewed in R1 as Blocker 2).
        cases = {
            "report_text under the minimum":
                lambda tid: self.receipt_of(tid, report_text="y" * 199),
            "report_fp does not match report_text":
                lambda tid: self.receipt_of(tid, report_fp="f" * 64),
            "report_fp is not a digest":
                lambda tid: self.receipt_of(tid, report_fp="nope"),
            "task_id belongs to another task":
                lambda tid: self.receipt_of(tid, task_id="some-other-task"),
            "finished_at precedes registered_at":
                lambda tid: self.receipt_of(
                    tid, finished_at=self.task(tid)["registered_at"] - 60),
            "missing exit_code": lambda tid: self.receipt_of(tid, exit_code=None),
            "non-integer exit_code": lambda tid: self.receipt_of(tid, exit_code="0"),
            "missing finished_at": lambda tid: self.receipt_of(tid, finished_at=None),
            "unknown schema_version": lambda tid: self.receipt_of(tid, schema_version=2),
            "status outside the contract": lambda tid: self.receipt_of(tid, status="done"),
            "receipt is not an object": lambda tid: json.dumps([{"task_id": tid}]),
        }
        for label, build in cases.items():
            tid = "g2-mx-" + str(abs(hash(label)) % 10 ** 6)
            with self.subTest(case=label):
                self.register(tid, "codex", extra=("--receipt-mode", "json"))
                self.write_raw_receipt(tid, build(tid))
                self.tick(tid)
                self.assertEqual(self.events_for(tid), [],
                                 f"{label} must not create an event")
                self.assertEqual(self.bad_receipts(tid), 1)

    def test_json_mode_contradictory_claim_downgrades(self):
        # report_ready alongside a failing exit code is not a completion: it becomes
        # stopped_unfinished (Spec §2.5B) and still counts as a rejected claim.
        self.register("g2-contr", "codex", extra=("--receipt-mode", "json"))
        self.write_raw_receipt("g2-contr",
                               self.receipt_of("g2-contr", exit_code=1))
        self.tick("g2-contr")
        ev = self.only_event("g2-contr")
        self.assertEqual(ev["status"], "stopped_unfinished")
        self.assertEqual(self.bad_receipts("g2-contr"), 1)

    def test_receipt_older_than_registration_is_rejected(self):
        self.register("g2-stale", "codex", extra=("--receipt-mode", "json"))
        path = self.write_raw_receipt("g2-stale", self.receipt_of("g2-stale"))
        old = self.task("g2-stale")["registered_at"] - 120
        os.utime(path, (old, old))
        self.tick("g2-stale")
        self.assertEqual(self.events(), {}, "a previous run's receipt is not this run's")
        self.assertEqual(self.bad_receipts("g2-stale"), 1)

    def test_tmp_sibling_without_a_final_name_is_never_read(self):
        self.register("g2-tmp", "codex", extra=("--receipt-mode", "json"))
        path = self.receipt("g2-tmp")
        self.write_raw_receipt("g2-tmp", self.receipt_of("g2-tmp"), key="session_path")
        with open(path, encoding="utf-8") as f:
            body = f.read()
        os.remove(path)
        with open(path + ".tmp", "w", encoding="utf-8") as f:
            f.write(body)
        self.tick("g2-tmp")
        self.assertEqual(self.events(), {}, "only the final receipt name is ever opened")
        self.assertEqual(self.bad_receipts("g2-tmp"), 0)

    def test_exitcode_mode_zero_nonzero_and_missing_report(self):
        report = os.path.join(self.workdir, "report.md")
        with open(report, "w", encoding="utf-8") as f:
            f.write("exit mode report\n")
        alive = str(os.getpid())   # keeps the stall detector out of these verdicts

        def exit_body(**fields):
            body = {"pid": DEAD_PID, "exit_code": 0, "artifact": report,
                    "finished_at": int(time.time())}
            for key, val in fields.items():
                if val is None:
                    body.pop(key, None)
                else:
                    body[key] = val
            return json.dumps(body)

        self.register("g2-exit-ok", "exit", extra=("--agent-name", "Exit Runner",
                                                   "--receipt-mode", "exitcode",
                                                   "--report-path", report,
                                                   "--pid", alive))
        self.assertEqual(self.task("g2-exit-ok")["receipt_mode"], "exitcode")
        # a bare integer is no longer the exitcode contract (Spec §2.5C: exit.json)
        self.write_raw_receipt("g2-exit-ok", "0\n")
        self.tick("g2-exit-ok")
        self.assertEqual(self.events_for("g2-exit-ok"), [],
                         "exitcode mode reads a json object, not an int")
        self.assertEqual(self.bad_receipts("g2-exit-ok"), 1)

        # success while the named pid still runs: wait, do not judge
        with mock.patch.object(H, "pid_exists", return_value=True):
            self.write_raw_receipt("g2-exit-ok", exit_body(pid=os.getpid()))
            self.tick("g2-exit-ok")
        self.assertEqual(self.events_for("g2-exit-ok"), [],
                         "a running worker has not finished yet")

        self.write_raw_receipt("g2-exit-ok", exit_body())
        with mock.patch.object(H, "pid_exists", return_value=False):
            self.tick("g2-exit-ok")
        ev = self.only_event("g2-exit-ok")
        self.assertEqual(ev["status"], "report_ready")
        with open(ev["receipt_path"], encoding="utf-8") as f:
            rec = json.load(f)
        self.assertIn(report, rec["final_text"])
        self.assertIn(str(os.path.getsize(report)), rec["final_text"])

        self.register("g2-exit-fail", "exit", extra=("--agent-name", "Exit Runner",
                                                    "--receipt-mode", "exitcode",
                                                    "--report-path", report,
                                                    "--pid", alive))
        self.write_raw_receipt("g2-exit-fail", exit_body(exit_code=2))
        self.tick("g2-exit-fail")
        ev = self.only_event("g2-exit-fail")
        self.assertEqual(ev["status"], "failed")
        self.assertIn("exit_code=2", ev["reason"])

        # exit 0 with a zero-byte product proves nothing: rejected, not terminal
        empty = os.path.join(self.workdir, "empty.md")
        open(empty, "w").close()
        self.register("g2-exit-empty", "exit", extra=("--agent-name", "Exit Runner",
                                                     "--receipt-mode", "exitcode",
                                                     "--report-path", empty,
                                                     "--pid", alive))
        self.write_raw_receipt("g2-exit-empty", exit_body(artifact=empty))
        self.tick("g2-exit-empty")
        self.assertEqual(self.events_for("g2-exit-empty"), [],
                         "a zero-byte artifact is not a report")
        self.assertEqual(self.bad_receipts("g2-exit-empty"), 1)

        # ...and neither is exit 0 pointing at a product that never appeared
        self.register("g2-exit-noreport", "exit",
                      extra=("--agent-name", "Exit Runner", "--receipt-mode", "exitcode",
                             "--report-path", os.path.join(self.workdir, "gone.md"),
                             "--pid", alive))
        self.write_raw_receipt("g2-exit-noreport", exit_body(
            artifact=os.path.join(self.workdir, "gone.md")))
        self.tick("g2-exit-noreport")
        self.assertEqual(self.events_for("g2-exit-noreport"), [],
                         "a missing artifact is not a report")
        self.assertEqual(self.bad_receipts("g2-exit-noreport"), 1)


    def test_force_reregister_clears_stale_receipt_files(self):
        self.register("g2-force", "cursor", extra=("--receipt-mode", "json"))
        path = self.write_receipt("g2-force", json.dumps(
            {"task_id": "g2-force", "status": "report_ready"}))
        rc, out = self.cli("register", "--task-id", "g2-force",
                           "--workdir", self.workdir, "--goal", "second run",
                           "--source", "cursor", "--receipt-mode", "json",
                           "--origin-target", TG_TARGET, "--force")
        self.assertEqual(rc, 0, out)
        self.assertIn("cleared stale receipt file(s)", out)
        self.assertFalse(os.path.exists(path),
                         "a stale receipt must not make the new run look finished")
        self.tick("g2-force")
        self.assertEqual(self.events(), {})


class LocalRoutingTests(BaseCase):
    """Gap 3: the origin may be this desktop session instead of a Telegram chat."""

    def test_validate_origin_target_local_forms(self):
        for ok in ("local", LOCAL_TARGET, "local:abcd1234efghijkl"):
            self.assertEqual(H.validate_origin_target(ok), ok)
        for bad in ("local:", "local:short", "local:bad space", "local:../x",
                    "", "  local", "local:abcd1234efgh extra"):
            with self.assertRaises(ValueError, msg=bad):
                H.validate_origin_target(bad)

    def test_register_accepts_local_target_and_routing_notifies_the_origin(self):
        # Spec G3-10: notify_telegram keeps its name but means "the script channel owes
        # the origin a notification", so a ready local route sets it too - the router
        # branches on channel, never on this flag alone.
        rc, out = self.register("g3-local", "cursor", target=LOCAL_TARGET)
        self.assertEqual(rc, 0, out)
        routing = H.task_routing(self.task("g3-local"))
        self.assertEqual(routing["channel"], "local")
        self.assertTrue(routing["notify_origin"])
        self.assertTrue(routing["notify_telegram"])
        self.assertEqual(routing["route_state"], "ready")

        rc, out = self.register("g3-bare", "cursor", target="local")
        self.assertEqual(rc, 0, out)
        routing = H.task_routing(self.task("g3-bare"))
        self.assertEqual(routing["channel"], "local")
        self.assertTrue(routing["notify_origin"])

        rc, out = self.register("g3-tg", "cursor", target=TG_TARGET)
        self.assertEqual(rc, 0, out)
        routing = H.task_routing(self.task("g3-tg"))
        self.assertEqual(routing["channel"], "telegram")
        self.assertTrue(routing["notify_telegram"])
        # a telegram origin is still the origin: notify_origin stays True for both
        # channels, and the router branches on channel, never on notify_origin alone
        self.assertTrue(routing["notify_origin"])

    def test_claim_carries_local_routing_to_the_router(self):
        self.register("g3-claim", "cursor", target=LOCAL_TARGET)
        self.write_receipt("g3-claim", "report\n")
        self.tick("g3-claim")
        eid = self.only_event("g3-claim")["event_id"]
        rc, out = self.jcli("claim", eid, "--claimer", R.ROUTER_CLAIMER, "--lease-seconds", "120")
        self.assertEqual(rc, 0)
        self.assertEqual(out["routing"]["channel"], "local")
        self.assertTrue(out["routing"]["notify_origin"])

    # -- router dispatch (fake run seam: handoff.py in-process, Hermes canned) --
    def run_router(self, fake_run, eid):
        self.log = []
        summary = R.run_router(data_root=self.root,
                               handoff_py=os.path.join(PROJECT, "handoff.py"),
                               hermes_bin="hermes.exe",
                               hermes_python="python.exe",
                               hermes_agent_dir=self.workdir,
                               target_event_id=eid,
                               now=int(time.time()),
                               run=fake_run, log=self.log.append)
        return summary

    def make_delivered_event(self, tid, target=LOCAL_TARGET, source="cursor", extra=()):
        rc, out = self.register(tid, source, target=target, extra=extra)
        self.assertEqual(rc, 0, out)
        self.write_receipt(tid, "report\n")
        self.tick(tid)
        ev = self.only_event(tid)
        self.patch_event(ev["event_id"], state="delivered", delivered_at=int(time.time()))
        return ev["event_id"]

    def test_router_mirrors_local_session_and_acks_accepted(self):
        eid = self.make_delivered_event("g3-r-ok")
        fake = FakeRun(mirror_marker="1")
        summary = self.run_router(fake, eid)
        self.assertEqual([d["channel"] for d in summary["dispatched"]], ["local"])
        self.assertEqual(self.events()[eid]["verdict"], "accepted")
        self.assertIn("本地会话", self._ack_note(eid))
        self.assertTrue(any(a[1] == "-c" for a in fake.calls),
                        "local routing must go through the Hermes mirror helper")

    def test_router_defers_when_named_local_session_is_absent(self):
        # Spec §4.2: a session Hermes refuses is transient, exactly like a timeout. The
        # bounded retry ladder, not the mirror marker, decides when it becomes blocked.
        eid = self.make_delivered_event("g3-r-missing")
        summary = self.run_router(FakeRun(mirror_marker="0"), eid)
        ev = self.events()[eid]
        self.assertEqual(len(summary["deferred"]), 1)
        self.assertIn("本地目标会话不存在", ev["last_retry_reason"])
        self.assertEqual(ev["retry_state"], "retry_pending")
        self.assertNotIn("verdict", ev,
                        "a missing session must not close the event out on the first try")

    def _mirror_payload(self, fake):
        calls = [a for a in fake.calls if a[1] == "-c"]
        self.assertEqual(len(calls), 1, str(fake.calls))
        return json.loads(calls[0][4])

    def test_bare_local_uses_the_registered_session_id(self):
        eid = self.make_delivered_event("g3-r-sid", target="local")
        reg = H.load_registry(self.root)
        reg["tasks"]["g3-r-sid"]["session_id"] = LOCAL_TARGET.split(":", 1)[1]
        H.write_json_atomic(H.p_registry(self.root), reg)
        fake = FakeRun(mirror_marker="1")
        summary = self.run_router(fake, eid)
        self.assertEqual([d["channel"] for d in summary["dispatched"]], ["local"])
        payload = self._mirror_payload(fake)
        self.assertEqual(payload["session_id"], LOCAL_TARGET.split(":", 1)[1])
        self.assertEqual(payload["session_key"], LOCAL_TARGET.split(":", 1)[1],
                        "a bare local target must never hand session_key='local' over")

    def test_bare_local_falls_back_to_the_environment_session(self):
        eid = self.make_delivered_event("g3-r-env", target="local")
        sid = LOCAL_TARGET.split(":", 1)[1]
        fake = FakeRun(mirror_marker="1")
        with mock.patch.dict(os.environ, {"AGENT_HANDOFF_LOCAL_SESSION": sid}):
            summary = self.run_router(fake, eid)
        self.assertEqual([d["channel"] for d in summary["dispatched"]], ["local"], summary)
        self.assertEqual(self._mirror_payload(fake)["session_id"], sid)

    def test_unresolvable_bare_local_defers_without_spawning_anything(self):
        # Major 3: no session id means there is nothing to mirror into. The old code
        # spawned python with session_key="local" and let Hermes guess a destination.
        eid = self.make_delivered_event("g3-r-none", target="local")
        fake = FakeRun(mirror_marker="1")
        env = {k: v for k, v in os.environ.items() if k != "AGENT_HANDOFF_LOCAL_SESSION"}
        with mock.patch.dict(os.environ, env, clear=True):
            summary = self.run_router(fake, eid)
        self.assertEqual([a for a in fake.calls if a[1] == "-c"], [],
                        "an unresolvable session must not reach the mirror helper")
        self.assertEqual(len(summary["deferred"]), 1)
        self.assertIn("transient", self.events()[eid]["last_retry_reason"])
        self.assertEqual(self.events()[eid]["retry_state"], "retry_pending")
        self.assertNotIn("verdict", self.events()[eid])

    def test_router_defers_bare_local_failure_as_transient(self):
        eid = self.make_delivered_event("g3-r-bare", target="local")
        summary = self.run_router(FakeRun(mirror_marker="0"), eid)
        ev = self.events()[eid]
        self.assertEqual(summary["deferred"][0]["retry_after"],
                         R.RETRY_BACKOFF_SCHEDULE[0])
        self.assertNotIn("verdict", ev)
        self.assertEqual(ev["retry_state"], "retry_pending")

    def test_router_defers_when_mirror_process_cannot_start(self):
        eid = self.make_delivered_event("g3-r-exc")
        summary = self.run_router(FakeRun(mirror_error=OSError("boom")), eid)
        self.assertEqual(len(summary["deferred"]), 1)
        self.assertEqual(self.events()[eid]["retry_state"], "retry_pending")
        self.assertNotIn("verdict", self.events()[eid])

    def test_router_sends_telegram_through_hermes_send(self):
        eid = self.make_delivered_event("g3-r-tg", target=TG_TARGET)
        fake = FakeRun(telegram_rc=0)
        summary = self.run_router(fake, eid)
        self.assertEqual([d["channel"] for d in summary["dispatched"]], ["telegram"])
        self.assertEqual(self.events()[eid]["verdict"], "accepted")
        send = [a for a in fake.calls if a[1] == "send"]
        self.assertEqual(send[0][2:4], ["--to", TG_TARGET])
        self.assertTrue(send[0][5].startswith("[Cursor Agent 进程退出回执]"),
                        "the subject must carry the registered display name")
        self.assertEqual(summary["verify_queued"], [eid],
                        "a delivered report is handed to the verifier by the same pass")
        self.assertEqual(self.verify_doc(eid)["claim_state"], "claimed_by_script")

    def test_router_blocks_immediately_on_hermes_send_usage_error(self):
        # Spec I9: exit 2 is the CLI refusing the command before it sent anything, so the
        # retry ladder cannot heal it. It is graded before the stderr marker text, which
        # is only as trustworthy as whatever Hermes happened to print.
        eid = self.make_delivered_event("g3-r-rc2", target=TG_TARGET)
        fake = FakeRun(telegram_rc=2, telegram_stderr="no such option: --style")
        summary = self.run_router(fake, eid)
        self.assertEqual(self.events()[eid]["verdict"], "blocked")
        self.assertIn("exit 2", summary["blocked"][0]["reason"])
        self.assertNotIn("retry_state", self.events()[eid])
        self.assertEqual(summary["verify_queued"], [],
                        "a report that never arrived must not be queued for review")

    def test_router_defers_a_plain_telegram_failure(self):
        eid = self.make_delivered_event("g3-r-rc1", target=TG_TARGET)
        fake = FakeRun(telegram_rc=1, telegram_stderr="connection reset by peer")
        summary = self.run_router(fake, eid)
        self.assertEqual(len(summary["deferred"]), 1)
        self.assertEqual(self.events()[eid]["retry_state"], "retry_pending")
        self.assertNotIn("verdict", self.events()[eid])

    def _ack_note(self, eid):
        path = H.p_acks(self.root)
        with open(path, encoding="utf-8") as f:
            return [json.loads(x) for x in f if x.strip()][-1]["note"]


class FakeRun:
    """Router subprocess seam.

    handoff.py calls run in-process (so the real CLI semantics are exercised against
    the temp root); Hermes send / mirror results are canned per test.
    """

    def __init__(self, mirror_marker="1", mirror_rc=0, mirror_error=None,
                 telegram_rc=0, telegram_stderr=""):
        self.mirror_marker = mirror_marker
        self.mirror_rc = mirror_rc
        self.mirror_error = mirror_error
        self.telegram_rc = telegram_rc
        self.telegram_stderr = telegram_stderr
        self.calls = []

    def __call__(self, argv, timeout=None):
        argv = list(argv)
        self.calls.append(argv)
        if len(argv) > 1 and str(argv[1]).endswith("handoff.py"):
            return self._handoff(argv)
        if len(argv) > 1 and argv[1] == "-c":
            if self.mirror_error is not None:
                raise self.mirror_error
            return _res(self.mirror_rc, R.MIRROR_SENTINEL + self.mirror_marker, "")
        if self.telegram_rc == 0:
            return _res(0, "delivered", "")
        return _res(self.telegram_rc, "", self.telegram_stderr or "connection refused")

    def _handoff(self, argv):
        buf = io.StringIO()
        try:
            with redirect_stdout(buf), redirect_stderr(buf):
                rc = H.main(argv[2:])
        except SystemExit as e:  # argparse usage error inside a CLI call
            rc = int(e.code or 2)
        return _res(rc, buf.getvalue(), "")


def _res(rc, out, err):
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def _header(request, name):
    """Request.add_header capitalises keys, so match case-insensitively."""
    for key, value in request.header_items():
        if key.lower() == name.lower():
            return value
    return None


class LeaseRetryTests(BaseCase):
    """Gap 4: leases, bounded exponential retry, and the transient/permanent split."""

    def new_event(self, tid="g4-ev", target=TG_TARGET, status="report_ready"):
        self.register(tid, "cursor", target=target)
        self.write_receipt(tid, "report\n")
        self.tick(tid)
        if status != "report_ready":
            for ev in self.events().values():
                if ev["task_id"] == tid:
                    return ev["event_id"]
        return self.only_event(tid)["event_id"]

    def test_claim_lease_blocks_active_lease(self):
        eid = self.new_event()
        rc, out = self.jcli("claim", eid, "--claimer", R.ROUTER_CLAIMER, "--lease-seconds", "300")
        self.assertEqual(rc, 0)
        self.assertTrue(out["dispatch"])
        rc, out = self.jcli("claim", eid, "--claimer", "other", "--lease-seconds", "300")
        self.assertEqual(rc, 3)
        self.assertFalse(out["dispatch"])
        marker = self.doc(H.p_claim(self.root, eid))
        self.assertGreater(marker["lease_expires_at"], int(time.time()))

    def test_claim_steals_expired_lease_only_when_holder_dead(self):
        eid = self.new_event("g4-steal")
        self.jcli("claim", eid, "--claimer", "crashed", "--lease-seconds", "300")
        marker = self.doc(H.p_claim(self.root, eid))
        marker.update(claimed_at=1, lease_expires_at=1)
        H.write_json_atomic(H.p_claim(self.root, eid), marker)

        with mock.patch.object(H, "pid_exists", return_value=True):
            rc, out = self.jcli("claim", eid, "--claimer", "waiter")
            self.assertEqual(rc, 3, "an expired lease held by a live pid stays owned")

        marker = self.doc(H.p_claim(self.root, eid))
        marker["claimer_pid"] = DEAD_PID
        H.write_json_atomic(H.p_claim(self.root, eid), marker)
        with mock.patch.object(H, "pid_exists", return_value=False):
            rc, out = self.jcli("claim", eid, "--claimer", "thief")
        self.assertEqual(rc, 0)
        self.assertTrue(out["dispatch"])
        self.assertTrue(out.get("recovered"))
        self.assertEqual(out["prev_claimer"], "crashed")

    def test_release_removes_claim_and_refuses_after_verdict(self):
        eid = self.new_event("g4-rel")
        self.jcli("claim", eid, "--claimer", R.ROUTER_CLAIMER, "--lease-seconds", "120")
        rc, out = self.jcli("release", eid, "--reason", "重投", "--claimer", R.ROUTER_CLAIMER)
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(H.p_claim(self.root, eid)))

        self.jcli("claim", eid, "--claimer", R.ROUTER_CLAIMER)
        self.jcli("ack", eid, "--verdict", "accepted", "--note", "已投递")
        rc, _ = self.cli("release", eid)
        self.assertEqual(rc, 2, "a verdicted event is closed: releasing would re-dispatch")

    def test_defer_marks_retry_pending_and_validates_window(self):
        eid = self.new_event("g4-def")
        rc, out = self.jcli("defer", eid, "--retry-after", "60",
                            "--reason", "临时网络错误", "--claimer", R.ROUTER_CLAIMER)
        self.assertEqual(rc, 0, out)
        ev = self.events()[eid]
        self.assertEqual(ev["retry_state"], "retry_pending")
        self.assertEqual(ev["retry_count"], 1)
        self.assertEqual(ev["max_retries"], H.DEFAULT_MAX_RETRIES)
        self.assertGreater(ev["next_action_at"], int(time.time()))

        rc, _ = self.cli("defer", eid, "--retry-after", "1")
        self.assertEqual(rc, 2, "retry-after must stay inside the validated window")

    def test_retry_poke_fires_once_per_window(self):
        eid = self.new_event("g4-poke")
        self.patch_event(eid, state="delivered", delivered_at=1000)
        self.jcli("defer", eid, "--retry-after", "60", "--reason", "临时失败")
        ev = self.events()[eid]
        window = ev["next_action_at"]

        rc = H.run_send(self.root, LOOPBACK, SECRET_FILE, window + 1)
        self.assertEqual(rc, 0)
        ev = self.events()[eid]
        self.assertEqual(ev["state"], "delivered", "a poke must not re-open delivery")
        pokes = [h for h in ev["history"] if h.get("action") == "retry_poke"]
        self.assertEqual(len(pokes), 1)
        self.assertEqual(ev["last_retry_poke_at"], window + 1)

        rc = H.run_send(self.root, LOOPBACK, SECRET_FILE, window + 2)
        self.assertEqual(rc, 0)
        pokes = [h for h in self.events()[eid]["history"]
                 if h.get("action") == "retry_poke"]
        self.assertEqual(len(pokes), 1, "one poke per retry window, never a flood")

        # a new window re-arms exactly one more poke
        self.patch_event(eid, retry_state="retry_pending", retry_count=2,
                         next_action_at=window + 120)
        H.run_send(self.root, LOOPBACK, SECRET_FILE, window + 121)
        pokes = [h for h in self.events()[eid]["history"]
                 if h.get("action") == "retry_poke"]
        self.assertEqual(len(pokes), 2)

    def test_poke_uses_a_distinct_delivery_id_so_the_receiver_refires(self):
        eid = self.new_event("g4-poke2")
        self.patch_event(eid, state="delivered", delivered_at=1000)
        self.jcli("defer", eid, "--retry-after", "60", "--reason", "临时失败")
        window = self.events()[eid]["next_action_at"]
        before = self.events()[eid]["attempts"]
        H.run_send(self.root, LOOPBACK, SECRET_FILE, window + 1)
        # a re-post must look like a NEW delivery to the receiver (the Hermes adapter
        # answers 202 duplicate for a delivery id it has already seen)
        deliveries = [_header(c.args[0], "X-GitHub-Delivery")
                      for c in self.opener.open.call_args_list]
        self.assertEqual(deliveries, [f"{eid}-r1"])
        after = self.events()[eid]
        self.assertEqual(after["attempts"], before,
                         "a poke re-triggers the router; it is not a delivery attempt")
        self.assertEqual(after["state"], "delivered")

    def test_retry_pending_claimed_by_router_is_delivered_without_dispatch(self):
        """Blocker 1: the router must retry an event it owns.

        Spec §4.5 branch A: `defer` keeps the claim, so when the retry window opens the
        router's own `claim` answers already_claimed with ITS claimer. Demanding
        dispatch=true there deadlocked every transient failure forever: the poke could
        never deliver, and nothing else was allowed to.
        """
        eid = self.new_event("g4-selfretry")
        self.patch_event(eid, state="delivered", delivered_at=1000)
        rc, out = self.jcli("claim", eid, "--claimer", R.ROUTER_CLAIMER,
                            "--lease-seconds", "300")
        self.assertEqual(rc, 0, out)
        rc, out = self.jcli("defer", eid, "--retry-after", "60", "--reason", "临时失败")
        self.assertEqual(rc, 0, out)
        self.patch_event(eid, next_action_at=int(time.time()) - 1)

        # the marker is still live and owned by this router, so `claim` cannot grant
        # dispatch: the old code skipped here and the event never moved again
        rc, out = self.jcli("claim", eid, "--claimer", R.ROUTER_CLAIMER,
                            "--lease-seconds", "300")
        self.assertEqual(rc, 3)
        self.assertEqual(out["result"], "already_claimed")
        self.assertEqual(out["claimer"], R.ROUTER_CLAIMER)

        summary = self.run_router(FakeRun(), eid)
        self.assertEqual(summary["skipped"], [], summary["skipped"])
        ev = self.events()[eid]
        self.assertEqual(ev.get("verdict"), "accepted",
                         "a self-owned due retry must be delivered and acked")
        self.assertEqual(ev["state"], "delivered")

    def test_retry_pending_claimed_by_another_owner_is_still_skipped(self):
        """The self-owned shortcut must not leak to a foreign claimer."""
        eid = self.new_event("g4-otherretry")
        self.patch_event(eid, state="delivered", delivered_at=1000)
        rc, out = self.jcli("claim", eid, "--claimer", "other-router", "--lease-seconds", "300")
        self.assertEqual(rc, 0, out)
        self.jcli("defer", eid, "--retry-after", "60", "--reason", "临时失败")
        self.patch_event(eid, next_action_at=int(time.time()) - 1)

        summary = self.run_router(FakeRun(), eid)
        self.assertEqual([s["reason"] for s in summary["skipped"]], ["not_claimed"])
        self.assertNotIn("verdict", self.events()[eid])

    def test_poke_failure_keeps_the_retry_window_armed(self):
        """Blocker 1b: only an accepted poke may consume the window."""
        eid = self.new_event("g4-pokefail")
        self.patch_event(eid, state="delivered", delivered_at=1000)
        self.jcli("defer", eid, "--retry-after", "60", "--reason", "临时失败")
        window = self.events()[eid]["next_action_at"]
        resp = self.opener.open.return_value.__enter__.return_value
        resp.read.return_value = b'{"status":"ignored"}'

        H.run_send(self.root, LOOPBACK, SECRET_FILE, window + 1)
        ev = self.events()[eid]
        self.assertEqual(len([h for h in ev["history"]
                              if h.get("action") == "retry_poke"]), 1)
        self.assertNotIn("last_retry_poke_at", ev,
                         "a poke the receiver did not accept must not burn the window")

        H.run_send(self.root, LOOPBACK, SECRET_FILE, window + 2)
        self.assertEqual(len([h for h in self.events()[eid]["history"]
                              if h.get("action") == "retry_poke"]), 2,
                         "the next tick must poke again")

        # once it is accepted, the window is consumed and the poking stops. The
        # receiver correlates on the poke's own delivery id (<event_id>-r<retry>), so
        # echo exactly that header back.
        def _echo_accept(*_a):
            req = self.opener.open.call_args_list[-1].args[0]
            return json.dumps({"status": "accepted",
                               "delivery_id": _header(req, "X-GitHub-Delivery")}).encode()

        resp.read.side_effect = _echo_accept
        H.run_send(self.root, LOOPBACK, SECRET_FILE, window + 3)
        ev = self.events()[eid]
        self.assertEqual(ev["last_retry_poke_at"], window + 3,
                         "an accepted poke is correlated to the -r<retry_count> delivery id")
        H.run_send(self.root, LOOPBACK, SECRET_FILE, window + 5)
        self.assertEqual(len([h for h in self.events()[eid]["history"]
                              if h.get("action") == "retry_poke"]), 3)

    def test_retry_exhaustion_refuses_defer_with_rc2(self):
        eid = self.new_event("g4-exh")
        self.patch_event(eid, retry_count=H.DEFAULT_MAX_RETRIES)
        rc, out = self.jcli("defer", eid, "--retry-after", "60", "--reason", "still down")
        self.assertEqual(rc, 2)
        self.assertEqual(out["result"], "retry_exhausted")
        self.assertEqual(out["max_retries"], H.DEFAULT_MAX_RETRIES)
        ev = self.events()[eid]
        self.assertEqual(ev["retry_count"], H.DEFAULT_MAX_RETRIES,
                         "the refused defer must not consume budget")
        self.assertNotIn("verdict", ev)

    def test_permanent_telegram_error_blocks_without_retry(self):
        eid = self.new_event("g4-perm")
        self.patch_event(eid, state="delivered", delivered_at=1000)
        summary = self.run_router(FakeRun(telegram_rc=1,
                                         telegram_stderr="Bad Request: chat not found"),
                                  eid)
        self.assertEqual(self.events()[eid]["verdict"], "blocked")
        self.assertIn("chat not found", summary["blocked"][0]["reason"])
        self.assertNotIn("retry_state", self.events()[eid],
                         "a dead destination is a contract error, not a transient one")

    def test_transient_telegram_error_defers_with_backoff_schedule(self):
        eid = self.new_event("g4-trans")
        self.patch_event(eid, state="delivered", delivered_at=1000)
        summary = self.run_router(FakeRun(telegram_rc=1,
                                         telegram_stderr="connection refused"), eid)
        self.assertEqual(summary["deferred"][0]["retry_after"], 60)
        self.assertEqual(self.events()[eid]["retry_count"], 1)

        # the next cron pass: the marker still says hermes-webhook owns the claim, so
        # an open retry window is self-owned and must be re-delivered without a release
        self.patch_event(eid, retry_count=2, retry_state="retry_pending",
                         next_action_at=0)
        summary = self.run_router(FakeRun(telegram_rc=1,
                                         telegram_stderr="connection refused"), eid)
        self.assertEqual(summary["deferred"][0]["retry_after"], 240,
                         "the second retry window must be 4 minutes wide")

    def test_exhausted_retries_escalate_to_blocked_verdict(self):
        eid = self.new_event("g4-esc")
        self.patch_event(eid, state="delivered", delivered_at=1000,
                         retry_count=H.DEFAULT_MAX_RETRIES,
                         retry_state="retry_pending", next_action_at=0)
        summary = self.run_router(FakeRun(telegram_rc=1,
                                         telegram_stderr="connection refused"), eid)
        self.assertEqual(self.events()[eid]["verdict"], "blocked")
        self.assertTrue(summary["blocked"][0]["escalated"])
        self.assertIn("投递重试耗尽", summary["blocked"][0]["reason"])

    def test_backoff_schedule_matches_documented_windows(self):
        self.assertEqual(R.RETRY_BACKOFF_SCHEDULE, (60, 120, 240, 480, 600))
        self.assertEqual(H.DEFAULT_MAX_RETRIES, 5)
        self.assertEqual([R.backoff_seconds(n) for n in (0, 1, 2, 3, 4, 5, 9)],
                         [60, 120, 240, 480, 600, 600, 600])

    def run_router(self, fake_run, eid):
        log = []
        return R.run_router(data_root=self.root,
                            handoff_py=os.path.join(PROJECT, "handoff.py"),
                            hermes_bin="hermes.exe",
                            hermes_python="python.exe",
                            hermes_agent_dir=self.workdir,
                            target_event_id=eid,
                            now=int(time.time()),
                            run=fake_run, log=log.append)


class RoutingContractTests(BaseCase):
    """The cross-channel contracts the happy path hides (Majors 1/6/8, Minors 3/4/6)."""

    def stalled_event(self, tid):
        self.register(tid, "cursor", extra=("--pid", str(DEAD_PID)))
        self.tick(tid)
        ev = self.only_event(tid)
        self.assertEqual(ev["status"], "stalled")
        return ev["event_id"]

    def new_event(self, tid):
        self.register(tid, "cursor")
        self.write_receipt(tid, "report\n")
        self.tick(tid)
        return self.only_event(tid)["event_id"]

    def test_verify_open_refuses_a_stalled_event(self):
        # Spec §1.5: only a report_ready report has an artifact worth reviewing
        eid = self.stalled_event("g6-stall")
        rc, out = self.jcli("claim", eid, "--claimer", "hermes-webhook", "--lease-seconds", "300")
        self.assertEqual(rc, 0, str(out))
        rc, out = self.jcli("verify-open", eid)
        self.assertEqual(rc, 2, str(out))
        self.assertEqual(out["result"], "not_report_ready")
        self.assertEqual(self.verify_doc(eid), {})

    def test_verify_open_refuses_a_released_claim(self):
        # I2: releasing hands the event back, so the queue must close again with it
        self.register("g6-rel")
        self.write_receipt("g6-rel", "report\n")
        self.tick("g6-rel")
        eid = self.only_event("g6-rel")["event_id"]
        self.jcli("claim", eid, "--claimer", "hermes-webhook", "--lease-seconds", "300")
        rc, out = self.jcli("release", eid, "--reason", "交回队列", "--claimer", "hermes-webhook")
        self.assertEqual(rc, 0, str(out))
        self.assertFalse(os.path.exists(H.p_claim(self.root, eid)))
        rc, out = self.jcli("verify-open", eid)
        self.assertEqual(rc, 3, str(out))
        self.assertEqual(out["result"], "not_claimed_by_script")

    def test_lease_takeover_journals_the_event_as_it_is_on_disk(self):
        # Major 6 / I3: the journal used to be appended to the copy read BEFORE the lock,
        # which quietly rolled back anything committed in between.
        self.register("g6-take")
        self.write_receipt("g6-take", "report\n")
        self.tick("g6-take")
        eid = self.only_event("g6-take")["event_id"]
        rc, out = self.jcli("claim", eid, "--claimer", "hermes-webhook", "--lease-seconds", "1")
        self.assertEqual(rc, 0, str(out))
        marker = self.doc(H.p_claim(self.root, eid))
        marker["lease_expires_at"] = int(time.time()) - 1
        marker["claimer_pid"] = DEAD_PID
        H.write_json_atomic(H.p_claim(self.root, eid), marker)

        self.patch_event(eid, attempts=7)
        real_load = H.load_events
        stale = {"pending": True}

        def load_with_a_stale_first_read(root):
            events = real_load(root)
            if stale["pending"]:
                stale["pending"] = False
                events = dict(events)
                events[eid] = dict(events[eid], attempts=0, history=[])
            return events

        load_patch = mock.patch.object(H, "load_events",
                                       side_effect=load_with_a_stale_first_read)
        pid_patch = mock.patch.object(H, "pid_exists", return_value=False)
        with load_patch, pid_patch:
            rc, out = self.jcli("claim", eid, "--claimer", "second-shift",
                                "--lease-seconds", "60")
        self.assertEqual(rc, 0, str(out))
        self.assertTrue(out.get("recovered"), str(out))
        ev = real_load(self.root)[eid]
        self.assertEqual(ev["attempts"], 7, "a takeover must not undo a committed write")
        self.assertTrue([h for h in ev["history"] if h.get("action") == "lease_takeover"],
                        "the takeover belongs in the journal")

    def test_ack_pending_reports_the_remaining_retry_window(self):
        # Minor 3: the line used to say "retry_pending" without saying for how long
        self.register("g6-wait", "cursor", extra=("--pid", str(DEAD_PID)))
        self.tick("g6-wait")
        eid = self.only_event("g6-wait")["event_id"]
        self.patch_event(eid, state="delivered", delivered_at=int(time.time()),
                         retry_state="retry_pending", next_action_at=int(time.time()) + 300)
        rc, out = self.cli("ack-pending")
        self.assertEqual(rc, 0, out)
        rows = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
        row = [r for r in rows if r["event_id"] == eid]
        self.assertEqual(len(row), 1, out)
        self.assertTrue(290 <= row[0]["retry_wait_seconds"] <= 300, str(row[0]))
        self.patch_event(eid, next_action_at=int(time.time()) - 60)
        rc, out = self.cli("ack-pending")
        rows = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
        self.assertEqual([r for r in rows if r["event_id"] == eid][0]["retry_wait_seconds"], 0,
                        "an open window must never read as a negative wait")

    def test_defer_uses_an_explicit_event_budget_then_the_task_then_the_default(self):
        # Minor 6: an event budget is only meaningful when someone stored one
        eid = self.new_event("g6-budget")
        self.patch_event(eid, max_retries=2)
        rc, out = self.jcli("defer", eid, "--retry-after", "60", "--reason", "一次")
        self.assertEqual(rc, 0, str(out))
        self.assertEqual(out["max_retries"], 2)
        reg = H.load_registry(self.root)
        reg["tasks"]["g6-budget"]["max_retries"] = 9
        H.write_json_atomic(H.p_registry(self.root), reg)
        rc, out = self.jcli("defer", eid, "--retry-after", "60", "--reason", "二次")
        self.assertEqual(out["max_retries"], 2, "the stored event budget outranks the task")
        other = self.new_event("g6-budget2")
        self.patch_event(other, max_retries=None)
        reg = H.load_registry(self.root)
        reg["tasks"]["g6-budget2"]["max_retries"] = 9
        H.write_json_atomic(H.p_registry(self.root), reg)
        rc, out = self.jcli("defer", other, "--retry-after", "60", "--reason", "一次")
        self.assertEqual(out["max_retries"], 9, str(out))
        reg = H.load_registry(self.root)
        reg["tasks"]["g6-budget2"].pop("max_retries")
        H.write_json_atomic(H.p_registry(self.root), reg)
        rc, out = self.jcli("defer", other, "--retry-after", "60", "--reason", "二次")
        self.assertEqual(out["max_retries"], H.DEFAULT_MAX_RETRIES, str(out))

    def test_pid_alive_treats_every_unknown_answer_as_alive(self):
        # Major 8: one probe for both processes, and "I cannot tell" is never licence
        for answer, expected in ((None, True), (True, True), (False, False)):
            lib = mock.Mock()
            lib.pid_exists.return_value = answer
            with mock.patch.object(R, "_handoff_lib", return_value=lib):
                self.assertEqual(R.pid_alive(4242), expected, str(answer))
            lib.pid_exists.assert_called_once_with(4242)
        with mock.patch.object(R, "_handoff_lib", return_value=None):
            self.assertTrue(R.pid_alive(4242), "an unloadable helper must not steal a lock")
        boom = mock.Mock(side_effect=OSError("probe broke"))
        with mock.patch.object(R, "_handoff_lib", return_value=mock.Mock(pid_exists=boom)):
            self.assertTrue(R.pid_alive(4242))

    def test_router_exits_zero_when_another_copy_holds_the_lock(self):
        # Spec V4: an overlapping cron run is the designed steady state, not a failure
        with mock.patch.object(R, "run_router",
                               return_value={"ok": False, "result": "lock_busy"}) as rr:
            self.assertEqual(R.main([]), 0)
        rr.assert_called_once()
        with mock.patch.object(R, "run_router", return_value={"ok": False, "result": "boom"}):
            self.assertEqual(R.main([]), 1)

class ArchivePruneTests(BaseCase):
    """Gap 5: the registry stays small without losing any audit trail."""

    def closed_task(self, tid, *, age_days=30, verdict="accepted", pid=None,
                    state="delivered", retry_state=None, recent=False):
        self.register(tid, "cursor", extra=(["--pid", str(pid)] if pid else []))
        self.write_receipt(tid, "report\n")
        self.tick(tid)
        eid = self.only_event(tid)["event_id"]
        if verdict:
            rc, out = self.jcli("ack", eid, "--verdict", verdict, "--note", "已核验")
            self.assertEqual(rc, 0, out)
        stamp = int(time.time()) - age_days * 86400
        if recent:
            stamp = int(time.time())
        fields = {"state": state, "created_at": stamp, "updated_at": stamp}
        if verdict:
            fields["verdict_at"] = stamp
        if retry_state:
            fields["retry_state"] = retry_state
        self.patch_event(eid, **fields)
        reg = H.load_registry(self.root)
        reg["tasks"][tid]["registered_at"] = stamp
        H.write_json_atomic(H.p_registry(self.root), reg)
        return eid

    def test_archive_dry_run_changes_nothing(self):
        self.closed_task("g5-a1")
        rc, out = self.jcli("archive", "--older-than-days", "14", "--dry-run")
        self.assertEqual(rc, 0, str(out))
        self.assertEqual(out["archived_task_ids"], ["g5-a1"])
        self.assertEqual(out["dry_run"], True)
        self.assertIn("g5-a1", H.load_registry(self.root)["tasks"])
        self.assertFalse(os.path.exists(H.p_archive(self.root)))

    def test_archive_moves_only_closed_aged_tasks(self):
        self.closed_task("g5-done")                       # eligible
        self.closed_task("g5-live-pid", pid=os.getpid())  # still running
        self.closed_task("g5-unacked", verdict="")        # no verdict yet
        self.closed_task("g5-retry", retry_state="retry_pending")
        self.closed_task("g5-recent", recent=True)        # inside the age window

        rc, out = self.jcli("archive", "--older-than-days", "14")
        self.assertEqual(rc, 0, str(out))
        self.assertEqual(out["archived_task_ids"], ["g5-done"], str(out["blocked"]))
        blocked = out["blocked"]
        self.assertIn("still alive", blocked["g5-live-pid"])
        self.assertIn("has no verdict", blocked["g5-unacked"])
        self.assertIn("retry window still open", blocked["g5-retry"])
        self.assertIn("inside the age window", blocked["g5-recent"])
        self.assertEqual(sorted(H.load_registry(self.root)["tasks"]),
                         ["g5-live-pid", "g5-recent", "g5-retry", "g5-unacked"])

        arch = self.doc(H.p_archive(self.root))
        self.assertEqual(list(arch["archived_tasks"]), ["g5-done"])
        self.assertTrue(arch["archived_tasks"]["g5-done"]["archived_at"])
        # the audit trail does not move: events stay where they are
        self.assertTrue(os.path.isdir(H.p_events_dir(self.root)))
        self.assertEqual(len(self.events()), 5)

        rc, out = self.jcli("archive", "--older-than-days", "14")
        self.assertEqual(rc, 0, str(out))
        self.assertEqual(out["archived_task_ids"], [], "archiving is idempotent")

    def test_archive_rejects_negative_window(self):
        rc, _ = self.cli("archive", "--older-than-days", "-1")
        self.assertEqual(rc, 2)

    def test_prune_claims_drops_verdicted_markers_at_any_age(self):
        old = int(time.time()) - 40 * 86400
        fresh = int(time.time())
        eids = {}
        for tid in ("g5-p-old-done", "g5-p-old-open", "g5-p-fresh-done"):
            eids[tid] = self.new_event(tid)
        self.jcli("ack", eids["g5-p-old-done"], "--verdict", "accepted", "--note", "n")
        self.jcli("ack", eids["g5-p-fresh-done"], "--verdict", "accepted", "--note", "n")

        for eid, when in ((eids["g5-p-old-done"], old), (eids["g5-p-old-open"], old),
                          (eids["g5-p-fresh-done"], fresh)):
            H.write_json_atomic(H.p_claim(self.root, eid),
                                {"event_id": eid, "claimer": "router",
                                 "claimed_at": when, "claimer_pid": DEAD_PID})

        # Minor 4: a marker only exists to stop a second delivery. Once a verdict (or a
        # deleted event) makes it useless its age no longer matters.
        rc, out = self.jcli("prune-claims")
        self.assertEqual(rc, 0, str(out))
        self.assertEqual(sorted(out["pruned_event_ids"]),
                         sorted([eids["g5-p-old-done"], eids["g5-p-fresh-done"]]))
        self.assertTrue(os.path.exists(H.p_claim(self.root, eids["g5-p-old-open"])),
                        "an unverdicted marker is the only guard against a replay")

    def test_prune_claims_dry_run_changes_nothing(self):
        eid = self.new_event("g5-p-dry")
        self.jcli("ack", eid, "--verdict", "accepted", "--note", "n")
        H.write_json_atomic(H.p_claim(self.root, eid),
                            {"event_id": eid, "claimer": "router",
                             "claimed_at": int(time.time()) - 40 * 86400,
                             "claimer_pid": DEAD_PID})
        rc, out = self.jcli("prune-claims", "--dry-run")
        self.assertEqual(rc, 0, str(out))
        self.assertEqual(out["pruned_event_ids"], [eid])
        self.assertTrue(os.path.exists(H.p_claim(self.root, eid)))

        rc, out = self.jcli("prune-claims")
        self.assertEqual(rc, 0, str(out))
        self.assertEqual(out["pruned_event_ids"], [eid],
                         "the verdict that just landed already closes the marker")

    def test_prune_claims_cleans_verify_markers_too(self):
        # A verify marker whose event file is gone can never be resumed.
        eid = self.new_event("g5-p-ver")
        H.write_json_atomic(H.p_verify_claim(self.root, eid),
                            {"event_id": eid, "claimer": "hermes-verify",
                             "claimed_at": int(time.time()), "claimer_pid": DEAD_PID})
        os.remove(H.p_event(self.root, eid))
        rc, out = self.jcli("prune-claims")
        self.assertEqual(rc, 0, str(out))
        self.assertIn(eid, out["pruned_event_ids"])
        self.assertFalse(os.path.exists(H.p_verify_claim(self.root, eid)))

    def test_prune_claims_keeps_a_live_verify_marker(self):
        # The other half of the rule: an un-judged verify claim on an event that is still
        # in the queue guards a verifier at work, so prune must leave it alone.
        eid = self.new_event("g5-p-ver2")
        self.open_verify(eid)
        rc, out = self.jcli("verify-claim", eid, "--claimer", "hermes-verify",
                            "--lease-seconds", "300")
        self.assertEqual(rc, 0, str(out))
        marker = H.p_verify_claim(self.root, eid)
        rc, out = self.jcli("prune-claims")
        self.assertEqual(rc, 0, str(out))
        self.assertNotIn(eid, out["pruned_event_ids"], str(out))
        self.assertTrue(os.path.exists(marker))

    def test_archive_named_task_bypasses_the_age_window(self):
        self.closed_task("named-fresh", age_days=0)
        self.closed_task("unnamed-fresh", age_days=0)
        rc, out = self.jcli("archive", "--task", "named-fresh")
        self.assertEqual(rc, 0, str(out))
        self.assertEqual(out["archived_task_ids"], ["named-fresh"])
        self.assertEqual(out["named_task_ids"], ["named-fresh"])
        self.assertIn("unnamed-fresh", H.load_registry(self.root)["tasks"],
                      "naming one task must not sweep the others along")

    def test_archive_named_task_still_needs_a_closed_task(self):
        # --task waives the age gate only; the verdict / live-pid gates still apply
        self.new_event("named-open")
        rc, out = self.jcli("archive", "--task", "named-open")
        self.assertEqual(rc, 0, str(out))
        self.assertEqual(out["archived_count"], 0)
        self.assertEqual(list(out["blocked"]), ["named-open"], str(out["blocked"]))
        self.assertIn("named-open", out["blocked"]["named-open"])

    def test_archive_rejects_unknown_named_task(self):
        self.closed_task("named-real")
        rc, out = self.cli("archive", "--task", "nope")
        self.assertEqual(rc, 2, out)
        self.assertIn("unknown task_id", out)

    def test_archive_archives_an_aged_synthetic_drill_without_a_flag(self):
        # Minor 1: a synthetic drill has no artifact to verify, so it never earns a
        # terminal_event_id - it must still leave the active set once the window passes.
        self.register("syn-old", "cursor",
                      extra=("--synthetic", "--pid", str(DEAD_PID)))
        self.tick("syn-old")
        ev = self.only_event("syn-old")
        rc, out = self.jcli("ack", ev["event_id"], "--verdict", "blocked",
                            "--note", "演练收尾")
        self.assertEqual(rc, 0, str(out))
        reg = H.load_registry(self.root)
        reg["tasks"]["syn-old"]["registered_at"] = int(time.time()) - 40 * 86400
        H.write_json_atomic(H.p_registry(self.root), reg)
        rc, out = self.jcli("archive", "--older-than-days", "14")
        self.assertEqual(rc, 0, str(out))
        self.assertEqual(out["archived_task_ids"], ["syn-old"], str(out["blocked"]))
        self.assertEqual(self.doc(H.p_archive(self.root)).get("archived_tasks", {})
                         .get("syn-old", {}).get("task_id"), "syn-old")

    def new_event(self, tid):
        self.register(tid, "cursor")
        self.write_receipt(tid, "report\n")
        self.tick(tid)
        return self.only_event(tid)["event_id"]


class ReceiptRepairR1Tests(BaseCase):
    """Phase 4-R1: the six receipt-family findings of the 2026-11-13 review.

    One test per behavioural finding (F1, F2, F4, F5) plus the documentation contract
    (F3, F6). Each was written against the pre-repair tree and fails there.
    """

    def wait_next_second(self):
        """Cross an integer-second boundary so a re-registration gets a new registered_at."""
        boundary = int(time.time()) + 1
        while int(time.time()) < boundary:
            time.sleep(0.02)

    # -- F1 (Blocker): a receipt verdict must carry a run-level fingerprint ---
    def test_r1_re_registered_run_gets_its_own_routable_event(self):
        self.register("r1-f1", "cursor", extra=("--receipt-mode", "json"))
        # byte-identical report text for both runs: only the RUN identity may tell the
        # two events apart, so this test cannot pass by accident of a changed report
        self.write_receipt("r1-f1", "identical report body")
        self.tick("r1-f1")
        old = self.only_event("r1-f1")
        old_doc = json.dumps(old, sort_keys=True)
        with open(old["receipt_path"], encoding="utf-8") as f:
            old_receipt = f.read()

        self.wait_next_second()
        rc, out = self.cli("register", "--task-id", "r1-f1",
                           "--workdir", self.workdir, "--goal", "second run",
                           "--source", "cursor", "--receipt-mode", "json",
                           "--origin-target", TG_TARGET, "--force")
        self.assertEqual(rc, 0, out)
        self.write_receipt("r1-f1", "identical report body")
        tick_out = self.tick("r1-f1")
        self.assertNotIn("(duplicate)", tick_out,
                         "F1: the second run must not fold onto the first event")

        found = self.events_for("r1-f1")
        self.assertEqual(len(found), 2, f"F1: one event per run, got {found}")
        new = [e for e in found if e["event_id"] != old["event_id"]][0]
        registered_at = self.task("r1-f1")["registered_at"]
        self.assertGreaterEqual(new["created_at"], registered_at,
                                "the new event must be routable under the new registration")
        self.assertEqual(self.task("r1-f1")["terminal_event_id"], new["event_id"])

        # the new event claims and routes; the old one stays blocked as pre-registration
        rc, doc = self.jcli("claim", new["event_id"], "--claimer", "hermes-webhook",
                            "--lease-seconds", "300")
        self.assertEqual(rc, 0, str(doc))
        self.assertTrue(doc["dispatch"])
        self.assertEqual(doc["routing"]["route_state"], "ready", str(doc["routing"]))
        rc, doc = self.jcli("claim", old["event_id"], "--claimer", "hermes-webhook",
                            "--lease-seconds", "300")
        self.assertEqual(rc, 0, str(doc))
        self.assertEqual(doc["routing"]["route_state"], "blocked", str(doc["routing"]))
        self.assertIn("事件早于当前注册", doc["routing"]["reason"])

        # ...and the first run's outbox event is untouched, not overwritten
        self.assertEqual(json.dumps(self.events()[old["event_id"]], sort_keys=True), old_doc)
        with open(old["receipt_path"], encoding="utf-8") as f:
            self.assertEqual(f.read(), old_receipt,
                             "F1: the earlier report must survive the later run")

    # -- F2 (Major): a failing exit code is a verdict, not a rejection ---------
    def test_r1_failed_exit_with_empty_or_missing_artifact_reaches_failed(self):
        alive = str(os.getpid())   # keeps the stall detector out of these verdicts
        empty = os.path.join(self.workdir, "r1-empty.md")
        open(empty, "w").close()
        gone = os.path.join(self.workdir, "r1-gone.md")
        for tid, artifact in (("r1-f2-empty", empty), ("r1-f2-gone", gone)):
            self.register(tid, "exit", extra=("--agent-name", "Exit Runner",
                                              "--receipt-mode", "exitcode",
                                              "--report-path", artifact,
                                              "--pid", alive))
            self.write_raw_receipt(tid, json.dumps({
                "pid": DEAD_PID, "exit_code": 3, "artifact": artifact,
                "finished_at": int(time.time())}))
            self.tick(tid)
            ev = self.only_event(tid)
            self.assertEqual(ev["status"], "failed",
                             f"F2: exit_code=3 with artifact {artifact!r} must be terminal")
            self.assertIn("exit_code=3", ev["reason"])
            self.assertEqual(self.bad_receipts(tid), 0,
                             "a failed verdict is not a rejected receipt")
            self.assertTrue(self.task(tid)["terminal_event_id"],
                            "the task must close instead of retrying forever")

        # the zero-byte guard stays put for a SUCCESSFUL exit (existing contract)
        self.register("r1-f2-ok-empty", "exit", extra=("--agent-name", "Exit Runner",
                                                       "--receipt-mode", "exitcode",
                                                       "--report-path", empty,
                                                       "--pid", alive))
        self.write_raw_receipt("r1-f2-ok-empty", json.dumps({
            "pid": DEAD_PID, "exit_code": 0, "artifact": empty,
            "finished_at": int(time.time())}))
        self.tick("r1-f2-ok-empty")
        self.assertEqual(self.events_for("r1-f2-ok-empty"), [],
                         "exit 0 on a zero-byte artifact is still a rejection")
        self.assertEqual(self.bad_receipts("r1-f2-ok-empty"), 1)

    # -- F4 (Minor): the receipt branch records liveness under the shared key ---
    def test_r1_receipt_branch_records_pid_status(self):
        self.register("r1-f4", "cursor", extra=("--receipt-mode", "json",
                                                "--pid", str(DEAD_PID)))
        self.write_receipt("r1-f4", "liveness report\n")
        with mock.patch.object(H, "pid_exists", return_value=False):
            self.tick("r1-f4")
        ev = self.only_event("r1-f4")
        with open(ev["receipt_path"], encoding="utf-8") as f:
            rec = json.load(f)
        self.assertIs(rec["pid_status"], False,
                      "F4: the archived receipt must carry the real liveness")
        st = H.load_state(self.root, "r1-f4")
        self.assertIs(st["pid_status"], False)
        self.assertNotIn("pid_alive", st, "one liveness key, not two")

    # -- F5 (Minor): --force clears the previous run's receipt files ------------
    def test_r1_force_clears_external_receipt_paths(self):
        ext = os.path.join(self.root, "external")
        os.makedirs(ext)
        receipt = os.path.join(ext, "run.json")
        exit_file = os.path.join(ext, "exit.json")
        self.register("r1-f5", "cursor", extra=("--receipt-mode", "json",
                                                "--session-path", receipt,
                                                "--exit-code-path", exit_file))
        # written immediately before the re-registration: inside the 2s mtime grace
        # window of _receipt_is_stale, so deletion is the only thing that saves the
        # next run from reporting a verdict for a task that never re-ran
        self.write_raw_receipt("r1-f5", self.receipt_of("r1-f5"), key="session_path")
        with open(exit_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({"exit_code": 0, "finished_at": int(time.time())}))
        self.assertTrue(os.path.isfile(receipt) and os.path.isfile(exit_file))

        rc, out = self.cli("register", "--task-id", "r1-f5",
                           "--workdir", self.workdir, "--goal", "second run",
                           "--source", "cursor", "--receipt-mode", "json",
                           "--session-path", receipt, "--exit-code-path", exit_file,
                           "--origin-target", TG_TARGET, "--force")
        self.assertEqual(rc, 0, out)
        self.assertIn("cleared stale receipt file(s)", out)
        self.assertFalse(os.path.exists(receipt),
                         "F5: the previous run's receipt must go, wherever it lives")
        self.assertFalse(os.path.exists(exit_file),
                         "F5: --exit-code-path is cleared like --session-path")
        self.tick("r1-f5")
        self.assertEqual(self.events_for("r1-f5"), [],
                         "a grace-window receipt from the old run must not reach a verdict")

    # -- F3 + F6 (Minor/Nit): the help text must match the shipped contract ----
    def test_r1_help_text_matches_receipt_and_routing_contract(self):
        # the shipped CLI text, not a private parser attribute: this is what an agent
        # reads before it decides whether marker mode has to produce a report file
        rc, out = self.cli("register", "--help")
        self.assertEqual(rc, 0, out)
        flat = " ".join(out.split())   # argparse wraps at terminal width; compare flattened

        # F3: marker mode takes the fingerprint claim alone; only exitcode mode verifies
        self.assertIn("exitcode mode verifies", flat, out)
        self.assertIn("marker mode records the fingerprint claim", flat, out)
        self.assertNotIn("verified as a task artifact", flat,
                         "the old blanket claim implied marker mode checked the file")

        # F6: every source's default display name, not just the legacy two
        for phrase in ("pi -> Pi", "claude -> Claude Code", "cursor -> Cursor Agent",
                       "codex -> Codex", "dsh -> DSH"):
            self.assertIn(phrase, flat, out)
        # F6: local routing forms
        self.assertIn("local:<session-id>", flat, out)
        self.assertIn("telegram:<chat_id>", flat, out)
        # F6: the compat table had no readers
        self.assertNotIn("LEGACY_AGENT_NAMES", vars(H),
                         "an unreferenced table only invites edits to the wrong place")


class ReceiptRepairR3Tests(BaseCase):
    """Phase 4-R3: the two F5 deletion-guard boundaries of the 2026-11-13 re-review.

    The R2 repair deleted the right files but asked the wrong question: it looked at
    the source THIS command registers, never at the source of the entry it replaced.
    Both tests were written against the R2 tree and fail there.
    """

    def force_register(self, tid, source, extra=()):
        args = ["register", "--task-id", tid, "--workdir", self.workdir,
                "--goal", "second run", "--source", source,
                "--origin-target", TG_TARGET, "--force"]
        return self.cli(*args, *extra)

    # -- F5 boundary 1: crossing INTO the receipt family must not eat the old log ----
    def test_r3_cross_source_force_keeps_the_legacy_session_log(self):
        tid = "r3-xsource"
        log = os.path.join(self.workdir, "pi-session.jsonl")
        with open(log, "w", encoding="utf-8") as f:
            f.write(json.dumps({"type": "assistant", "message": {"stopReason": "stop",
                                       "content": [{"type": "text",
                                                    "text": "first run report"}]}}) + "\n")
        rc, out = self.register(tid, "pi", extra=("--session-path", log))
        self.assertEqual(rc, 0, out)
        # a receipt already sitting on the path the NEW registration will default to:
        # the guard is about the legacy log, not about keeping every file in the tree
        rs = H.p_receipt_source_dir(self.root, tid)
        os.makedirs(rs, exist_ok=True)
        stale_receipt = os.path.join(rs, "receipt.json")
        with open(stale_receipt, "w", encoding="utf-8") as f:
            f.write(json.dumps({"schema_version": 1, "task_id": tid, "exit_code": 0,
                                "status": "report_ready", "report_text": "stale run",
                                "finished_at": int(time.time())}))

        rc, out = self.force_register(tid, "cursor", ("--receipt-mode", "json"))
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.task(tid)["source"], "cursor", str(out))
        self.assertTrue(os.path.isfile(log),
                        "F5: a pi session log is not a receipt, whatever --force says")
        self.assertFalse(os.path.exists(stale_receipt),
                         "the guard must not widen into 'clear nothing': " + out)
        self.assertIn("receipt.json", out, out)

    # -- F5 boundary 2: a report named like a receipt is still a report --------------
    def test_r3_force_keeps_an_artifact_named_like_a_receipt(self):
        tid = "r3-artifact-name"
        rs = H.p_receipt_source_dir(self.root, tid)
        receipt = os.path.join(rs, "run.json")      # this task's real receipt path
        artifact = os.path.join(rs, "exit.json")    # a DEFAULT receipt name, wrong role
        rc, out = self.register(tid, "cursor", extra=("--receipt-mode", "json",
                                                     "--session-path", receipt,
                                                     "--report-path", artifact))
        self.assertEqual(rc, 0, out)
        with open(artifact, "w", encoding="utf-8") as f:
            f.write("produced report body, never a receipt\n")

        # round two keeps --report-path: the CURRENT round's report must be protected
        rc, out = self.force_register(tid, "cursor", ("--receipt-mode", "json",
                                                      "--session-path", receipt,
                                                      "--report-path", artifact))
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.isfile(artifact),
                        "F5: the basename sweep must not delete a report by its name")
        self.assertNotIn("cleared stale receipt file(s)", out,
                         "nothing here is a receipt, so nothing may be reported cleared")
        with open(artifact, encoding="utf-8") as f:
            self.assertEqual(f.read(), "produced report body, never a receipt\n")

        # round three drops it: only the PREVIOUS entry still calls it a report
        rc, out = self.force_register(tid, "cursor", ("--receipt-mode", "json",
                                                      "--session-path", receipt))
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.isfile(artifact),
                        "F5: a report named in the previous entry stays protected")
        self.assertNotIn("cleared stale receipt file(s)", out, out)

        # control: report and receipt sharing ONE file means the file IS the receipt
        shared = os.path.join(H.p_receipt_source_dir(self.root, "r3-shared"),
                              "receipt.json")
        rc, out = self.register("r3-shared", "cursor",
                                extra=("--receipt-mode", "json", "--report-path", shared))
        self.assertEqual(rc, 0, out)
        with open(shared, "w", encoding="utf-8") as f:
            f.write(self.receipt_of("r3-shared"))
        rc, out = self.force_register("r3-shared", "cursor",
                                      ("--receipt-mode", "json", "--report-path", shared))
        self.assertEqual(rc, 0, out)
        self.assertFalse(os.path.exists(shared),
                         "a shared file is the previous receipt: the grace window applies")
        self.assertIn("cleared stale receipt file(s)", out)

    # -- F1 side item: pin the same-run dedup that R2's report only argued -----------
    def test_r3_same_run_force_tick_stays_duplicate(self):
        tid = "r3-same-run"
        self.register(tid, "cursor", extra=("--receipt-mode", "json"))
        self.write_receipt(tid, "byte-identical body for both ticks")
        first = self.tick(tid)
        self.assertNotIn("(duplicate)", first, first)
        event_id = self.only_event(tid)["event_id"]

        rc, out = self.cli("tick", "--task", tid, "--no-send", "--force")
        self.assertEqual(rc, 0, out)
        self.assertIn("(duplicate)", out,
                      "F1: one registered_at and one receipt must stay one event")
        self.assertEqual(len(self.events_for(tid)), 1, str(self.events_for(tid)))
        self.assertEqual(self.only_event(tid)["event_id"], event_id)


if __name__ == "__main__":
    unittest.main(verbosity=2)
