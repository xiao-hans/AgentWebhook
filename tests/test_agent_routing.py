#!/usr/bin/env python3
"""Synthetic unit tests; no sockets, real sessions or credentials.

Run: python -m unittest discover -s tests -p test_agent_routing.py -v
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT)

import fake_receiver  # noqa: E402
import handoff as H  # noqa: E402


class AgentRoutingTests(unittest.TestCase):
    def setUp(self):
        scratch = os.path.join(PROJECT, "tmp")
        os.makedirs(scratch, exist_ok=True)
        temp = tempfile.TemporaryDirectory(prefix="routing-unit-", dir=scratch)
        self.addCleanup(temp.cleanup)
        self.root = temp.name
        self.session = os.path.join(self.root, "synthetic-session.jsonl")
        with open(self.session, "w", encoding="utf-8") as f:
            f.write(json.dumps({"message": {"role": "assistant", "content": "synthetic report",
                                           "stopReason": "stop"}}) + "\n")
        self.opener = mock.MagicMock()
        response = self.opener.open.return_value.__enter__.return_value
        response.getcode.return_value = 202
        response.read.return_value = b'{"accepted":true}'
        opener_patch = mock.patch.object(H.urllib.request, "build_opener", return_value=self.opener)
        opener_patch.start()
        self.addCleanup(opener_patch.stop)
        secret_patch = mock.patch.object(H, "load_secret", return_value=b"synthetic-unit-secret")
        self.load_secret = secret_patch.start()
        self.addCleanup(secret_patch.stop)

    def cli(self, *args):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            try:
                code = H.main(["--root", self.root, *args])
            except SystemExit as e:
                code = e.code
        return code, output.getvalue()

    def register(self, tid="unit-task", *extra):
        return self.cli("register", "--task-id", tid, "--session-path", self.session,
                        "--workdir", self.root, "--goal", "synthetic routing check", *extra)

    def event(self, tid="unit-task"):
        task = H.load_registry(self.root)["tasks"][tid]
        ev, _ = H.create_event(self.root, task, H.load_state(self.root, tid),
                               "report_ready", "synthetic report", "unit text",
                               task["registered_at"])
        return ev

    def test_metadata_register_and_status(self):
        for index, target in enumerate(("telegram:12345", "telegram:-10012345",
                                        "telegram:-10012345:27", "telegram:+12345:1")):
            tid = f"target-{index}"
            rc, output = self.register(tid, "--agent-name", "Actual Agent",
                                       "--origin-target", target)
            self.assertEqual(rc, 0, output)
            echo = json.loads(output.removeprefix("registered "))
            self.assertEqual(echo["agent_name"], "Actual Agent")
            self.assertEqual(echo["origin_target"], target)
            task = H.load_registry(self.root)["tasks"][tid]
            self.assertEqual(task["source"], "pi")
            self.assertEqual(task["agent_name"], "Actual Agent")
            self.assertEqual(task["origin_target"], target)
            rc, output = self.cli("status", "--json")
            self.assertEqual(rc, 0, output)
            status = json.loads(output)[tid]
            self.assertEqual(status["task"]["origin_target"], target)
            self.assertEqual(status["task"]["agent_name"], "Actual Agent")
            self.assertEqual(status["routing"]["route_state"], "ready")
            self.assertIs(status["routing"]["notify_telegram"], True)
        rc, output = self.cli("status")
        self.assertEqual(rc, 0, output)
        self.assertIn("Actual Agent", output)
        self.assertIn("telegram:-10012345:27", output)

    def test_invalid_targets_rejected_before_registration(self):
        bad_targets = ("", "telegram:", "telegram:abc", "telegram:1:", "telegram:1:0",
                       "telegram:0", "telegram:-0", "telegram:+0", "telegram:00012345",
                       "telegram:-00012345", "telegram:+00012345", "telegram:1:01",
                       "telegram:1:000", "telegram:1:-1", "telegram:1:+1", "telegram:1:1:2",
                       "telegram:1\n", "telegram:1\r\n--to telegram:2", "telegram:1\x00",
                       " telegram:1", "telegram:1 ", "telegram:1\t", "telegram:١٢٣",
                       "telegram:1:２", "telegram:--1", "telegram:1;echo bad",
                       "telegram:1?thread=2", "session-12345", "home", "slack:1")
        for target in bad_targets:
            with self.subTest(target=target):
                rc, output = self.register("bad-target", "--origin-target", target)
                self.assertEqual(rc, 2, output)
                self.assertIn("origin_target", output)
                self.assertEqual(H.load_registry(self.root)["tasks"], {})
        for value in (None, 123, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                H.validate_origin_target(value)
        for name in ("", "  ", "Agent\nInjected", "Agent\x00"):
            with self.subTest(name=name):
                rc, output = self.register("bad-name", "--agent-name", name)
                self.assertEqual(rc, 2, output)
                self.assertEqual(H.load_registry(self.root)["tasks"], {})

    def test_legacy_defaults_and_source_independence(self):
        for source, expected in (("pi", "Pi"), ("claude", "Claude Code")):
            extra = ("--session-id", "session-unit-1234") if source == "claude" else ()
            rc, output = self.register(source, "--source", source, *extra)
            self.assertEqual(rc, 0, output)
            task = H.load_registry(self.root)["tasks"][source]
            self.assertEqual(task["agent_name"], expected)
            rc, output = self.register(source + "-custom", "--source", source, *extra,
                                       "--agent-name", "Different Agent")
            self.assertEqual(rc, 0, output)
            task = H.load_registry(self.root)["tasks"][source + "-custom"]
            self.assertEqual(task["source"], source)
            self.assertEqual(task["agent_name"], "Different Agent")
        rc, output = self.register("parser-check", "--source", "pi", "--agent-name", "Claude Code")
        self.assertEqual(rc, 0, output)
        rc, output = self.cli("tick", "--task", "parser-check", "--no-send")
        self.assertEqual(rc, 0, output)
        events = H.load_events(self.root)
        self.assertEqual(len(events), 1)
        self.assertEqual(next(iter(events.values()))["status"], "report_ready")

    def test_missing_null_and_empty_source_use_pi(self):
        for tid, source in (("missing-source", None), ("null-source", None),
                            ("empty-source", "")):
            with self.subTest(tid=tid):
                rc, output = self.register(tid, "--origin-target", "telegram:12345")
                self.assertEqual(rc, 0, output)
                reg = H.load_registry(self.root)
                task = reg["tasks"][tid]
                task.pop("agent_name")
                if tid == "missing-source":
                    task.pop("source")
                else:
                    task["source"] = source
                H.write_json_atomic(H.p_registry(self.root), reg)
                rc, output = self.cli("status", "--json")
                self.assertEqual(rc, 0, output)
                route = json.loads(output)[tid]["routing"]
                self.assertEqual(route["agent_name"], "Pi")
                self.assertEqual(route["route_state"], "ready")
                rc, output = self.cli("tick", "--task", tid, "--no-send")
                self.assertEqual(rc, 0, output)
                events = [ev for ev in H.load_events(self.root).values() if ev["task_id"] == tid]
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["status"], "report_ready")
                rc, output = self.cli("claim", events[0]["event_id"])
                self.assertEqual(rc, 0, output)
                self.assertEqual(json.loads(output)["routing"], route)
        self.opener.open.assert_not_called()

    def test_stored_agent_name_is_trimmed_without_rewriting_registry(self):
        rc, output = self.register("spaced-name", "--origin-target", "telegram:12345")
        self.assertEqual(rc, 0, output)
        reg = H.load_registry(self.root)
        reg["tasks"]["spaced-name"]["agent_name"] = "  Actual Agent  "
        H.write_json_atomic(H.p_registry(self.root), reg)
        with open(H.p_registry(self.root), "rb") as f:
            before = f.read()
        ev = self.event("spaced-name")
        rc, output = self.cli("status", "--json")
        self.assertEqual(rc, 0, output)
        route = json.loads(output)["spaced-name"]["routing"]
        self.assertEqual(route["agent_name"], "Actual Agent")
        self.assertEqual(route["route_state"], "ready")
        rc, output = self.cli("claim", ev["event_id"])
        self.assertEqual(rc, 0, output)
        self.assertEqual(json.loads(output)["routing"], route)
        with open(H.p_registry(self.root), "rb") as f:
            self.assertEqual(f.read(), before)
        self.opener.open.assert_not_called()

    def test_legacy_missing_route_blocks_acceptance_without_rewriting_registry(self):
        rc, output = self.register("legacy", "--source", "claude",
                                   "--session-id", "session-unit-1234")
        self.assertEqual(rc, 0, output)
        reg = H.load_registry(self.root)
        reg["tasks"]["legacy"].pop("agent_name")
        reg["tasks"]["legacy"].pop("origin_target")
        H.write_json_atomic(H.p_registry(self.root), reg)
        with open(H.p_registry(self.root), "rb") as f:
            before = f.read()
        ev = self.event("legacy")
        rc, output = self.cli("status", "--json")
        self.assertEqual(rc, 0, output)
        route = json.loads(output)["legacy"]["routing"]
        self.assertEqual(route["agent_name"], "Claude Code")
        self.assertIsNone(route["origin_target"])
        self.assertEqual(route["route_state"], "blocked")
        self.assertIs(route["notify_telegram"], False)
        self.assertIn("missing origin_target", route["reason"])
        self.assertNotEqual(route["origin_target"], "session-unit-1234")
        rc, output = self.cli("claim", ev["event_id"], "--claimer", "unit")
        self.assertEqual(rc, 0, output)
        self.assertEqual(json.loads(output)["routing"], route)
        self.assertEqual(json.loads(output)["result"], "claimed")
        rc, output = self.cli("claim", ev["event_id"], "--claimer", "duplicate")
        self.assertEqual(rc, 3, output)
        self.assertIs(json.loads(output)["dispatch"], False)
        rc, output = self.cli("ack", ev["event_id"], "--verdict", "accepted")
        self.assertEqual(rc, 2, output)
        self.assertIn("missing origin_target", output)
        self.assertNotIn("verdict", H.load_events(self.root)[ev["event_id"]])
        self.assertFalse(os.path.exists(H.p_acks(self.root)))
        rc, output = self.cli("ack", ev["event_id"], "--verdict", "blocked",
                              "--note", "missing origin_target; no fallback")
        self.assertEqual(rc, 0, output)
        self.assertEqual(H.load_events(self.root)[ev["event_id"]]["verdict"], "blocked")
        with open(H.p_registry(self.root), "rb") as f:
            self.assertEqual(f.read(), before)
        self.opener.open.assert_not_called()
        self.assertEqual(H.task_routing({})["agent_name"], "Pi")
        unknown = H.task_routing({"source": "unknown", "origin_target": "telegram:12345"})
        self.assertEqual(unknown["route_state"], "blocked")
        self.assertIsNone(unknown["agent_name"])

    def test_invalid_stored_route_and_missing_registry_block_acceptance(self):
        rc, output = self.register("changed", "--origin-target", "telegram:-10012345:9")
        self.assertEqual(rc, 0, output)
        ev = self.event("changed")
        reg = H.load_registry(self.root)
        for target in ("", "telegram:1\n", "telegram:1:0", "session-unit-1234"):
            with self.subTest(target=target):
                reg["tasks"]["changed"]["origin_target"] = target
                H.write_json_atomic(H.p_registry(self.root), reg)
                rc, output = self.cli("ack", ev["event_id"], "--verdict", "accepted")
                self.assertEqual(rc, 2, output)
                self.assertIn("origin_target", output)
                self.assertFalse(os.path.exists(H.p_claim(self.root, ev["event_id"])))
        reg["tasks"] = {}
        H.write_json_atomic(H.p_registry(self.root), reg)
        rc, output = self.cli("ack", ev["event_id"], "--verdict", "accepted")
        self.assertEqual(rc, 2, output)
        self.assertIn("task missing from registry", output)

    def test_hand_edited_unknown_source_blocks_the_route(self):
        # Spec §2.6: an unknown source means an unknown display name, so it must not
        # borrow another agent's - it blocks before the agent_name fallback is reached.
        rc, output = self.register("rogue", "--source", "cursor",
                                   "--origin-target", "telegram:-10012345:9")
        self.assertEqual(rc, 0, output)
        ev = self.event("rogue")
        reg = H.load_registry(self.root)
        reg["tasks"]["rogue"]["source"] = "totally-made-up"
        reg["tasks"]["rogue"]["agent_name"] = "Claude Code"
        H.write_json_atomic(H.p_registry(self.root), reg)
        rc, output = self.cli("status", "--json")
        self.assertEqual(rc, 0, output)
        route = json.loads(output)["rogue"]["routing"]
        self.assertEqual(route["route_state"], "blocked")
        self.assertIsNone(route["agent_name"],
                          "an unknown source must not reuse a stored display name")
        self.assertIs(route["notify_telegram"], False)
        self.assertIs(route["notify_origin"], False)
        self.assertIn("unknown source", route["reason"])
        rc, output = self.cli("claim", ev["event_id"], "--claimer", "unit")
        self.assertEqual(rc, 0, output)
        self.assertEqual(json.loads(output)["routing"]["route_state"], "blocked")

    def test_force_reregister_blocks_old_event_routing_to_new_target(self):
        with mock.patch.object(H.time, "time", return_value=100):
            rc, output = self.register("reregistered", "--origin-target", "telegram:12345")
        self.assertEqual(rc, 0, output)
        ev = self.event("reregistered")
        self.assertEqual(ev["created_at"], 100)
        with mock.patch.object(H.time, "time", return_value=200):
            rc, output = self.register("reregistered", "--force",
                                       "--origin-target", "telegram:-10012345:9")
        self.assertEqual(rc, 0, output)
        self.assertEqual(H.load_registry(self.root)["tasks"]["reregistered"]["registered_at"], 200)
        rc, output = self.cli("status", "--json")
        self.assertEqual(rc, 0, output)
        current_route = json.loads(output)["reregistered"]["routing"]
        self.assertEqual(current_route["origin_target"], "telegram:-10012345:9")
        self.assertEqual(current_route["route_state"], "ready")
        rc, output = self.cli("claim", ev["event_id"])
        self.assertEqual(rc, 0, output)
        claim = json.loads(output)
        self.assertIs(claim["dispatch"], True)
        self.assertEqual(claim["routing"]["route_state"], "blocked")
        self.assertEqual(claim["routing"]["reason"], "事件早于当前注册")
        self.assertIs(claim["routing"]["notify_telegram"], False)
        # an overridden route must be silenced on BOTH flags, or a router reading
        # notify_origin would still post an old event's report to the new registration
        self.assertIs(claim["routing"]["notify_origin"], False)
        rc, output = self.cli("claim", ev["event_id"], "--claimer", "duplicate")
        self.assertEqual(rc, 3, output)
        self.assertIs(json.loads(output)["dispatch"], False)
        self.assertEqual(json.loads(output)["routing"], claim["routing"])
        with open(H.p_event(self.root, ev["event_id"]), "rb") as f:
            before = f.read()
        rc, output = self.cli("ack", ev["event_id"], "--verdict", "accepted")
        self.assertEqual(rc, 2, output)
        self.assertIn("事件早于当前注册", output)
        self.assertFalse(os.path.exists(H.p_acks(self.root)))
        with open(H.p_event(self.root, ev["event_id"]), "rb") as f:
            self.assertEqual(f.read(), before)
        rc, output = self.cli("ack", ev["event_id"], "--verdict", "blocked")
        self.assertEqual(rc, 0, output)
        self.assertEqual(H.load_events(self.root)[ev["event_id"]]["verdict"], "blocked")
        self.opener.open.assert_not_called()

    def test_ack_cannot_overwrite_existing_verdict(self):
        for first, second in (("blocked", "accepted"), ("accepted", "blocked")):
            with self.subTest(first=first):
                rc, output = self.register(first, "--origin-target", "telegram:12345")
                self.assertEqual(rc, 0, output)
                ev = self.event(first)
                rc, output = self.cli("ack", ev["event_id"], "--verdict", first)
                self.assertEqual(rc, 0, output)
                paths = (H.p_event(self.root, ev["event_id"]), H.p_acks(self.root),
                         H.p_claim(self.root, ev["event_id"]), H.p_journal(self.root))
                before = {}
                for path in paths:
                    with open(path, "rb") as f:
                        before[path] = f.read()
                for verdict in (second, first):
                    with self.subTest(verdict=verdict):
                        rc, output = self.cli("ack", ev["event_id"], "--verdict", verdict,
                                              "--note", "must not overwrite")
                        self.assertEqual(rc, 2, output)
                        self.assertIn("verdict already recorded", output)
                        self.assertEqual(H.load_events(self.root)[ev["event_id"]]["verdict"], first)
                        for path in paths:
                            with open(path, "rb") as f:
                                self.assertEqual(f.read(), before[path], path)
        self.opener.open.assert_not_called()

    def test_ready_and_synthetic_claim_ack(self):
        for tid, extra, state, notify in (
                ("real-fixture", ("--origin-target", "telegram:-10012345:9"), "ready", True),
                ("synthetic", ("--synthetic",), "synthetic", False),
                ("synthetic-target", ("--synthetic", "--origin-target", "telegram:12345"),
                 "synthetic", False)):
            with self.subTest(tid=tid):
                rc, output = self.register(tid, *extra)
                self.assertEqual(rc, 0, output)
                ev = self.event(tid)
                rc, output = self.cli("claim", ev["event_id"])
                self.assertEqual(rc, 0, output)
                doc = json.loads(output)
                self.assertEqual(doc["routing"]["route_state"], state)
                self.assertIs(doc["routing"]["notify_telegram"], notify)
                rc, output = self.cli("ack", ev["event_id"], "--verdict", "accepted")
                self.assertEqual(rc, 0, output)
                self.assertEqual(H.load_events(self.root)[ev["event_id"]]["state"], "pending")
        self.opener.open.assert_not_called()
    def test_selected_send_preserves_every_other_event(self):
        ids = {}
        for tid in ("selected", "other", "future", "delivered", "blocked", "verdicted"):
            rc, output = self.register(tid, "--synthetic")
            self.assertEqual(rc, 0, output)
            ids[tid] = self.event(tid)["event_id"]
        for tid, fields in (("future", {"next_retry_at": 10**12}),
                            ("delivered", {"state": "delivered"}),
                            ("blocked", {"state": "blocked", "reason_blocked": "unit block"}),
                            ("verdicted", {"verdict": "blocked"})):
            path = H.p_event(self.root, ids[tid])
            ev = H.read_json(path, {})
            ev.update(fields)
            H.write_json_atomic(path, ev)
        before = {}
        for eid in ids.values():
            with open(H.p_event(self.root, eid), "rb") as f:
                before[eid] = f.read()
        rc, output = self.cli("send", "--url", "http://127.0.0.1:1/unit",
                              "--secret-file", "unused-mocked-secret", "--event-id", ids["selected"])
        self.assertEqual(rc, 0, output)
        self.opener.open.assert_called_once()
        payload = json.loads(self.opener.open.call_args.args[0].data)
        self.assertEqual(payload["event_id"], ids["selected"])
        self.assertEqual(H.load_events(self.root)[ids["selected"]]["state"], "delivered")
        for tid, eid in ids.items():
            if tid != "selected":
                with open(H.p_event(self.root, eid), "rb") as f:
                    self.assertEqual(f.read(), before[eid], tid)
        with open(H.p_journal(self.root), encoding="utf-8") as f:
            sends = [json.loads(line) for line in f if json.loads(line)["action"] != "created"]
        self.assertEqual([entry["event_id"] for entry in sends], [ids["selected"]])
        for tid in ("selected", "future", "delivered", "blocked", "verdicted"):
            self.opener.open.reset_mock()
            self.load_secret.reset_mock()
            rc, output = self.cli("send", "--url", "http://127.0.0.1:1/unit",
                                  "--secret-file", "unused-mocked-secret", "--event-id", ids[tid])
            self.assertEqual(rc, 0, output)
            self.opener.open.assert_not_called()
            self.load_secret.assert_not_called()
        for target in ("", "evt-unknown", ids["other"][:-1], ids["other"] + "suffix", "../event"):
            with self.subTest(event_id=target):
                rc, output = self.cli("send", "--url", "http://127.0.0.1:1/unit",
                                      "--secret-file", "unused-mocked-secret", "--event-id", target)
                self.assertEqual(rc, 1, output)
                self.assertIn("unknown event_id", output)
                self.opener.open.assert_not_called()
                self.load_secret.assert_not_called()
        for tid, eid in ids.items():
            if tid != "selected":
                with open(H.p_event(self.root, eid), "rb") as f:
                    self.assertEqual(f.read(), before[eid], tid)

    def test_selected_retry_does_not_touch_other_pending_event(self):
        ids = {}
        for tid in ("retry-selected", "retry-other"):
            rc, output = self.register(tid, "--synthetic")
            self.assertEqual(rc, 0, output)
            ids[tid] = self.event(tid)["event_id"]
        other_path = H.p_event(self.root, ids["retry-other"])
        with open(other_path, "rb") as f:
            before = f.read()
        self.opener.open.side_effect = H.urllib.error.URLError("synthetic network failure")
        rc, output = self.cli("send", "--url", "http://127.0.0.1:1/unit",
                              "--secret-file", "unused-mocked-secret",
                              "--event-id", ids["retry-selected"])
        self.assertEqual(rc, 0, output)
        self.opener.open.assert_called_once()
        event = H.load_events(self.root)[ids["retry-selected"]]
        self.assertEqual(event["state"], "pending")
        self.assertEqual(event["attempts"], 1)
        self.assertGreater(event["next_retry_at"], event["updated_at"])
        with open(other_path, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_unfiltered_send_keeps_batch_behavior(self):
        ids = set()
        for tid in ("batch-one", "batch-two"):
            rc, output = self.register(tid, "--synthetic")
            self.assertEqual(rc, 0, output)
            ids.add(self.event(tid)["event_id"])
        rc, output = self.cli("send", "--url", "http://127.0.0.1:1/unit",
                              "--secret-file", "unused-mocked-secret")
        self.assertEqual(rc, 0, output)
        sent = {json.loads(call.args[0].data)["event_id"]
                for call in self.opener.open.call_args_list}
        self.assertEqual(sent, ids)
        self.assertEqual(self.opener.open.call_count, 2)

    def test_webhook_still_signed_four_fields_and_injected_target_rejected(self):
        rc, output = self.register("wire", "--agent-name", "Actual Agent",
                                   "--origin-target", "telegram:-10012345:27")
        self.assertEqual(rc, 0, output)
        ev = self.event("wire")
        # Even unexpected local event metadata cannot enter the allow-listed envelope.
        ev.update(origin_target="telegram:99999", agent_name="Injected Agent")
        H.write_json_atomic(H.p_event(self.root, ev["event_id"]), ev)
        rc, output = self.cli("send", "--url", "http://127.0.0.1:1/unit",
                              "--secret-file", "unused-mocked-secret", "--event-id", ev["event_id"])
        self.assertEqual(rc, 0, output)
        request = self.opener.open.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(set(payload), fake_receiver.ALLOWED_FIELDS)
        self.assertEqual(payload, {"schema_version": H.SCHEMA_VERSION, "task_id": "wire",
                                   "event_id": ev["event_id"], "status": "report_ready"})
        self.assertEqual(request.get_header("X-hub-signature-256"),
                         H.sign(b"synthetic-unit-secret", request.data))
        self.assertEqual(request.get_header("X-request-id"), "agent-handoff-" + ev["event_id"])
        self.assertNotIn(b"telegram:", request.data)
        self.assertNotIn(b"Agent", request.data)
        receiver = fake_receiver.Receiver(os.path.join(self.root, "fake-receiver"),
                                          "ok", b"synthetic-unit-secret")
        for extra in ({"origin_target": "telegram:99999"}, {"agent_name": "Injected Agent"}):
            body = json.dumps({**payload, **extra}).encode("utf-8")
            code, response = receiver.handle({"X-Hub-Signature-256": H.sign(
                b"synthetic-unit-secret", body), "X-Event-Type": H.EVENT_TYPE}, body)
            self.assertEqual(code, 400)
            self.assertEqual(response["reason"], "payload_fields_not_allowed")
        rc, output = self.cli("claim", ev["event_id"])
        self.assertEqual(rc, 0, output)
        route = json.loads(output)["routing"]
        self.assertEqual(route["origin_target"], "telegram:-10012345:27")
        self.assertEqual(route["agent_name"], "Actual Agent")


if __name__ == "__main__":
    unittest.main()
