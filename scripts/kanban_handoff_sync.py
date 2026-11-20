#!/usr/bin/env python3
"""kanban_handoff_sync.py — project the pi-handoff ledger onto the Hermes kanban.

Deterministic, zero-LLM, zero-network, stdlib-only. The ledger is read-only. The
only board writes land on cards this projector owns, i.e. cards whose
idempotency key starts with ``handoff:``; cards owned by anyone else are never
transitioned, commented on, edited, deleted or archived.

Usage
-----
    kanban_handoff_sync.py             # full reconcile (cron tick / webhook)
    kanban_handoff_sync.py --sweep     # identical to no-arg
    kanban_handoff_sync.py --dry-run   # print the plan, write nothing
    kanban_handoff_sync.py --json      # machine-readable dry-run plan

Every entry path runs the same full reconcile: a JSON payload on stdin is only a
trigger, so all modes are idempotent.

Exit codes: 0 = ok (including lock contention, silent), 1 = error (logged),
2 = bad arguments (argparse).
"""

import argparse
import contextlib
import errno
import glob
import importlib
import itertools
import json
import os
import re
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Literal

# --------------------------------------------------------------------------
# Paths and constants. Every path is overridable (flag, then env, then the
# production default) so tests and dry runs stay completely offline.
# --------------------------------------------------------------------------

def _default_hermes_root() -> str:
    local_app = os.environ.get("LOCALAPPDATA")
    if local_app:
        cand = os.path.join(local_app, "hermes")
        if os.path.isdir(cand):
            return cand
    cand = os.path.join(os.path.expanduser("~"), ".hermes")
    if os.path.isdir(cand):
        return cand
    return os.path.join(os.path.expanduser("~"), "AppData", "Local", "hermes")

def _load_toml_settings() -> dict[str, str]:
    res: dict[str, str] = {}
    config_env = os.environ.get("AGENT_HANDOFF_CONFIG")
    candidates = []
    if config_env:
        candidates.append(config_env)
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.extend([
        os.path.join(here, "agentwebhook.toml"),
        os.path.join(os.path.dirname(here), "agentwebhook.toml"),
        os.path.join(os.path.dirname(here), "scripts", "agentwebhook.toml"),
        os.path.join(_default_hermes_root(), "scripts", "agentwebhook.toml"),
    ])
    for cand in candidates:
        if os.path.isfile(cand):
            try:
                import tomllib
                with open(cand, "rb") as f:
                    data = tomllib.load(f)
                    if isinstance(data, dict):
                        for k, v in data.items():
                            if isinstance(v, str):
                                res[k] = v
                break
            except Exception:
                pass
    return res

_CFG = _load_toml_settings()

HERMES_ROOT = _default_hermes_root()
HERMES_HOME = os.environ.get("HERMES_HOME", HERMES_ROOT)
LEDGER_ROOT = (
    os.environ.get("AGENT_HANDOFF_DATA_ROOT")
    or os.environ.get("PI_HANDOFF_DATA_ROOT")
    or _CFG.get("AGENT_HANDOFF_DATA_ROOT")
    or _CFG.get("AGENT_HANDOFF_ROOT")
    or os.path.join(HERMES_ROOT, "pi-handoff", "data")
)
HERMES_AGENT_DIR = (
    os.environ.get("AGENT_HANDOFF_HERMES_AGENT_DIR")
    or _CFG.get("AGENT_HANDOFF_HERMES_AGENT_DIR")
    or (os.path.join(HERMES_HOME, "hermes-agent") if os.path.isdir(os.path.join(HERMES_HOME, "hermes-agent")) else os.path.join(HERMES_ROOT, "hermes-agent"))
)
BOARD_DB = (
    os.environ.get("HERMES_KANBAN_DB")
    or (os.path.join(HERMES_HOME, "kanban.db") if os.path.exists(os.path.join(HERMES_HOME, "kanban.db")) else os.path.join(HERMES_ROOT, "kanban.db"))
)
STATE_DIR = os.environ.get("AGENT_HANDOFF_STATE_DIR",
                           os.path.join(HERMES_ROOT, "state"))
LOG_PATH = os.environ.get("AGENT_HANDOFF_KANBAN_SYNC_LOG",
                          os.path.join(HERMES_ROOT, "logs", "kanban-handoff-sync.log"))

KEY_PREFIX = "handoff:"          # single-writer boundary
CARD_AUTHOR = "pi-handoff-sync"  # created_by marker (secondary ownership guard)
CARD_ASSIGNEE = "handoff-tracker" # non-spawnable lane assignee to avoid auto-dispatch
ACTIVITY_WINDOW_SECONDS = 15 * 60   # brief: "flow activity within 15 minutes"
LOCK_NAME = "kanban-handoff-sync.lock"
LOCK_STALE_SECONDS = 15 * 60        # only stolen after this AND when owner is dead
STDIN_READ_BUDGET_SECONDS = 1.0     # a payload is a trigger, never worth blocking

# Ledger states (the brief's mapping table) and the board column each projects
# to. ``running`` deliberately never reaches the board: Hermes' dispatcher
# requeues every claimless running card on each tick
# (kanban_db_dispatch.reconcile_orphaned_running), so a projector that wrote
# ``running`` would fight the dispatcher forever. Active work therefore lands on
# ``ready`` with an ACTIVE evidence comment, and the ledger state stays visible
# in both the comment and the card body.
S_DONE, S_REVIEW, S_BLOCKED, S_RUNNING, S_READY = (
    "done", "review", "blocked", "running", "ready")
BOARD_STATE = {S_DONE: "done", S_REVIEW: "review", S_BLOCKED: "blocked",
               S_RUNNING: "ready", S_READY: "ready"}
BOARD_STATES = ("ready", "review", "blocked", "done")

# Event statuses that mean "the run ended without delivering finished work".
FAILED_STATUSES = ("failed", "stalled", "stopped_unfinished")
REPORT_READY = "report_ready"

# Acceptance verdicts. verify-acks carries a ``verdict`` field on every row
# written by the current tooling; the note wording is a fallback for older rows
# only. Acceptance is matched as a fixed completion phrase (or an English whole
# word), never as a bare substring: 「通过」 inside 「修复后可以通过」 is a promise
# about the future, not a verdict (review Major 1). Failure words keep
# substring matching and are checked *first*, so a note that contains both a
# failure word and an acceptance phrase stays blocked.
_ACCEPT_PHRASES = ("核验通过", "验收通过", "检查通过", "复核通过", "验证通过",
                   "审核通过", "评审通过", "确认通过", "通过验收", "通过核验",
                   "通过评审", "通过检查")
_ACCEPT_WORDS = re.compile(r"\b(?:accepted|approved|passed|passes)\b")
_FAIL_MARKS = ("不通过", "未通过", "核验失败", "验收失败", "驳回", "阻塞",
               "rejected", "reject", "blocked", "not accepted", "fail")
# A modal in front of an acceptance phrase turns it into a plan, not a verdict:
# 「可以通过验收」 and 「修复后可以通过」 must never read as accepted. The window
# checked is the two characters before the phrase, plus a few deferral markers
# that veto acceptance wherever they appear in the note.
_MODAL_BEFORE = "可能应将待需要够"
_DEFERRAL_MARKS = ("修复后", "修改后", "调整后", "补齐后", "重跑后", "预计",
                   "计划", "尚待", "还差", "可以通过", "应可通过", "才可以通过")
# ``verdict`` field spellings seen in real ledgers and in the spec.
_ACCEPT_VALUES = {"accepted", "accept", "approved", "pass", "passed", "done"}
_REJECT_VALUES = {"blocked", "reject", "rejected", "not_accepted", "unaccepted",
                  "fail", "failed"}

COMMENT_MARKER = "[handoff-sync evidence="


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

class SyncError(Exception):
    """Any failure the run reports as an error (exit 1, logged)."""


def _int(value: Any) -> int | None:
    """Best-effort integer/epoch coercion; None when the value is not an int."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        try:
            return int(value)
        except (OverflowError, ValueError):
            return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _iso(ts: Any = None) -> str:
    stamp = _int(ts)
    if stamp is None:
        stamp = int(time.time())
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(stamp))
    except (OverflowError, OSError, ValueError):
        return str(stamp)


def _short(text: Any, limit: int = 88) -> str:
    flat = " ".join(str(text if text is not None else "").split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "\u2026"


def _is_missing_file(exc: BaseException) -> bool:
    return isinstance(exc, FileNotFoundError) or getattr(exc, "errno", None) == errno.ENOENT


class NullLogger:
    """Logger double: keeps the pure code paths free of file side effects."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.dropped: list[str] = []

    def write(self, level: str, message: str) -> None:
        self.lines.append(f"{_iso()} [{level}] {message}")

    def info(self, message: str) -> None:
        self.write("INFO", message)

    def warn(self, message: str) -> None:
        self.write("WARN", message)

    def error(self, message: str) -> None:
        self.write("ERROR", message)


class Logger(NullLogger):
    """Append-only log file. Logging failures never mask the sync result."""

    def __init__(self, path: str | None, echo: bool = False) -> None:
        super().__init__()
        self.path = path
        self.echo = echo

    def write(self, level: str, message: str) -> None:
        line = f"{_iso()} [{level}] {message}"
        self.lines.append(line)
        if self.echo:
            with contextlib.suppress(OSError, ValueError):
                sys.stderr.write(line + "\n")
        if not self.path:
            return
        try:
            parent = os.path.dirname(os.path.abspath(self.path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except (OSError, ValueError) as exc:
            # A broken log must not turn a good sweep into a failure.
            self.dropped.append(f"{level}: {exc}")


class FileLock:
    """``O_CREAT|O_EXCL`` lock with a re-checked stale-theft window.

    Contention is a normal condition (another sweep owns the board right now):
    ``acquired`` stays False and the caller exits 0 silently. Reclaiming a stale
    lock is an arbitration, not a delete: the observed lock is renamed aside
    atomically and only the winner of that rename may create a new one, so two
    contenders can never both believe they hold the board (review Major 3).
    """

    _tokens = itertools.count(1)

    def __init__(self, path: str, logger: Any = None,
                 stale_seconds: int = LOCK_STALE_SECONDS,
                 steal_probe: Any = None) -> None:
        self.path = path
        self.log = logger or NullLogger()
        self.stale_seconds = stale_seconds
        self.steal_probe = steal_probe
        self.acquired = False
        # Identifies *this* acquisition, not just this process: two contenders in
        # one process (tests) or a recycled pid still cannot be confused.
        self.token_id = f"{os.getpid()}-{next(FileLock._tokens)}"

    def __enter__(self) -> "FileLock":
        self.acquired = self._try_acquire()
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, tb: Any) -> Literal[False]:
        if self.acquired:
            try:
                os.unlink(self.path)
            except OSError as exc:
                if not _is_missing_file(exc):
                    self.log.warn(f"could not release lock {self.path}: {exc}")
        return False

    def _try_acquire(self) -> bool:
        try:
            parent = os.path.dirname(os.path.abspath(self.path))
            if parent:
                os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            raise SyncError(f"cannot create state dir for lock: {exc}") from exc
        for attempt in (0, 1, 2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise SyncError(f"cannot take lock {self.path}: {exc}") from exc
                # Steal at most once, then only create if the path is free again.
                if attempt or not self._steal_if_stale():
                    return False
                continue
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(f"{os.getpid()}\n{_iso()}\n{self.token_id}\n")
            except OSError as exc:  # fd is already open: do not leak it
                raise SyncError(f"cannot write lock {self.path}: {exc}") from exc
            return True
        return False

    def _observe_lock(self) -> tuple[int, str] | None:
        """(mtime_ns, owner line) as it is right now; None when unreadable/gone."""
        try:
            stamp = os.stat(self.path)
            with open(self.path, encoding="utf-8", errors="replace") as handle:
                owner = handle.readline().rstrip("\r\n")
        except OSError:
            return None
        return (int(stamp.st_mtime_ns), owner)

    def _steal_if_stale(self) -> bool:
        observed = self._observe_lock()
        if observed is None:
            return True  # vanished or unreadable: retrying O_EXCL is harmless
        age = time.time() - observed[0] / 1_000_000_000
        owner = _int(observed[1])
        if age < self.stale_seconds:
            return False
        if owner is not None and pid_alive(owner) is True:
            self.log.warn(f"lock {self.path} is {age:.0f}s old but owner {owner} "
                          f"is still alive: leaving it alone")
            return False
        self.log.warn(f"stale lock {self.path} (age={age:.0f}s owner={owner}): "
                      f"attempting reclaim")
        if self.steal_probe is not None:
            self.steal_probe()          # test seam: the window between check and theft
        return self._reclaim(observed)

    def _reclaim(self, observed: tuple[int, str]) -> bool:
        """Move *observed* aside, and only if nobody beat us to it.

        ``os.rename`` is the arbitration: exactly one contender can move the
        observed file, the loser gets an error and backs off. Never unlink a
        lock we did not just confirm is still the one we saw.
        """
        if self._observe_lock() != observed:
            return False    # replaced during the window: it is not ours to take
        quarantine = f"{self.path}.stale-{self.token_id}-{time.time_ns()}"
        try:
            os.rename(self.path, quarantine)
        except OSError as exc:
            if not _is_missing_file(exc):
                self.log.warn(f"cannot quarantine stale lock {self.path}: {exc}")
            return False
        try:
            os.unlink(quarantine)
        except OSError as exc:
            if not _is_missing_file(exc):
                self.log.warn(f"cannot remove quarantined lock {quarantine}: {exc}")
        return True


def pid_alive(pid: Any) -> bool | None:
    """True / False / None (unknown). Mirrors handoff.py's ctypes approach."""
    value = _int(pid)
    if not value or value <= 0:
        return None
    if os.name == "nt":
        return _pid_alive_windows(value)
    try:
        os.kill(value, 0)
    except OSError as exc:
        return False if exc.errno == errno.ESRCH else None
    return True


def _pid_alive_windows(pid: int) -> bool | None:
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32  # noqa: S405 - documented OS API
        process_query_limited_information = 0x1000
        still_active = 259
        error_access_denied = 5
        kernel32.OpenProcess.restype = wintypes.HANDLE
        handle = kernel32.OpenProcess(process_query_limited_information, True, pid)
        if not handle:
            # Access denied proves the pid exists but belongs to another user.
            return ctypes.GetLastError() == error_access_denied
        code = wintypes.DWORD()
        ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
        kernel32.CloseHandle(handle)
    except Exception as exc:  # noqa: BLE001 - liveness must never break a sweep
        NullLogger().warn(f"pid_alive({pid}) probe failed: {exc}")
        return None
    if not ok:
        return None
    return code.value == still_active


# --------------------------------------------------------------------------
# Ledger (read-only)
# --------------------------------------------------------------------------

def _read_json(path: str, default: Any = None) -> Any:
    """Read one JSON document. Missing file -> ``default``; broken file -> error."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as exc:
        raise SyncError(f"ledger file is not valid JSON: {path} ({exc})") from exc
    except OSError as exc:
        raise SyncError(f"cannot read ledger file {path}: {exc}") from exc


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise SyncError(f"cannot read ledger file {path}: {exc}") from exc


def load_ledger(root: str) -> dict[str, Any]:
    """Read every fact this sync needs. Touches nothing outside ``root``."""
    registry = _read_json(os.path.join(root, "registry.json"), {})
    tasks = registry.get("tasks") if isinstance(registry, dict) else None
    if not isinstance(tasks, dict):
        raise SyncError(f"registry.json has no tasks object: {root}")
    events, events_by_task = _load_events(os.path.join(root, "outbox", "events"))
    acks = _load_acks(os.path.join(root, "outbox", "verify-acks.jsonl"), events)
    return {
        "root": root,
        "tasks": tasks,
        "events": events,
        "events_by_task": events_by_task,
        "acks": acks,
        "states": _load_states(os.path.join(root, "tasks")),
    }


def _load_events(events_dir: str) -> tuple[dict[str, dict], dict[str, list[dict]]]:
    events: dict[str, dict] = {}
    by_task: dict[str, list[dict]] = {}
    try:
        paths = sorted(glob.glob(os.path.join(events_dir, "evt-*.json")))
    except OSError as exc:  # pragma: no cover - glob rarely raises
        raise SyncError(f"cannot list {events_dir}: {exc}") from exc
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                raw = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue  # a torn event file is not this projector's problem
        if not isinstance(raw, dict):
            continue
        event = dict(raw)
        event["event_path"] = path
        event["event_id"] = event.get("event_id") or os.path.basename(path)[:-len(".json")]
        events[event["event_id"]] = event
        task_id = event.get("task_id")
        if task_id:
            by_task.setdefault(task_id, []).append(event)
    for bucket in by_task.values():
        bucket.sort(key=lambda item: (_int(item.get("created_at")) or 0,
                                      str(item.get("event_id") or "")))
    return events, by_task


def _load_acks(acks_path: str, events: dict[str, dict]) -> dict[str, dict]:
    """Parse verify-acks.jsonl into ``{event_id: ack}``.

    This file is the ledger's acceptance record. ``verdict`` comes from its field
    when present, otherwise from the note wording (the brief's fallback clause).
    """
    acks: dict[str, dict] = {}
    for line in _read_lines(acks_path):
        text = line.strip()
        if not text:
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        event_id = record.get("event_id")
        if not event_id:
            continue
        note = str(record.get("note") or "")
        verdict = _verdict_from_field(record.get("verdict")) or _verdict_from_note(note)
        linked = events.get(event_id) or {}
        acks[event_id] = {
            "event_id": event_id,
            "task_id": record.get("task_id") or linked.get("task_id"),
            "verdict": verdict,
            "note": note,
            "at": _int(record.get("at")),
            "claimer": record.get("claimer"),
        }
    return acks


def _verdict_from_field(value: Any) -> str | None:
    """Map the ack ``verdict`` field to the two verdicts the rules know.

    An unknown value is not a verdict: the note wording then decides, exactly as
    for a fieldless ack.
    """
    text = str(value or "").strip().lower()
    if not text:
        return None
    if text in _REJECT_VALUES:
        return "blocked"
    if text in _ACCEPT_VALUES:
        return "accepted"
    return None


def _note_accepts(text: str) -> bool:
    """A fixed completion phrase, never the same phrase inside a promise."""
    if any(mark in text for mark in _DEFERRAL_MARKS):
        return False
    for phrase in _ACCEPT_PHRASES:
        start = 0
        while True:
            index = text.find(phrase, start)
            if index < 0:
                break
            window = text[max(0, index - 2):index]
            if not any(char in _MODAL_BEFORE for char in window):
                return True
            start = index + 1
    return bool(_ACCEPT_WORDS.search(text))


def _verdict_from_note(note: str) -> str | None:
    """Legacy acks without a verdict field: the note wording decides (R1/R2).

    Failure first, then a fixed acceptance phrase. No match means *no
    acceptance*: it returns None and never promotes a card to done.
    """
    text = (note or "").lower()
    if any(mark in text for mark in _FAIL_MARKS):
        return "blocked"
    if _note_accepts(text):
        return "accepted"
    return None


def _load_states(tasks_dir: str) -> dict[str, dict]:
    states: dict[str, dict] = {}
    for path in sorted(glob.glob(os.path.join(tasks_dir, "*", "state.json"))):
        task_id = os.path.basename(os.path.dirname(path))
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                state = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(state, dict):
            state["state_path"] = path
            states[task_id] = state
    return states


def resolve_terminal_event(task: dict, ledger: dict) -> dict | None:
    """Pointer first, then the newest event recorded for the task id.

    Nine registry entries carry ``terminal_event_id: null`` while outbox/events
    already holds their terminal event, so a pointer-only read would silently
    drop their evidence.
    """
    task_id = task.get("task_id")
    pointer = task.get("terminal_event_id")
    if pointer:
        event = ledger["events"].get(pointer)
        if event:
            return event
        return {"event_id": pointer, "task_id": task_id, "missing": True}
    bucket = ledger["events_by_task"].get(task_id) or []
    return bucket[-1] if bucket else None


def read_exit_receipt(task: dict, root: str) -> dict | None:
    """Read the exit-code artifact; None when the task declares none.

    ``registry.exit_code_success`` is a *configuration* default handoff.py fills
    in at registration time, so it is not evidence: only the artifact is. A
    declared-but-missing artifact is reported as such, because handoff.py itself
    rejects a receipt whose artifact is gone.
    """
    declared = task.get("exit_code_path")
    if not declared:
        return None
    candidates = [declared]
    if not os.path.isabs(declared):
        candidates.insert(0, os.path.join(root, declared))
    for path in candidates:
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                raw = json.load(handle)
        except FileNotFoundError:
            continue
        except json.JSONDecodeError as exc:
            return {"path": path, "present": True, "exit_code": None,
                    "error": f"unreadable exit artifact: {exc}"}
        except OSError as exc:
            return {"path": path, "present": True, "exit_code": None,
                    "error": f"cannot read exit artifact: {exc}"}
        code = _int(raw.get("exit_code", raw.get("exitCode", raw.get("code")))) \
            if isinstance(raw, dict) else _int(raw)
        return {"path": path, "present": True, "exit_code": code, "error": None}
    return {"path": declared, "present": False, "exit_code": None,
            "error": "artifact listed in the registry is missing",
            "declared_success": _int(task.get("exit_code_success"))}


def exit_receipt_usable(receipt: Any) -> bool:
    """True only for a receipt that is present, readable, and carries a code.

    ``present`` alone is not evidence. A truncated, unreadable, or codeless
    artifact has ``exit_code=None`` with an ``error`` (or nothing usable) and
    must neither read as a zero exit nor count as "no exit artifact at all",
    which is what used to let a corrupt receipt fall through to R7/R8 (review
    Major 2).
    """
    if not receipt or receipt.get("present") is not True:
        return False
    if receipt.get("error") is not None:
        return False
    return _int(receipt.get("exit_code")) is not None


def _mtime(path: str) -> int | None:
    try:
        return int(os.path.getmtime(path))
    except OSError:
        return None


def activity_signal(task: dict, state: dict | None, now: float, root: str) -> dict:
    """Latest observed liveness: registry pid, stream activity stamp, session mtime.

    Deliberately narrow. `last_tick_at`/`last_scan_at` and the `state.json`
    mtime are written by the ledger scanner for *every* task on *every* tick,
    so they measure the scanner, not the worker; using them would make a task
    that finished weeks ago look active. Only signals that move when the worker
    moves count: `state.last_activity_at`, the transcript file mtime, and a
    live pid.
    """
    pid = _int(task.get("pid"))
    alive = pid_alive(pid) if pid else None
    stamps: list[int] = []
    source = None
    value = _int((state or {}).get("last_activity_at"))
    if value is not None:
        stamps.append(value)
        source = "last_activity_at"
    session = task.get("session_path")
    if session:
        candidates = [session]
        if not os.path.isabs(session):
            candidates.insert(0, os.path.join(root, session))
        for candidate in candidates:
            got = _mtime(candidate)
            if got is not None:
                stamps.append(got)
                if source is None:
                    source = "session_mtime"
                break
    latest = max(stamps) if stamps else None
    if latest is not None and latest == (_int((state or {}).get("last_activity_at")) or None):
        source = "last_activity_at"
    age = None if latest is None else int(now - latest)
    active = alive is True or (age is not None and age <= ACTIVITY_WINDOW_SECONDS)
    return {"pid": pid, "pid_alive": alive, "last_activity_at": latest,
            "activity_source": source, "activity_age_s": age, "active": bool(active)}


# --------------------------------------------------------------------------
# Classification — the state mapping
# --------------------------------------------------------------------------
#
# Rules in evaluation order; the first match wins. R1-R4 and R7-R8 are the
# brief's table; R6 is the extension the table implies for report-family tasks.
#
#   R1 done     acceptance ack verdict=accepted
#   R2 blocked  acceptance ack verdict=blocked (or a rejecting note)
#   R3 blocked  exit artifact present with exit_code != 0
#   R4 blocked  terminal event status in FAILED_STATUSES
#   R5 review   exit artifact present with exit_code == 0, no acceptance yet
#   R6 review   terminal event report_ready and no exit artifact (source=claude
#               and pi/cursor report tasks deliver a report, not an exit file;
#               the ledger already called them report-ready, so the honest board
#               column is "awaiting acceptance", not "queued")
#   R7 running  no terminal evidence and (pid alive or activity <= 15 min)
#   R8 ready    no terminal evidence and no recent activity
#
# ``verdict`` on an event is NOT acceptance: handoff.py writes it for delivery
# bookkeeping ("informational only, not an acceptance"), which is why 14 events
# pair status=failed with verdict=accepted. Only verify-acks.jsonl decides
# done/blocked by acceptance.

class _Evidence:
    """Everything one mapping rule reads, gathered once per task."""

    __slots__ = ("task_id", "task", "event", "ack", "receipt", "activity", "root")

    def __init__(self, task_id: str, task: dict, ledger: dict, clock: float,
                 root: str) -> None:
        event = resolve_terminal_event(task, ledger)
        event_id = (event or {}).get("event_id")
        self.task_id = task_id
        self.task = task
        self.event = event or {}
        self.ack = ledger["acks"].get(event_id) if event_id else None
        self.receipt = read_exit_receipt(task, root) or {}
        self.activity = activity_signal(task, ledger["states"].get(task_id), clock, root)
        self.root = root

    @property
    def has_exit(self) -> bool:
        return bool(self.receipt.get("present"))

    @property
    def exit_code(self) -> int | None:
        return self.receipt.get("exit_code") if self.receipt else None

    @property
    def exit_usable(self) -> bool:
        return exit_receipt_usable(self.receipt)

    @property
    def event_status(self) -> Any:
        return self.event.get("status")

    @property
    def event_reason(self) -> str:
        return _short(self.event.get("reason") or "", 160)


def _rule_acceptance(ev: _Evidence) -> tuple[str, str, str] | None:
    """R1/R2: verify-acks is the only acceptance record in the ledger."""
    ack = ev.ack
    if not ack:
        return None
    verdict = ack.get("verdict")
    event_id = ev.event.get("event_id")
    if verdict == "accepted":
        return ("R1", S_DONE,
                f"acceptance passed by {ack.get('claimer') or 'verifier'} for {event_id}")
    if verdict == "blocked":
        return ("R2", S_BLOCKED,
                f"acceptance rejected for {event_id}: {_short(ack.get('note'), 120)}")
    return None


def _rule_failure(ev: _Evidence) -> tuple[str, str, str] | None:
    """R3/R4: the run ended badly (non-zero exit, an unusable receipt, or an
    unfinished status)."""
    if ev.exit_usable and ev.exit_code != 0:
        return ("R3", S_BLOCKED, f"exit receipt exit_code={ev.exit_code} "
                                 f"({ev.receipt.get('path')})")
    if ev.has_exit and not ev.exit_usable and ev.event_status != REPORT_READY:
        # Corrupt or codeless artifact: the run cannot be trusted, and a task
        # that reported nothing is not "still working" either.
        return ("R3", S_BLOCKED, f"exit artifact present but unusable: "
                                 f"{ev.receipt.get('error') or 'no exit_code field'} "
                                 f"({ev.receipt.get('path')})")
    if ev.event_status in FAILED_STATUSES:
        return ("R4", S_BLOCKED, f"terminal event status={ev.event_status}: "
                                 f"{ev.event_reason}")
    return None


def _rule_delivered(ev: _Evidence) -> tuple[str, str, str] | None:
    """R5/R6: work is delivered and waiting for acceptance."""
    if ev.exit_usable and ev.exit_code == 0:
        return ("R5", S_REVIEW, "exit receipt exit_code=0, no acceptance verdict yet")
    if ev.event_status == REPORT_READY and not ev.exit_usable:
        return ("R6", S_REVIEW, "terminal event report_ready without a usable exit "
                                f"artifact: {ev.event_reason}")
    return None


def _rule_liveness(ev: _Evidence) -> tuple[str, str, str]:
    """R7/R8: nothing terminal yet, so the column follows the activity clock."""
    if ev.activity.get("active"):
        return ("R7", S_RUNNING, f"no terminal evidence; {_activity_text(ev.activity)}")
    return ("R8", S_READY, f"no terminal evidence and no worker activity in the "
                           f"last {ACTIVITY_WINDOW_SECONDS} s "
                           f"({_absent_text(ev.activity)})")


RULES = (_rule_acceptance, _rule_failure, _rule_delivered, _rule_liveness)


def classify(task_id: str, task: dict, ledger: dict, now: float | None = None,
             root: str | None = None) -> dict:
    clock = time.time() if now is None else now
    base = root or ledger["root"]
    evidence = _Evidence(task_id, task, ledger, clock, base)
    rule, state, reason = next(
        got for got in (candidate(evidence) for candidate in RULES) if got)
    return {
        "task_id": task_id,
        "state": state,
        "board_state": BOARD_STATE[state],
        "rule": rule,
        "reason": reason,
        "event": evidence.event or None,
        "ack": evidence.ack,
        "exit_receipt": evidence.receipt or None,
        "activity": evidence.activity,
        "task": task,
    }


def _activity_text(activity: dict) -> str:
    bits: list[str] = []
    if activity.get("pid_alive") is True:
        bits.append(f"pid {activity.get('pid')} alive")
    age = activity.get("activity_age_s")
    if age is not None:
        source = activity.get("activity_source") or "activity"
        bits.append(f"{source} {age}s ago")
    return ", ".join(bits) if bits else "activity unknown"


def _absent_text(activity: dict) -> str:
    """Name the signals that were missing, so a `ready` card is auditable."""
    missing: list[str] = []
    if activity.get("pid_alive") is not True:
        pid = activity.get("pid")
        missing.append(f"pid={pid}" if pid else "no pid")
    if activity.get("last_activity_at") is None:
        missing.append("no stream activity stamp")
    else:
        missing.append(f"last activity {activity.get('activity_age_s')}s ago")
    return "; ".join(missing)


# --------------------------------------------------------------------------
# Card content
# --------------------------------------------------------------------------

def card_title(task: dict) -> str:
    agent = _short(task.get("agent_name") or task.get("source") or "unknown", 32)
    goal = _short(task.get("goal") or task.get("task_id") or "(no goal)", 80)
    return f"[handoff] {agent} \u00b7 {goal}"


def card_body(decision: dict, root: str) -> str:
    """Stable card content: no field here changes from tick to tick.

    Volatile evidence (state, activity, exit codes) belongs in the deduplicated
    evidence comment, not the body, or every tick would rewrite every card.
    """
    task = decision["task"]
    event = decision.get("event") or {}
    registered = _int(task.get("registered_at"))
    lines = [
        f"handoff task: {decision['task_id']}",
        f"agent: {task.get('agent_name') or '(unnamed)'}",
        f"source: {task.get('source') or '(unknown)'}",
        f"workdir: {task.get('workdir') or '(unknown)'}",
        f"report_path: {task.get('report_path') or '(none)'}",
        f"registered_at: {registered if registered is not None else '(unknown)'}",
        f"registered_at_iso: {_iso(registered) if registered is not None else '(unknown)'}",
        f"terminal_event_id: {event.get('event_id') or '(none)'}",
        f"ledger_root: {root}",
        f"idempotency_key: {card_key(decision['task_id'])}",
        "",
        "Projection of the pi-handoff ledger by kanban_handoff_sync.py.",
        "Board column follows the ledger evidence rules (R1-R8 in the script);",
        "acceptance in outbox/verify-acks.jsonl is the only path to done.",
    ]
    return "\n".join(lines)


def evidence_token(decision: dict) -> str:
    """Stable de-duplication key for one decision's evidence comment.

    The event id alone went stale: an ack that lands later, or an exit code
    that changes under the same event, is *new* evidence and must project
    exactly one new comment (review Major 4). So the token is the event id plus
    the acceptance verdict plus the exit code. A task with no terminal event
    keeps the state token. `]` may never appear: COMMENT_MARKER closes on it.
    """
    event = decision.get("event") or {}
    event_id = event.get("event_id")
    if event_id and not event.get("missing"):
        base = f"evt:{event_id}"
    elif event_id:
        base = f"evt-missing:{event_id}"
    else:
        base = f"state:{decision['state']}"
    ack = decision.get("ack")
    verdict = (ack or {}).get("verdict")
    ack_part = "ack:none" if not ack else f"ack:{verdict or 'pending'}"
    receipt = decision.get("exit_receipt")
    if not receipt:
        exit_part = "exit:undeclared"
    elif receipt.get("present") is not True:
        exit_part = "exit:missing"
    elif not exit_receipt_usable(receipt):
        exit_part = "exit:unreadable"
    else:
        exit_part = f"exit:{receipt.get('exit_code')}"
    return f"{base}|{ack_part}|{exit_part}"


def evidence_comment(decision: dict, token: str, root: str) -> str:
    task = decision["task"]
    event = decision.get("event") or {}
    ack = decision.get("ack")
    receipt = decision.get("exit_receipt")
    activity = decision.get("activity") or {}
    lines = [f"{COMMENT_MARKER}{token}] {decision['state']}: {decision['reason']}"]
    if event:
        suffix = " (registry pointer, artifact missing)" if event.get("missing") else ""
        lines.append(f"- event: {event.get('event_id')} status={event.get('status') or '?'} "
                     f"verdict={event.get('verdict') or '?'}{suffix}")
        if event.get("reason"):
            lines.append(f"- event reason: {_short(event['reason'], 200)}")
        if event.get("receipt_path"):
            lines.append(f"- event receipt: {event['receipt_path']}")
        created = _int(event.get("created_at"))
        if created is not None:
            lines.append(f"- event created_at: {created} ({_iso(created)})")
    if receipt:
        note = f" \u2014 {receipt['error']}" if receipt.get("error") else ""
        lines.append(f"- exit receipt: {receipt.get('path')} present="
                     f"{receipt.get('present')} exit_code={receipt.get('exit_code')}"
                     f"{note}")
    if ack:
        lines.append(f"- acceptance: verdict={ack.get('verdict')} "
                     f"by {ack.get('claimer')} at {ack.get('at')}")
        if ack.get("note"):
            lines.append(f"- acceptance note: {_short(ack['note'], 240)}")
    else:
        lines.append("- acceptance: no verify-ack record for this event")
    report = task.get("report_path")
    if report:
        lines.append(f"- report: {report} exists={os.path.exists(_abs(report, root))}")
    lines.append(f"- activity: pid={activity.get('pid')} alive="
                 f"{activity.get('pid_alive')} last_activity_at="
                 f"{activity.get('last_activity_at')} age={activity.get('activity_age_s')}s")
    if decision["state"] == S_RUNNING:
        lines.append("- ACTIVE: the board column stays ready on purpose; Hermes' "
                     "dispatcher requeues claimless running cards every tick.")
    return "\n".join(lines)


def _abs(path: str, root: str) -> str:
    return path if os.path.isabs(path) else os.path.join(root, path)


# --------------------------------------------------------------------------
# Planning (pure: ledger + board snapshot in, action list out)
# --------------------------------------------------------------------------

def card_key(task_id: str) -> str:
    return KEY_PREFIX + str(task_id)


def build_plan(ledger: dict, cards: dict, comments: dict, now: float | None = None,
               root: str | None = None) -> tuple[list[dict], list[tuple[str, str]]]:
    """Return ``(actions, skipped)`` for one reconcile pass."""
    clock = time.time() if now is None else now
    base = root or ledger["root"]
    plan: list[dict] = []
    skipped: list[tuple[str, str]] = []
    for task_id in sorted(ledger["tasks"]):
        raw = ledger["tasks"][task_id]
        task = dict(raw) if isinstance(raw, dict) else {}
        task.setdefault("task_id", task_id)
        decision = classify(task_id, task, ledger, clock, base)
        key = card_key(task_id)
        card = cards.get(key)
        title = card_title(task)
        body = card_body(decision, base)
        token = evidence_token(decision)
        comment = None
        if card is None or token not in _tokens(comments.get(card.id)):
            comment = evidence_comment(decision, token, base)
        if card is None:
            plan.append({"kind": "create", "task_id": task_id, "key": key,
                         "title": title, "body": body, "state": decision["board_state"],
                         "ledger_state": decision["state"], "rule": decision["rule"],
                         "reason": decision["reason"], "comment": comment})
            continue
        if card.status == "archived":
            skipped.append((task_id, f"card {card.id} is archived; human ownership "
                                     "suppresses projection"))
            continue
        if card.status != decision["board_state"]:
            if card.status not in BOARD_STATES:
                # A human re-columned this card (todo/triage/scheduled): the
                # transition is theirs to make, the evidence trail stays ours.
                skipped.append((task_id, f"card {card.id} sits in column "
                                         f"{card.status!r}, outside this projector's "
                                         f"write set"))
            else:
                plan.append({"kind": "transition", "task_id": task_id, "key": key,
                             "card_id": card.id, "from": card.status,
                             "to": decision["board_state"], "rule": decision["rule"],
                             "reason": decision["reason"]})
        elif card.title != title or card.body != body:
            plan.append({"kind": "refresh", "task_id": task_id, "key": key,
                         "card_id": card.id, "title": title, "body": body,
                         "from": card.status,
                         "reason": "card content drifted from the ledger"})
        if comment:
            plan.append({"kind": "comment", "task_id": task_id, "key": key,
                         "card_id": card.id, "state": decision["board_state"],
                         "ledger_state": decision["state"], "rule": decision["rule"],
                         "reason": decision["reason"], "token": token,
                         "comment": comment})
    return plan, skipped


def _tokens(bodies: Any) -> set[str]:
    found: set[str] = set()
    for body in bodies or ():
        text = getattr(body, "body", None)
        if not isinstance(text, str):
            text = body if isinstance(body, str) else ""
        start = text.find(COMMENT_MARKER)
        if start < 0:
            continue
        end = text.find("]", start)
        if end > start:
            found.add(text[start + len(COMMENT_MARKER):end])
    return found


def summarise(actions: list[dict]) -> dict[str, int]:
    counts = {"create": 0, "transition": 0, "refresh": 0, "comment": 0}
    for action in actions:
        counts[action["kind"]] = counts.get(action["kind"], 0) + 1
    return counts


# --------------------------------------------------------------------------
# Board backends
# --------------------------------------------------------------------------

class Card:
    __slots__ = ("id", "key", "status", "title", "body", "created_by")

    def __init__(self, cid: str, key: str, status: str, title: str = "",
                 body: str = "", created_by: str | None = None) -> None:
        self.id = cid
        self.key = key
        self.status = status
        self.title = title
        self.body = body
        self.created_by = created_by

    def __repr__(self) -> str:
        return f"Card({self.id} {self.status} {self.key})"


def _sqlite_uri(path: str) -> str:
    text = os.path.abspath(path).replace("\\", "/")
    return text if not (len(text) >= 2 and text[1] == ":") else "/" + text


class ReadOnlyBoard:
    """stdlib sqlite in ``mode=ro`` — the dry-run backend.

    Hermes' own connect() initialises the schema and re-enables WAL, which are
    writes; a dry run must not do that to a live board.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def snapshot(self) -> tuple[dict[str, Card], dict[str, list[str]]]:
        import sqlite3

        cards: dict[str, Card] = {}
        comments: dict[str, list[str]] = {}
        if not os.path.exists(self.db_path):
            return cards, comments
        uri = f"file:{_sqlite_uri(self.db_path)}?mode=ro"
        try:
            connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        except sqlite3.Error as exc:
            raise SyncError(f"cannot open board {self.db_path} read-only: {exc}") from exc
        try:
            connection.row_factory = sqlite3.Row
            try:
                rows = connection.execute(
                    "SELECT id, idempotency_key, status, title, body, created_by "
                    "FROM tasks WHERE idempotency_key IS NOT NULL "
                    "AND idempotency_key LIKE ?",
                    (KEY_PREFIX + "%",),
                ).fetchall()
            except sqlite3.Error as exc:
                raise SyncError(f"cannot read board {self.db_path}: {exc}") from exc
            cards_by_id: dict[str, Card] = {}
            for row in rows:
                card = Card(row["id"], row["idempotency_key"], row["status"],
                            row["title"] or "", row["body"] or "", row["created_by"])
                cards[card.key] = card
                cards_by_id[card.id] = card
            try:
                notes = connection.execute(
                    "SELECT task_id, body FROM task_comments ORDER BY id").fetchall()
            except sqlite3.Error:
                notes = []
            for note in notes:
                card = cards_by_id.get(note["task_id"])
                if card is not None:
                    comments.setdefault(card.id, []).append(note["body"] or "")
        finally:
            with contextlib.suppress(sqlite3.Error):
                connection.close()
        return cards, comments

    def close(self) -> None:
        pass


class HermesBoard:
    """Write path through ``hermes_cli.kanban_db`` (archive-sweep precedent).

    Every mutation re-checks ownership (``handoff:`` key prefix) and the status
    the plan was built against, so a human move between plan and apply is
    respected instead of stomped.
    """

    def __init__(self, agent_dir: str, db_path: str | None = None,
                 logger: Any = None) -> None:
        self.agent_dir = agent_dir
        self.db_path = db_path
        self.log = logger or NullLogger()
        self._kb: Any = None
        self._conn: Any = None
        self._ctx: Any = None

    def open(self) -> "HermesBoard":
        if not os.path.isdir(self.agent_dir):
            raise SyncError(f"hermes-agent dir not found: {self.agent_dir}")
        if self.agent_dir not in sys.path:
            sys.path.insert(0, self.agent_dir)
        try:
            kb = importlib.import_module("hermes_cli.kanban_db")
            kbc = importlib.import_module("hermes_cli.kanban_db_connect")
        except Exception as exc:  # noqa: BLE001 - any hermes import failure
            raise SyncError(f"cannot import hermes kanban modules from "
                            f"{self.agent_dir}: {exc}") from exc
        self._kb = kb
        try:
            target = Path(self.db_path) if self.db_path else None
            self._ctx = kbc.connect_closing(db_path=target)
            self._conn = self._ctx.__enter__()
        except PermissionError as exc:
            # agent.delegation_context fences kanban writes inside delegate_task
            # children: not a bug to retry, just not this process's job.
            raise SyncError(f"board writes are fenced for this process: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - surfaced as a logged sync error
            raise SyncError(f"cannot open kanban db {self.db_path}: {exc}") from exc
        return self

    def close(self) -> None:
        if self._ctx is None:
            return
        try:
            self._ctx.__exit__(None, None, None)
        except Exception as exc:  # noqa: BLE001 - closing must not fail the run
            self.log.warn(f"board close failed: {exc}")
        finally:
            self._ctx = None
            self._conn = None

    def snapshot(self) -> tuple[dict[str, Card], dict[str, list[str]]]:
        kb = self._kb
        cards: dict[str, Card] = {}
        comments: dict[str, list[str]] = {}
        for task in kb.list_tasks(self._conn, include_archived=True):
            key = getattr(task, "idempotency_key", None)
            if not key or not str(key).startswith(KEY_PREFIX):
                continue
            cards[key] = Card(task.id, key, task.status, task.title or "",
                              task.body or "", getattr(task, "created_by", None))
        for card in cards.values():
            try:
                bodies = [str(getattr(note, "body", "") or "")
                          for note in kb.list_comments(self._conn, card.id)]
            except Exception as exc:  # noqa: BLE001 - degrade to "unknown comments"
                self.log.warn(f"list_comments({card.id}) failed: {exc}")
                bodies = []
            comments[card.id] = bodies
        return cards, comments

    def apply(self, action: dict, owned_ids: set[str]) -> str:
        """Apply one planned action. ``owned_ids`` proved ownership earlier."""
        kind = action["kind"]
        if kind == "create":
            self._assert_key(action["key"])
            return self._create(action)
        card_id = action.get("card_id")
        if card_id not in owned_ids:
            self._assert_key(action.get("key"))
            raise SyncError(f"refusing to touch card {card_id}: not a {KEY_PREFIX} card")
        current = self._current_status(card_id)
        if current is None:
            return "skipped_gone"
        if kind == "transition":
            if current != action.get("from"):
                return "skipped_moved"  # a human got there first: leave it alone
            if current == "done":
                self.log.warn(f"card {card_id} is done on the board; a downgrade to "
                              f"{action.get('to')} is an operator decision")
                return "skipped_done"
            return self._transition(card_id, action["to"], action["reason"], current)
        if kind == "refresh":
            if current == "done":
                return "skipped_done"
            self._kb.edit_task(self._conn, card_id, title=action["title"],
                               body=action["body"])
            return "refreshed"
        if kind == "comment":
            self._kb.add_comment(self._conn, card_id, CARD_AUTHOR, action["comment"])
            return "commented"
        raise SyncError(f"unknown action kind {kind!r}")

    def _assert_key(self, key: Any) -> None:
        if not str(key or "").startswith(KEY_PREFIX):
            raise SyncError(f"refusing to touch {key!r}: idempotency key lacks the "
                            f"{KEY_PREFIX} prefix")

    def _current_status(self, card_id: str) -> str | None:
        task = self._kb.get_task(self._conn, card_id)
        return getattr(task, "status", None) if task is not None else None

    def _create(self, action: dict) -> str:
        kb = self._kb
        target = action["state"]
        task_id = kb.create_task(
            self._conn,
            title=action["title"],
            body=action["body"],
            assignee=CARD_ASSIGNEE,
            created_by=CARD_AUTHOR,
            idempotency_key=action["key"],
            # Only `blocked` can be parked at creation; every other card lands
            # `ready` and is then walked to its evidence column below.
            initial_status="blocked" if target == "blocked" else "running",
        )
        status = self._current_status(task_id)
        if status == "running":
            # Defensive only: a claimless card lands in `ready`. Should hermes
            # ever change that, writing `running` by hand is exactly what this
            # projector must not do, so log and let the dispatcher reclaim it.
            self.log.warn(f"card {task_id} landed in running without a claim; "
                          f"expecting the dispatcher to requeue it")
        if target in ("review", "done"):
            text = _short(action["reason"], 200) or "handoff evidence"
            if target == "review":
                kb.request_review(self._conn, task_id, summary=text)
            else:
                kb.complete_task(self._conn, task_id, result=text, summary=text)
        if action.get("comment"):
            kb.add_comment(self._conn, task_id, CARD_AUTHOR, action["comment"])
        return "created"

    def _transition(self, card_id: str, target: str, reason: str, current: str) -> str:
        kb = self._kb
        if current == target:
            return "noop"
        text = _short(reason, 200) or "handoff evidence"
        if target == "done":
            return "transitioned" if kb.complete_task(
                self._conn, card_id, result=text, summary=text) else "refused"
        if target == "review":
            if current == "blocked":
                kb.unblock_task(self._conn, card_id)
            return "transitioned" if kb.request_review(
                self._conn, card_id, summary=text) else "refused"
        if target == "blocked":
            if current == "review":
                kb.reopen_review_task(self._conn, card_id)  # review -> ready
            return "transitioned" if kb.block_task(
                self._conn, card_id, reason=text) else "refused"
        if target == "ready":
            if current == "blocked":
                ok = kb.unblock_task(self._conn, card_id)
            elif current == "review":
                ok = kb.reopen_review_task(self._conn, card_id)
            else:
                return "refused"
            return "transitioned" if ok else "refused"
        raise SyncError(f"unsupported board target state {target!r}")


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------

def read_stdin_payload(budget: float = STDIN_READ_BUDGET_SECONDS,
                       stream: Any = None) -> dict | None:
    """Return a webhook payload if stdin already holds one, else None.

    The payload is only a trigger, so no tick may risk blocking on it: the read
    runs in a daemon thread with a hard budget.
    """
    source = sys.stdin if stream is None else stream
    box: dict[str, Any] = {}

    def _drain() -> None:
        try:
            box["raw"] = source.read()
        except Exception as exc:  # noqa: BLE001 - unreadable stdin is not fatal
            box["error"] = str(exc)

    reader = threading.Thread(target=_drain, daemon=True)
    reader.start()
    reader.join(budget)
    if reader.is_alive():
        box["error"] = f"stdin read exceeded {budget:.1f}s"
        return None
    raw = str(box.get("raw") or "").strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"_unparsed": _short(raw, 200)}
    return parsed if isinstance(parsed, dict) else {"_payload": parsed}


def consume_trigger_payload(stream: Any = None) -> dict | None:
    """Read a payload from stdin only when something other than a tty feeds it."""
    source = sys.stdin if stream is None else stream
    if source is None:
        return None
    try:
        if source.isatty():
            return None
    except Exception:  # noqa: BLE001 - odd streams: assume no payload
        return None
    return read_stdin_payload(stream=source)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="kanban_handoff_sync.py",
        description="Project the pi-handoff ledger onto the Hermes kanban board.")
    parser.add_argument("--sweep", action="store_true",
                        help="full reconcile (the default; also the no-arg mode)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the planned actions and write nothing")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="emit the plan as JSON")
    parser.add_argument("--ledger", default=os.environ.get("KANBAN_SYNC_LEDGER",
                                                           LEDGER_ROOT))
    parser.add_argument("--board-db", default=os.environ.get("HERMES_KANBAN_DB")
                        or BOARD_DB)
    parser.add_argument("--agent-dir", default=os.environ.get("KANBAN_SYNC_AGENT_DIR",
                                                              HERMES_AGENT_DIR))
    parser.add_argument("--state-dir", default=os.environ.get("KANBAN_SYNC_STATE_DIR",
                                                              STATE_DIR))
    parser.add_argument("--log-file", default=os.environ.get("KANBAN_SYNC_LOG", LOG_PATH))
    parser.add_argument("--now", type=float, default=None,
                        help="override the clock (epoch seconds) for reproducibility")
    parser.add_argument("--no-stdin", action="store_true",
                        help="do not look for a webhook payload on stdin")
    parser.add_argument("--no-lock", action="store_true",
                        help="skip the lockfile (tests only)")
    parser.add_argument("--verbose", action="store_true", help="echo log lines to stderr")
    return parser.parse_args(argv)


def run(argv: list[str] | None = None, stdout: Any = None, stderr: Any = None) -> int:
    args = _parse_args(argv)
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    log = Logger(args.log_file, echo=args.verbose)
    now = args.now if args.now is not None else time.time()

    payload = None if args.no_stdin else consume_trigger_payload()
    if payload:
        log.info(f"trigger payload: {_short(json.dumps(payload, ensure_ascii=False), 200)}")

    try:
        return _guarded(args, now, log, out, err)
    except SyncError as exc:
        log.error(f"sync failed: {exc}")
        _write(err, f"kanban_handoff_sync: {exc}\n")
        return 1
    except Exception:  # noqa: BLE001 - the hook swallows us, the log must not
        log.error(f"unexpected failure:\n{traceback.format_exc()}")
        _write(err, f"kanban_handoff_sync: unexpected failure (see {args.log_file})\n")
        return 1


def _guarded(args: argparse.Namespace, now: float, log: Logger, out: Any,
             err: Any) -> int:
    if args.no_lock:
        return _reconcile(args, now, log, out, err)
    with FileLock(os.path.join(args.state_dir, LOCK_NAME), log) as lock:
        if not lock.acquired:
            return 0  # another sweep owns the board: stay silent, exit clean
        return _reconcile(args, now, log, out, err)


def _write(stream: Any, text: str) -> None:
    with contextlib.suppress(OSError, ValueError):
        stream.write(text)  # stdout may be a closed pipe under a webhook caller


def _reconcile(args: argparse.Namespace, now: float, log: Logger, out: Any,
               err: Any) -> int:
    root = os.path.abspath(args.ledger)
    if not os.path.isdir(root):
        raise SyncError(f"ledger root does not exist: {root}")
    ledger = load_ledger(root)

    if args.dry_run:
        cards, comments = ReadOnlyBoard(args.board_db).snapshot()
        plan, skipped = build_plan(ledger, cards, comments, now, root)
        return _emit_plan(plan, skipped, cards, ledger, args, out)

    board = HermesBoard(args.agent_dir, args.board_db, log).open()
    try:
        cards, comments = board.snapshot()
        plan, skipped = build_plan(ledger, cards, comments, now, root)
        owned_ids = {card.id for card in cards.values()}
        tally = {"created": 0, "transitioned": 0, "refreshed": 0, "commented": 0,
                 "skipped": 0}
        for action in plan:
            tag = board.apply(action, owned_ids)
            if tag not in ("created", "transitioned", "refreshed", "commented"):
                tally["skipped"] += 1
                log.warn(f"{tag} task={action['task_id']} {_short(action['reason'], 120)}")
                continue
            tally[tag] += 1
            rule_label = action.get("rule") or action.get("kind") or "sync"
            reason_text = action.get("reason") or action.get("comment") or ""
            log.info(f"{tag} task={action.get('task_id', '?')} [{rule_label}] "
                     f"{_short(reason_text, 120)}")
        for task_id, why in skipped:
            log.warn(f"skipped task={task_id} {why}")
        moved = tally["created"] + tally["transitioned"] + tally["refreshed"]
        if moved or tally["commented"]:
            _write(out, f"kanban-handoff-sync: created={tally['created']} "
                        f"transitioned={tally['transitioned']} "
                        f"refreshed={tally['refreshed']} "
                        f"comments={tally['commented']} skipped={tally['skipped']} "
                        f"(tasks={len(ledger['tasks'])}, cards={len(cards)})\n")
        log.info(f"sweep done tasks={len(ledger['tasks'])} cards={len(cards)} "
                 f"counts={json.dumps(tally, sort_keys=True)}")
        return 0
    finally:
        board.close()


def _emit_plan(plan: list[dict], skipped: list[tuple[str, str]], cards: dict,
               ledger: dict, args: argparse.Namespace, out: Any) -> int:
    counts = summarise(plan)
    if args.as_json:
        _write(out, json.dumps({"dry_run": True, "tasks": len(ledger["tasks"]),
                                "cards": len(cards), "counts": counts,
                                "plan": plan, "skipped": skipped},
                               ensure_ascii=False, indent=2) + "\n")
        return 0
    for action in plan:
        _write(out, _plan_line(action) + "\n")
    for task_id, why in skipped:
        _write(out, f"SKIP  task={task_id} {why}\n")
    _write(out, f"DRY-RUN tasks={len(ledger['tasks'])} cards={len(cards)} "
                f"create={counts['create']} transition={counts['transition']} "
                f"refresh={counts['refresh']} comment={counts['comment']}\n")
    return 0


def _plan_line(action: dict) -> str:
    kind = action["kind"].upper()
    task_id = _short(action["task_id"], 58)
    if kind == "CREATE":
        return (f"PLAN  create     task={task_id:<58} -> {action['state']:<7} "
                f"[{action['rule']}] {_short(action['reason'], 70)}")
    if kind == "TRANSITION":
        return (f"PLAN  transition task={task_id:<58} {action['from']} -> "
                f"{action['to']} [{action['rule']}] {_short(action['reason'], 60)}")
    if kind == "REFRESH":
        return f"PLAN  refresh    task={task_id:<58} card content drifted"
    return (f"PLAN  comment    task={task_id:<58} evidence={action['token']} "
            f"[{action['rule']}]")


if __name__ == "__main__":
    sys.exit(run())
