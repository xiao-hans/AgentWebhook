#!/usr/bin/env python3
"""Agent -> receiver completion-callback handoff recorder.

Cron-invoked once per minute; no resident process; the model does not have to
remember to notify anything. Python standard library only.

State layout (under --root, or $AGENT_HANDOFF_ROOT, default <script dir>/data):
  registry.json                        task registry (atomic replace)
  tasks/<task_id>/state.json           read cursor + tool timeline
  tasks/<task_id>/receipts/<event>.json  bounded receipt (never a full session copy)
  outbox/events/<event_id>.json        authoritative event record (persist before send)
  outbox/journal.jsonl                 append-only audit trail
  outbox/claims/<event_id>             atomic receiver claim marker (rc 3 = already_claimed:
                                       dispatch only on result == "claimed")
  outbox/acks.jsonl                    receiver verdicts
  lock                                 coarse lock for registry mutation

The webhook payload carries ONLY schema_version, task_id, event_id, status:
no body text, no paths, no credentials.

All emitted console text is ASCII (Windows codepage safety).
"""

import argparse
import contextlib
import hashlib
import hmac
import http.client
import json
import os
import re
import shutil
import sys
import time

try:  # config file support: stdlib tomllib needs Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - older interpreter
    tomllib = None
import urllib.error
import urllib.request
from urllib.parse import urlparse

SCHEMA_VERSION = 1
EVENT_TYPE = "agent_task_handoff"
PROTOCOL_STATUSES = ("report_ready", "stopped_unfinished", "failed", "stalled")

TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SESSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
ORIGIN_TARGET_RE = re.compile(
    r"telegram:[+-]?[1-9][0-9]*(?::[1-9][0-9]*)?|local|local:[A-Za-z0-9][A-Za-z0-9._-]{7,63}"
)
SOURCE_CHOICES = ("pi", "claude", "receipt", "exit", "cursor", "codex", "dsh")
RECEIPT_FAMILY_SOURCES = ("receipt", "exit", "cursor", "codex", "dsh")
DEFAULT_AGENT_NAMES = {
    "pi": "Pi",
    "claude": "Claude Code",
    "cursor": "Cursor Agent",
    "codex": "Codex",
    "dsh": "DSH",
}
RECEIPT_MODES = ("marker", "json", "exitcode")
MARKER_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
DEFAULT_MARKER_NAME = "done"
DEFAULT_RECEIPT_MODE = "json"
DEFAULT_EXIT_CODE_SUCCESS = 0
DEFAULT_MIN_REPORT_CHARS = 200
MIN_MIN_REPORT_CHARS = 50
MAX_MIN_REPORT_CHARS = 4000
DEFAULT_MAX_RETRIES = 5
SCRIPT_CHANNEL_CLAIMER = "hermes-webhook"  # the notification side of record
MIN_RETRY_AFTER = 5
MAX_RETRY_AFTER = 3600
RECEIPT_STATUSES = ("report_ready", "failed", "stopped_unfinished")

RECEIPT_SOURCE_DIR = "receipt-source"

MAX_RECEIPT_BYTES = 64 * 1024
MAX_FINAL_CHARS = 8000
MAX_TIMELINE = 50
MAX_TEXT_FIELDS = 2000
MAX_RESPONSE_BYTES = 64 * 1024
RETRYABLE_STATUS = (408, 429, 500, 502, 503, 504)

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
#
# One resolution order for every setting: environment variable, then the
# config file, then the command line flag. Nothing below falls back to a path
# that only exists on one machine, so a value the code cannot work without is
# reported by name and the command exits non-zero.
#
# The config file is TOML (stdlib tomllib, Python 3.11+) read from
# $AGENT_HANDOFF_CONFIG, else <script dir>/agentwebhook.toml. Its keys are the
# environment names themselves, so the two forms are interchangeable and
# .env.example is the equivalent export of config.example.toml.

CONFIG_ENV_KEY = "AGENT_HANDOFF_CONFIG"
DEFAULT_CONFIG_NAME = "agentwebhook.toml"
LEGACY_ENV_PREFIX = "PI_HANDOFF_"
NEW_ENV_PREFIX = "AGENT_HANDOFF_"

# Every key this program reads. t13_renamed_settings walks this list, so a
# renamed key cannot be missing from the fail-fast coverage unnoticed; the
# fail-fast itself scans the live environment, so even an unknown old spelling
# is refused rather than read as "not configured".
ENV_KEYS = (
    "AGENT_HANDOFF_ROOT",
    "AGENT_HANDOFF_URL",
    "AGENT_HANDOFF_VERIFY_URL",
    "AGENT_HANDOFF_SECRET_FILE",
    "AGENT_HANDOFF_MAX_ATTEMPTS",
    "AGENT_HANDOFF_MAX_RECORDS",
    "AGENT_HANDOFF_MAX_BYTES",
    "AGENT_HANDOFF_STALL_SECONDS",
    "AGENT_HANDOFF_LOCAL_SESSION",
    "AGENT_HANDOFF_DATA_ROOT",
    "AGENT_HANDOFF_SCRIPT",
    "AGENT_HANDOFF_CONFIG",
    "AGENT_HANDOFF_HERMES_BIN",
    "AGENT_HANDOFF_HERMES_PYTHON",
    "AGENT_HANDOFF_HERMES_AGENT_DIR",
)

_CONFIG_CACHE = {}


def config_path():
    """Config file location: $AGENT_HANDOFF_CONFIG, else <script dir> file."""
    explicit = os.environ.get(CONFIG_ENV_KEY)
    if explicit:
        return os.path.realpath(explicit)
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.realpath(os.path.join(here, DEFAULT_CONFIG_NAME))


def load_config(path=None):
    """Flat TOML keys as strings; a missing file or no tomllib reads as empty."""
    path = path or config_path()
    if path in _CONFIG_CACHE:
        return _CONFIG_CACHE[path]
    values = {}
    if tomllib is not None and os.path.isfile(path):
        try:
            with open(path, "rb") as handle:
                parsed = tomllib.load(handle)
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"config file {path} is not readable as TOML: {exc}"
            ) from exc
        for key, value in parsed.items():
            name = str(key).upper().replace("-", "_")
            if isinstance(value, bool):
                values[name] = "1" if value else "0"
            elif isinstance(value, (int, float)):
                values[name] = str(value)
            elif isinstance(value, str):
                values[name] = value
    _CONFIG_CACHE[path] = values
    return values


def setting(name, environ=None):
    """Resolve one setting: environment first, config file second, else None.

    An empty value counts as unset either way, which is how callers clear a
    key for one run.
    """
    env = os.environ if environ is None else environ
    value = env.get(name)
    if value:
        return value
    value = load_config().get(name)
    return value or None


def legacy_env_offenders(environ=None):
    """Old PI_HANDOFF_* names that are set while the new twin resolves unset.

    The rename ships without a compatibility mapping, so an old name is a
    mistake: it would otherwise read as "not configured" and silently change
    behaviour. Any name under the old prefix is refused, which also catches a
    mistyped old key instead of letting it pass for free.
    """
    env = os.environ if environ is None else environ
    config = load_config()
    offenders = []
    for name in sorted(set(env) | set(config)):
        if not name.startswith(LEGACY_ENV_PREFIX):
            continue
        if not (env.get(name) or config.get(name)):
            continue
        twin = NEW_ENV_PREFIX + name[len(LEGACY_ENV_PREFIX):]
        if setting(twin, env):
            continue
        offenders.append((name, twin))
    return offenders


def legacy_env_errors(offenders):
    """ASCII lines naming the new key for every offender (spec 1.1)."""
    lines = []
    for old, new in offenders:
        lines.append(
            f"ERROR: {old} is set but {new} is not. The PI_HANDOFF_* names were "
            f"renamed and are not mapped: set {new}, or the same key in "
            f"{config_path()}."
        )
    return lines


def missing_env_errors(names):
    """ASCII lines naming each required key that resolves in neither place."""
    lines = []
    path = config_path()
    for name in names:
        lines.append(
            f"ERROR: {name} is not configured. Set the {name} environment "
            f"variable, or put {name} in {path}."
        )
    return lines


def require_settings(names, action):
    """Fail-fast entry: return an error list for the keys `action` needs."""
    missing = [name for name in names if not setting(name)]
    if not missing:
        return None
    lines = [f"ERROR: {action} cannot run without configuration."]
    lines.extend(missing_env_errors(missing))
    return lines


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------

def default_root():
    env = setting("AGENT_HANDOFF_ROOT")
    if env:
        return os.path.realpath(env)
    return os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))


def p_registry(root):
    return os.path.join(root, "registry.json")


def p_task_dir(root, tid):
    return os.path.join(root, "tasks", tid)


def p_state(root, tid):
    return os.path.join(p_task_dir(root, tid), "state.json")


def p_receipts_dir(root, tid):
    return os.path.join(p_task_dir(root, tid), "receipts")


def p_events_dir(root):
    return os.path.join(root, "outbox", "events")


def p_event(root, event_id):
    return os.path.join(p_events_dir(root), event_id + ".json")


def p_claims_dir(root):
    return os.path.join(root, "outbox", "claims")


def p_claim(root, event_id):
    return os.path.join(p_claims_dir(root), event_id)


def p_acks(root):
    return os.path.join(root, "outbox", "acks.jsonl")


def p_journal(root):
    return os.path.join(root, "outbox", "journal.jsonl")


def p_verify_dir(root):
    return os.path.join(root, "outbox", "verify")


def p_verify(root, eid):
    return os.path.join(p_verify_dir(root), f"{eid}.json")


def p_verify_claims_dir(root):
    return os.path.join(root, "outbox", "verify-claims")


def p_verify_claim(root, eid):
    return os.path.join(p_verify_claims_dir(root), f"{eid}.json")


def p_verify_acks(root):
    return os.path.join(root, "outbox", "verify-acks.jsonl")


def p_archive(root):
    return os.path.join(root, "archive", "registry-archive.json")


def p_receipt_source_dir(root, tid):
    return os.path.join(p_task_dir(root, tid), RECEIPT_SOURCE_DIR)


# ---------------------------------------------------------------------------
# small io helpers
# ---------------------------------------------------------------------------

def read_json(path, fallback):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return fallback
    except (OSError, ValueError):
        return fallback


def _ensure_dir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as e:
        raise SystemExit(f"ERROR: cannot create directory {path}: {e}") from e


def _atomic_write(path, data):
    """Bytes written+fsynced to a temp file, then atomically replaced on top.

    Windows can refuse the replace with a sharing violation (WinError 5) while a
    reader or the file indexer still holds the destination. The payload is already
    durable in the temp file, so a short bounded retry is safe: it keeps a
    momentary lock from being reported as a write failure.
    """
    _ensure_dir(os.path.dirname(path))
    tmp = f"{path}.tmp{os.getpid()}"
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.02 * (attempt + 1))
    except OSError as e:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise SystemExit(f"ERROR: write failed for {path}: {e}") from e


def write_json_atomic(path, obj):
    data = (json.dumps(obj, ensure_ascii=True, indent=1, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write(path, data)


def append_jsonl(path, obj):
    line = (json.dumps(obj, ensure_ascii=True, sort_keys=True) + "\n").encode("utf-8")
    _ensure_dir(os.path.dirname(path))
    try:
        with open(path, "ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
    except OSError as e:
        raise SystemExit(f"ERROR: append failed for {path}: {e}") from e


@contextlib.contextmanager
def file_lock(root, timeout=10.0):
    """Registry-mutation lock held by a live pid.

    A lock file is only removed when its recorded pid is verifiably gone; age
    alone never justifies takeover (a slow tick would otherwise lose its registry
    writes to a second process). An unreadable or unverifiable pid falls back to
    the age limit so a corrupt lock cannot wedge the cron forever.
    """
    lp = os.path.join(root, "lock")
    _ensure_dir(root)
    deadline = time.time() + timeout
    while True:
        try:
            fd = os.open(lp, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "wb") as f:
                f.write(str(os.getpid()).encode())
            break
        except FileExistsError:
            holder = None
            try:
                with open(lp, encoding="ascii") as lf:
                    holder = int(lf.read().strip() or 0)
            except (OSError, ValueError):
                holder = None
            alive = pid_exists(holder)
            try:
                age = time.time() - os.path.getmtime(lp)
            except OSError:
                age = timeout + 1
            if alive is False or (alive is None and age > timeout):
                with contextlib.suppress(OSError):
                    os.remove(lp)
                continue
            if time.time() >= deadline:
                raise SystemExit("ERROR: another handoff process holds the lock; retry next tick") from None
            time.sleep(0.05)
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            os.remove(lp)


# ---------------------------------------------------------------------------
# entry-boundary validation
# ---------------------------------------------------------------------------

def validate_task_id(tid):
    if not TASK_ID_RE.match(tid or "") or ".." in tid:
        raise ValueError(f"invalid task_id {tid!r} (need [A-Za-z0-9._-], start alnum, <=64 chars, no '..')")
    return tid


def validate_session_id(sid):
    """Entry-boundary only: a claude session id is trusted once, at registration."""
    if not SESSION_ID_RE.match(sid or ""):
        raise ValueError(f"invalid session_id {sid!r} (need [A-Za-z0-9._-], start alnum, 8-64 chars)")
    return sid


def validate_agent_name(name):
    if not isinstance(name, str) or not name.strip() or not name.isprintable():
        raise ValueError("agent_name must be a non-empty display name without control characters")
    return name.strip()


def validate_origin_target(target):
    if not isinstance(target, str) or not ORIGIN_TARGET_RE.fullmatch(target):
        raise ValueError("origin_target must be telegram:<signed-decimal-chat-id>"
                         "[:<positive-thread-id>], 'local', or 'local:<session-id>' "
                         "(no whitespace or extra fields)")
    return target


def task_routing(task):
    """Resolve only registry metadata; never infer a destination from session_id.

    `notify_telegram` keeps its historical name but means "the script channel notifies the
    origin", which is true of a local mirror exactly as of a telegram (Spec G3-10): a
    reviewer that sees a ready route and no notify flag would wait for a notification that
    is never coming. `notify_origin` is the same value under the channel-neutral name, so
    neither field can contradict the other about a route this function just certified.
    """
    if task is None:
        return {"agent_name": None, "origin_target": None, "channel": None,
                "route_state": "blocked", "notify_telegram": False, "notify_origin": False,
                "reason": "task missing from registry"}
    raw_source = task.get("source")
    source = raw_source or "pi"
    # no .get fallback here: an unknown source must yield None and fail
    # validate_agent_name(None) -> route_state=blocked
    agent_name = task.get("agent_name", DEFAULT_AGENT_NAMES.get(source))
    target = task.get("origin_target")
    if isinstance(target, str) and target.startswith("telegram:"):
        channel = "telegram"
    elif isinstance(target, str) and (target == "local" or target.startswith("local:")):
        channel = "local"
    else:
        channel = None
    routing = {"agent_name": agent_name, "origin_target": target, "channel": channel,
               "route_state": "synthetic", "notify_telegram": False, "notify_origin": False,
               "reason": ""}
    if task.get("synthetic"):
        return routing
    try:
        # Checked before any agent_name fallback: a source this build never heard of is a
        # hand-edited or stale registry entry, and guessing which agent owns the task could
        # announce one agent's work under another agent's name.
        if raw_source not in (None, "") and raw_source not in SOURCE_CHOICES:
            # Blocked AND unnamed, before any agent_name fallback: guessing a display
            # name would announce one agent's work under another agent's name, which
            # is the whole risk here.
            routing.update(route_state="blocked", agent_name=None,
                           reason=f"unknown source {raw_source!r} in registry")
            return routing
        if target is None:
            raise ValueError("missing origin_target in registry; no fallback destination")
        validate_origin_target(target)
        agent_name = validate_agent_name(agent_name)
    except ValueError as e:
        routing.update(route_state="blocked", reason=str(e))
    else:
        routing.update(agent_name=agent_name, route_state="ready",
                       notify_telegram=True, notify_origin=True)
    return routing


def _no_traversal(raw):
    if ".." in re.split(r"[\\/]+", raw or ""):
        raise ValueError(f"path must not contain '..' segments: {raw!r}")


def validate_session_path(raw):
    if not raw:
        raise ValueError("session path is required")
    _no_traversal(raw)
    if not os.path.isabs(raw):
        raise ValueError(f"session path must be absolute: {raw!r}")
    real = os.path.realpath(raw)
    if not os.path.isfile(real):
        raise ValueError(f"session path is not an existing file: {raw!r}")
    return real


def validate_workdir(raw):
    if not raw:
        raise ValueError("workdir is required")
    _no_traversal(raw)
    if not os.path.isabs(raw):
        raise ValueError(f"workdir must be absolute: {raw!r}")
    real = os.path.realpath(raw)
    if not os.path.isdir(real):
        raise ValueError(f"workdir is not an existing directory: {raw!r}")
    return real


def validate_under_roots(real, roots, name):
    for base in roots:
        b = os.path.realpath(base)
        if real == b or real.startswith(b + os.sep):
            return
    raise ValueError(f"{name} resolves outside allowed roots {roots}: {real!r}")


def validate_loopback_url(url):
    u = urlparse(url or "")
    if u.scheme not in ("http", "https"):
        raise ValueError(f"scheme must be http/https: {url!r}")
    if not u.netloc or "@" in u.netloc:
        raise ValueError(f"URL must have host and no userinfo: {url!r}")
    host = (u.hostname or "").lower()
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError(f"only loopback receivers allowed (127.0.0.1/localhost): {url!r}")
    return url


# ---------------------------------------------------------------------------
# process liveness -- never os.kill(pid, 0) on Windows
# ---------------------------------------------------------------------------

def pid_exists(pid):
    """True alive / False definitely exited / None unknown (cannot verify)."""
    if pid is None:
        return None
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    if pid <= 0:
        return None
    if os.name == "nt":
        import ctypes
        if pid == os.getpid():
            return True
        QUERY_LIMITED = 0x1000
        STILL_ACTIVE = 259
        ERROR_INVALID_PARAMETER = 87
        # use_last_error must be set on the DLL object: passing it per-call leaves
        # ctypes.get_last_error() at 0, so an exited pid (OpenProcess fails with
        # ERROR_INVALID_PARAMETER) was misread as unknown on non-child pids
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # HANDLE is pointer-sized: without restype/argtypes a >32-bit handle or the
        # pid argument is truncated on win-amd64
        k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        h = k32.OpenProcess(QUERY_LIMITED, False, pid)
        if not h:
            if ctypes.get_last_error() == ERROR_INVALID_PARAMETER:
                return False
            # access denied etc: unknown, never "exited"
            return None
        try:
            code = ctypes.c_ulong(0)
            if k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return code.value == STILL_ACTIVE
            return None
        finally:
            k32.CloseHandle(h)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None


# ---------------------------------------------------------------------------
# session JSONL parsing / classification
# ---------------------------------------------------------------------------

def parse_session_line(line, source="pi"):
    """Dispatch one JSONL record by the registered stream format.

    Both parsers return the same 7-tuple; only claude fills `info` (index 6), and
    the session_id trust check is made once per record by scan_task, which needs to
    see foreign result records so it can name them in a terminal reason.
    """
    if source == "claude":
        return parse_claude_session_line(line)
    return parse_pi_session_line(line)


def parse_pi_session_line(line):
    """(role, stop_reason, text, tool_names, ts, is_result, info) or None.

    Accepts {"message": {...}} and a top-level message object. Returns None for
    unparsable/foreign records so the caller counts them as bad_lines and a tick
    never aborts on one odd line. pi has no result record: is_result is False and
    info (the claude trust payload) is always None.
    """
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    if not isinstance(rec, dict):
        return None
    msg = rec.get("message")
    if isinstance(msg, str):
        try:
            msg = json.loads(msg)
        except ValueError:
            return None
    if not isinstance(msg, dict):
        return None
    role = msg.get("role")
    if role not in ("assistant", "user", "toolResult", "tool_use", "tool"):
        return None
    stop = msg.get("stopReason") or msg.get("stop_reason")
    content = msg.get("content")
    if isinstance(content, str):
        parts = [{"type": "text", "text": content}]
    elif isinstance(content, list):
        parts = [b for b in content if isinstance(b, dict)]
    else:
        parts = []
    texts, tools = [], []
    for b in parts:
        bt = str(b.get("type") or "").lower().replace("_", "")
        if bt == "text" and b.get("text"):
            texts.append(str(b["text"]))
        elif bt in ("tooluse", "toolcall"):
            tools.append(str(b.get("name") or b.get("toolName") or "?"))
    ts = rec.get("timestamp") or msg.get("timestamp")
    return role, (stop if isinstance(stop, str) else None), ("\n".join(texts) or None), tools, \
        (ts if isinstance(ts, (int, float)) else None), False, None


def parse_claude_session_line(line):
    """Claude Code stream-json records -> (role, stop, text, tools, ts, is_result, info).

    Only {"type":"result"} is a terminal candidate (is_result=True); assistant/user
    wrap an Anthropic API message and carry activity only. `info` always names the
    record's session_id, subtype/is_error for a result; trust against the registered
    session_id is judged once per record by scan_task, which must still see a foreign
    result so it can name it in an exit reason instead of silently ignoring it.
    """
    try:
        rec = json.loads(line)
    except ValueError:
        return None
    if not isinstance(rec, dict):
        return None
    sid = rec.get("session_id")
    sid = sid if isinstance(sid, str) else None
    if rec.get("type") == "result":
        text = rec.get("result")
        subtype = rec.get("subtype")
        return "result", None, (text if isinstance(text, str) else None), [], None, True, \
            {"session_id": sid,
             "subtype": subtype if isinstance(subtype, str) else None,
             "is_error": bool(rec.get("is_error"))}
    msg = rec.get("message")
    if not isinstance(msg, dict):
        # system init/hook frames carry no message: they are liveness, not content
        return None
    role = msg.get("role")
    if role not in ("assistant", "user"):
        return None
    stop = msg.get("stop_reason")
    content = msg.get("content")
    if isinstance(content, str):
        parts = [{"type": "text", "text": content}]
    elif isinstance(content, list):
        parts = [b for b in content if isinstance(b, dict)]
    else:
        parts = []
    texts, tools = [], []
    for b in parts:
        bt = str(b.get("type") or "").lower().replace("_", "")
        if bt == "text" and b.get("text"):
            texts.append(str(b["text"]))
        elif bt == "tooluse":
            tools.append(str(b.get("name") or "?"))
    ts = rec.get("timestamp")
    return role, (stop if isinstance(stop, str) else None), ("\n".join(texts) or None), tools, \
        (ts if isinstance(ts, str) else None), False, {"session_id": sid}


SUMMARY_PATTERNS = (
    r"上下文交接摘要",
    r"压缩摘要",
    r"上下文交接",
    r"\bcontext[ -]?handoff summary\b",
    r"\bcompaction summary\b",
    r"\bhandoff summary\b",
)


def classify_final_text(text):
    """'summary' (handoff/compaction digest) -> unfinished; else 'report'.

    A marker phrase inside the text alone never proves completion: completion is
    derived from stopReason or a verifiable process exit, and this function only
    decides which of report/summary a finished assistant text was.
    """
    t = text or ""
    for pat in SUMMARY_PATTERNS:
        if re.search(pat, t, re.IGNORECASE):
            return "summary"
    return "report"


# ---------------------------------------------------------------------------
# registry / state / events / acks
# ---------------------------------------------------------------------------

def load_registry(root):
    reg = read_json(p_registry(root), None)
    if not isinstance(reg, dict) or not isinstance(reg.get("tasks"), dict):
        return {"tasks": {}}
    return reg


def load_state(root, tid):
    st = read_json(p_state(root, tid), None)
    if not isinstance(st, dict):
        st = {}
    st.setdefault("offset", 0)
    st.setdefault("line_seq", 0)
    st.setdefault("tool_open", False)
    st.setdefault("last_tool", None)
    st.setdefault("tool_timeline", [])
    st.setdefault("bad_lines", 0)
    st.setdefault("skipped_bytes", 0)
    st.setdefault("over_limit", False)
    st.setdefault("last_event_id", None)
    return st


def load_events(root):
    out = {}
    d = p_events_dir(root)
    try:
        names = os.listdir(d)
    except FileNotFoundError:
        return out
    for n in names:
        if not n.endswith(".json"):
            continue
        ev = read_json(os.path.join(d, n), None)
        if isinstance(ev, dict) and ev.get("event_id"):
            out[ev["event_id"]] = ev
    return out


def save_event(root, ev, action):
    write_json_atomic(os.path.join(p_events_dir(root), ev["event_id"] + ".json"), ev)
    append_jsonl(p_journal(root), {"at": ev.get("updated_at", ev["created_at"]),
                                   "event_id": ev["event_id"], "action": action,
                                   "state": ev.get("state"), "status": ev.get("status")})


def load_acks(root):
    merged = {}
    try:
        with open(p_acks(root), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    a = json.loads(line)
                except ValueError:
                    continue
                eid = a.get("event_id")
                if eid:
                    merged.setdefault(eid, {}).update(a)
    except FileNotFoundError:
        pass
    return merged


# ---------------------------------------------------------------------------
# incremental reader (partial lines, truncation, byte budget)
# ---------------------------------------------------------------------------

def read_incremental(path, offset, max_bytes, final_ok=False, max_records=0, source="pi"):
    """Consume only newline-terminated lines from `offset`, up to max_bytes.

    A trailing partial line (session still mid-write) stays unconsumed until the
    newline arrives. `final_ok` additionally allows a stable tail that has no
    newline, but the caller only sets it once the task process is verifiably
    exited -- a size that stopped changing is not proof the writer finished.
    `max_records` bounds the lines per tick; the cut lands on a record boundary
    so nothing is lost, only deferred. `source` selects the record format.
    Returns (records, new_offset, backlog, bad_lines, size, hit_cap, skipped_bytes);
    skipped_bytes is the byte count of whole windows that exceeded the read bound
    and were discarded without being parsed.
    """
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            buf = f.read(max_bytes)
            size = f.seek(0, os.SEEK_END)
    except OSError as e:
        raise OSError(f"session unreadable: {path}: {e}") from e
    eof = (offset + len(buf)) >= size
    if not buf:
        return [], offset, False, 0, size, False, 0
    cut = buf.rfind(b"\n")
    hit_cap = False
    if cut == -1:
        if eof:
            if final_ok:
                consumed = buf  # writer verifiably exited: the tail is final data
            else:
                return [], offset, False, 0, size, False, 0  # mid-write partial tail: hold it
        else:
            # one record larger than the read window: advance whole windows so the reader
            # cannot wedge; the split line fails to parse and counts as bad_lines
            return [], offset + len(buf), True, 1, size, False, len(buf)
    else:
        consumed = buf[:cut + 1]
    if max_records:
        seen, pos = 0, 0
        for ln in consumed.splitlines(True):
            pos += len(ln)
            if ln.strip():
                seen += 1
                if seen == max_records:
                    break
        # cut only where a further record actually follows, on the exact byte boundary
        if seen >= max_records and any(ln.strip() for ln in consumed[pos:].splitlines(True)):
            consumed = consumed[:pos]
            hit_cap = True
    new_offset = offset + len(consumed)
    records, bad = [], 0
    for raw in consumed.split(b"\n"):
        if not raw.strip():
            continue
        try:
            p = parse_session_line(raw.decode("utf-8"), source)
        except UnicodeDecodeError:
            bad += 1
            continue
        if p is None:
            bad += 1
            continue
        records.append(p)
    backlog = new_offset < size or hit_cap
    return records, new_offset, backlog, bad, size, hit_cap, 0


# ---------------------------------------------------------------------------
# receipt + event creation
# ---------------------------------------------------------------------------

def make_event_id(task_id, status, reason, report_fp=None):
    """Stable per (task_id,status,reason[,report_fp]) so a rescan or retry never
    duplicates work, while a different report under the same reason text gets a
    distinct id (a re-registered run must not collide with the old event)."""
    parts = [task_id, status, reason] if report_fp is None else [task_id, status, reason, report_fp]
    fp = hashlib.sha256(("\0".join(parts)).encode("utf-8")).hexdigest()
    return "evt-" + fp[:20]


def build_receipt(root, task, st, status, reason, final_text, now, eid, text_truncated=False):
    txt = final_text or ""
    trimmed = len(txt) > MAX_FINAL_CHARS or text_truncated
    if trimmed:
        txt = txt[:MAX_FINAL_CHARS]
    rec = {
        "schema_version": SCHEMA_VERSION,
        "event_id": eid,
        "task_id": task["task_id"],
        "status": status,
        "reason": reason[:500],
        "synthetic": bool(task.get("synthetic")),
        "created_at": now,
        "goal": str(task.get("goal") or "")[:MAX_TEXT_FIELDS],
        "next_phases": [str(x)[:MAX_TEXT_FIELDS] for x in (task.get("next_phases") or [])][:20],
        "workdir": str(task.get("workdir") or ""),
        "pid": task.get("pid"),
        "pid_status": st.get("pid_status"),
        "tool_open": bool(st.get("tool_open")),
        "last_tool": st.get("last_tool"),
        "tool_timeline": list(st.get("tool_timeline", []))[-MAX_TIMELINE:],
        "lines_seen": st.get("line_seq", 0),
        "bad_lines": st.get("bad_lines", 0),
        "skipped_bytes": int(st.get("skipped_bytes", 0)),
        "over_limit": bool(st.get("over_limit")),
        "final_text": txt,
        "final_text_truncated": trimmed,
    }
    for opt_key in ("receipt_mode", "report_path", "exit_code_path"):
        val = task.get(opt_key)
        if val is not None:
            rec[opt_key] = val
    if task.get("source") == "claude":
        # pi receipts keep their exact pre-claude key set; claude names how many
        # records were sighted but not trusted (missing/foreign session_id)
        rec["untrusted_records"] = int(st.get("untrusted_records", 0))
    if len(json.dumps(rec, ensure_ascii=True).encode("utf-8")) > MAX_RECEIPT_BYTES:
        before = len(rec["final_text"])
        rec["final_text"] = rec["final_text"][:1000]
        rec["tool_timeline"] = rec["tool_timeline"][-10:]
        rec["receipt_overflow_trim"] = True
        if len(rec["final_text"]) < before:
            rec["final_text_truncated"] = True
    return rec


def create_event(root, task, st, status, reason, final_text, now, report_fp=None,
                 text_truncated=False):
    if status not in PROTOCOL_STATUSES:
        raise ValueError(f"illegal status {status!r}")
    tid = task["task_id"]
    eid = make_event_id(tid, status, reason, report_fp)
    existing = load_events(root).get(eid)
    if existing is not None:
        # duplicate rescan/retry: keep the existing event (and its send state) intact
        st["last_event_id"] = eid
        return existing, False
    rec = build_receipt(root, task, st, status, reason, final_text, now, eid, text_truncated)
    rdir = p_receipts_dir(root, tid)
    _ensure_dir(rdir)
    rpath = os.path.join(rdir, eid + ".json")
    body = json.dumps(rec, ensure_ascii=True, indent=1, sort_keys=True).encode("utf-8")
    if len(body) > MAX_RECEIPT_BYTES:
        if rec["final_text"]:
            rec["final_text"] = ""
            rec["final_text_truncated"] = True
        rec["receipt_overflow_trim"] = True
        body = json.dumps(rec, ensure_ascii=True, indent=1, sort_keys=True).encode("utf-8")
    _atomic_write(rpath, body)

    ev = {
        "schema_version": SCHEMA_VERSION,
        "event_id": eid,
        "task_id": tid,
        "status": status,
        "reason": reason[:500],
        "synthetic": bool(task.get("synthetic")),
        "created_at": now,
        "updated_at": now,
        "receipt_path": rpath,
        "receipt_bytes": len(body),
        "state": "pending",
        "attempts": 0,
        "max_attempts": int(setting("AGENT_HANDOFF_MAX_ATTEMPTS") or 60),
        "next_retry_at": now,
        "history": [],
        "retry_count": 0,
        # the task-level budget is recorded here so `defer` can enforce it without
        # re-reading the registry (a task may be archived while its events still retry)
        "max_retries": int(task.get("max_retries", DEFAULT_MAX_RETRIES)),
        "retry_after_at": None,
        "last_retry_reason": None,
    }
    save_event(root, ev, "created")
    st["last_event_id"] = eid
    # Spec §1.5: no verify queue doc is written here. The handoff to the independent
    # verifier is opened by the script channel (verify-open) only after its claim was
    # granted, so an event that never dispatched - or whose route is blocked - cannot
    # leave a doc behind for a verifier to act on.
    return ev, True


# ---------------------------------------------------------------------------
# tick
# ---------------------------------------------------------------------------

def stall_seconds():
    return int(setting("AGENT_HANDOFF_STALL_SECONDS") or 3600)


def _reset_incremental_state(st):
    for k, v in (("offset", 0), ("line_seq", 0), ("tool_open", False), ("last_tool", None),
                 ("tool_timeline", []), ("bad_lines", 0), ("pending_size", None),
                 ("skipped_bytes", 0), ("over_limit", False),
                 ("stalled_event_id", None), ("candidate_final", None),
                 ("candidate_result", None), ("untrusted_records", 0),
                 ("last_activity_at", None)):
        st[k] = v
    return st


def claude_result_verdict(info, text):
    """(status, reason) for one claude result record the caller already trusted.

    Session_id trust is decided by the caller, once per record; this judges only the
    content. The reason names the subtype and is_error so a reader can see which field
    made the call, and never claims acceptance -- the receiver still decides that.
    """
    subtype = info.get("subtype")
    is_error = info.get("is_error")
    if is_error or (subtype or "").startswith("error"):
        return "failed", (f"claude result reported a failed run (subtype={subtype}, "
                          f"is_error={is_error}): "
                          "the run errored or stopped on a limit; informational only, "
                          "not an accepted result")
    if subtype != "success":
        return "stopped_unfinished", (f"claude result subtype={subtype} is not a trustworthy "
                                      "success: unfinished work, not an accepted "
                                      "result")
    if not text:
        return "stopped_unfinished", ("claude result subtype=success carried no result "
                                      "text: there is no report to hand off, unfinished "
                                      "work, not an accepted result")
    if classify_final_text(text) == "summary":
        return "stopped_unfinished", ("claude result subtype=success but the text is a "
                                      "context handoff/compaction summary: unfinished "
                                      "work, not an accepted result")
    return "report_ready", "claude result subtype=success with a final report"


def scan_task_claude(root, task, st, actions, records, bad, skipped, new_offset, size,
                     backlog, hit_cap, max_records, offset, now, reg_sid):
    """Claude stream-json pass: only a trustworthy result record is terminal.

    assistant/user frames (including stop_reason=end_turn, tool_use, tool_result) are
    activity only: the trusted ones maintain the same tool_open/last_tool/tool_timeline
    state as the pi pass, so a receipt never reports "no tool in flight" for a run that
    died mid tool call. A record whose session_id is missing or differs from the
    registered one -- or a registry entry whose session_id is missing -- is counted
    untrusted and can never be a terminal event; if the process then verifiably exits,
    that untrusted sighting is named in the reason rather than hidden.
    """
    tid = task["task_id"]
    untrusted = 0
    pre_act = st.get("last_activity_at")
    untrusted_seen = int(st.get("untrusted_records", 0))
    pending = st.get("candidate_result")
    for role, _stop, text, tools, ts, is_result, info in records:
        st["line_seq"] += 1
        rec_sid = info.get("session_id")
        if reg_sid is None or rec_sid is None or rec_sid != reg_sid:
            # single trust comparison: a foreign session_id, a record without one, or a
            # hand-edited registry entry without one are never evidence of this run's
            # outcome, whatever their type says (absent never matches absent)
            untrusted += 1
            if is_result:
                pending = None
            continue
        # pi parity: a trusted assistant tool_use frame opens the tool state, a trusted
        # user frame (its tool_result) closes it; build_receipt reads these from st
        if role == "assistant" and tools:
            st["tool_open"] = True
            st["last_tool"] = {"tool": tools[-1], "at": ts}
            st["tool_timeline"].append({"seq": st["line_seq"], "tool": tools[-1], "at": ts})
            if len(st["tool_timeline"]) > MAX_TIMELINE:
                del st["tool_timeline"][:-MAX_TIMELINE]
        elif role == "user" and st.get("tool_open"):
            st["tool_open"] = False
        if is_result:
            raw_txt = text or ""
            pending = {"text": raw_txt[:MAX_FINAL_CHARS],
                       "trunc": len(raw_txt) > MAX_FINAL_CHARS,
                       "subtype": info.get("subtype"), "is_error": info.get("is_error")}
    st["bad_lines"] = st.get("bad_lines", 0) + bad
    if skipped:
        st["skipped_bytes"] = int(st.get("skipped_bytes", 0)) + skipped
        st["over_limit"] = True
    if untrusted:
        st["untrusted_records"] = untrusted_seen + untrusted
    st["offset"] = new_offset
    st["pending_size"] = size if new_offset < size else None
    if records:
        st["last_activity_at"] = now
    st["last_tick_at"] = now
    tail_open = backlog or bool(st["pending_size"])
    # pi parity: a trusted result stays pending while the tail is open (it may still
    # be superseded by a later record), and decides the outcome once it closes
    st["candidate_result"] = pending
    write_json_atomic(p_state(root, tid), st)
    if hit_cap:
        actions.append(f"{tid}: record cap {max_records} reached, {new_offset - offset} bytes read, more pending")
    elif backlog:
        actions.append(f"{tid}: consumed to offset {new_offset}, backlog remains (max-bytes/tick)")

    cand = st["candidate_result"] if not tail_open else None
    if cand is not None:
        st["candidate_result"] = None
        write_json_atomic(p_state(root, tid), st)
        status, reason = claude_result_verdict(cand, cand["text"])
        fp = "{}:{}:{}".format(task.get("registered_at"), st["line_seq"],
                               hashlib.sha256((cand["text"] or "").encode("utf-8"))
                               .hexdigest()[:12])
        ev, created = create_event(root, task, st, status, reason, cand["text"], now, fp,
                                   cand.get("trunc", False))
        actions.append("{}: EVENT {} {}{}".format(
            tid, ev["status"], ev["event_id"], "" if created else " (duplicate)"))
        return actions, st, ev

    if tail_open:
        if task.get("pid") is not None and st["pid_status"] is False:
            actions.append(f"{tid}: process exited but the log is not fully consumed; deferring exit verdict")
    elif task.get("pid") is not None and st["pid_status"] is False:
        if st.get("over_limit"):
            status = "stopped_unfinished"
            why = ("session record larger than the per-tick read bound was skipped unread "
                   "(over-limit); no claude result record was ever read -- unfinished, not "
                   "an accepted result, and records existed: this is not a no-record-seen stall")
            fp = "claude-overlimit:{}".format(task.get("registered_at"))
        elif st.get("line_seq", 0) == 0:
            if st.get("stalled_event_id"):
                actions.append(f"{tid}: stall already reported for the exited process; no new event")
                return actions, st, None
            status, why = "stalled", "process exited before any session record was observed"
            fp = "stall:{}:{}".format(task.get("registered_at"), st["offset"])
        else:
            status = "stopped_unfinished"
            why = ("claude process exited without a trustworthy result record "
                   "(subtype=success with a report matching the registered session_id)")
            if st.get("untrusted_records"):
                why += "; {} record(s) were seen with a missing or foreign session_id " \
                       "and were not trusted".format(st["untrusted_records"])
            fp = "claude-exit:{}:{}:{}".format(task.get("registered_at"), st["line_seq"],
                                               st["offset"])
        ev, created = create_event(root, task, st, status, why, None, now, fp)
        if status == "stalled":
            st["stalled_event_id"] = ev["event_id"]
            write_json_atomic(p_state(root, tid), st)
        actions.append("{}: EVENT {} {}{} (pid exit)".format(
            tid, ev["status"], ev["event_id"], "" if created else " (duplicate)"))
        return actions, st, ev

    last_act = pre_act or task.get("registered_at") or now
    idle = now - int(last_act)
    if idle >= stall_seconds() and not st.get("stalled_event_id"):
        if st.get("over_limit"):
            why = ("no fully readable claude result record within the stall window: records "
                   "larger than the per-tick read bound were skipped unread (over-limit); "
                   "unfinished work, not an accepted result")
        else:
            why = (f"no readable claude result record within the stall window "
                   f"(>= {stall_seconds()}s idle); unfinished work, not an accepted result")
        ev, _created = create_event(root, task, st, "stalled", why, None, now,
                                    "stall:{}:{}".format(task.get("registered_at"), st["offset"]))
        st["stalled_event_id"] = ev["event_id"]
        write_json_atomic(p_state(root, tid), st)
        actions.append(f"{tid}: EVENT stalled {ev['event_id']} (idle {idle}s)")
        return actions, st, ev

    if not actions:
        actions.append(f"{tid}: consumed to offset {new_offset}")
    return actions, st, None


def _bad_receipt(st):
    """Count a rejected receipt. Rejection is NOT a verdict: no event, no terminal state,
    so a corrected receipt from the same run still lands on the next tick (Spec §2.6)."""
    st["bad_receipts"] = int(st.get("bad_receipts", 0)) + 1


def _read_receipt_file(path):
    """Read the final receipt file, or (None, reason). Only the final name is ever opened,
    so a half-written `.tmp` sibling that was never renamed stays invisible (Spec §2.5)."""
    if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
        return None, None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(MAX_RECEIPT_BYTES), None
    except OSError as e:
        return None, f"receipt file unreadable: {e}"


def _receipt_is_stale(path, registered_at):
    """I6: a receipt older than the registration belongs to a previous run."""
    try:
        return os.path.getmtime(path) < registered_at - 2
    except OSError:
        return False


def _int_field(data, key):
    val = data.get(key)
    if isinstance(val, bool) or not isinstance(val, int):
        return None
    return val


def _sha256_hex(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdefABCDEF" for ch in value)


def _receipt_marker(raw, success):
    """Spec §2.5A marker parse: `exit=<int>` plus a non-empty `report_fp=<sha256hex>`.

    Returns (kind, status, reason, text); kind is "verdict" or "reject".
    """
    fields = {}
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        fields[key.strip()] = val.strip()
    exit_raw = fields.get("exit")
    if not isinstance(exit_raw, str):
        return ("reject", None, "marker has no exit=<int> line", "")
    try:
        code = int(exit_raw.strip())
    except ValueError:
        return ("reject", None, "marker exit line is not an integer", "")
    fp = fields.get("report_fp")
    if fp is None:
        return ("reject", None, "marker has no report_fp= line", "")
    if not fp:
        # An empty fingerprint means no report was ever produced. Held as a rejection
        # rather than Spec §2.5A's stopped_unfinished so the claim never closes the task
        # on an unverifiable artifact; the corrected marker for this run can still land.
        return ("reject", None, "marker report_fp is empty", "")
    if not _sha256_hex(fp):
        return ("reject", None, "marker report_fp is not a sha256 hex digest", "")
    body = f"exit={code} report_fp={fp}"
    if code != success:
        return ("verdict", "failed", f"marker exit={code}", body)
    return ("verdict", "report_ready", "marker exit succeeded with a report fingerprint", body)


def _receipt_json(task, raw, success):
    """Spec §2.5B json receipt validation.

    Returns (kind, status, reason, text); kind is "verdict", "reject", "wait" or
    "downgrade" (a report_ready claim whose exit_code says failure).
    """
    try:
        data = json.loads(raw)
    except ValueError:
        if pid_exists(task.get("pid")) is True:
            return ("wait", None, "partial json while the registered pid is alive", "")
        return ("reject", None, "json receipt does not parse", "")
    if not isinstance(data, dict):
        return ("reject", None, "json receipt is not an object", "")
    if _int_field(data, "schema_version") != SCHEMA_VERSION:
        return ("reject", None, f"schema_version must be {SCHEMA_VERSION}", "")
    if data.get("task_id") != task["task_id"]:
        return ("reject", None, "json receipt task_id does not match this task", "")
    status = data.get("status")
    if status not in RECEIPT_STATUSES:
        return ("reject", None, f"json receipt status {status!r} is not a known status", "")
    exit_code = _int_field(data, "exit_code")
    if exit_code is None:
        return ("reject", None, "json receipt is missing an integer exit_code", "")
    text = data.get("report_text")
    if not isinstance(text, str):
        if status == "report_ready":
            return ("reject", None, "json receipt report_text is missing or not a string", "")
        text = ""
    if status == "report_ready":
        low = int(task.get("min_report_chars") or DEFAULT_MIN_REPORT_CHARS)
        low = max(MIN_MIN_REPORT_CHARS, min(low, MAX_MIN_REPORT_CHARS))
        if len(text.strip()) < low:
            return ("reject", None,
                    f"json receipt report_text is shorter than {low} characters", "")
        if not _sha256_hex(data.get("report_fp", "")):
            return ("reject", None, "json receipt report_fp is not a sha256 hex digest", "")
        if data["report_fp"].lower() != hashlib.sha256(text.encode("utf-8")).hexdigest():
            return ("reject", None, "json receipt report_fp does not match report_text", "")
    finished_at = _int_field(data, "finished_at")
    if finished_at is None:
        return ("reject", None, "json receipt is missing an integer finished_at", "")
    if finished_at < int(task.get("registered_at", 0)):
        return ("reject", None, "json receipt finished_at precedes registered_at", "")
    if status == "report_ready" and exit_code != success:
        return ("downgrade", None,
                f"json receipt claims report_ready with exit_code={exit_code}", "")
    summary = data.get("summary") or text or json.dumps(data, ensure_ascii=True)
    return ("verdict", status, data.get("reason") or f"json receipt {status}", summary)


def _receipt_exitcode(task, raw, success):
    """Spec §2.5C exit.json verdict. Returns (kind, status, reason, text)."""
    try:
        data = json.loads(raw)
    except ValueError:
        return ("reject", None, "exitcode receipt does not parse", "")
    if not isinstance(data, dict):
        return ("reject", None, "exitcode receipt is not an object", "")
    code = _int_field(data, "exit_code")
    if code is None:
        return ("reject", None, "exitcode receipt is missing an integer exit_code", "")
    claimed_pid = _int_field(data, "pid")
    if claimed_pid is not None and claimed_pid > 0 and pid_exists(claimed_pid) is True:
        # Spec §2.5C calls pid audit-only, but R1 requires a wait while the worker still
        # runs: a success verdict on a half-written artifact would close the task early.
        return ("wait", None, f"exitcode receipt names pid {claimed_pid} which is alive", "")
    artifact = data.get("artifact")
    if artifact is not None and not isinstance(artifact, str):
        return ("reject", None, "exitcode receipt artifact is not a path string", "")
    rp = task.get("report_path") or artifact
    if rp:
        try:
            _no_traversal(rp)
        except ValueError as e:
            return ("reject", None, f"exitcode receipt artifact rejected: {e}", "")
        if not os.path.isabs(rp):
            return ("reject", None, "exitcode artifact must be an absolute path", "")
    size = os.path.getsize(rp) if rp and os.path.isfile(rp) else None
    if code != success:
        # A failing exit code is a verdict on its own. It is checked BEFORE the
        # artifact shape: a failed run that truncated or never created its report is
        # exactly what failure looks like, and holding it as a rejection left the task
        # non-terminal forever so the origin was never told the run failed.
        return ("verdict", "failed", f"exitcode receipt exit_code={code}",
                f"exit_code={code} artifact={rp or 'none'}")
    if size == 0:
        # Same override as the empty marker fingerprint: a zero-byte product is held as a
        # rejection, so the task stays open for a real artifact instead of closing early.
        return ("reject", None, "exitcode receipt artifact is zero bytes", "")
    if size is None:
        return ("reject", None,
                "exitcode receipt reports success but the artifact is missing", "")
    return ("verdict", "report_ready", f"exitcode receipt exit_code={code}",
            f"exit_code={code} artifact={rp} bytes={size}")


def scan_task_receipt(root, task, st):
    """Receipt-family scanner: marker/json/exitcode files stand in for a session log.

    Every rejection path counts a bad receipt and returns no status, which keeps the task
    eligible for the next tick (Spec §2.6; R1 Blocker 2).
    """
    mode = task.get("receipt_mode") or DEFAULT_RECEIPT_MODE
    pid = task.get("pid")
    alive = pid_exists(pid) if pid else False
    registered_at = int(task.get("registered_at", 0))
    raw_success = task.get("exit_code_success")
    success = int(DEFAULT_EXIT_CODE_SUCCESS if raw_success is None else raw_success)

    def reject(why):
        _bad_receipt(st)
        return (None, f"receipt rejected ({mode}): {why}", "")

    if mode == "marker":
        path = task.get("session_path")
        missing = ("stalled", f"pid {pid} exited without marker file",
                   f"missing or empty marker: {path}")
        waiting = "waiting for marker file"
    elif mode == "exitcode":
        path = task.get("exit_code_path") or task.get("session_path")
        missing = ("stalled", f"pid {pid} exited without exitcode file", "")
        waiting = "waiting for exitcode"
    else:
        path = task.get("session_path")
        missing = ("stalled", f"pid {pid} exited without json receipt", "")
        waiting = "waiting for json receipt"

    def parse(raw):
        if mode == "marker":
            return _receipt_marker(raw, success)
        if mode == "exitcode":
            return _receipt_exitcode(task, raw, success)
        return _receipt_json(task, raw, success)

    raw, err = _read_receipt_file(path)
    if err:
        return reject(err)
    if raw is None:
        if pid and alive is False:
            return missing
        return (None, waiting, "")
    if _receipt_is_stale(path, registered_at):
        return reject("mtime precedes registered_at")
    kind, status, reason, text = parse(raw)
    if kind == "reject":
        return reject(reason)
    if kind == "wait":
        return (None, reason, "")
    if kind == "downgrade":
        _bad_receipt(st)
        return ("stopped_unfinished", reason,
                "contradictory receipt: report_ready with a failing exit_code")
    return (status, reason, text)


def _receipt_run_fp(task, text):
    """Run-level fingerprint for a receipt-family verdict, passed as create_event's
    report_fp (Spec §2.5; review 2026-11-13 finding 1).

    make_event_id hashes (task_id, status, reason) alone unless a fingerprint is given,
    and receipt reasons are fixed per mode, so without one a `register --force` re-run
    that reaches the same status recomputes the PREVIOUS run's event id: create_event
    then keeps the older final_text/created_at, the new report is dropped, and claim
    blocks that stale event as "事件早于当前注册". registered_at is the run boundary --
    the same role it plays inside the pi and claude fingerprints -- and the report text
    hash keeps two runs registered in the same second apart. Stable within one run, so
    a rescan or `tick --force` of the unchanged receipt still dedups.
    """
    digest = hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:12]
    return "receipt:{}:{}".format(task.get("registered_at"), digest)


def scan_task(root, task, now, max_bytes, max_records=0):
    """One incremental pass over a registered task. Returns (actions, st, terminal)."""
    tid = task["task_id"]
    st = load_state(root, tid)
    # stall idle is measured from the last read BEFORE this tick's ingest: silence for
    # a full window is a stall even if the next record lands on this very tick
    pre_act = st.get("last_activity_at")
    actions = []
    source = task.get("source") or "pi"
    if source in RECEIPT_FAMILY_SOURCES:
        status, reason, text = scan_task_receipt(root, task, st)
        st["last_scan_at"] = int(time.time())
        # the shared key: build_receipt archives st["pid_status"], so writing a private
        # name here left every receipt-family receipt reporting liveness as unknown
        st["pid_status"] = pid_exists(task["pid"]) if task.get("pid") else None
        if status is not None:
            st["terminal"] = True
            st["terminal_status"] = status
            st["terminal_reason"] = reason
            write_json_atomic(p_state(root, tid), st)
            ev, created = create_event(root, task, st, status, reason, text, int(time.time()),
                                       _receipt_run_fp(task, text))
            actions.append("{}: EVENT {} {}{}".format(
                tid, ev["status"], ev["event_id"], "" if created else " (duplicate)"))
            return actions, st, ev
        write_json_atomic(p_state(root, tid), st)
        actions.append(f"{tid}: {reason}")
        return actions, st, None
    session = task["session_path"]
    if not os.path.isfile(session):
        st["missing_file_at"] = now
        write_json_atomic(p_state(root, tid), st)
        return [f"{tid}: session file missing (no event emitted)"], st, None

    offset = int(st.get("offset", 0))
    source = task.get("source") or "pi"
    # register already requires a format-valid session_id for a claude task, so this is
    # the single comparison point; a hand-edited registry entry without one (reg_sid
    # None) is never trusted either -- scan_task_claude judges reg_sid None and a
    # record-side missing session_id untrusted outright, so no record can reach a
    # success verdict that way
    reg_sid = task.get("session_id")
    try:
        size = os.path.getsize(session)
    except OSError as e:
        actions.append(f"{tid}: cannot stat session: {e}; no event this tick")
        write_json_atomic(p_state(root, tid), st)
        return actions, st, None
    if size < offset:  # rotated/truncated: rescan from 0; stable event_id suppresses duplicates
        offset = 0
        _reset_incremental_state(st)
        actions.append(f"{tid}: file shrank, rescan from offset 0")
    st["pid_status"] = pid_exists(task.get("pid"))
    # a tail without a newline is only final data once the writer verifiably exited;
    # size stability alone is not evidence the session finished writing
    final_ok = st["pid_status"] is False
    try:
        records, new_offset, backlog, bad, size, hit_cap, skipped = read_incremental(
            session, offset, max_bytes, final_ok, max_records, source)
    except OSError as e:
        actions.append(f"{tid}: {e}; no event this tick")
        write_json_atomic(p_state(root, tid), st)
        return actions, st, None

    if source == "claude":
        return scan_task_claude(root, task, st, actions, records, bad, skipped, new_offset,
                                size, backlog, hit_cap, max_records, offset, now, reg_sid)

    for role, stop, text, tools, ts, _is_result, _info in records:
        st["line_seq"] += 1
        if role == "assistant":
            if stop == "error":
                # pi error turns often carry no text at all and may abort mid tool
                # call: error outranks the tool branch so the turn still reports failed
                st["tool_open"] = False
                raw_txt = text or ""
                st["candidate_final"] = {"text": raw_txt[:MAX_FINAL_CHARS], "stop": stop,
                                         "trunc": len(raw_txt) > MAX_FINAL_CHARS}
            elif tools:
                st["tool_open"] = True
                st["last_tool"] = {"tool": tools[-1], "at": ts}
                st["tool_timeline"].append({"seq": st["line_seq"], "tool": tools[-1], "at": ts})
                if len(st["tool_timeline"]) > MAX_TIMELINE:
                    del st["tool_timeline"][:-MAX_TIMELINE]
                st["candidate_final"] = None
            elif text and stop in ("stop", "length"):
                # a turn still being streamed has no stopReason yet -> not final
                st["tool_open"] = False
                st["candidate_final"] = {"text": text[:MAX_FINAL_CHARS], "stop": stop,
                                         "trunc": len(text) > MAX_FINAL_CHARS}
            elif text:
                st["candidate_final"] = None
        else:
            # a newer user/toolResult record ends the previous turn: a terminal text
            # saved earlier in this batch or in an earlier tick is no longer the report
            if st.get("tool_open"):
                st["tool_open"] = False
            st["candidate_final"] = None
    st["bad_lines"] = st.get("bad_lines", 0) + bad
    if skipped:
        # over-limit bytes are dropped whole; remember that they existed so no
        # later verdict can claim "no session record was ever seen"
        st["skipped_bytes"] = int(st.get("skipped_bytes", 0)) + skipped
        st["over_limit"] = True
    st["offset"] = new_offset
    st["pending_size"] = size if new_offset < size else None
    if records:
        st["last_activity_at"] = now
    st["last_tick_at"] = now
    write_json_atomic(p_state(root, tid), st)
    if hit_cap:
        actions.append(f"{tid}: record cap {max_records} reached, {new_offset - offset} bytes read, more pending")
    elif backlog:
        actions.append(f"{tid}: consumed to offset {new_offset}, backlog remains (max-bytes/tick)")

    # single verdict source: the candidate the loop left standing. Reading only st has
    # two consequences: a later record in the same batch supersedes an earlier report,
    # and a candidate persisted across a backlogged tick still decides the outcome.
    # A held half-line tail defers too: the partial record may yet clear the candidate.
    tail_open = backlog or bool(st.get("pending_size"))
    cand = st.get("candidate_final") if not tail_open else None
    if cand is not None:
        final_text, final_stop = cand["text"], cand["stop"]
        st["candidate_final"] = None
        write_json_atomic(p_state(root, tid), st)
        # report_fp keeps the id stable for the same report under a stable reason,
        # but distinct for a different run's report (registered_at + line_seq + text
        # hash: a re-registered task must not collide with the previous delivered event)
        fp = "{}:{}:{}".format(task.get("registered_at"), st["line_seq"],
                               hashlib.sha256(final_text.encode("utf-8")).hexdigest()[:12])
        kind = classify_final_text(final_text)
        if final_stop == "error":
            reason = ("assistant turn ended with stopReason=error: the run failed; "
                      "informational only, not an accepted result")
            ev, created = create_event(root, task, st, "failed", reason, final_text, now, fp,
                                       cand.get("trunc", False))
        elif kind == "summary":
            reason = ("final assistant text is a context handoff/compaction summary "
                      f"(stopReason={final_stop}): unfinished work, not an accepted result")
            ev, created = create_event(root, task, st, "stopped_unfinished", reason, final_text,
                                       now, fp, cand.get("trunc", False))
        elif final_stop != "stop":
            reason = (f"final assistant text ended with stopReason={final_stop}: output "
                      "incomplete; informational report, not accepted")
            ev, created = create_event(root, task, st, "stopped_unfinished", reason, final_text,
                                       now, fp, cand.get("trunc", False))
        else:
            # pid_status lives in the receipt only: reason text must stay stable so the
            # event_id never forks on later rescans of the same report
            reason = "final assistant report (stopReason=stop)"
            ev, created = create_event(root, task, st, "report_ready", reason, final_text, now,
                                       fp, cand.get("trunc", False))
        actions.append("{}: EVENT {} {}{}".format(
            tid, ev["status"], ev["event_id"], "" if created else " (duplicate)"))
        return actions, st, ev

    # backlog or an unconsumed tail: the unread bytes may still hold the terminal
    # turn, so no process-exit verdict is formed until the log is fully consumed.
    # Stalled detection still runs: a silent tail is not a reason to stop reporting.
    if tail_open:
        if task.get("pid") is not None and st["pid_status"] is False:
            actions.append(f"{tid}: process exited but the log is not fully consumed; deferring exit verdict")
    else:
        if task.get("pid") is not None and st["pid_status"] is False:
            if st.get("tool_open"):
                # tool result may still land after the exit check; never report an
                # outcome while a tool call is unresolved -- stalled covers long silence
                actions.append(f"{tid}: process exited with a tool call unresolved; no event")
            elif st.get("line_seq", 0) == 0:
                if st.get("over_limit"):
                    # records existed but exceeded the bounded read window and were
                    # skipped: say so instead of pretending nothing was ever written
                    if st.get("stalled_event_id"):
                        actions.append(f"{tid}: over-limit stop already reported; no new event")
                        return actions, st, None
                    status = "stopped_unfinished"
                    why = ("session record larger than the per-tick read bound was skipped "
                           "unread (over-limit); the final report was never read -- "
                           "unfinished, not an accepted result, and records existed: this "
                           "is not a no-record-seen stall")
                    ev, created = create_event(root, task, st, status, why, None, now,
                                               "overlimit:{}".format(task.get("registered_at")))
                    st["stalled_event_id"] = ev["event_id"]
                    write_json_atomic(p_state(root, tid), st)
                    actions.append("{}: EVENT {} {}{} (over-limit)".format(
                        tid, status, ev["event_id"], "" if created else " (duplicate)"))
                    return actions, st, ev
                if st.get("stalled_event_id"):
                    actions.append(f"{tid}: stall already reported for the exited process; no new event")
                    return actions, st, None
                status, why = "stalled", "process exited before any session record was observed"
                ev, created = create_event(root, task, st, status, why, None, now,
                                           "stall:{}:{}".format(task.get("registered_at"), st["offset"]))
                st["stalled_event_id"] = ev["event_id"]
                write_json_atomic(p_state(root, tid), st)
                actions.append("{}: EVENT {} {}{} (pid exit)".format(
                    tid, status, ev["event_id"], "" if created else " (duplicate)"))
                return actions, st, ev
            else:
                status, why = "stopped_unfinished", "task process exited without a final assistant report"
                # registered_at/line_seq/offset are stable once the file is fully
                # consumed, so a rescan of this run dedups while a re-registered run
                # gets a new id
                ev, created = create_event(root, task, st, status, why, None, now,
                                           "exit:{}:{}:{}".format(task.get("registered_at"),
                                                                  st["line_seq"], st["offset"]))
                actions.append("{}: EVENT {} {}{} (pid exit)".format(
                    tid, status, ev["event_id"], "" if created else " (duplicate)"))
                return actions, st, ev

        if task.get("pid") is not None and st["pid_status"] is None and st.get("line_seq", 0) == 0:
            # liveness unverifiable and nothing observed: say so instead of guessing
            actions.append("{}: pid {} liveness unknown (no verification interface); no event".format(tid, task.get("pid")))

    # stalled: registered but silent for longer than the stall window. fired once per
    # run: the reason text is constant, so the run-scoped stall fingerprint in the
    # event_id keeps rescans deduped while a re-registered run gets a fresh event.
    # Recovery within the same run: tick --force clears stalled_event_id.
    last_act = pre_act or st.get("registered_at") or task.get("registered_at") or now
    idle = now - int(last_act)
    if idle >= stall_seconds() and not st.get("stalled_event_id"):
        # reason must not embed idle/pid_status: the event_id hashes the reason text
        if st.get("over_limit"):
            why = ("no fully readable session record within the stall window: records "
                   "larger than the per-tick read bound were skipped unread "
                   "(over-limit); unfinished work, not an accepted result")
        else:
            why = (f"no session records observed for a full stall window "
                   f"(>= {stall_seconds()}s idle); unfinished work, not an accepted result")
        ev, _created = create_event(root, task, st, "stalled", why, None, now,
                          "stall:{}:{}".format(task.get("registered_at"), st["offset"]))
        st["stalled_event_id"] = ev["event_id"]
        write_json_atomic(p_state(root, tid), st)
        actions.append(f"{tid}: EVENT stalled {ev['event_id']} (idle {idle}s)")
        return actions, st, ev  # stalled is not terminal: caller keeps the task eligible

    if not actions:
        actions.append(f"{tid}: consumed to offset {new_offset}")
    return actions, st, None


def cmd_tick(args, root):
    max_records = int(setting("AGENT_HANDOFF_MAX_RECORDS") or 0)
    actions = []
    with file_lock(root):
        # registry read, filter, scan and write-back all happen under one lock so a
        # concurrent register/unregister can never be overwritten by a stale copy
        reg = load_registry(root)
        now = int(time.time())
        eligible = []
        for tid, task in sorted(reg["tasks"].items()):
            if args.task and tid != args.task:
                continue
            if args.allow_root:
                sp = task["session_path"]
                if ((task.get("source") or "pi") in RECEIPT_FAMILY_SOURCES
                        and not os.path.isfile(sp)):
                    # a receipt-family task may not have written its marker/json/exit
                    # file yet: validate the resolved path without requiring isfile
                    sp = os.path.realpath(sp)
                try:
                    validate_under_roots(sp, args.allow_root, "session path")
                except ValueError as e:
                    print(f"SKIP {tid}: {e}")
                    continue
            eligible.append(task)
        if not eligible:
            print("tick: no eligible tasks")
        for task in eligible:
            # --force re-arms a task that already produced a verdict, terminal or
            # stalled-only (a stalled event never sets terminal_event_id, so without
            # last_stalled_event_id a stalled task could never re-arm)
            force = bool(args.force) and (task.get("terminal_event_id")
                                          or task.get("last_stalled_event_id"))
            if task.get("terminal_event_id") and not force:
                continue
            if force:
                task["terminal_event_id"] = None
                task["last_stalled_event_id"] = None
                st0 = load_state(root, task["task_id"])
                _reset_incremental_state(st0)
                write_json_atomic(p_state(root, task["task_id"]), st0)
            a, _st, ev = scan_task(root, task, now, args.max_bytes, max_records)
            actions.extend(a)
            if ev is not None and ev["status"] != "stalled":
                task["terminal_event_id"] = ev["event_id"]
            elif ev is not None:
                task["last_stalled_event_id"] = ev["event_id"]
        save_registry_locked(root, reg)
    for a in actions:
        print(a)

    rc = 0
    if not args.no_send:
        rc = run_send(root, args.url, args.secret_file, now, verbose=args.verbose_send)
    return rc


def save_registry_locked(root, reg):
    write_json_atomic(p_registry(root), reg)


# ---------------------------------------------------------------------------
# outbox sender
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # 3xx surfaces as HTTPError and is recorded as blocked


def sign(secret, body):
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def load_secret(secret_file):
    if not secret_file:
        raise ValueError("no secret file given (--secret-file / $AGENT_HANDOFF_SECRET_FILE); "
                         "refusing to fall back to any default credential")
    real = os.path.realpath(secret_file)
    if not os.path.isfile(real):
        raise ValueError(f"secret file not found: {real}")
    try:
        with open(real, "rb") as f:
            data = f.read().strip()
    except OSError as e:
        raise ValueError(f"secret file unreadable: {real}: {e}") from e
    if not data:
        raise ValueError("secret file is empty")
    return data


# Response-body keys that name a DELIVERY. "event"/"route"/"cron_job" are excluded on
# purpose: the real Hermes 202 body uses them for the event TYPE ("agent_task_handoff"), the
# route and the cron job id, so none of them identifies the event we sent.
DELIVERY_ID_KEYS = ("delivery_id", "event_id", "request_id")

# Statuses that are an explicit receiver refusal. They veto acceptance even together
# with accepted:true or a job_id: a body cannot both reject the event and deliver it.
# "duplicate" is deliberately absent - it is handled by _is_duplicate_marker, which
# terminates retries when the id correlates with this event.
REFUSAL_STATUS = ("rejected", "failed", "error", "blocked", "denied", "refused")


def _delivery_identifiers(obj):
    """Non-empty delivery identifiers a receiver echoes back, normalized to strings."""
    ids = set()
    for key in DELIVERY_ID_KEYS:
        val = obj.get(key)
        if isinstance(val, str):
            val = val.strip()
        if not isinstance(val, bool) and isinstance(val, (str, int)) and str(val):
            ids.add(str(val))
    return ids


def _is_duplicate_marker(obj):
    """A receiver saying "I already hold this event".

    Retrying the same event_id can never change that answer, so this terminates the
    retry loop. It is receiver-side bookkeeping: it never means the task finished.
    """
    if str(obj.get("status", "")).strip().lower() == "duplicate":
        return True
    return obj.get("duplicate") is True or obj.get("deduped") is True


def classify_response(obj, raw, event_id):
    """Verdict on a 2xx body: only a positively correlated answer is delivery.

    Returns (kind, detail) with kind in "accepted" | "ignored" | "rejected"; detail is
    "" on acceptance, or the reason the event stays pending. 2xx is never accepted on
    its own and an arbitrary "status" is never accepted. Accepted shapes:
      status:accepted + a delivery identifier of THIS event - the current real Hermes
        202 body {"status":"accepted","route":...,"cron_job":...,"event":...,
        "delivery_id":<event id>}, which carries no accepted flag at all
      duplicate marker that names THIS event - receiver already holds it: delivered,
        with a note, so retries stop without inventing business completion
      accepted:true / truthy job_id with NOTHING to contradict them - legacy shapes kept
        for compatibility (the synthetic test double, REPAIR-BRIEF.md:9). They never
        outrank a veto: an explicit refusal status, accepted:false, or a delivery id that
        is not this event's turns them into a rejection.
    Veto order (checked before any acceptance shape): refusal status, accepted:false,
    then correlation. Correlation rejects a body that echoes a delivery id of another
    delivery, and a body whose ids name conflicting deliveries (this event AND a foreign
    id) - an ambiguous answer proves nothing. Both spellings of THIS event's id
    (event_id and the agent-handoff-<event_id> request id) together are not a conflict.
    Everything else is rejected: ignored/filtered, a status that is not accepted,
    "accepted" with no identifier, an uncorrelated duplicate marker, a non-object
    body, unparseable JSON, or a response at/over MAX_RESPONSE_BYTES. Identifiers are
    matched against the event_id we sent and the stable X-Request-ID header value
    ("agent-handoff-<event_id>").
    Receiver acceptance is delivery only: the task-level verdict still comes from
    claim/ack (cmd_claim / cmd_ack), never from this classification.
    """
    if len(raw) >= MAX_RESPONSE_BYTES:
        return "rejected", "response oversized; not delivered"
    if not isinstance(obj, dict):
        return "rejected", "response is not a verifiable acceptance; not delivered"
    status = obj.get("status")
    status_s = status.strip().lower() if isinstance(status, str) else ""
    if status_s in ("ignored", "filtered"):
        return "ignored", f"receiver {status} the event; not delivered"
    ids = _delivery_identifiers(obj)
    expect = {event_id, f"agent-handoff-{event_id}"}
    # vetoes first: they outrank accepted:true and job_id alike
    if status_s in REFUSAL_STATUS:
        return "rejected", (f"receiver {status_s} the event "
                            "(explicit refusal status); not delivered")
    if obj.get("accepted") is False:
        return "rejected", "receiver answered accepted:false; not delivered"
    foreign = ids - expect
    if foreign:
        if ids & expect:
            return "rejected", ("response names conflicting delivery ids "
                                f"({sorted(foreign)[:3]} alongside this event); not delivered")
        return "rejected", ("delivery correlation mismatch (response ids "
                            f"{sorted(ids)[:3]} != this event); not delivered")
    correlated = bool(ids & expect)
    if _is_duplicate_marker(obj) and correlated:
        return "accepted", "receiver already holds this delivery; not a task verdict"
    if status_s == "accepted":
        if correlated:
            return "accepted", ""
        return "rejected", "accepted without a verifiable delivery identifier; not delivered"
    if obj.get("accepted") is True:
        # legacy explicit verdict with nothing to contradict it. This also covers the
        # synthetic test double's 200 {accepted:true,deduped:true}: a duplicate marker
        # that carries no delivery id at all stays unverified on its own, but the
        # receiver's explicit accepted:true is the pre-existing shape we honour.
        return "accepted", ""
    if obj.get("job_id"):
        return "accepted", ""
    if _is_duplicate_marker(obj):
        return "rejected", "duplicate without a verifiable delivery identifier; not delivered"
    return "rejected", ("response is not a verifiable acceptance "
                        f"(status {status_s[:32] or 'missing'}); not delivered")


def send_one(root, ev, url, secret, now, timeout=5.0):
    """One delivery attempt: network I/O runs OUTSIDE the shared lock, the result is
    persisted as a fresh read-modify-write of send-owned fields only, so a concurrent
    receiver ack (verdict/verdict_at) can never be overwritten by this write-back."""
    payload = {"schema_version": ev["schema_version"], "task_id": ev["task_id"],
               "event_id": ev["event_id"], "status": ev["status"]}
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")  # noqa: S310 (scheme+loopback validated at entry boundary)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Hub-Signature-256", sign(secret, body))
    req.add_header("X-Event-Type", EVENT_TYPE)
    # the Hermes webhook adapter only recognises X-GitHub-Event/X-GitLab-Event; a send
    # with X-Event-Type alone returned 200 {"status": "ignored"} (notes item 1)
    req.add_header("X-GitHub-Event", EVENT_TYPE)
    req.add_header("X-GitHub-Delivery", ev["event_id"])
    req.add_header("X-Request-ID", "agent-handoff-{}".format(ev["event_id"]))  # fixed across retries
    # loopback must never traverse an env proxy; redirects stay refused
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    code, detail, obj = None, "", None
    raw = b""
    # URL is scheme+loopback-validated at the entry boundary (validate_loopback_url).
    # Only the network call is inside try: a failing disk write afterwards must not
    # look like a transport error and re-send an already-delivered event.
    try:
        with opener.open(req, timeout=timeout) as resp:
            code = resp.getcode()
            raw = resp.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as e:
        code = e.code
        with contextlib.suppress(Exception):
            raw = e.read(MAX_RESPONSE_BYTES)
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        code = None
        detail = str(getattr(e, "reason", e))[:200]
    if code is not None:
        try:
            obj = json.loads(raw.decode("utf-8", "replace")) if raw else None
        except (ValueError, UnicodeDecodeError):
            obj = None
        entry = {"at": now, "code": code}
    else:
        entry = {"at": now, "error": detail}
    # 2xx alone is not delivery: the body must verifiably accept THIS event - see
    # classify_response for the accepted shapes and the rejection cases.
    kind, reject_detail = classify_response(obj, raw, ev["event_id"])
    with file_lock(root):
        # reload the authoritative record: only send-owned fields are written here
        cur = read_json(p_event(root, ev["event_id"]), None)
        if not isinstance(cur, dict):
            cur = dict(ev)
        cur["history"] = list(cur.get("history", [])) + [entry]
        cur["attempts"] = int(cur.get("attempts", 0)) + 1
        attempts = cur["attempts"]
        if code is not None and 200 <= code < 300:
            if kind == "accepted":
                cur["state"] = "delivered"
                cur["delivered_at"] = now
                if reject_detail:  # duplicate correlation: delivered, but no task verdict
                    cur["history"][-1]["note"] = reject_detail
                detail = reject_detail
            else:
                # ignored/filtered, or no verifiable acceptance for this event
                detail = reject_detail
                cur["state"] = "pending"
        elif code is not None and 300 <= code < 400:
            cur["state"] = "blocked"  # loopback receivers post directly; a redirect is refused
            detail = cur["reason_blocked"] = f"redirect rejected (http {code})"
        elif code is not None and 400 <= code < 500 and code not in RETRYABLE_STATUS:
            cur["state"] = "blocked"  # auth/protocol: stop auto-retry, never bypass auth
            detail = cur["reason_blocked"] = f"http {code}"
        else:
            # transport error, 408/429 or 5xx: back off and retry, never drop the event
            cur["state"] = "pending"
        cur["updated_at"] = now
        action = cur["state"]
        if cur["state"] == "pending":
            backoff = min(300, 10 * (2 ** min(attempts - 1, 5)))
            cur["next_retry_at"] = now + backoff
            cur.pop("reason_blocked", None)
            if attempts >= int(cur.get("max_attempts", 60)):
                cur["state"] = "blocked"
                cur["reason_blocked"] = "max attempts exceeded"
                detail = cur["reason_blocked"]
                action = "blocked"
            else:
                action = "retry_scheduled"
        save_event(root, cur, action)
    return cur["state"], detail


def send_poke(root, ev, url, secret, now, timeout=5.0):
    """Re-post an already-delivered event to re-trigger the receiver-side router.

    A distinct X-GitHub-Delivery (<event_id>-r<retry_count>) lets the Hermes webhook's
    non-durable delivery-id guard accept the retry trigger and re-fire the router
    cron. The event's send state machine is NOT touched: only history and
    last_retry_poke_at are written, so send-owned fields stay send-owned.
    """
    payload = {"schema_version": ev["schema_version"], "task_id": ev["task_id"],
               "event_id": ev["event_id"], "status": ev["status"]}
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    suffix = "-r{}".format(int(ev.get("retry_count", 0)))
    req = urllib.request.Request(url, data=body, method="POST")  # noqa: S310 (loopback validated)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Hub-Signature-256", sign(secret, body))
    req.add_header("X-Event-Type", EVENT_TYPE)
    req.add_header("X-GitHub-Event", EVENT_TYPE)
    req.add_header("X-GitHub-Delivery", ev["event_id"] + suffix)
    req.add_header("X-Request-ID", "agent-handoff-{}{}".format(ev["event_id"], suffix))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    code, detail, obj = None, "", None
    raw = b""
    try:
        with opener.open(req, timeout=timeout) as resp:
            code = resp.getcode()
            raw = resp.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as e:
        code = e.code
        with contextlib.suppress(Exception):
            raw = e.read(MAX_RESPONSE_BYTES)
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        code = None
        detail = str(getattr(e, "reason", e))[:200]
    if code is not None:
        try:
            obj = json.loads(raw.decode("utf-8", "replace")) if raw else None
        except (ValueError, UnicodeDecodeError):
            obj = None
    # The poke only counts when the receiver accepts THIS poke: correlation is against
    # the suffixed delivery id we sent, not the original one (send_one uses the plain
    # id). Anything else leaves the window armed so the next tick tries again.
    kind, reject_detail = classify_response(obj, raw, ev["event_id"] + suffix)
    accepted = code is not None and 200 <= code < 300 and kind == "accepted"
    entry = {"at": now, "action": "retry_poke",
             **({"code": code} if code is not None else {"error": detail})}
    if not accepted and code is not None and 200 <= code < 300:
        entry["note"] = reject_detail
    with file_lock(root):
        cur = read_json(p_event(root, ev["event_id"]), None)
        if isinstance(cur, dict):
            cur["history"] = list(cur.get("history", [])) + [entry]
            # Spec §4.5: a failed poke must NOT burn the window, otherwise one timeout
            # silences the retry escalation for a whole backoff period.
            if accepted:
                cur["last_retry_poke_at"] = now
            cur["updated_at"] = now
            save_event(root, cur, "retry_poke")
    if accepted:
        return "delivered", ""
    return ("poke_failed", detail or reject_detail)


def load_verify_acks(root):
    """Latest verify-ack record per event_id (the verifier's own ledger)."""
    merged = {}
    try:
        with open(p_verify_acks(root), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    a = json.loads(line)
                except ValueError:
                    continue
                eid = a.get("event_id")
                if eid:
                    merged.setdefault(eid, {}).update(a)
    except FileNotFoundError:
        pass
    return merged


def list_verify_queue(root):
    """All verify queue docs (outbox/verify/*.json), skipping .tmp files."""
    d = p_verify_dir(root)
    if not os.path.isdir(d):
        return []
    items = []
    for name in sorted(os.listdir(d)):
        if not name.endswith(".json") or name.endswith(".tmp"):
            continue
        doc = read_json(os.path.join(d, name), None)
        if isinstance(doc, dict) and doc.get("event_id"):
            items.append(doc)
    return items


def _verify_queue_open(vdoc):
    """A queue doc needs a verify webhook send only while it is neither delivered nor closed.

    sent_at/verify_state=sent means the verify Agent was already woken for this event;
    a recorded verify verdict (or verify_state=acked) means the independent review is
    already on the ledger, so re-notifying would only produce duplicate reviews.
    verify_state=failed and an exhausted attempt budget close the doc as well: without
    that the tick would keep POSTing an endpoint that demonstrably never accepts.
    """
    if vdoc.get("verify_state") in ("sent", "acked", "failed") or vdoc.get("sent_at") \
            or vdoc.get("verdict"):
        return False
    try:
        attempts = int(vdoc.get("attempts") or 0)
        max_attempts = int(vdoc.get("max_attempts")
                           or setting("AGENT_HANDOFF_MAX_ATTEMPTS") or 60)
    except (TypeError, ValueError):
        return True
    return attempts < max_attempts


def verify_delivery_id(event_id, attempts):
    """Delivery id for attempt N of a verify POST.

    The first try uses the plain verify-<event_id>; every later try gets a fresh id, so a
    receiver that de-duplicates on the delivery id cannot silently drop the resend (the
    same reason send_poke suffixes its pokes).
    """
    return ("verify-" + event_id if int(attempts) <= 0
            else f"verify-{event_id}-a{int(attempts)}")


def send_verify_one(root, vdoc, url, secret, now, timeout=5.0):
    """Post the signed 4-field payload of one verify-queue item to the verify webhook.

    A 2xx alone is not acceptance: the reply goes through classify_response against the id
    we actually sent, so an endpoint that answers 200 while ignoring the event leaves the
    doc queued instead of closing it. attempts counts every try, and once the doc's own
    max_attempts budget is used up it becomes verify_state=failed with the last reason
    recorded - otherwise a dead verify webhook would be POSTed to on every tick forever.
    """
    eid = vdoc["event_id"]
    path = p_verify(root, eid)
    with file_lock(root):
        cur = read_json(path, None)
    attempts = int(cur.get("attempts") or 0) if isinstance(cur, dict) \
        else int(vdoc.get("attempts") or 0)
    did = verify_delivery_id(eid, attempts)
    payload = {"schema_version": SCHEMA_VERSION, "task_id": vdoc["task_id"],
               "event_id": eid, "status": vdoc.get("status", "")}
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")  # noqa: S310 (loopback validated)
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Hub-Signature-256", sign(secret, body))
    req.add_header("X-Event-Type", EVENT_TYPE)
    req.add_header("X-GitHub-Event", EVENT_TYPE)
    req.add_header("X-GitHub-Delivery", did)
    req.add_header("X-Request-ID", "agent-handoff-" + did)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    code, detail, obj, raw = None, "", None, b""
    try:
        with opener.open(req, timeout=timeout) as resp:
            code = resp.getcode()
            raw = resp.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as e:
        code = e.code
        with contextlib.suppress(Exception):
            raw = e.read(MAX_RESPONSE_BYTES)
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        code = None
        detail = str(getattr(e, "reason", e))[:200]
    if code is not None:
        try:
            obj = json.loads(raw.decode("utf-8", "replace")) if raw else None
        except (ValueError, UnicodeDecodeError):
            obj = None
    # the same acceptance rule the origin channel applies to its responses
    kind, reject_detail = classify_response(obj, raw, did)
    two_xx = code is not None and 200 <= code < 300
    accepted = two_xx and kind == "accepted"
    if two_xx and not accepted:
        detail = reject_detail or "verify webhook did not acknowledge this event"
    with file_lock(root):
        cur = read_json(path, None)
        if isinstance(cur, dict):
            attempts = int(cur.get("attempts") or 0) + 1
            cur["attempts"] = attempts
            if accepted:
                cur["verify_state"] = "sent"
                cur["sent_at"] = now
            else:
                try:
                    max_attempts = int(cur.get("max_attempts")
                                       or setting("AGENT_HANDOFF_MAX_ATTEMPTS") or 60)
                except (TypeError, ValueError):
                    max_attempts = 0
                if max_attempts and attempts >= max_attempts:
                    cur["verify_state"] = "failed"
                    cur["failed_at"] = now
                    cur["last_error"] = (detail or f"http {code}")[:200]
            cur.setdefault("history", []).append(
                {"at": now, "action": "verify_sent" if accepted else "verify_send_failed",
                 "code": code, "delivery_id": did,
                 "detail": (detail[:200] if detail else "")})
            write_json_atomic(path, cur)
    return accepted, detail


def run_send(root, url, secret_file, now, verbose=False, event_id=None, verify_url=None,
             verify_only=False):
    url = url or setting("AGENT_HANDOFF_URL")
    verify_url = verify_url if verify_url is not None else setting("AGENT_HANDOFF_VERIFY_URL")
    secret_file = secret_file or setting("AGENT_HANDOFF_SECRET_FILE")
    events = load_events(root)
    if event_id is not None and event_id not in events:
        print(f"ERROR: unknown event_id {event_id!r}; no events sent")
        return 1
    # a verdicted event already reached the receiver side: resending it is noise
    pending = [] if verify_only else [e for e in events.values()
                                       if (event_id is None or e["event_id"] == event_id)
                                       and e.get("state") == "pending" and not e.get("verdict")
                                       and int(e.get("next_retry_at", 0)) <= now]
    # deferred events whose retry window has elapsed: re-poke the webhook so the
    # receiver-side router re-fires; one poke per window (last_retry_poke_at guard)
    retries = [] if verify_only else [e for e in events.values()
                                       if (event_id is None or e["event_id"] == event_id)
                                       and e.get("state") == "delivered" and not e.get("verdict")
                                       and e.get("retry_state") == "retry_pending"
                                       and int(e.get("next_action_at", 0)) <= now
                                       and (not e.get("last_retry_poke_at")
                                            or int(e.get("last_retry_poke_at", 0))
                                            < int(e.get("next_action_at", 0)))]
    verify_items = [v for v in (list_verify_queue(root) if verify_url else [])
                    if (event_id is None or v.get("event_id") == event_id)
                    and _verify_queue_open(v)]
    if not pending and not retries and not verify_items:
        if verbose:
            print("send: nothing pending")
        return 0
    if pending and not url:
        print("send skipped: no receiver configured ($AGENT_HANDOFF_URL or --url); "
              f"{len(pending)} event(s) stay pending")
        pending = []
    secret = None
    if (pending or retries or verify_items):
        try:
            if pending or retries:
                validate_loopback_url(url)
            if verify_items:
                validate_loopback_url(verify_url)
            secret = load_secret(secret_file)
        except ValueError as e:
            print(f"send skipped: {e} (events stay persisted)")
            return 2
    for ev in sorted(pending, key=lambda e: e["event_id"]):
        state, detail = send_one(root, ev, url, secret, now)
        # a receiver that answered without accepting (ignored/filtered/anomalous body)
        # keeps the event pending but must stay visible in cron output
        if verbose or state != "pending" or detail:
            print("send {} -> {}{}".format(ev["event_id"], state, (f" [{detail}]") if detail else ""))
    for ev in sorted(retries, key=lambda e: e["event_id"]):
        state, detail = send_poke(root, ev, url, secret, now)
        if verbose or state != "delivered" or detail:
            print("retry-poke {} -> {}{}".format(ev["event_id"], state,
                                                  (f" [{detail}]") if detail else ""))
    for vdoc in verify_items:
        accepted, detail = send_verify_one(root, vdoc, verify_url, secret, now)
        if verbose or not accepted or detail:
            print("verify-send {} -> {}{}".format(vdoc["event_id"], "sent" if accepted else "pending",
                                                   (f" [{detail}]") if detail else ""))
    return 0


def cmd_send(args, root):
    if args.url:
        try:
            validate_loopback_url(args.url)
        except ValueError as e:
            print(f"ERROR: {e}")
            return 2
    if getattr(args, "verify_url", None):
        try:
            validate_loopback_url(args.verify_url)
        except ValueError as e:
            print(f"ERROR: {e}")
            return 2
    return run_send(root, args.url, args.secret_file, int(time.time()), verbose=True,
                    event_id=args.event_id, verify_url=getattr(args, "verify_url", None))


def cmd_send_verify(args, root):
    if args.url:
        try:
            validate_loopback_url(args.url)
        except ValueError as e:
            print(f"ERROR: {e}")
            return 2
    return run_send(root, None, args.secret_file, int(time.time()), verbose=True,
                    event_id=args.event_id, verify_url=args.url, verify_only=True)


# ---------------------------------------------------------------------------
# receiver side: atomic claim + verdict (used by Hermes / test receiver)
# ---------------------------------------------------------------------------

def claim_event(root, event_id, claimer, now, lease_seconds=0):
    """Atomic claim: duplicates never dispatch work twice.

    The shared file_lock covers BOTH the O_EXCL first-create and the empty-marker
    recovery read/write: without it two processes recovering the same marker could
    both claim dispatch=true. Callers that already hold the lock must use
    _claim_locked (file_lock is not reentrant).
    """
    ev = load_events(root).get(event_id)
    if ev is None:
        return {"ok": False, "result": "unknown_event", "event_id": event_id}
    with file_lock(root):
        doc = _claim_locked(root, event_id, ev, claimer, now, lease_seconds)
        task = load_registry(root)["tasks"].get(ev["task_id"])
        doc["routing"] = task_routing(task)
        if task is not None and ev.get("created_at", 0) < task.get("registered_at", 0):
            # I6: a re-registered task must not let an old event reach either channel,
            # and the verify side keys off notify_origin, so clear both flags.
            doc["routing"].update(route_state="blocked", notify_telegram=False,
                                  notify_origin=False, reason="事件早于当前注册")
        return doc


def _claim_locked(root, event_id, ev, claimer, now, lease_seconds=0):
    # I3/I7: every write-back below must land on the freshest event on disk, never on a
    # snapshot taken before the lock - a concurrent ack or send read-modify-write would
    # otherwise be wiped by the lease_takeover journal write.
    fresh = load_events(root).get(event_id)
    if isinstance(fresh, dict):
        ev = fresh
    d = p_claims_dir(root)
    _ensure_dir(d)
    marker = os.path.join(d, event_id)
    try:
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"event_id": event_id, "task_id": ev["task_id"], "claimer": claimer,
                       "claimed_at": now, "claimer_pid": os.getpid(),
                       **({"lease_expires_at": now + int(lease_seconds)}
                          if int(lease_seconds) > 0 else {})},
                      f, ensure_ascii=True, sort_keys=True)
        return {"ok": True, "result": "claimed", "dispatch": True, "event_id": event_id,
                "task_id": ev["task_id"], "status": ev["status"],
                "synthetic": bool(ev.get("synthetic")), "claimed_at": now}
    except FileExistsError:
        first = read_json(marker, {})
        if not isinstance(first, dict) or "claimed_at" not in first:
            # a crash between O_EXCL create and write leaves an empty marker; a marker
            # with no readable claim never dispatched work, so it is safe to re-claim
            _atomic_write(marker, json.dumps(
                {"event_id": event_id, "task_id": ev["task_id"], "claimer": claimer,
                 "claimed_at": now, "claimer_pid": os.getpid(),
                 "recovered_empty_marker": True,
                 **({"lease_expires_at": now + int(lease_seconds)}
                    if int(lease_seconds) > 0 else {})},
                ensure_ascii=True, sort_keys=True).encode("utf-8"))
            return {"ok": True, "result": "claimed", "dispatch": True, "event_id": event_id,
                    "task_id": ev["task_id"], "status": ev["status"],
                    "synthetic": bool(ev.get("synthetic")), "claimed_at": now}
        lease_expires_at = first.get("lease_expires_at")
        if (isinstance(lease_expires_at, int) and now >= lease_expires_at
                and pid_exists(first.get("claimer_pid")) is False):
            # lease takeover: the holder recorded an expiry, the lease has elapsed,
            # and the holder pid is verifiably dead -> the claim is atomically stolen
            prev_claimer = first.get("claimer", "")
            _atomic_write(marker, json.dumps(
                {"event_id": event_id, "task_id": ev["task_id"], "claimer": claimer,
                 "claimed_at": now, "claimer_pid": os.getpid(),
                 **({"lease_expires_at": now + int(lease_seconds)}
                    if int(lease_seconds) > 0 else {})},
                ensure_ascii=True, sort_keys=True).encode("utf-8"))
            ev.setdefault("history", []).append(
                {"at": now, "action": "lease_takeover",
                 "prev_claimer": prev_claimer, "claimer": claimer})
            ev["updated_at"] = now
            save_event(root, ev, "lease_takeover")
            return {"ok": True, "result": "claimed", "dispatch": True, "recovered": True,
                    "event_id": event_id, "task_id": ev["task_id"], "status": ev["status"],
                    "synthetic": bool(ev.get("synthetic")), "claimed_at": now,
                    "prev_claimer": prev_claimer}
        return {"ok": True, "result": "already_claimed", "dispatch": False, "event_id": event_id,
                "first_claimed_at": first["claimed_at"],
                "claimer": first.get("claimer", "")}


def _sync_verify_notify_state(root, event_id, value):
    """Mirror the notification side's state into the verify queue doc (Spec §1.5).

    Read-modify-write of our own file under the shared lock. A missing doc is not an
    error here: it only means this event never entered the verify queue (blocked route,
    synthetic drill, or a `claim` from a tool that is not the router).
    """
    with file_lock(root):
        path = p_verify(root, event_id)
        doc = read_json(path, None)
        if isinstance(doc, dict) and doc.get("event_id") == event_id:
            doc["notify_state"] = value
            write_json_atomic(path, doc)


def cmd_claim(args, root):
    lease = int(args.lease_seconds)
    if lease < 0:
        print("ERROR: lease-seconds must be >= 0")
        return 2
    doc = claim_event(root, args.event_id, args.claimer or "", int(time.time()), lease)
    print(json.dumps(doc, ensure_ascii=True))
    if doc["ok"] and doc.get("result") == "claimed":
        return 0
    if doc.get("result") == "already_claimed":
        # rc 3, distinct from unknown/failed: the first claimer owns the work, so a
        # shell `claim ... && dispatch` can never re-dispatch a duplicate delivery
        return 3
    return 1


def cmd_release(args, root):
    now = int(time.time())
    with file_lock(root):
        ev = load_events(root).get(args.event_id)
        if ev is None:
            print("ERROR: unknown event_id")
            return 1
        if ev.get("verdict"):
            # G4-4: a verdicted event is closed; releasing it would re-arm
            # dispatch on work that already has a recorded outcome
            print("ERROR: event already has verdict; cannot release")
            return 2
        marker = p_claim(root, args.event_id)
        removed = False
        if os.path.exists(marker):
            try:
                os.remove(marker)
                removed = True
            except OSError as e:
                print(f"ERROR: cannot remove claim marker: {e}")
                return 1
        for key in ("retry_state", "next_action_at"):
            ev.pop(key, None)
        ev.setdefault("history", []).append(
            {"at": now, "action": "released", "reason": (args.reason or "")[:500],
             "claimer": args.claimer or ""})
        ev["updated_at"] = now
        save_event(root, ev, "released")
    print(json.dumps({"ok": True, "event_id": args.event_id,
                      "released": True, "marker_removed": removed}, ensure_ascii=True))
    return 0


def cmd_defer(args, root):
    retry_after = int(args.retry_after)
    if not (MIN_RETRY_AFTER <= retry_after <= MAX_RETRY_AFTER):
        print(f"ERROR: retry-after must be {MIN_RETRY_AFTER}..{MAX_RETRY_AFTER} seconds")
        return 2
    now = int(time.time())
    with file_lock(root):
        ev = load_events(root).get(args.event_id)
        if ev is None:
            print("ERROR: unknown event_id")
            return 1
        if ev.get("verdict"):
            print("ERROR: event already has verdict; cannot defer")
            return 2
        task = load_registry(root)["tasks"].get(ev["task_id"])
        task_max = (task or {}).get("max_retries")
        # an event only carries a budget when someone stored one deliberately; anything
        # else falls back to the task level, then to the default
        if ev.get("max_retries") is not None:
            max_retries = int(ev["max_retries"])
        elif task_max is not None:
            max_retries = int(task_max)
        else:
            max_retries = DEFAULT_MAX_RETRIES
        retry_count = int(ev.get("retry_count", 0))
        if retry_count + 1 > int(max_retries):
            # G4-2/G4-10: the Nth defer beyond max_retries is refused without
            # incrementing, so the router escalates to ack --verdict blocked
            print(json.dumps({"ok": False, "result": "retry_exhausted",
                              "event_id": args.event_id, "retry_count": retry_count,
                              "max_retries": int(max_retries)}, ensure_ascii=True))
            return 2
        ev["retry_state"] = "retry_pending"
        ev["retry_count"] = retry_count + 1
        ev["next_action_at"] = now + retry_after
        ev["last_retry_reason"] = (args.reason or "")[:500]
        ev.setdefault("history", []).append(
            {"at": now, "action": "deferred", "reason": (args.reason or "")[:500],
             "retry_after": retry_after, "claimer": args.claimer or ""})
        ev["updated_at"] = now
        save_event(root, ev, "deferred")
    print(json.dumps({"ok": True, "event_id": args.event_id,
                      "retry_count": retry_count + 1, "max_retries": int(max_retries),
                      "next_action_at": now + retry_after}, ensure_ascii=True))
    return 0


def cmd_ack(args, root):
    if args.verdict not in ("accepted", "blocked"):
        print("ERROR: verdict must be accepted|blocked")
        return 2
    now = int(time.time())
    # one lock across claim + verdict write: the event file is reloaded inside the
    # lock so a concurrent send-side read-modify-write can only land on send-owned
    # fields, and this verdict write lands on the freshest copy
    with file_lock(root):
        ev = load_events(root).get(args.event_id)
        if ev is None:
            print("ERROR: unknown event_id")
            return 1
        if ev.get("verdict"):
            print("ERROR: verdict already recorded; cannot overwrite")
            return 2
        task = load_registry(root)["tasks"].get(ev["task_id"])
        routing = task_routing(task)
        if task is not None and ev.get("created_at", 0) < task.get("registered_at", 0):
            routing.update(route_state="blocked", notify_telegram=False,
                           reason="事件早于当前注册")
        if args.verdict == "accepted" and routing["route_state"] == "blocked":
            print("ERROR: acceptance blocked: " + routing["reason"]
                  + "; record --verdict blocked instead")
            return 2
        claim = _claim_locked(root, args.event_id, ev, args.claimer or "ack", now)  # ack implies claim
        if not claim["ok"]:
            print(json.dumps(claim, ensure_ascii=True))
            return 1
        rec = {"event_id": args.event_id, "task_id": ev["task_id"], "verdict": args.verdict,
               "note": (args.note or "")[:500], "at": now}
        append_jsonl(p_acks(root), rec)
        ev["verdict"] = args.verdict
        ev["verdict_at"] = now
        ev["updated_at"] = now
        save_event(root, ev, "acked")
        state = ev["state"]
    _sync_verify_notify_state(root, args.event_id, args.verdict)
    # the ack echoes the event's real send state: an ack never implies the receiver
    # accepted delivery, and "processing" was not a state this tool ever sets
    print(json.dumps({"ok": True, "event_id": args.event_id, "verdict": args.verdict,
                      "state": state, "claim": claim["result"]}, ensure_ascii=True))
    return 0


# ---------------------------------------------------------------------------
# register / unregister / status
# ---------------------------------------------------------------------------

def _receipt_default_name(mode, marker_name=DEFAULT_MARKER_NAME):
    """Default receipt file name inside a task's dedicated receipt-source dir (Spec §2.5)."""
    if mode == "marker":
        return f"{marker_name or DEFAULT_MARKER_NAME}.done"
    return {"exitcode": "exit.json", "json": "receipt.json"}[mode]


def _validate_pending_path(raw, name):
    """Absolute, traversal-free path that may legitimately not exist yet.

    Receipt-family files are written by the executor AFTER registration, so the
    session-path rule (already an existing file) cannot apply to them; only the
    containment rules are enforceable at register time.
    """
    _no_traversal(raw)
    if not os.path.isabs(raw):
        raise ValueError(f"{name} must be absolute: {raw!r}")
    return os.path.realpath(raw)


def cmd_register(args, root):
    tid = validate_task_id(args.task_id)
    source = args.source
    wd = validate_workdir(args.workdir)
    receipt_mode = report_path = exit_code_path = None
    rs_dir = None
    stale = []
    marker_name = getattr(args, "marker_name", None) or DEFAULT_MARKER_NAME
    if not MARKER_NAME_RE.match(marker_name):
        print(f"ERROR: --marker-name must match {MARKER_NAME_RE.pattern}")
        return 2
    raw_success = getattr(args, "exit_code_success", None)
    raw_min_chars = getattr(args, "min_report_chars", None)
    raw_max_retries = getattr(args, "max_retries", None)
    try:
        exit_code_success = (DEFAULT_EXIT_CODE_SUCCESS if raw_success is None
                             else int(raw_success))
        min_report_chars = (DEFAULT_MIN_REPORT_CHARS if raw_min_chars is None
                            else int(raw_min_chars))
        max_retries = DEFAULT_MAX_RETRIES if raw_max_retries is None else int(raw_max_retries)
    except (TypeError, ValueError):
        print("ERROR: --exit-code-success/--min-report-chars/--max-retries must be integers")
        return 2
    if not MIN_MIN_REPORT_CHARS <= min_report_chars <= MAX_MIN_REPORT_CHARS:
        print(f"ERROR: --min-report-chars must be within "
              f"{MIN_MIN_REPORT_CHARS}-{MAX_MIN_REPORT_CHARS}")
        return 2
    if max_retries < 0:
        print("ERROR: --max-retries must be >= 0")
        return 2
    if source in RECEIPT_FAMILY_SOURCES:
        receipt_mode = args.receipt_mode or DEFAULT_RECEIPT_MODE
        if source == "exit" and args.receipt_mode is None:
            print("WARN: --source exit now defaults to json receipts; "
                  "pass --receipt-mode exitcode for receipt-source/exit.json")
        rs_dir = p_receipt_source_dir(root, tid)
        _ensure_dir(rs_dir)
        if args.session_path:
            sp = _validate_pending_path(args.session_path, "receipt path")
            parent = os.path.dirname(sp)
            if not os.path.isdir(parent) and parent != os.path.realpath(rs_dir):
                raise ValueError(f"receipt path parent directory does not exist: {parent!r}")
        else:
            sp = os.path.realpath(os.path.join(rs_dir, _receipt_default_name(receipt_mode,
                                                                            marker_name)))
    else:
        if getattr(args, "receipt_mode", None) is not None or args.exit_code_path is not None:
            print("ERROR: --receipt-mode/--exit-code-path only valid for receipt-family sources")
            return 2
        # pi/claude keep the legacy contract: the log file must already exist
        sp = validate_session_path(args.session_path)
    if args.report_path is not None:
        report_path = _validate_pending_path(args.report_path, "report path")
    if args.exit_code_path is not None:
        exit_code_path = _validate_pending_path(args.exit_code_path, "exit code path")
    elif source in RECEIPT_FAMILY_SOURCES and receipt_mode == "exitcode":
        exit_code_path = sp
    if args.allow_root:
        # every path here is already realpath()'d: a receipt file that does not exist
        # yet must still be checked against the allowed roots
        validate_under_roots(sp, args.allow_root, "session path")
        validate_under_roots(wd, args.allow_root, "workdir")
        for path, name in ((report_path, "report path"), (exit_code_path, "exit code path")):
            if path is not None:
                validate_under_roots(path, args.allow_root, name)
    pid = None
    if args.pid is not None:
        pid = int(args.pid)
        if pid <= 0:
            print("ERROR: pid must be > 0")
            return 2
        if pid_exists(pid) is None:
            print(f"WARN: pid {pid} liveness unverifiable; status will read unknown")
    sid = args.session_id
    if source == "claude":
        # claude frames carry no task identity: the session_id is the only link
        # between the log and this task, so it is required and format-checked here
        sid = validate_session_id(sid)
    elif source in RECEIPT_FAMILY_SOURCES and sid:
        # A receipt-family task is identified by its task_id inside the receipt, so a
        # session id here would only invite routing to a session nobody verified (Spec §2.3).
        print(f"ERROR: --session-id is not valid with --source {source}; "
              "use --origin-target local:<session-id> for delivery")
        return 2
    elif sid:
        sid = validate_session_id(sid)
    else:
        sid = None
    if args.agent_name is not None:
        agent_name = validate_agent_name(args.agent_name)
    else:
        agent_name = DEFAULT_AGENT_NAMES.get(source)
        if agent_name is None:
            # receipt/exit carry no vendor identity: guessing one would mislabel the
            # receipt that a human reads back in Telegram
            print(f"ERROR: --agent-name is required with --source {source} "
                  "(no default display name for this source)")
            return 2
    origin_target = (validate_origin_target(args.origin_target)
                     if args.origin_target is not None else None)
    with file_lock(root):
        reg = load_registry(root)
        re_register = tid in reg["tasks"]
        if re_register and not args.force:
            print(f"ERROR: task {tid} already registered (use --force)")
            return 2
        # captured before the new entry replaces it: --force must clear the PREVIOUS run's
        # receipt files, whose names may differ from the ones this registration computes
        prev_entry = dict(reg["tasks"].get(tid) or {})
        entry = {
            "task_id": tid,
            "session_path": sp,
            "workdir": wd,
            "goal": args.goal,
            "next_phases": args.next_phase or [],
            "pid": pid,
            "synthetic": bool(args.synthetic),
            "source": source,
            "agent_name": agent_name,
            "origin_target": origin_target,
            "registered_at": int(time.time()),
            "terminal_event_id": None,
        }
        if sid:
            # pi tasks keep no session_id key, so old registry entries are unchanged
            entry["session_id"] = sid
        # legacy pi/claude entries stay byte-compatible: these keys exist only when set
        receipt_cfg = None
        if source in RECEIPT_FAMILY_SOURCES:
            receipt_cfg = (("marker_name", marker_name if receipt_mode == "marker" else None),
                           ("exit_code_success", exit_code_success),
                           ("min_report_chars", min_report_chars),
                           ("max_retries", max_retries))
        for key, val in (("receipt_mode", receipt_mode), ("report_path", report_path),
                         ("exit_code_path", exit_code_path)) + tuple(receipt_cfg or ()):
            if val is not None:
                entry[key] = val
        reg["tasks"][tid] = entry
        write_json_atomic(p_registry(root), reg)
        if re_register:
            # a fresh run under the same task_id must not inherit the old read cursor
            write_json_atomic(p_state(root, tid), _reset_incremental_state(load_state(root, tid)))
            # ...nor the previous run's receipt: a stale marker would make the very
            # next tick report a terminal status for a task that never ran again. The
            # old entry's own paths are cleared wherever they point, not only inside
            # receipt-source/, because --session-path/--exit-code-path accept any
            # absolute path and _receipt_is_stale's 2s mtime grace window cannot tell a
            # receipt written moments before the re-registration from a fresh one.
            # Both sets are gated on the PREVIOUS entry's source, never on this
            # command's: a pi/claude session_path IS the session log, and this command
            # has never been allowed to delete it, so --force across sources into a
            # receipt family must leave the old log where it is.
            if rs_dir is not None:
                prev_receipt_paths = [prev_entry.get(key)
                                      for key in ("session_path", "exit_code_path")]
                prev_receipt_paths = ([p for p in prev_receipt_paths if p]
                                      if prev_entry.get("source") in RECEIPT_FAMILY_SOURCES
                                      else [])
                victims = list(prev_receipt_paths)
                names = {_receipt_default_name(m, marker_name) for m in RECEIPT_MODES}
                for path in prev_receipt_paths:
                    names.add(os.path.basename(path))
                if prev_entry.get("marker_name"):
                    names.add(_receipt_default_name("marker", prev_entry["marker_name"]))
                # --report-path names a produced report, not a receipt, in either round,
                # so the basename sweep has to skip a file that only LOOKS like a
                # receipt because it sits in receipt-source/ under a receipt's name.
                # One exception: when the report path IS the previous receipt path the
                # two share a file, and the 2s grace window still demands that file go.
                produced = {os.path.realpath(p)
                            for p in (prev_entry.get("report_path"), report_path) if p}
                receipts = {os.path.realpath(p) for p in prev_receipt_paths}
                for name in sorted(names):
                    swept = os.path.realpath(os.path.join(rs_dir, name))
                    if swept in produced and swept not in receipts:
                        continue
                    victims.append(swept)
                for path in dict.fromkeys(victims):
                    if not os.path.isfile(path):
                        continue
                    try:
                        os.remove(path)
                    except OSError as e:
                        # a receipt this command could not clear is precisely the stale
                        # verdict the next tick may report, so say it out loud
                        print(f"WARN: register --force could not clear {path}: {e}")
                        continue
                    stale.append(path)
    _ensure_dir(p_receipts_dir(root, tid))
    echo = {"task_id": tid, "session_path": sp, "workdir": wd,
            "goal": args.goal, "next_phases": args.next_phase or [],
            "pid": pid, "synthetic": bool(args.synthetic), "source": source,
            "agent_name": agent_name, "origin_target": origin_target}
    if sid:
        echo["session_id"] = sid
    for key, val in (("receipt_mode", receipt_mode), ("report_path", report_path),
                     ("exit_code_path", exit_code_path)) + tuple(receipt_cfg or ()):
        if val is not None:
            echo[key] = val
    print(f"registered {json.dumps(echo, ensure_ascii=True)}")
    if re_register and stale:
        print(f"register --force: cleared stale receipt file(s): "
              f"{', '.join(os.path.basename(p) for p in stale)}")
    if origin_target is None and not args.synthetic:
        print("WARN: routing blocked: missing origin_target; no fallback destination")
    return 0


def cmd_unregister(args, root):
    tid = validate_task_id(args.task_id)
    with file_lock(root):
        reg = load_registry(root)
        if tid not in reg["tasks"]:
            print("ERROR: no such task")
            return 1
        del reg["tasks"][tid]
        write_json_atomic(p_registry(root), reg)
    print(f"unregistered {tid} (events/receipts kept for audit)")
    return 0


def cmd_status(args, root):
    reg = load_registry(root)
    evs = load_events(root)
    acks = load_acks(root)
    if args.json:
        out = {}
        for tid, task in sorted(reg["tasks"].items()):
            st = load_state(root, tid)
            t_evs = [e for e in evs.values() if e.get("task_id") == tid]
            out[tid] = {"task": {k: task[k] for k in
                                 ("session_path", "goal", "next_phases", "synthetic", "pid",
                                  "source", "session_id", "agent_name", "origin_target",
                                  "terminal_event_id", "receipt_mode", "report_path",
                                  "exit_code_path") if k in task},
                        "routing": task_routing(task),
                        "state": st,
                        "events": [{**{k: e[k] for k in ("event_id", "status", "state", "attempts",
                                                         "reason", "receipt_bytes", "created_at",
                                                         "retry_state", "next_action_at") if k in e},
                                    "retry_count": int(e.get("retry_count", 0)),
                                    "verdict": acks.get(e["event_id"], {}).get("verdict", "-")}
                                   for e in sorted(t_evs, key=lambda x: x["created_at"])]}
        print(json.dumps(out, ensure_ascii=True, indent=1, sort_keys=True))
        return 0
    if not reg["tasks"]:
        print("no tasks registered")
        return 0
    lines = []
    for tid, task in sorted(reg["tasks"].items()):
        st = load_state(root, tid)
        lines.append(f"task {tid}")
        lines.append("  source={} routing={}".format(task.get("source") or "pi",
                     json.dumps(task_routing(task), ensure_ascii=True, sort_keys=True)))
        lines.append("  synthetic={} pid={} pid_status={} terminal_event={}".format(task.get("synthetic"), task.get("pid"), st.get("pid_status"),
                        task.get("terminal_event_id")))
        lines.append("  offset={} lines_seen={} bad_lines={} tool_open={} last_activity={}".format(st.get("offset"), st.get("line_seq"), st.get("bad_lines"),
                        st.get("tool_open"), st.get("last_activity_at")))
        for e in sorted([e for e in evs.values() if e.get("task_id") == tid],
                        key=lambda x: x["created_at"]):
            verdict = acks.get(e["event_id"], {}).get("verdict", "-")
            blocked = (" blocked:{}".format(e.get("reason_blocked"))) if e.get("state") == "blocked" else ""
            lines.append("  event {} status={} state={} attempts={} verdict={}{}".format(e["event_id"], e["status"], e["state"], e.get("attempts", 0),
                            verdict, blocked))
    print("\n".join(lines))
    return 0


def cmd_ack_pending(args, root):
    shown = 0
    now = int(time.time())
    for ev in sorted(load_events(root).values(), key=lambda e: e["created_at"]):
        # delivered-but-unacked is exactly what the receiver still owes a verdict for
        if ev.get("state") not in ("pending", "delivered") or ev.get("verdict"):
            continue
        shown += 1
        next_action_at = ev.get("next_action_at")
        wait = (max(0, int(next_action_at) - now)
                if isinstance(next_action_at, int) and next_action_at else 0)
        print(json.dumps({"event_id": ev["event_id"], "task_id": ev["task_id"],
                          "status": ev["status"],
                          "claimed": os.path.exists(p_claim(root, ev["event_id"])),
                          "retry_state": ev.get("retry_state"),
                          "retry_count": int(ev.get("retry_count", 0)),
                          "next_action_at": next_action_at,
                          "retry_wait_seconds": wait},
                         ensure_ascii=True))
    if not shown:
        print("ack-pending: nothing open")
    return 0


# ---------------------------------------------------------------------------
# receiver side: independent verification ledger (verify queue docs)
#
# The verify channel is a second, separate ledger: outbox/verify/<eid>.json plus
# outbox/verify-claims/<eid>.json and outbox/verify-acks.jsonl. Nothing here reads
# or writes ev["verdict"] in outbox/events/<eid>.json, so the router's notification
# ack and the verifier's judgement can never overwrite each other (Invariant I3).
# ---------------------------------------------------------------------------

def _verify_claim_locked(root, event_id, claimer, now, lease_seconds):
    """Atomic once-only claim of the verify queue entry (never the router claim).

    A verifier that crashed mid-review is recoverable: the marker records its pid and
    a lease, so a caller may steal it only once the lease elapsed AND the recorded pid
    is verifiably gone."""
    _ensure_dir(p_verify_claims_dir(root))
    marker = p_verify_claim(root, event_id)
    payload = {"event_id": event_id, "claimer": claimer, "claimed_at": now,
               "claimer_pid": os.getpid()}
    if int(lease_seconds) > 0:
        payload["lease_expires_at"] = now + int(lease_seconds)
    try:
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=True, sort_keys=True)
        return {"ok": True, "result": "claimed", "dispatch": True}
    except FileExistsError:
        first = read_json(marker, {})
        if not isinstance(first, dict) or "claimed_at" not in first:
            # an unreadable verify claim never dispatched a review, so it is safe to re-claim
            _atomic_write(marker, json.dumps(payload, ensure_ascii=True,
                                             sort_keys=True).encode("utf-8"))
            return {"ok": True, "result": "claimed", "dispatch": True,
                    "recovered": True, "recovered_empty_marker": True}
        expires = first.get("lease_expires_at")
        if (isinstance(expires, int) and now >= expires
                and pid_exists(first.get("claimer_pid")) is False):
            prev = first.get("claimer", "")
            _atomic_write(marker, json.dumps(payload, ensure_ascii=True,
                                             sort_keys=True).encode("utf-8"))
            return {"ok": True, "result": "claimed", "dispatch": True, "recovered": True,
                    "prev_claimer": prev}
        return {"ok": True, "result": "already_claimed", "dispatch": False,
                "first_claimed_at": first["claimed_at"], "claimer": first.get("claimer", "")}


def load_verify_doc(root, event_id):
    """The verify queue doc for an event, or None when it has none.

    Only open_verify_doc() below creates the file (Spec §1.5): the script channel hands
    work to the verifier, so a missing doc means "no work for you" and is never papered
    over here by rebuilding one.
    """
    doc = read_json(p_verify(root, event_id), None)
    if isinstance(doc, dict) and doc.get("event_id") == event_id:
        return doc
    return None


def open_verify_doc(root, event_id, now=None):
    """(response, rc) for opening or refreshing one verify queue doc.

    The handoff exists only for a non-synthetic `report_ready` event whose route is ready,
    and only once the script channel has been granted the dispatch: `failed` and `stalled`
    are notification traffic rather than artifact reviews, and a blocked route has no
    origin waiting on a verdict. Every field comes from the local ledger (event file +
    registry.json), never from a webhook body, so no remote caller can invent a
    destination, a workdir or a goal. Re-opening refreshes the routing mirror while the
    send state a previous attempt earned is kept, which makes the call idempotent.
    """
    now = int(time.time() if now is None else now)
    ev = load_events(root).get(event_id)
    if ev is None:
        return {"ok": False, "result": "unknown_event", "event_id": event_id}, 1
    if ev.get("synthetic"):
        # Spec §4.5: a synthetic drill notifies nobody and reviews nothing
        return {"ok": False, "result": "synthetic_not_queued", "event_id": event_id}, 2
    if ev.get("status") != "report_ready":
        return {"ok": False, "result": "not_report_ready", "event_id": event_id,
                "status": ev.get("status")}, 2
    task = load_registry(root)["tasks"].get(ev.get("task_id"))
    routing = task_routing(task)
    if routing.get("route_state") != "ready":
        return {"ok": False, "result": "route_not_ready", "event_id": event_id,
                "route_state": routing.get("route_state")}, 2
    # Spec §1.5: the queue opens for the notification side's OWN claim, and the claim
    # marker is the durable proof of it. A foreign holder (a manual `claim --claimer ack`,
    # another router) or an event nobody claimed must never put work in front of the
    # verifier; `notify_state` below only mirrors the delivery side for operators.
    marker = read_json(p_claim(root, event_id), None)
    holder = marker.get("claimer") if isinstance(marker, dict) else None
    if holder != SCRIPT_CHANNEL_CLAIMER:
        return {"ok": False, "result": "not_claimed_by_script", "event_id": event_id,
                "claimer": holder}, 3
    notify_state = ev.get("verdict") or ev.get("state") or "pending"
    path = p_verify(root, event_id)
    with file_lock(root):
        old = read_json(path, None)
        old = old if isinstance(old, dict) and old.get("event_id") == event_id else {}
        doc = {"event_id": event_id,
               "task_id": ev.get("task_id"),
               "status": ev.get("status"),
               "reason": (ev.get("reason") or "")[:500],
               "agent_name": routing.get("agent_name"),
               "source": (task or {}).get("source") or "pi",
               "origin_target": routing.get("origin_target"),
               "channel": routing.get("channel"),
               "workdir": (task or {}).get("workdir"),
               "goal": (task or {}).get("goal"),
               "next_phases": (task or {}).get("next_phases") or [],
               "receipt_path": ev.get("receipt_path"),
               "report_path": (task or {}).get("report_path"),
               # the verifier prompt branches on these three: synthetic drills never get
               # here, and a doc whose route or claim moved must be refused, not judged.
               "synthetic": bool(ev.get("synthetic")),
               "route_state": routing.get("route_state"),
               "claim_state": "claimed_by_script",
               "notify_state": notify_state,
               "verify_state": "queued",
               "created_at": int(ev.get("created_at") or now),
               "sent_at": None,
               "attempts": 0,
               "max_attempts": int(ev.get("max_attempts")
                                   or setting("AGENT_HANDOFF_MAX_ATTEMPTS") or 60)}
        # a doc that already travelled keeps its own send history, verdict and budget;
        # only the routing mirror above is refreshed, so re-opening never resets progress
        for key in ("created_at", "sent_at", "attempts", "max_attempts", "verify_state",
                    "verdict", "verdict_at", "note", "history"):
            if old.get(key) is not None:
                doc[key] = old[key]
        _ensure_dir(p_verify_dir(root))
        write_json_atomic(path, doc)
    return {"ok": True, "result": "already_opened" if old else "opened",
            "event_id": event_id, "verify_state": doc.get("verify_state"),
            "claim_state": doc.get("claim_state")}, 0


def cmd_verify_open(args, root):
    resp, rc = open_verify_doc(root, args.event_id)
    print(json.dumps(resp, ensure_ascii=True))
    return rc


def _verify_queue_refusal(root, event_id):
    """(result, rc) when no queue doc is there.

    rc 3 is "no work for you" and covers a review that already closed (verify ledger
    verdict), a synthetic drill, and a real event the script channel never dispatched; an
    event this state root has never seen at all is rc 1.
    """
    if load_verify_acks(root).get(event_id, {}).get("verdict"):
        return "already_verified", 3
    ev = load_events(root).get(event_id)
    if ev is None:
        return "unknown_event", 1
    if ev.get("synthetic"):
        return "synthetic_not_queued", 3
    return "not_queued", 3


def cmd_verify_show(args, root):
    """Print the verify queue doc without creating anything.

    This is the step the verifier Agent runs first: the doc exists only because the
    script channel opened it after a granted dispatch, so its absence is the answer
    (rc 3 "no work" / rc 1 unknown event) and must never be papered over here.
    """
    doc = load_verify_doc(root, args.event_id)
    if doc is None:
        result, rc = _verify_queue_refusal(root, args.event_id)
        print(json.dumps({"ok": False, "result": result, "event_id": args.event_id},
                         ensure_ascii=True))
        return rc
    print(json.dumps({"ok": True, "event_id": args.event_id, "verify": doc},
                     ensure_ascii=True))
    return 0


def cmd_verify_claim(args, root):
    lease = int(args.lease_seconds)
    if lease < 0:
        print("ERROR: lease-seconds must be >= 0")
        return 2
    now = int(time.time())
    with file_lock(root):
        vdoc = load_verify_doc(root, args.event_id)
        if vdoc is None:
            result, rc = _verify_queue_refusal(root, args.event_id)
            print(json.dumps({"ok": False, "result": result, "event_id": args.event_id,
                              "dispatch": False}, ensure_ascii=True))
            return rc
        verdict = vdoc.get("verdict") or load_verify_acks(root).get(args.event_id, {}).get("verdict")
        if verdict:
            # the review is already on the verify ledger: rc 3 = "no work for you"
            print(json.dumps({"ok": True, "result": "already_verified", "dispatch": False,
                              "event_id": args.event_id, "verdict": verdict}, ensure_ascii=True))
            return 3
        doc = _verify_claim_locked(root, args.event_id, args.claimer or "", now, lease)
        doc["event_id"] = args.event_id
        doc["task_id"] = vdoc.get("task_id")
        doc["verify"] = vdoc
    print(json.dumps(doc, ensure_ascii=True))
    if doc["ok"] and doc.get("result") == "claimed":
        return 0
    if doc.get("result") == "already_claimed":
        return 3
    return 1


def cmd_verify_ack(args, root):
    """Record the independent verification verdict in the verify ledger only."""
    if args.verdict not in ("accepted", "blocked"):
        print("ERROR: verify verdict must be accepted|blocked")
        return 2
    now = int(time.time())
    with file_lock(root):
        if load_verify_acks(root).get(args.event_id, {}).get("verdict"):
            print("ERROR: verify verdict already recorded; cannot overwrite")
            return 2
        vdoc = load_verify_doc(root, args.event_id)
        if vdoc is None:
            result, rc = _verify_queue_refusal(root, args.event_id)
            if result == "unknown_event":
                print("ERROR: unknown event_id")
            else:
                print(json.dumps({"ok": False, "result": result,
                                  "event_id": args.event_id}, ensure_ascii=True))
            return rc
        if vdoc.get("verdict"):
            print("ERROR: verify verdict already recorded; cannot overwrite")
            return 2
        note = (args.note or "")[:500]
        append_jsonl(p_verify_acks(root), {"event_id": args.event_id,
                                          "task_id": vdoc.get("task_id"),
                                          "verdict": args.verdict, "note": note,
                                          "claimer": args.claimer or "", "at": now})
        vdoc["verdict"] = args.verdict
        vdoc["verdict_at"] = now
        vdoc["verify_state"] = "acked"
        vdoc["note"] = note
        # the ledger line above is the durable record, so the queue entry is closed by
        # removing it: a kept doc would sit in outbox/verify/ looking un-dispatched
        write_json_atomic(p_verify(root, args.event_id), vdoc)
        append_jsonl(p_journal(root), {"at": now, "event_id": args.event_id,
                                      "action": "verify_acked", "verdict": args.verdict,
                                      "state": None, "status": vdoc.get("status")})
        # The queue entry is closed here: the ledger line above is the durable record, so
        # the doc is removed rather than left looking un-dispatched, and the verifier's own
        # claim marker goes with it (the verify ledger keeps the claimer for the audit).
        # A doc that is already gone is the same end state, and a removal failure cannot
        # undo the verdict, so both cases are reported instead of pretending to retry.
        queue_doc = "closed"
        for path in (p_verify(root, args.event_id), p_verify_claim(root, args.event_id)):
            if not os.path.exists(path):
                continue
            try:
                os.remove(path)
            except OSError as e:
                queue_doc = f"left in place: {e}"
    print(json.dumps({"ok": True, "event_id": args.event_id, "verdict": args.verdict,
                      "task_id": vdoc.get("task_id"), "queue_doc": queue_doc},
                     ensure_ascii=True))
    return 0


def cmd_verify_clear(args, root):
    """Drop unacked verify queue docs so a historical backlog cannot flood Agents.

    A doc carrying a verify verdict is never removed: it is the record of a review that
    already happened. Everything else is safe to drop -- the router re-opens the queue doc
    (verify-open) for any report_ready event it dispatches -- so clearing is idempotent:
    an already-absent doc is not an error, and rc 0 covers "nothing to clear" too.
    """
    reason = (args.reason or "").strip()
    if not reason:
        print("ERROR: --reason must be non-empty")
        return 2
    now = int(time.time())
    cleared, kept, absent = [], [], []
    with file_lock(root):
        if args.event_id:
            docs = [(args.event_id, read_json(p_verify(root, args.event_id), None))]
        else:
            docs = [(v["event_id"], v) for v in list_verify_queue(root)]
        for eid, doc in docs:
            if not isinstance(doc, dict):
                absent.append(eid)
                continue
            if doc.get("verdict") or doc.get("verify_state") == "acked":
                kept.append(eid)
                continue
            try:
                os.remove(p_verify(root, eid))
            except FileNotFoundError:
                absent.append(eid)
                continue
            except OSError as e:
                print(f"ERROR: cannot clear verify doc {eid}: {e}")
                return 1
            with contextlib.suppress(OSError):
                os.remove(p_verify_claim(root, eid))
            append_jsonl(p_journal(root), {"at": now, "event_id": eid,
                                          "action": "verify_cleared", "reason": reason[:500],
                                          "state": None, "status": doc.get("status")})
            cleared.append(eid)
    print(json.dumps({"ok": True, "cleared": len(cleared), "event_ids": cleared,
                      "skipped_verdicted": kept, "absent": absent,
                      "reason": reason[:500]}, ensure_ascii=True))
    return 0


# ---------------------------------------------------------------------------
# registry housekeeping: archive / prune-claims
# ---------------------------------------------------------------------------

def _task_last_seen(task, t_events):
    """Newest timestamp across registration and this task's events.

    Kept for reporting only: the archive window itself is measured from registered_at,
    because an event's updated_at moves every time a send or defer touches it, so a task
    that is merely being retried would never age out of the live registry.
    """
    stamps = [int(task.get("registered_at") or 0)]
    for e in t_events:
        for key in ("created_at", "updated_at", "verdict_at"):
            val = e.get(key)
            if isinstance(val, int) and val:
                stamps.append(val)
    return max(stamps)


def _archive_block_reason(task, t_events, cutoff, named=False):
    """Why this task must stay in the live registry (None means it is eligible).

    `named` comes from an explicit --task: it waives the age window only. A live pid, a
    missing terminal event or an unjudged event still blocks, because those are the
    conditions an archive would silently orphan.
    """
    tid = task["task_id"]
    # synthetic drills get no real terminal routing, so they used to need
    # --include-synthetic. The flag is gone: a synthetic task past the window
    # archives like any other.
    if not task.get("terminal_event_id") and not task.get("synthetic"):
        return f"{tid}: no terminal event recorded"
    if task.get("pid") and pid_exists(task["pid"]) is True:
        return f"{tid}: pid {task['pid']} still alive"
    for e in sorted(t_events, key=lambda x: x['event_id']):
        if not e.get("verdict"):
            return f"{tid}: event {e['event_id']} has no verdict"
        # a verdict IS the terminal record: run_send only picks up events without
        # one, and an escalated delivery (ack blocked after a retry that never
        # landed) stays state=pending by design. Gating on the delivery state here
        # used to make every blocked event unarchivable.
        if e.get("retry_state") == "retry_pending":
            return f"{tid}: event {e['event_id']} retry window still open"
    registered_at = int(task.get("registered_at") or 0)
    if not named and registered_at > cutoff:
        return f"{tid}: registered at {registered_at} is inside the age window"
    return None


def cmd_archive(args, root):
    """Move closed, verdicted, quiet tasks from registry.json to the archive file.

    Events, receipts, claims and per-task state are left untouched: the archive only
    shrinks what every tick has to scan, and the audit trail stays where it is.
    """
    days = float(args.older_than_days)
    if days < 0:
        print("ERROR: older-than-days must be >= 0")
        return 2
    now = int(time.time())
    cutoff = now - int(days * 86400)
    named = set(args.task or [])
    unknown = sorted(named - set(load_registry(root)["tasks"])) if named else []
    if unknown:
        # naming a task that is not registered is an operator error (typo, or already
        # archived); silently archiving "nothing" would hide it
        print("ERROR: unknown task_id(s): " + ", ".join(unknown))
        return 2
    with file_lock(root):
        reg = load_registry(root)
        evs = load_events(root)
        eligible, blocked = [], {}
        for tid, task in sorted(reg["tasks"].items()):
            t_events = [e for e in evs.values() if e.get("task_id") == tid]
            reason = _archive_block_reason(task, t_events, cutoff, named=bool(tid in named))
            if reason:
                blocked[tid] = reason
            else:
                eligible.append(tid)
        if eligible and not args.dry_run:
            arch = read_json(p_archive(root), None)
            if not isinstance(arch, dict) or not isinstance(arch.get("archived_tasks"), dict):
                arch = {"schema_version": SCHEMA_VERSION, "archived_tasks": {}}
            for tid in eligible:
                entry = dict(reg["tasks"][tid])
                entry["archived_at"] = now
                arch["archived_tasks"][tid] = entry
                del reg["tasks"][tid]
            write_json_atomic(p_archive(root), arch)
            write_json_atomic(p_registry(root), reg)
            append_jsonl(p_journal(root), {"at": now, "action": "archived",
                                          "task_ids": eligible, "state": None,
                                          "status": None})
        summary = {"ok": True, "dry_run": bool(args.dry_run),
                   "archived_count": len(eligible), "archived_task_ids": eligible,
                   "remaining_count": len(reg["tasks"]), "blocked": blocked,
                   "older_than_days": days, "named_task_ids": sorted(named), "at": now}
    print(json.dumps(summary, ensure_ascii=True))
    return 0


def _marker_stems(directory, suffix):
    """Marker names in a claims dir as (stem, path) pairs, skipping .tmp leftovers."""
    if not os.path.isdir(directory):
        return []
    out = []
    for name in sorted(os.listdir(directory)):
        if not name or name.endswith(".tmp"):
            continue
        if suffix and not name.endswith(suffix):
            continue
        stem = name[:-len(suffix)] if suffix else name
        if stem:
            out.append((stem, os.path.join(directory, name)))
    return out


def cmd_prune_claims(args, root):
    """Delete claim markers that can no longer guard anything.

    Age is not the criterion: a marker is dropped once it protects nothing, which is
    either (a) the delivery or the review already carries a verdict, or (b) the marker is
    an orphan - its event file was pruned away and no ack names it, so no replay can
    ever find something to deduplicate against again. An unverdicted marker whose event
    still exists is the only thing standing between a webhook replay and a second
    dispatch, and stays regardless of how old it is.
    """
    now = int(time.time())
    events = load_events(root)
    acks = load_acks(root)
    verify_acks = load_verify_acks(root)

    def _router_state(eid):
        """(verdict, orphans) for a notification claim marker."""
        ev = events.get(eid)
        verdict = (ev or {}).get("verdict") or acks.get(eid, {}).get("verdict")
        return verdict, ev is None

    def _verify_state(eid):
        doc = read_json(p_verify(root, eid), None)
        verdict = (doc.get("verdict") if isinstance(doc, dict) else None) \
            or verify_acks.get(eid, {}).get("verdict")
        # a verify marker without an event file is an orphan by definition; an acked
        # event whose queue doc was cleared still has its verdict on the ledger above
        return verdict, events.get(eid) is None and not verdict

    pruned, kept = [], []
    with file_lock(root):
        scopes = (("", p_claims_dir(root), _router_state),
                  (".json", p_verify_claims_dir(root), _verify_state))
        for suffix, directory, state_of in scopes:
            for stem, marker in _marker_stems(directory, suffix):
                doc = read_json(marker, {})
                if not isinstance(doc, dict) or not isinstance(doc.get("claimed_at"), int):
                    # a marker we cannot read proves nothing about ownership: keep it
                    kept.append(stem)
                    continue
                verdict, orphan = state_of(stem)
                if not (verdict or orphan):
                    kept.append(stem)
                    continue
                if not args.dry_run:
                    try:
                        os.remove(marker)
                    except OSError as e:
                        print(f"ERROR: cannot remove claim marker {stem}: {e}")
                        return 1
                pruned.append(stem)
        if pruned and not args.dry_run:
            append_jsonl(p_journal(root), {"at": now, "action": "claims_pruned",
                                          "event_ids": pruned, "state": None, "status": None})
    print(json.dumps({"ok": True, "dry_run": bool(args.dry_run),
                      "pruned_count": len(pruned), "pruned_event_ids": pruned,
                      "kept_count": len(kept), "at": now},
                     ensure_ascii=True))
    return 0


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(
        prog="handoff.py",
        description="AgentWebhook completion-callback handoff recorder")
    ap.add_argument("--root", default=None,
                    help="state dir (default $AGENT_HANDOFF_ROOT, else <script dir>/data)")
    sub = ap.add_subparsers(dest="cmd")
    sub.required = True

    r = sub.add_parser("register", help="add a task to watch (read-only on the session)")
    r.add_argument("--task-id", required=True)
    r.add_argument("--session-path", default=None,
                   help="absolute path of the pi task session JSONL; required for "
                        "--source pi/claude, optional for receipt-family sources "
                        "(default: a dedicated file under tasks/<task-id>/receipt-source/)")
    r.add_argument("--workdir", required=True)
    r.add_argument("--goal", required=True)
    r.add_argument("--next-phase", action="append", default=[],
                   help="repeatable; phases are registry data, never executed paths/commands")
    r.add_argument("--pid", type=int, default=None)
    r.add_argument("--synthetic", action="store_true",
                   help="test handoff: receiver only acks with a test receipt, no engineering action")
    r.add_argument("--allow-root", action="append", default=[],
                   help="registered paths must resolve under this root (repeatable)")
    r.add_argument("--source", choices=SOURCE_CHOICES, default="pi",
                   help="terminal-status input: pi JSONL / claude stream-json log parser, "
                        "or a receipt-family source (receipt, exit, cursor, codex, dsh) "
                        "whose status comes from an external receipt file instead of a log")
    r.add_argument("--receipt-mode", choices=RECEIPT_MODES, default=None,
                   help="receipt-family only: json (default), marker, or exitcode")
    r.add_argument("--marker-name", default=DEFAULT_MARKER_NAME,
                   help="marker mode: receipt-source/<name>.done (1-32 chars of "
                        "A-Za-z0-9._-)")
    r.add_argument("--exit-code-success", type=int, default=None,
                   help=f"receipt-family only: exit code that means success "
                        f"(default {DEFAULT_EXIT_CODE_SUCCESS})")
    r.add_argument("--min-report-chars", type=int, default=None,
                   help=f"json mode: minimum report_text length for report_ready "
                        f"(default {DEFAULT_MIN_REPORT_CHARS}, "
                        f"range {MIN_MIN_REPORT_CHARS}-{MAX_MIN_REPORT_CHARS})")
    r.add_argument("--max-retries", type=int, default=None,
                   help=f"task-level retry ceiling used by defer "
                        f"(default {DEFAULT_MAX_RETRIES})")
    r.add_argument("--report-path", default=None,
                   help="receipt-family only: absolute report file an exitcode/marker "
                        "receipt points at. exitcode mode verifies it as a task artifact "
                        "(present, non-empty); marker mode records the fingerprint claim "
                        "from the marker alone and never checks this file. Never executed")
    r.add_argument("--exit-code-path", default=None,
                   help="receipt-family only: absolute file holding the executor exit code "
                        "(default: the receipt path itself in exitcode mode)")
    r.add_argument("--session-id", default=None,
                   help="required with --source claude: the session_id every trusted "
                        "record must carry; checked once per record against this value")
    r.add_argument("--agent-name", default=None,
                   help="actual triggering agent display name; independent of --source "
                        "(defaults: pi -> Pi, claude -> Claude Code, cursor -> Cursor "
                        "Agent, codex -> Codex, dsh -> DSH; --source receipt/exit has no "
                        "default and requires this flag)")
    r.add_argument("--origin-target", default=None,
                   help="current origin: telegram:<chat_id>[:<positive_thread_id>], "
                        "local (this CLI session) or local:<session-id> for the mirror "
                        "channel; missing on a real task blocks routing and acceptance, "
                        "with no fallback")
    r.add_argument("--force", action="store_true")

    t = sub.add_parser("tick", help="incremental scan, create events, then flush outbox")
    t.add_argument("--task", default=None)
    t.add_argument("--max-bytes", type=int,
                   default=int(setting("AGENT_HANDOFF_MAX_BYTES") or 262144))
    t.add_argument("--no-send", action="store_true", help="create events only")
    t.add_argument("--allow-root", action="append", default=[])
    t.add_argument("--force", action="store_true", help="re-evaluate a terminal task")
    t.add_argument("--verbose-send", action="store_true")
    t.add_argument("--url", default=None, help="override $AGENT_HANDOFF_URL for this tick")
    t.add_argument("--secret-file", default=None, help="override $AGENT_HANDOFF_SECRET_FILE")

    s = sub.add_parser("send", help="flush pending outbox events now")
    s.add_argument("--url", required=True)
    s.add_argument("--secret-file", required=True)
    s.add_argument("--event-id", default=None,
                   help="send only this exact event if pending and due; never flush other events")
    s.add_argument("--verify-url", default=None,
                   help="also notify the independent verify subscription "
                        "(http/https loopback only) about open outbox/verify queue docs")

    sv = sub.add_parser("send-verify", help="flush the verify queue only, never the events outbox")
    sv.add_argument("--url", required=True, help="verify subscription receiver URL (loopback only)")
    sv.add_argument("--secret-file", required=True)
    sv.add_argument("--event-id", default=None,
                   help="send only this exact verify queue entry")

    sub.add_parser("ack-pending", help="list pending events (receiver helper)")

    c = sub.add_parser("claim", help="receiver: atomically claim an event_id (dedup)")
    c.add_argument("event_id")
    c.add_argument("--claimer", default="")
    c.add_argument("--lease-seconds", type=int, default=0,
                   help="record an expiry + holder pid so a claim whose holder died "
                        "can be taken over; 0 (default) means the claim is permanent")

    rl = sub.add_parser("release", help="receiver: give up a claim so the event can be retried")
    rl.add_argument("event_id")
    rl.add_argument("--reason", default="")
    rl.add_argument("--claimer", default="")

    df = sub.add_parser("defer", help="receiver: schedule a bounded retry instead of a verdict")
    df.add_argument("event_id")
    df.add_argument("--retry-after", type=int, required=True,
                   help=f"seconds until the retry window opens ({MIN_RETRY_AFTER}..{MAX_RETRY_AFTER})")
    df.add_argument("--reason", default="")
    df.add_argument("--claimer", default="")

    vc = sub.add_parser("verify-claim", help="verifier: atomically claim a verify queue entry")
    vc.add_argument("event_id")
    vc.add_argument("--claimer", default="")
    vc.add_argument("--lease-seconds", type=int, default=300,
                   help="review lease; an expired lease whose holder pid is gone is stealable")

    va = sub.add_parser("verify-ack", help="verifier: record the independent review verdict")
    va.add_argument("event_id")
    va.add_argument("--verdict", required=True, choices=["accepted", "blocked"])
    va.add_argument("--note", default="")
    va.add_argument("--claimer", default="")

    vsh = sub.add_parser("verify-show", help="verifier: read a verify queue doc, creating nothing")
    vsh.add_argument("event_id")

    vo = sub.add_parser("verify-open",
                        help="script channel: open the verify handoff doc of a dispatched "
                             "report_ready event (idempotent)")
    vo.add_argument("event_id")

    vl = sub.add_parser("verify-clear", help="drop unacked verify queue docs (backlog guard)")
    vl.add_argument("--event-id", default=None, help="clear only this queue entry")
    vl.add_argument("--reason", required=True, help="why the backlog is being cleared")

    ar = sub.add_parser("archive", help="move closed, verdicted, quiet tasks out of the live registry")
    ar.add_argument("--older-than-days", type=float, default=14.0,
                    help="age window measured from registered_at; 0 archives eligible tasks today "
                         "(default 14)")
    ar.add_argument("--dry-run", action="store_true", help="report eligibility, change nothing")
    ar.add_argument("--task", action="append", default=None, metavar="TASK_ID",
                    help="archive this task even if it has not aged out (repeatable); the "
                         "terminal-event, live-pid and verdict gates still apply")

    pc = sub.add_parser("prune-claims", help="delete claim markers that guard nothing anymore")
    pc.add_argument("--dry-run", action="store_true", help="report markers, change nothing")

    a = sub.add_parser("ack", help="receiver: record accepted/blocked verdict")
    a.add_argument("event_id")
    a.add_argument("--verdict", required=True, choices=["accepted", "blocked"])
    a.add_argument("--note", default="")
    a.add_argument("--claimer", default="")

    st = sub.add_parser("status", help="readback of tasks/events/acks")
    st.add_argument("--json", action="store_true")

    u = sub.add_parser("unregister")
    u.add_argument("--task-id", required=True)

    c = sub.add_parser("clean", help="remove a synthetic-verification scratch root")
    c.add_argument("--root", required=True, help="scratch root to delete, must be absolute")
    return ap


def cmd_clean(args, root):
    """Delete a scratch root created by synthetic verification.

    This tool never installs Windows cron jobs, so it removes no scheduled tasks;
    the name reflects that scope, and the path guard keeps it out of real state.
    """
    # validate the RAW argument first: realpath() turns a relative path into an
    # absolute one, so an isabs check after normalization could never fire
    raw = args.root or ""
    if not os.path.isabs(raw) or ".." in re.split(r"[\\/]+", raw):
        print("ERROR: clean needs an absolute scratch root path without '..'")
        return 2
    target = os.path.realpath(raw)
    if target == os.path.realpath(default_root()):
        print(f"ERROR: refusing to clean the live default root {target}")
        return 2
    if not os.path.isdir(target):
        print(f"nothing to clean: {target} is not a directory")
        return 0
    try:
        shutil.rmtree(target)
    except OSError as e:
        print(f"ERROR: clean failed: {e}")
        return 1
    print(f"cleaned scratch root: {target}")
    return 0


HANDLERS = {"register": cmd_register, "unregister": cmd_unregister, "tick": cmd_tick,
            "send": cmd_send, "status": cmd_status, "claim": cmd_claim, "ack": cmd_ack,
            "ack-pending": cmd_ack_pending, "clean": cmd_clean,
            "send-verify": cmd_send_verify, "release": cmd_release, "defer": cmd_defer,
            "verify-claim": cmd_verify_claim, "verify-ack": cmd_verify_ack,
            "verify-show": cmd_verify_show, "verify-open": cmd_verify_open,
            "verify-clear": cmd_verify_clear, "archive": cmd_archive,
            "prune-claims": cmd_prune_claims}


def main(argv=None):
    # Renamed settings are NOT mapped (spec 1.1): an old PI_HANDOFF_* name that
    # is set while its AGENT_HANDOFF_* twin resolves unset would otherwise read
    # as "not configured" and silently change behaviour. Fail at startup and
    # name the new key.
    offenders = legacy_env_offenders()
    if offenders:
        for line in legacy_env_errors(offenders):
            print(line, file=sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
    # session paths may legitimately contain non-ASCII; keep stdout ASCII-safe when
    # redirected through a legacy codepage instead of raising UnicodeEncodeError
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):
                reconfigure(errors="backslashreplace")
    root = os.path.realpath(args.root or default_root())
    if args.cmd != "clean":
        # clean must not create the very directory it may refuse to delete
        try:
            _ensure_dir(root)
        except SystemExit as e:
            print(f"ERROR: {e}")
            return 2
    handler = HANDLERS.get(args.cmd)
    if handler is None:
        print(f"ERROR: unknown command {args.cmd!r}")
        return 2
    try:
        return handler(args, root)
    except ValueError as e:
        # validation failures (task_id, paths, URL) exit with a message, not a traceback
        print(f"ERROR: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
