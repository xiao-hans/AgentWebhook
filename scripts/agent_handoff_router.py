#!/usr/bin/env python3
"""agent_handoff_router.py — receiver-side dispatcher for agent handoff events.

STAGED COPY (repo-owned, unit-testable). The live deployment target is
`<hermes-home>/scripts/agent_handoff_router.py` and is NOT touched by this
file; promotion is an explicit, separate step.

Contract (identical to the live router, hardened):
  * one process at a time via <data_root>/router.lock, with stale-lock recovery;
  * a candidate is a delivered event with no verdict whose retry window (if any)
    has opened; nothing is dispatched unless handoff.py `claim` reports
    dispatch=true, so a crashed holder is the only way a second attempt appears;
  * routing decisions come from the registry through handoff.py's claim result,
    never from the webhook body and never guessed here;
  * a permanent contract error is closed with `ack --verdict blocked`; a transient
    delivery failure becomes `defer --retry-after` with a bounded backoff, and the
    exhaustion of that budget escalates to `ack --verdict blocked` so no event can
    stay pending forever.

The module is importable: run_router(...) takes every path and the subprocess seam
as arguments, so tests can drive the whole decision tree with mocks and zero sockets.
"""

import contextlib
import json
import os
import subprocess
import sys
import time

try:  # config file support: stdlib tomllib needs Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - older interpreter
    tomllib = None

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
#
# Spec 2 removed every machine-specific default from this file. Resolution is
# environment variable, then the config file, then a named failure: the router
# never falls back to a directory that only exists on one workstation.
#
# The flat TOML reader below is deliberately self-contained. handoff.py carries
# the same rule, but this router has to resolve AGENT_HANDOFF_SCRIPT before it
# can import anything, so it cannot ask handoff.py where handoff.py is. The
# file name, the key spelling and the env-first order are shared; only the
# lookup order of these three lines is repeated.

CONFIG_ENV_KEY = "AGENT_HANDOFF_CONFIG"
DEFAULT_CONFIG_NAME = "agentwebhook.toml"
LEGACY_ENV_PREFIX = "PI_HANDOFF_"
NEW_ENV_PREFIX = "AGENT_HANDOFF_"

# Hermes is ONE OPTIONAL delivery adapter (spec 2.1): a receiver that runs
# neither channel is still a complete router, and a configured channel falls
# back to blocked with the key it needs. Each channel's own requirement lives
# next to its sender.
HERMES_SCRIPT_KEY = "AGENT_HANDOFF_SCRIPT"
HERMES_DATA_KEY = "AGENT_HANDOFF_DATA_ROOT"
HERMES_BIN_KEY = "AGENT_HANDOFF_HERMES_BIN"
HERMES_PYTHON_KEY = "AGENT_HANDOFF_HERMES_PYTHON"
HERMES_AGENT_DIR_KEY = "AGENT_HANDOFF_HERMES_AGENT_DIR"
# A bare `local` origin needs the registered session; this is the fallback the
# recorder and the router read alike (spec 1.1).
LOCAL_SESSION_KEY = "AGENT_HANDOFF_LOCAL_SESSION"

# Without these two there is no state to read and no recorder to call.
REQUIRED_SETTINGS = (HERMES_DATA_KEY, HERMES_SCRIPT_KEY)

_CONFIG_VALUES = None


def config_path():
    """Config file location: $AGENT_HANDOFF_CONFIG, else next to the repo."""
    explicit = os.environ.get(CONFIG_ENV_KEY)
    if explicit:
        return os.path.realpath(explicit)
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (os.path.join(here, DEFAULT_CONFIG_NAME),
                      os.path.join(os.path.dirname(here), DEFAULT_CONFIG_NAME)):
        if os.path.isfile(candidate):
            return os.path.realpath(candidate)
    return os.path.realpath(os.path.join(os.path.dirname(here), DEFAULT_CONFIG_NAME))


def load_config():
    """Flat TOML keys as strings; absent file or absent tomllib reads as empty."""
    global _CONFIG_VALUES
    if _CONFIG_VALUES is not None:
        return _CONFIG_VALUES
    values = {}
    path = config_path()
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
    _CONFIG_VALUES = values
    return values


def setting(name, environ=None):
    """Environment first, config file second, else None; empty counts as unset."""
    env = os.environ if environ is None else environ
    value = env.get(name)
    if value:
        return value
    value = load_config().get(name)
    return value or None


def legacy_env_offenders(environ=None):
    """Old PI_HANDOFF_* names set while the AGENT_HANDOFF_* twin resolves unset."""
    env = os.environ if environ is None else environ
    offenders = []
    for name in sorted(set(env) | set(load_config())):
        if not name.startswith(LEGACY_ENV_PREFIX):
            continue
        if not (env.get(name) or load_config().get(name)):
            continue
        twin = NEW_ENV_PREFIX + name[len(LEGACY_ENV_PREFIX):]
        if setting(twin, env):
            continue
        offenders.append((name, twin))
    return offenders


def configuration_errors(data_root=None, handoff_py=None):
    """ASCII lines for a router that cannot start: renamed keys and missing keys."""
    lines = []
    for old, new in legacy_env_offenders():
        lines.append(
            f"ERROR: {old} is set but {new} is not. The PI_HANDOFF_* names were "
            f"renamed and are not mapped: set {new}, or the same key in "
            f"{config_path()}."
        )
    resolved = {HERMES_DATA_KEY: data_root, HERMES_SCRIPT_KEY: handoff_py}
    for name in REQUIRED_SETTINGS:
        if resolved[name] or setting(name):
            continue
        lines.append(
            f"ERROR: {name} is not configured. Set the {name} environment "
            f"variable or put {name} in {config_path()}; the dispatcher takes "
            f"no path flags on purpose."
        )
    return lines

CLAIM_LEASE_SECONDS = 120          # > telegram `timeout=45` plus ack/subprocess slack
LOCK_STALE_SECONDS = 300
SEND_TIMEOUT = 45
MIRROR_TIMEOUT = 60
# One claimer string everywhere (claim / defer / ack / the retry-ownership check in
# route_event). Spec §4.5 and AGENT-RECEIPT-ROUTER-PROMPT.txt use this exact value, so
# the prompt and the script can never disagree about who owns a claim.
ROUTER_CLAIMER = "hermes-webhook"

# G4: bounded backoff; index = min(retry_count, 4). Beyond the schedule the budget
# is spent, and `defer` itself refuses (rc 2) -> escalate to a blocked verdict.
RETRY_BACKOFF_SCHEDULE = (60, 120, 240, 480, 600)

# Errors that will never heal on retry: a bad destination is a contract problem,
# not a transient one, so retrying it would only burn the budget silently.
PERMANENT_SEND_MARKERS = (
    "chat not found", "bot was blocked", "unauthorized", "invalid target",
    "unknown platform", "peer_id_invalid", "Forbidden: bot",
)

# argv JSON -> helper snippet -> marker on stdout. Nothing is interpolated into a
# shell command line: the payload travels as one argv element to a python -c script.
MIRROR_SENTINEL = "HANDOFF_MIRROR="
MIRROR_SNIPPET = (
    "import json, sys\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "p = json.loads(sys.argv[2])\n"
    "try:\n"
    "    from gateway.mirror import mirror_to_session\n"
    "except Exception as e:\n"
    "    print('HANDOFF_MIRROR=error:import: ' + repr(e)); sys.exit(3)\n"
    "try:\n"
    "    ok = mirror_to_session(p['channel'], p['session_key'], p['text'],\n"
    "                           source_label='handoff-router', role='user',\n"
    "                           session_id=p['session_id'])\n"
    "except Exception as e:\n"
    "    print('HANDOFF_MIRROR=error: ' + repr(e)); sys.exit(4)\n"
    "print('HANDOFF_MIRROR=' + ('1' if ok else '0'))\n"
)


class FileLock:
    """O_CREAT|O_EXCL lock file holding the owner pid, with stale-lock recovery.

    A lock older than stale_after whose recorded pid is gone is stolen (and the
    theft is logged): without this, one killed run would wedge routing forever.
    """

    def __init__(self, path, stale_after=LOCK_STALE_SECONDS, log=None):
        self.path = path
        self.stale_after = stale_after
        self.log = log if log is not None else (lambda *a: None)
        self.fd = None

    def _holder(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                pid = int((f.read().strip().splitlines() or ["0"])[0])
        except (OSError, ValueError):
            return None
        return pid if pid > 0 else None

    def acquire(self):
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            for _ in range(3):        # brief wait, then a stale-lock decision
                time.sleep(0.2)
                try:
                    age = time.time() - os.path.getmtime(self.path)
                except OSError:
                    return False
                if age < self.stale_after:
                    continue
                holder = self._holder()
                if holder is not None and pid_alive(holder):
                    continue           # alive but quiet: still not ours
                try:
                    os.remove(self.path)
                    self.log(f"stale router lock recovered (age={int(age)}s "
                             f"holder={holder})")
                    fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    break
                except OSError:
                    continue
            else:
                return False
        except OSError:
            return False
        os.write(fd, str(os.getpid()).encode("ascii"))
        self.fd = fd
        return True

    def release(self):
        if self.fd is not None:
            with contextlib.suppress(OSError):
                os.close(self.fd)
            self.fd = None
        with contextlib.suppress(OSError):
            os.remove(self.path)


_HANDOFF_LIB = None
_HANDOFF_LIB_ERROR = None


def _handoff_lib():
    """Import handoff.py as a module so process liveness has ONE rule in this project.

    handoff.py already carries the tested ctypes handling - the handle-returning type,
    the argument types, and the difference between "no such process" and "could not ask"
    - which the router previously duplicated badly enough to call a live peer dead.
    Returns None when the script cannot be loaded, and the caller then assumes alive.
    """
    global _HANDOFF_LIB, _HANDOFF_LIB_ERROR
    if _HANDOFF_LIB is not None:
        return _HANDOFF_LIB
    import importlib.util
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = (setting(HERMES_SCRIPT_KEY),
                  os.path.join(os.path.dirname(here), "handoff.py"))
    for path in candidates:
        if not path or not os.path.isfile(path):
            continue
        try:
            spec = importlib.util.spec_from_file_location("agent_handoff_lib", path)
            loader = getattr(spec, "loader", None)
            if spec is None or loader is None:
                _HANDOFF_LIB_ERROR = f"{path}: no import loader"
                continue
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
        except Exception as e:            # a broken handoff.py must not take the router down
            _HANDOFF_LIB_ERROR = f"{path}: {e}"
            continue
        _HANDOFF_LIB = module
        return module
    return None


def pid_alive(pid):
    """Is this pid still a process we must not steal a lock from?

    Unknown answers are ALIVE: guessing dead would let a second router dispatch the same
    event while the first is still working, which is the one outcome the claim protocol
    exists to prevent.
    """
    module = _handoff_lib()
    if module is None:
        return True
    try:
        alive = module.pid_exists(pid)
    except (OSError, TypeError, ValueError):
        # a probe that cannot answer is not a licence to steal the lock
        return True
    return True if alive is None else bool(alive)

def backoff_seconds(retry_count):
    return RETRY_BACKOFF_SCHEDULE[min(max(int(retry_count or 0), 0),
                                      len(RETRY_BACKOFF_SCHEDULE) - 1)]


def default_run():
    """Real subprocess seam; tests inject their own."""
    def run(argv, timeout=None):
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    return run


def _text(res):
    return ((getattr(res, "stdout", "") or "") + " " +
            (getattr(res, "stderr", "") or "")).strip()


def _out(res):
    return (getattr(res, "stdout", "") or "").strip()


def permanent_send_error(message):
    low = (message or "").lower()
    return next((m for m in PERMANENT_SEND_MARKERS if m.lower() in low), None)


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return default
    return data if isinstance(data, dict) else default


def discover_candidates(events_dir, now, target_event_id=None):
    """Delivered, verdict-free events whose retry window (if any) has opened.

    Returns [(event_id, event_doc)]. Expired *claims* are not filtered here: the
    atomic `claim --lease-seconds` in handoff.py is what decides takeover, so the
    router never has to reason about another process's liveness.
    """
    found = []
    try:
        names = sorted(os.listdir(events_dir))
    except OSError:
        return found
    for name in names:
        if not name.endswith(".json"):
            continue
        eid = name[:-5]
        if target_event_id and eid != target_event_id:
            continue
        ev = read_json(os.path.join(events_dir, name))
        if not ev or ev.get("event_id") != eid:
            continue
        if ev.get("state") != "delivered" or ev.get("verdict"):
            continue
        if (ev.get("retry_state") == "retry_pending"
                and int(ev.get("next_action_at") or 0) > now):
            continue            # window not open yet: leave it to the next pass
        found.append((eid, ev))
    return found


def deliver_telegram(hermes_bin, origin_target, subject, body, run):
    """Send one telegram through Hermes' own CLI. Returns (ok, detail, timed_out, rc).

    timed_out distinguishes a 60s hang from a quick refusal: a timeout can never be
    proof the remote side rejected anything, so the permanent-failure markers must not
    close it out. rc is the CLI's own exit code because Spec I9 grades the outcome by it
    (2 = the command was refused before sending: nothing can arrive, so retrying is
    pointless) while 1 and a timeout stay transient. Hermes' stderr text is not a
    trustworthy classification on its own; a timeout whose text happens to quote a marker
    still defers.
    """
    argv = [hermes_bin, "send", "--to", origin_target, "--subject", subject, body]
    try:
        res = run(argv, timeout=SEND_TIMEOUT + 15)
    except subprocess.TimeoutExpired:
        return False, f"hermes send timed out after {SEND_TIMEOUT}s", True, None
    except OSError as e:
        return False, f"hermes send could not start: {e}", False, None
    rc = int(getattr(res, "returncode", 1))
    if rc == 0:
        return True, _text(res), False, rc
    return False, _text(res) or f"hermes send exit {rc}", False, rc


def resolve_local_session(origin_target, task):
    """(session_id, None) for a local target, or (None, why) when it cannot be resolved.

    `local:<sid>` names the session outright; a bare `local` is the self-notification case
    and must resolve to the registered session (`--session-id` reaches the task as
    session_id) or to AGENT_HANDOFF_LOCAL_SESSION. Returning a reason instead of a guess is
    the point: with no session id there is nothing to mirror into, and handing session_key
    = "local" to Hermes would ask it to invent a destination.
    """
    if ":" in origin_target:
        sid = origin_target.split(":", 1)[1]
        if sid:
            return sid, None
    sid = (task or {}).get("session_id") or setting(LOCAL_SESSION_KEY) or ""
    sid = sid.strip()
    if sid:
        return sid, None
    return None, ("transient: local session_id unresolved - re-register with --session-id "
                  "or export AGENT_HANDOFF_LOCAL_SESSION")


def deliver_local(hermes_python, hermes_agent_dir, origin_target, text, run, task=None):
    """Mirror into a local pi session through Hermes' own gateway helper.

    Returns (ok, detail). Nothing here is permanent: an unresolvable session id is a
    registration gap the next tick can see fixed, and Spec §4.2 classes every local
    mirror failure - including a session Hermes refuses - as transient, so the bounded
    retry decides when it becomes blocked, not this function.
    """
    session_id, why = resolve_local_session(origin_target, task)
    if session_id is None:
        return False, why or "transient: local session_id unresolved"
    payload = {"channel": "local", "session_key": session_id,
               "text": text, "session_id": session_id}
    argv = [hermes_python, "-c", MIRROR_SNIPPET, hermes_agent_dir,
            json.dumps(payload, ensure_ascii=True)]
    try:
        res = run(argv, timeout=MIRROR_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, f"mirror timed out after {MIRROR_TIMEOUT}s"
    except OSError as e:
        return False, f"mirror could not start: {e}"
    out = _out(res)
    marker = next((line[len(MIRROR_SENTINEL):] for line in out.splitlines()
                   if line.startswith(MIRROR_SENTINEL)), None)
    if marker == "1" and int(getattr(res, "returncode", 1)) == 0:
        return True, "mirrored"
    if marker == "0":
        return False, "本地目标会话不存在，镜像被拒"
    return False, (f"mirror error: {marker or _text(res) or 'no marker'}"
                   f" (rc {getattr(res, 'returncode', '?')})")


def _resolve_hermes_python(hermes_python):
    """The mirror interpreter, or None when this receiver runs no Hermes adapter.

    A single configured key replaces the old build-directory scan: a stale glob
    silently fell back to sys.executable, which is not the Hermes toolchain.
    """
    return hermes_python or setting(HERMES_PYTHON_KEY) or None


def _resolve_hermes_bin(hermes_bin):
    """The send CLI, or None when this receiver runs no Hermes adapter."""
    return hermes_bin or setting(HERMES_BIN_KEY) or None


def _resolve_hermes_agent_dir(hermes_agent_dir):
    return hermes_agent_dir or setting(HERMES_AGENT_DIR_KEY) or None


def adapter_gap(hermes_bin, hermes_python, hermes_agent_dir, channel):
    """Names of the Hermes keys a channel needs but this receiver does not have.

    Empty list means the adapter is configured for that channel. Unconfigured is
    a deployment fact, not a delivery error: the event is blocked with the key
    name rather than crashed (spec 2.1).
    """
    if channel == "telegram":
        return [] if hermes_bin else [HERMES_BIN_KEY]
    if channel == "local":
        return [name for name, value in ((HERMES_PYTHON_KEY, hermes_python),
                                        (HERMES_AGENT_DIR_KEY, hermes_agent_dir))
                if not value]
    return []


def run_router(data_root=None, handoff_py=None,
               hermes_bin=None, hermes_python=None, hermes_agent_dir=None,
               target_event_id=None, now=None, run=None, log=None):
    """Route every eligible event once. Returns a summary dict (no exceptions on
    per-event failure: each outcome is recorded, because a raise here would abort
    the other tasks' routing).

    The two paths resolve as argument, then environment, then config file; an
    unresolved one returns `result="misconfigured"` with the key named instead of
    probing a default directory. The Hermes trio stays optional: unconfigured
    channels are blocked per event, and the rest of the routing runs.
    """
    data_root = data_root or setting(HERMES_DATA_KEY)
    handoff_py = handoff_py or setting(HERMES_SCRIPT_KEY)
    say = log or (lambda msg: None)
    errors = configuration_errors(data_root, handoff_py)
    # `not data_root or not handoff_py` cannot happen while errors is empty (the
    # same keys produce both), but spelling it out keeps the types below honest.
    if errors or not data_root or not handoff_py:
        if not errors:
            errors = configuration_errors(data_root, handoff_py)
        for line in errors:
            say(line)
        return {"ok": False, "result": "misconfigured", "errors": errors}
    now = int(time.time() if now is None else now)
    run = run or default_run()
    handoff_base = [sys.executable, handoff_py, "--root", data_root]
    hermes_bin = _resolve_hermes_bin(hermes_bin)
    hermes_python = _resolve_hermes_python(hermes_python)
    hermes_agent_dir = _resolve_hermes_agent_dir(hermes_agent_dir)

    summary = {"ok": True, "now": now, "data_root": data_root, "candidates": 0,
               "dispatched": [], "auto_acked": [], "blocked": [], "deferred": [],
               "skipped": [], "errors": [], "verify_queued": [], "verify_skipped": []}

    lock = FileLock(os.path.join(data_root, "router.lock"), log=say)
    if not lock.acquire():
        summary.update(ok=False, result="lock_busy")
        say("router lock held, exiting")
        return summary
    try:
        events_dir = os.path.join(data_root, "outbox", "events")
        registry = read_json(os.path.join(data_root, "registry.json"), {}) or {}
        tasks = registry.get("tasks") or {}
        for eid, ev in discover_candidates(events_dir, now, target_event_id):
            summary["candidates"] += 1
            rc, out = _handoff(handoff_base + ["claim", eid, "--claimer", ROUTER_CLAIMER,
                                               "--lease-seconds", str(CLAIM_LEASE_SECONDS)],
                               run, say, eid, summary)
            if rc is None:
                continue
            claim_data = out or {}
            task = tasks.get(claim_data.get("task_id") or ev.get("task_id")) or {}
            # Spec §4.5 branch A: `defer` keeps ownership (the claim marker survives),
            # so a due retry_pending event already claimed by THIS router is our own
            # work. Demanding dispatch=true here is what deadlocked retries: the poke
            # lands while our own 120s lease is still valid, `claim` answers
            # already_claimed, and nothing ever delivers again.
            own_retry = (claim_data.get("result") == "already_claimed"
                         and claim_data.get("claimer") == ROUTER_CLAIMER
                         and ev.get("retry_state") == "retry_pending"
                         and not ev.get("verdict")
                         and int(ev.get("next_action_at") or 0) <= now)
            outcome = route_event(eid, ev, claim_data, task, handoff_base, hermes_bin,
                                  hermes_python, hermes_agent_dir, run, say, summary,
                                  own_retry=own_retry)
            say(f"{eid}: {outcome}")
        return summary
    finally:
        lock.release()


def _handoff(argv, run, say, eid, summary):
    """Run a handoff.py subcommand, returning (rc, json-or-None). A crash or an
    unparsable reply is recorded and skipped: we never guess a verdict."""
    try:
        res = run(argv, timeout=30)
    except (subprocess.TimeoutExpired, OSError) as e:
        summary["errors"].append({"event_id": eid, "where": argv[3] if len(argv) > 3 else "?",
                                  "error": str(e)})
        say(f"{eid}: handoff.py call failed: {e}")
        return None, None
    rc = int(getattr(res, "returncode", 1))
    try:
        return rc, json.loads(_out(res))
    except ValueError:
        summary["errors"].append({"event_id": eid, "where": "handoff-json",
                                  "error": _text(res)[:200]})
        return None, None


def _ack(handoff_base, eid, verdict, note, run, say, summary):
    _handoff(handoff_base + ["ack", eid, "--verdict", verdict, "--note", note,
                             "--claimer", ROUTER_CLAIMER], run, say, eid, summary)


def open_verify_queue(handoff_base, eid, run, say, summary):
    """Hand a delivered report_ready event to the independent verifier (Spec §1.5).

    The queue doc belongs to the notification side, not to event creation: it is opened
    only here, only after a dispatch this router was granted, and only once the origin
    actually received the report. handoff.py re-checks status/route/claim, so a refusal is
    a recorded note rather than a second verdict - the notify ack is already written."""
    rc, out = _handoff(handoff_base + ["verify-open", eid], run, say, eid, summary)
    if rc is None:
        return
    if rc != 0:
        summary["verify_skipped"].append(
            {"event_id": eid, "result": (out or {}).get("result", f"rc {rc}"), "rc": rc})
        return
    summary["verify_queued"].append(eid)


def route_event(eid, ev, claim_data, task, handoff_base, hermes_bin, hermes_python,
                hermes_agent_dir, run, say, summary, own_retry=False):
    """Decide and perform one dispatch for a claimed event. Returns a label.

    `own_retry=True` is the router telling itself it already owns this event (see
    run_router): the delivery proceeds without a fresh dispatch grant.
    """
    if claim_data.get("dispatch") is not True and not own_retry:
        summary["skipped"].append({"event_id": eid, "reason": "not_claimed"})
        return "skipped (claim not granted)"

    if claim_data.get("synthetic"):
        _ack(handoff_base, eid, "accepted", "synthetic event auto-acked",
             run, say, summary)
        summary["auto_acked"].append(eid)
        return "auto-acked (synthetic)"

    routing = claim_data.get("routing") or {}
    channel = routing.get("channel")
    origin_target = routing.get("origin_target")
    if routing.get("route_state") != "ready" or not routing.get("notify_origin"):
        # contract error: no destination metadata -> retries cannot fix it
        note = "未配置来源路由或非真实通知事件: " + (routing.get("reason") or
                                                 f"route_state={routing.get('route_state')}")
        _ack(handoff_base, eid, "blocked", note, run, say, summary)
        summary["blocked"].append({"event_id": eid, "reason": note})
        return "blocked (routing contract)"
    if channel not in ("telegram", "local") or not origin_target:
        note = f"unsupported routing channel: {channel!r}"
        _ack(handoff_base, eid, "blocked", note, run, say, summary)
        summary["blocked"].append({"event_id": eid, "reason": note})
        return "blocked (channel)"

    # Hermes is one OPTIONAL sender (spec 2.1): a receiver that never configured
    # it still routes, and the event lands blocked naming the key to set rather
    # than crashing on a path that does not exist here.
    gap = adapter_gap(hermes_bin, hermes_python, hermes_agent_dir, channel)
    if gap:
        note = ("Hermes 适配器未配置: 请设置 " + " / ".join(gap) +
                f" (环境变量或 {config_path()}), 通道={channel}")
        _ack(handoff_base, eid, "blocked", note, run, say, summary)
        summary["blocked"].append({"event_id": eid, "reason": note,
                                   "missing": gap})
        return "blocked (adapter unconfigured)"

    agent_name = routing.get("agent_name") or "Agent"
    task_id = claim_data.get("task_id") or ev.get("task_id") or "?"
    subject = f"[{agent_name} 进程退出回执] {task_id}"
    goal = task.get("goal") or "无描述"
    body = (f"{agent_name} 进程已执行结束（待 Hermes 独立验收产物）。\n"
            f"目标：{goal}\n事件ID：{eid}")

    if channel == "telegram":
        ok, detail, timed_out, rc = deliver_telegram(hermes_bin, origin_target, subject,
                                                    body, run)
        if ok:
            _ack(handoff_base, eid, "accepted", f"已即时投递到 {origin_target}",
                 run, say, summary)
            summary["dispatched"].append({"event_id": eid, "channel": channel,
                                          "target": origin_target})
            open_verify_queue(handoff_base, eid, run, say, summary)
            return "delivered via telegram"
        if rc == 2:
            # Spec I9: exit 2 means the CLI refused the command itself, so no retry can
            # make it arrive. Graded before the stderr markers, which are only as
            # trustworthy as the text Hermes happened to print.
            note = f"hermes send 参数被拒(exit 2): {detail[:200]}"
            _ack(handoff_base, eid, "blocked", note, run, say, summary)
            summary["blocked"].append({"event_id": eid, "reason": note})
            return "blocked (hermes send usage)"
        marker = permanent_send_error(detail)
        if marker and not timed_out:
            _ack(handoff_base, eid, "blocked",
                 f"hermes send 永久失败({marker}): {detail[:200]}", run, say, summary)
            summary["blocked"].append({"event_id": eid, "reason": detail[:200]})
            return "blocked (permanent send error)"
        return _defer(handoff_base, eid, ev, f"hermes send 投递失败: {detail[:200]}",
                      run, say, summary)

    ok, detail = deliver_local(hermes_python, hermes_agent_dir, origin_target,
                               f"{subject}\n{body}", run, task)
    if ok:
        _ack(handoff_base, eid, "accepted", f"已镜像写入本地会话 {origin_target}",
             run, say, summary)
        summary["dispatched"].append({"event_id": eid, "channel": channel,
                                      "target": origin_target})
        open_verify_queue(handoff_base, eid, run, say, summary)
        return "delivered via local mirror"
    return _defer(handoff_base, eid, ev, f"本地镜像投递失败: {detail[:200]}",
                  run, say, summary)


def _defer(handoff_base, eid, ev, reason, run, say, summary):
    """Transient failure -> bounded retry. `defer` refuses past max_retries (rc 2),
    which is the escalation point: close it as blocked instead of leaving it
    pending forever."""
    delay = backoff_seconds(ev.get("retry_count", 0))
    rc, out = _handoff(handoff_base + ["defer", eid, "--retry-after", str(delay),
                                       "--reason", reason, "--claimer", ROUTER_CLAIMER],
                       run, say, eid, summary)
    if rc is None:
        return "defer call failed"
    if rc == 2:
        note = f"投递重试耗尽: {reason[:200]}"
        if out and out.get("result") != "retry_exhausted":
            note = f"{reason[:200]} (已判定/不可重试)"
        _ack(handoff_base, eid, "blocked", note, run, say, summary)
        summary["blocked"].append({"event_id": eid, "reason": note,
                                  "escalated": True})
        return "escalated to blocked"
    if rc == 0:
        summary["deferred"].append({"event_id": eid, "retry_after": delay,
                                    "retry_count": (out or {}).get("retry_count")})
        return f"deferred {delay}s"
    summary["errors"].append({"event_id": eid, "where": "defer", "rc": rc,
                              "detail": reason[:200]})
    return f"defer refused (rc {rc})"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    target = argv[0] if argv else None
    summary = run_router(target_event_id=target,
                         log=lambda msg: print(msg, file=sys.stderr))
    print(json.dumps(summary, ensure_ascii=True))
    # Spec V4: a router already holding the lock is the designed answer to an overlap, not
    # a failure. Returning non-zero there would make the cron wrapper report a broken
    # integration every time two passes meet.
    if summary.get("result") == "lock_busy":
        return 0
    return 0 if summary.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
