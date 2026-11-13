#!/usr/bin/env bash
# AgentWebhook cron tick.
#
# Every setting resolves in the documented order: environment variable, then the
# config file ($AGENT_HANDOFF_CONFIG, else agentwebhook.toml next to handoff.py),
# then a non-zero exit naming the missing key. Nothing in this file knows about a
# particular machine: no user directory, no install path, no receiver port.
#
# The routes themselves (/webhooks/agent-task-handoff and
# /webhooks/agent-task-handoff-verify, for event type agent_task_handoff) are
# configured on the receiving gateway; the URLs below are read from your config,
# never guessed here.
set -u

# The template lives in scripts/, so the recorder is the sibling file. That is a
# layout fact about this repository, not a machine path.
# A native Windows interpreter cannot open the /d/... spelling Git Bash uses, so
# the directory is converted when that shell is in play and left alone elsewhere.
native_dir() {
    local dir=$1 windows=""
    windows="$(cd "$dir" && pwd -W 2>/dev/null)" || windows=""
    if [ -n "$windows" ]; then printf '%s' "$windows"; else (cd "$dir" && pwd); fi
}

SCRIPT_DIR="$(native_dir "$(dirname "${BASH_SOURCE[0]}")")"
HANDOFF_PY="${AGENT_HANDOFF_SCRIPT:-$SCRIPT_DIR/../handoff.py}"
PYTHON_BIN="${PYTHON_BIN:-python}"

if [ ! -f "$HANDOFF_PY" ]; then
    echo "ERROR: handoff.py not found at $HANDOFF_PY; set AGENT_HANDOFF_SCRIPT." >&2
    exit 2
fi

# One loader, one rule: ask handoff.py which settings a cron send needs. This is
# the only place the env -> config-file -> fail order is implemented (spec 2.1).
"$PYTHON_BIN" - "$HANDOFF_PY" <<'PY' || exit 2
import importlib.util
import sys

script = sys.argv[1]
spec = importlib.util.spec_from_file_location("agent_handoff_lib", script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
lines = module.require_settings(
    ("AGENT_HANDOFF_URL", "AGENT_HANDOFF_VERIFY_URL", "AGENT_HANDOFF_SECRET_FILE"),
    "the cron tick",
)
if lines:
    for line in lines:
        print(line, file=sys.stderr)
    raise SystemExit(1)
PY

# Fail fast on a renamed variable left behind, then record and send. handoff.py
# checks the PI_HANDOFF_* names itself, so a stale deployment reports the new key
# instead of silently skipping the send.
"$PYTHON_BIN" "$HANDOFF_PY" tick "$@"
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "ERROR: handoff.py tick failed (exit $rc)" >&2
fi
exit "$rc"
