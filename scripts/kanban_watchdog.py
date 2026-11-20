"""Kanban Task Lightweight Watchdog.

Runs periodically via Hermes Cron (no-agent mode).
Supervises running/blocked/review Kanban tasks:
- Detects hangs/timeouts on running tasks (default 30m without progress).
- Flags blocked tasks requiring human arbitration.
- Alerts on review-ready tasks waiting for acceptance.
- Deduplicates alerts via local state to avoid spamming.
- Silent exit (no stdout) when all tasks are healthy or idle.
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

def hermes_home():
    configured = os.environ.get("HERMES_HOME")
    if not configured:
        raise RuntimeError("HERMES_HOME is required")
    return Path(configured)

HERMES_HOME = hermes_home()
STATE_FILE = HERMES_HOME / "state" / "kanban_watchdog_state.json"
LOG_FILE = HERMES_HOME / "logs" / "kanban-watchdog.log"
DEFAULT_RUNNING_TIMEOUT_SEC = 1800  # 30 minutes


def append_log(lines):
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] Watchdog Alert:\n")
            for line in lines:
                f.write(f"  {line}\n")
    except Exception:
        pass


def get_kanban_tasks():
    cmd = ["hermes", "kanban", "list", "--json"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            shell=True,
            timeout=30,
        )
        return json.loads(proc.stdout)
    except Exception as e:
        return []


def load_state():
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_state(state):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


def check_tasks(tasks=None):
    if tasks is None:
        tasks = get_kanban_tasks()
    if not tasks:
        # No tasks, clear state and stay silent
        save_state({})
        return

    now = int(time.time())
    state = load_state()
    prev_alerts = state.get("alerts", {})
    new_alerts = {}

    warnings = []
    reviews = []
    blockers = []

    for t in tasks:
        task_id = t.get("id")
        title = t.get("title", "")
        assignee = t.get("assignee", "unassigned")
        status = t.get("status", "")
        if assignee == "handoff-tracker":
            continue
        started_at = t.get("started_at")
        max_runtime = t.get("max_runtime_seconds") or DEFAULT_RUNNING_TIMEOUT_SEC
        last_error = t.get("last_failure_error")

        if status == "running":
            if started_at:
                runtime = now - started_at
                if runtime > max_runtime:
                    mins = runtime // 60
                    alert_key = f"{task_id}:running_timeout:{mins // 10}"
                    new_alerts[task_id] = alert_key
                    if alert_key != prev_alerts.get(task_id):
                        warnings.append(
                            f"- **[运行超时/停滞]** 任务 `{task_id}` ({title}) | 负责人: `{assignee}` | 已运行: {mins}分钟 (上限 {max_runtime // 60}m)"
                        )

        elif status == "blocked":
            alert_key = f"{task_id}:blocked:{last_error}"
            new_alerts[task_id] = alert_key
            if alert_key != prev_alerts.get(task_id):
                reason_str = f" | 原因: {last_error}" if last_error else ""
                blockers.append(
                    f"- **[任务阻塞]** 任务 `{task_id}` ({title}) | 负责人: `{assignee}`{reason_str}"
                )

        elif status == "review":
            alert_key = f"{task_id}:review"
            new_alerts[task_id] = alert_key
            if alert_key != prev_alerts.get(task_id):
                reviews.append(
                    f"- **[待验收 Review]** 任务 `{task_id}` ({title}) | 待 Router/协调者验收"
                )

    save_state({"last_check": now, "alerts": new_alerts})

    # Write alerts silently to local log file (no stdout to disturb chats)
    if warnings or blockers or reviews:
        lines = []
        if warnings:
            lines.extend(warnings)
        if blockers:
            lines.extend(blockers)
        if reviews:
            lines.extend(reviews)
        append_log(lines)


if __name__ == "__main__":
    check_tasks()
