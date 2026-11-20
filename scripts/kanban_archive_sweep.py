"""Kanban stale-task archive sweep.

Runs daily via Hermes Cron (no-agent mode). Archives DONE tasks whose
completed_at is older than ARCHIVE_DAYS. Archived tasks stay queryable
(include_archived) — this never uses --rm and never deletes anything.

Safety rules:
- Only terminal `done` tasks are ever archived (archiving a running task
  would kill its worker — that must never happen here).
- Silent on success (guard-style: log to file, no chat delivery);
  a nonzero exit with a log entry happens only on a real DB error.
- Idempotent: already-archived tasks are not listed by list_tasks, so a
  repeated sweep is a no-op.
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path

hermes_home = os.environ.get("HERMES_HOME")
if not hermes_home:
    raise RuntimeError("HERMES_HOME is required")
sys.path.insert(0, str(Path(hermes_home) / "hermes-agent"))
from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc

ARCHIVE_DAYS = int(os.environ.get("KANBAN_ARCHIVE_DAYS", "10"))
LOG_FILE = Path(hermes_home) / "logs" / "kanban-archive-sweep.log"
BOARD = None  # default board resolution, same as watchdog


def append_log(text: str) -> None:
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(f"[{ts}] {text}\n")
    except Exception:
        pass


def main() -> int:
    cutoff = time.time() - ARCHIVE_DAYS * 86400
    archived = []
    try:
        with kbc.connect_closing() as conn:
            for t in kb.list_tasks(conn):
                if t.status != "done" or not t.completed_at:
                    continue
                if t.completed_at < cutoff:
                    kb.archive_task(conn, t.id)
                    archived.append(f"{t.id} ({t.title[:40]}, done "
                                    f"{(time.time() - t.completed_at) // 86400:.0f}d ago)")
    except Exception as e:  # noqa: BLE001
        append_log(f"ERROR sweep failed: {e!r}")
        return 1
    if archived:
        append_log(f"archived {len(archived)} done tasks older than "
                   f"{ARCHIVE_DAYS} days: " + "; ".join(archived))
        print(f"archived {len(archived)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
