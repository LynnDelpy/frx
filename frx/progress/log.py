"""Heartbeat / command log to <case>/run.log.

A plain line-oriented log so a headless or tmux run is followable with
`tail -f`, independent of the rich TTY display (spec section 10). Thread-safe;
every line is timestamped and flushed.
"""

from __future__ import annotations

import datetime as _dt
import threading
from pathlib import Path


class RunLog:
    def __init__(self, case_dir: Path):
        self.path = Path(case_dir) / "run.log"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fh = self.path.open("a", encoding="utf-8")

    def line(self, msg: str) -> None:
        ts = _dt.datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self._fh.write(f"{ts} {msg}\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.close()
