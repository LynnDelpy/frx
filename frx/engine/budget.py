"""Global runtime budget and graceful stop (spec section 10).

A long pass must never lose collected work. Two things can end it early: the
`--max-runtime` soft budget expiring, or the user pressing Ctrl-C. Both set the
same stop flag, which the engine checks before dispatching each item. In-flight
tool calls are left to finish (or hit their own per-tool timeout); nothing new is
started. The caller then finalizes findings.jsonl and renders report.md as usual,
so the report always reflects everything found up to the stop.

A second Ctrl-C escalates to a hard abort (KeyboardInterrupt) for a run wedged in
a tool that ignores its timeout. The signal handler only runs in the main thread,
which is where the engine's dispatch loop lives, so the flag is seen promptly.
"""

from __future__ import annotations

import signal
import threading
import time
from typing import Optional


class Budget:
    """Tracks elapsed time against an optional deadline and a stop flag.

    `max_runtime` is in seconds; None means no time limit (stop only on signal).
    Time is measured with a monotonic clock so a wall-clock change never skews
    the budget. The class is the single source of truth for "should the pass keep
    going?" -- the engine asks `should_stop()`, never reads the clock itself.
    """

    def __init__(self, max_runtime: Optional[float] = None):
        self.max_runtime = max_runtime if (max_runtime and max_runtime > 0) else None
        self._start = time.monotonic()
        self._stop = threading.Event()
        self.reason: Optional[str] = None  # "runtime" | "signal" | None
        self._prev_handler = None
        self._installed = False

    # -- time ------------------------------------------------------------
    def elapsed(self) -> float:
        return time.monotonic() - self._start

    def remaining(self) -> Optional[float]:
        if self.max_runtime is None:
            return None
        return max(0.0, self.max_runtime - self.elapsed())

    # -- stop state ------------------------------------------------------
    def should_stop(self) -> bool:
        if self._stop.is_set():
            return True
        if self.max_runtime is not None and self.elapsed() >= self.max_runtime:
            if self.reason is None:
                self.reason = "runtime"
            self._stop.set()
            return True
        return False

    def stop(self, reason: str = "manual") -> None:
        if self.reason is None:
            self.reason = reason
        self._stop.set()

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    # -- SIGINT handling -------------------------------------------------
    def install_sigint(self, on_first=None) -> None:
        """Make the first Ctrl-C a graceful stop and the second a hard abort.

        Only installs in the main thread (Python forbids signal handlers in
        others); a no-op elsewhere so programmatic/threaded callers are safe.
        """
        if threading.current_thread() is not threading.main_thread():
            return

        def handler(signum, frame):
            if self._stop.is_set():
                # Second interrupt: restore default and let it propagate hard.
                signal.signal(signal.SIGINT, self._prev_handler or signal.SIG_DFL)
                raise KeyboardInterrupt
            self.stop("signal")
            if on_first is not None:
                try:
                    on_first()
                except Exception:
                    pass

        try:
            self._prev_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, handler)
            self._installed = True
        except (ValueError, OSError):
            # e.g. not in the main thread of an embedded interpreter.
            self._installed = False

    def restore_sigint(self) -> None:
        if self._installed:
            try:
                signal.signal(signal.SIGINT, self._prev_handler or signal.SIG_DFL)
            except (ValueError, OSError):
                pass
            self._installed = False
