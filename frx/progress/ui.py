"""Live terminal display for a long pass (spec section 10).

A `rich.live.Live` is driven by its own refresh thread at ~4 Hz. That thread
renders this object via the `__rich__` protocol, reading a snapshot of the state
under a lock; the worker threads only ever *write* that state (which item they
picked up, which tool is running, each finding as it lands). No worker thread
touches `Live`, so there is no cross-thread rendering to coordinate.

The whole display is optional: off a TTY (`--no-progress`, a pipe, a headless or
cron run) the caller simply never constructs a `ProgressUI`, and the run.log
heartbeat carries progress instead. The engine and runner guard every call, so a
`None` UI costs nothing.

Per-worker rows are keyed by thread identity, so neither the engine nor the
runner has to thread a worker id through every call: whichever thread is running
a tool is the row that updates.
"""

from __future__ import annotations

import threading
import time
from typing import Optional


def _fmt(seconds: Optional[float]) -> str:
    if seconds is None:
        return "-"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"


class ProgressUI:
    def __init__(self, mode: str, budget=None, queue=None, console=None):
        self.mode = mode
        self.budget = budget
        self.queue = queue
        self._console = console
        self._lock = threading.Lock()
        self.phase = "starting"
        self._rows: dict[int, dict] = {}   # thread ident -> worker row
        self._slot_seq = 0
        self._flags: list[tuple[str, list]] = []
        self._counts = {"flag": 0, "high": 0, "info": 0}
        self._live = None

    # -- wiring ----------------------------------------------------------
    def set_live(self, live) -> None:
        self._live = live
        if live is not None and self._console is None:
            self._console = live.console

    def set_phase(self, phase: str) -> None:
        with self._lock:
            self.phase = phase

    def _row(self) -> dict:
        tid = threading.get_ident()
        r = self._rows.get(tid)
        if r is None:
            r = {"slot": self._slot_seq, "item": None, "kind": None, "tool": None, "t0": None}
            self._slot_seq += 1
            self._rows[tid] = r
        return r

    # -- engine hooks ----------------------------------------------------
    def item_start(self, item) -> None:
        with self._lock:
            r = self._row()
            r["item"], r["kind"], r["tool"], r["t0"] = item.short, item.kind, None, None

    def item_end(self) -> None:
        with self._lock:
            r = self._row()
            r["item"], r["kind"], r["tool"], r["t0"] = None, None, None, None

    # -- runner observer hooks ------------------------------------------
    def tool_start(self, argv) -> None:
        with self._lock:
            r = self._row()
            r["tool"] = argv[0] if argv else "?"
            r["t0"] = time.monotonic()

    def tool_end(self, argv) -> None:
        with self._lock:
            r = self._row()
            r["tool"], r["t0"] = None, None

    # -- findings listener ----------------------------------------------
    def on_finding(self, f) -> None:
        with self._lock:
            sev = getattr(f, "severity", "info")
            if sev in self._counts:
                self._counts[sev] += 1
            if getattr(f, "flag", False):
                self._flags.append((f.value, list(getattr(f, "provenance", []))))

    def print_flag(self, value: str) -> None:
        """Surface a confirmed flag above the live region the instant it lands."""
        if self._console is not None:
            try:
                self._console.print(f"[bold green][FLAG][/] {value}")
                return
            except Exception:
                pass
        print(f"[FLAG] {value}")

    # -- rendering -------------------------------------------------------
    def __rich__(self):
        return self._render()

    def _render(self):
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        with self._lock:
            el = self.budget.elapsed() if self.budget else None
            rem = self.budget.remaining() if self.budget else None

            head = Text()
            head.append(f"mode={self.mode}  ", style="bold cyan")
            head.append(f"phase={self.phase}  elapsed={_fmt(el)}")
            if rem is not None:
                head.append(f"  remaining={_fmt(rem)}")

            if self.queue is not None:
                q = self.queue
                qline = Text(
                    f"queue  pending={q.pending}  done={q.done_count}  "
                    f"extracted={q.extracted_count} ({q.extracted_bytes // 1024} KiB)"
                )
            else:
                qline = Text("queue  -")

            workers = Table.grid(padding=(0, 2))
            for _ in range(4):
                workers.add_column()
            now = time.monotonic()
            for r in sorted(self._rows.values(), key=lambda x: x["slot"]):
                slot = f"[dim]w{r['slot']}[/]"
                if r["item"] is None:
                    workers.add_row(slot, "[dim]idle[/]", "", "")
                else:
                    tool = r["tool"] or "-"
                    tdur = _fmt(now - r["t0"]) if r["t0"] else ""
                    workers.add_row(slot, r["item"], r["kind"] or "", f"{tool} {tdur}".strip())

            counts = Text(
                f"findings  flag={self._counts['flag']}  "
                f"high={self._counts['high']}  info={self._counts['info']}",
                style="yellow",
            )

            if self._flags:
                ftxt = Text()
                for v, _prov in self._flags[-10:]:
                    ftxt.append(v + "\n", style="bold green")
                flags_panel = Panel(ftxt, title="FLAGS", border_style="green")
            else:
                flags_panel = Panel(Text("(none yet)", style="dim"), title="FLAGS", border_style="green")

            body = Panel(Group(head, qline, Text(""), workers, Text(""), counts),
                         title="frx", border_style="cyan")
        return Group(flags_panel, body)
