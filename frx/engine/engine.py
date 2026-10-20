"""The analysis pass: seed the queue, then drain it through handlers.

One broken item must not kill the run (spec section 0), so each handler call is
isolated: an exception becomes a finding and the pass continues.

The drain runs `--jobs` item workers in a thread pool (spec section 3/10). Items
are mostly I/O bound (they spend their time in external tools, which release the
GIL during subprocess waits), so threads give real parallelism here. The queue
is the only shared mutable structure the workers race on, and it is lock-guarded;
findings are written through a locked sink. A worker fully finishes an item's
handlers before the item is marked done, so a stop never truncates an item
mid-handler and a resume never skips unfinished work.

Stopping (budget expiry or SIGINT, spec section 10) is checked only before a new
item is dispatched: in-flight items are left to finish (bounded by each tool's
own timeout), nothing new is started, and the caller then finalizes the report.
"""

from __future__ import annotations

from pathlib import Path

from ..report.findings import Finding
from .context import Context
from .dispatch import handlers_for
from .identify import identify


class Engine:
    def __init__(self, ctx: Context):
        self.ctx = ctx

    # -- seeding --------------------------------------------------------
    def seed(self, inputs: list[str], kind_override: str | None = None) -> None:
        for raw in inputs:
            p = Path(raw)
            if not p.exists():
                self.ctx.emit(Finding(
                    severity="info", handler="engine", type="artifact",
                    value=f"input not found: {raw}", item_sha="0" * 64, provenance=[str(raw)],
                ))
                continue
            if p.is_dir():
                for child in sorted(p.rglob("*")):
                    if child.is_file():
                        self._seed_file(child, kind_override)
            else:
                self._seed_file(p, kind_override)

    def _seed_file(self, p: Path, kind_override: str | None) -> None:
        kind = identify(p, override=kind_override)
        item = self.ctx.queue.make_item(p, kind, 0, None, [p.name])
        self.ctx.queue.add(item, extracted=False)

    # -- draining -------------------------------------------------------
    def run(self) -> None:
        jobs = getattr(self.ctx, "jobs", 1) or 1
        if jobs > 1:
            self._run_parallel(jobs)
        else:
            self._run_sequential()
        self._log_stop_reason()

    def _stopped(self) -> bool:
        b = getattr(self.ctx, "budget", None)
        return b is not None and b.should_stop()

    def _run_sequential(self) -> None:
        q = self.ctx.queue
        while not self._stopped():
            item = q.pop()
            if item is None:
                break
            self._process(item)

    def _run_parallel(self, jobs: int) -> None:
        from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

        q = self.ctx.queue
        ex = ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="frx-worker")
        inflight: set = set()
        try:
            while True:
                if self._stopped():
                    break
                # Fill idle workers from whatever the queue holds right now.
                while len(inflight) < jobs:
                    item = q.pop()
                    if item is None:
                        break
                    inflight.add(ex.submit(self._process, item))
                if not inflight:
                    break  # queue empty and nothing running -> the pass is done
                # Wake periodically so children enqueued by running workers get
                # dispatched to idle workers without waiting for their producer.
                done, inflight = wait(inflight, timeout=0.2, return_when=FIRST_COMPLETED)
                for fut in done:
                    exc = fut.exception()
                    if exc is not None:  # _process catches handler errors itself
                        self.ctx.log(f"worker crashed: {type(exc).__name__}: {exc}")
        finally:
            if inflight:
                self.ctx.log(f"stopping: letting {len(inflight)} in-flight item(s) finish")
                wait(inflight)
            ex.shutdown(wait=True)

    def _process(self, item) -> None:
        """Run every handler for one item, isolating failures, then mark done."""
        ui = getattr(self.ctx, "ui", None)
        if ui is not None:
            ui.item_start(item)
        try:
            self.ctx.log(f"item {item.short} kind={item.kind} depth={item.depth}")
            for name, handle in handlers_for(item.kind):
                try:
                    handle(item, self.ctx)
                except Exception as e:  # fail loud per item, keep going
                    self.ctx.emit(Finding(
                        severity="info", handler=name, type="artifact",
                        value=f"handler error: {type(e).__name__}: {e}",
                        item_sha=item.sha256, provenance=item.provenance + [f"{name}:error"],
                    ))
                    self.ctx.log(f"  handler {name} error on {item.short}: {e}")
        finally:
            self.ctx.queue.mark_done(item)
            if ui is not None:
                ui.item_end()

    def _log_stop_reason(self) -> None:
        b = getattr(self.ctx, "budget", None)
        if b is not None and b.stopped:
            reason = {"runtime": "max-runtime budget reached",
                      "signal": "interrupted (SIGINT)"}.get(b.reason, b.reason or "stopped")
            self.ctx.log(f"pass stopped early: {reason}; finalizing report with work so far")
