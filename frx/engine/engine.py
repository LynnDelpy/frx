"""The analysis pass: seed the queue, then drain it through handlers.

One broken item must not kill the run (spec section 0), so each handler call is
isolated: an exception becomes an `error` finding and the pass continues. The
loop is sequential here; parallel item workers and the budget/SIGINT finalize
path are layered on in a later milestone without changing this contract.
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

    def run(self) -> None:
        q = self.ctx.queue
        while (item := q.pop()) is not None:
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
