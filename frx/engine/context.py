"""Shared context passed to every handler.

Bundles the services a handler needs (runner, finding sink, queue, flag engine,
case paths) so handlers stay small and take one argument. Handlers emit findings
through `emit_*` helpers and push extracted children through `enqueue_file`,
which namespaces output under extracted/<parent-sha>/ and applies the caps.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any, Callable, Optional

from ..flags.formats import FlagFormat
from ..flags.needles import Needle
from ..report.findings import Finding, FindingWriter
from .queue import Item, WorkQueue
from .runner import Runner


@dataclasses.dataclass
class Context:
    runner: Runner
    findings: FindingWriter
    queue: WorkQueue
    formats: list[FlagFormat]
    needles: list[Needle]
    case_dir: Path
    mode: str = "full"  # "recon" or "full"
    wordlist: Optional[str] = None
    vol_symbols: Optional[str] = None
    build_isf: Optional[str] = None
    system_map: Optional[str] = None
    vol_plugin_timeout: float = 300.0
    max_inmem: int = 64 * 1024**2  # scan raw bytes directly below this size
    decoder: Any = None  # set by the engine once the decode engine exists
    logfn: Optional[Callable[[str], None]] = None
    jobs: int = 1  # parallel item workers; >1 drains the queue in a thread pool
    budget: Any = None  # engine.budget.Budget: runtime cap + SIGINT graceful stop
    ui: Any = None  # progress.ui.ProgressUI when attached to a TTY, else None
    enforce_offline: bool = True  # whether the pass runs inside the unshare -rn sandbox
    mount: bool = False  # allow a read-only loop mount as a last resort (needs --no-sandbox)

    @property
    def extracted_dir(self) -> Path:
        d = self.case_dir / "extracted"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def log(self, msg: str) -> None:
        if self.logfn:
            self.logfn(msg)

    def emit(self, finding: Finding) -> None:
        self.findings.emit(finding)

    def emit_flag(self, item: Item, value: str, provenance: list[str], command: str | None = None, offset: int | None = None) -> None:
        self.emit(Finding(
            severity="flag", handler="", type="flag", value=value, item_sha=item.sha256,
            flag=True, confidence=1.0, provenance=provenance, command=command, offset=offset,
        ))

    def child_dir(self, parent: Item) -> Path:
        d = self.extracted_dir / parent.sha256
        d.mkdir(parents=True, exist_ok=True)
        return d

    def enqueue_file(self, path, parent: Item, label: str, kind: str = "other") -> bool:
        """Register an extracted child file: dedup + caps + provenance."""
        from .identify import identify

        p = Path(path)
        if not p.is_file():
            return False
        detected = identify(p) if kind == "other" else kind
        child = self.queue.make_item(
            p, detected, parent.depth + 1, parent.sha256, parent.provenance + [label]
        )
        added = self.queue.add(child, extracted=True)
        if added:
            self.emit(Finding(
                severity="info", handler="engine", type="extracted_file",
                value=str(p.relative_to(self.case_dir)) if self.case_dir in p.parents else str(p),
                item_sha=child.sha256, provenance=child.provenance,
            ))
        return added
