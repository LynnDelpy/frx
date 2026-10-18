"""Finding dataclass and append-only JSONL writer.

Every nontrivial action emits a Finding. The writer flushes per finding so an
interrupted run (SIGINT, budget hit, crash) never loses collected work.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import threading
from pathlib import Path
from typing import TextIO

SEVERITIES = ("flag", "high", "info")


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclasses.dataclass
class Finding:
    """One observation, with the provenance chain that produced it.

    provenance is the human-readable trail from the original input to this
    finding, e.g. ["input.pcap", "http-object-3", "base64", "CTF{...}"].
    command is the exact argv (joined) that produced it, for reproducibility.
    """

    severity: str
    handler: str
    type: str
    value: str
    item_sha: str
    provenance: list[str] = dataclasses.field(default_factory=list)
    flag: bool = False
    confidence: float = 0.0
    offset: int | None = None
    command: str | None = None
    ts: str = dataclasses.field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity!r}")

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        # Keep JSON lines compact and stable; drop null optionals.
        if d["offset"] is None:
            del d["offset"]
        if d["command"] is None:
            del d["command"]
        return d


class FindingWriter:
    """Append-only JSONL sink, flushed per write, thread-safe.

    Confirmed flags are mirrored to FLAGS.txt immediately. Callers may register
    a listener (e.g. the live UI) to receive each Finding as it lands.
    """

    def __init__(self, case_dir: Path):
        self.case_dir = Path(case_dir)
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self._jsonl_path = self.case_dir / "findings.jsonl"
        self._flags_path = self.case_dir / "FLAGS.txt"
        self._lock = threading.Lock()
        self._jsonl: TextIO = self._jsonl_path.open("a", encoding="utf-8")
        self._listeners: list = []
        self._seen_flags: set[str] = set()

    def add_listener(self, fn) -> None:
        self._listeners.append(fn)

    def emit(self, finding: Finding) -> None:
        line = json.dumps(finding.to_dict(), ensure_ascii=False)
        with self._lock:
            self._jsonl.write(line + "\n")
            self._jsonl.flush()
            if finding.flag and finding.value not in self._seen_flags:
                self._seen_flags.add(finding.value)
                with self._flags_path.open("a", encoding="utf-8") as fh:
                    prov = " -> ".join(finding.provenance)
                    fh.write(f"{finding.value}\t{prov}\n")
                    fh.flush()
        for fn in self._listeners:
            try:
                fn(finding)
            except Exception:
                pass

    def close(self) -> None:
        with self._lock:
            if not self._jsonl.closed:
                self._jsonl.close()

    def __enter__(self) -> "FindingWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
