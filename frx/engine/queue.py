"""The deduplicating work queue with depth/file/size caps (spec section 4, 12).

The engine is a queue, not a script: pop an item, identify it, dispatch to
handlers, which may push extracted children back with depth+1. Dedup is by
sha256 so re-extracted identical blobs are processed once. Caps are enforced at
enqueue time as the zip-bomb / carve-recursion / binwalk-loop guard: an item
rejected by a cap is counted and dropped, never processed.

Two milestone-7 additions, both inert unless opted into:
- a lock makes add/pop/mark_done safe to call from the parallel item workers;
- an optional `state_path` journals every enqueue and completion so a run killed
  by SIGINT or the runtime budget can be resumed (`--resume`) without redoing
  finished items. With no `state_path` the queue behaves exactly as before.
"""

from __future__ import annotations

import collections
import dataclasses
import hashlib
import json
import threading
from pathlib import Path
from typing import Optional, TextIO


@dataclasses.dataclass
class Item:
    sha256: str
    path: Path
    kind: str
    depth: int
    parent_sha: str | None
    provenance: list[str]
    size: int

    @property
    def short(self) -> str:
        return self.sha256[:12]


def sha256_file(path: Path, _bufsize: int = 1 << 20) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as fh:
        while chunk := fh.read(_bufsize):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


@dataclasses.dataclass
class RejectCounts:
    depth: int = 0
    files: int = 0
    size: int = 0
    duplicate: int = 0


class WorkQueue:
    def __init__(
        self,
        max_depth: int = 6,
        max_files: int = 50000,
        max_extracted_size: int = 4 * 1024**3,
        state_path: Optional[Path] = None,
    ):
        self.max_depth = max_depth
        self.max_files = max_files
        self.max_extracted_size = max_extracted_size
        self._q: collections.deque[Item] = collections.deque()
        self._seen: set[str] = set()
        self.extracted_count = 0
        self.extracted_bytes = 0
        self.done_count = 0
        self.rejects = RejectCounts()
        self._lock = threading.RLock()
        self._state_path = Path(state_path) if state_path else None
        self._state_fh: Optional[TextIO] = None
        if self._state_path is not None:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_fh = self._state_path.open("a", encoding="utf-8")

    # -- building items -------------------------------------------------
    def make_item(
        self,
        path,
        kind: str,
        depth: int,
        parent_sha: str | None,
        provenance: list[str],
    ) -> Item:
        sha, size = sha256_file(Path(path))
        return Item(sha, Path(path), kind, depth, parent_sha, list(provenance), size)

    # -- enqueue --------------------------------------------------------
    def add(self, item: Item, extracted: bool = False) -> bool:
        """Enqueue an item unless a cap or dedup rejects it.

        `extracted=True` means a child produced during the run; such items count
        against the file/size caps and the depth cap. Original inputs
        (extracted=False) bypass the file/size caps but still dedup.
        """
        with self._lock:
            if item.sha256 in self._seen:
                self.rejects.duplicate += 1
                return False
            if extracted:
                if item.depth > self.max_depth:
                    self.rejects.depth += 1
                    return False
                if self.extracted_count >= self.max_files:
                    self.rejects.files += 1
                    return False
                if self.extracted_bytes + item.size > self.max_extracted_size:
                    self.rejects.size += 1
                    return False
                self.extracted_count += 1
                self.extracted_bytes += item.size
            self._seen.add(item.sha256)
            self._q.append(item)
            self._journal_add(item, extracted)
            return True

    def pop(self) -> Item | None:
        with self._lock:
            if not self._q:
                return None
            item = self._q.popleft()
            self.done_count += 1
            return item

    def mark_done(self, item: Item) -> None:
        """Record that an item's handlers finished, so --resume can skip it.

        Called by the engine after dispatch, not on pop: an item popped but
        interrupted mid-handler is left un-done, so a resume reprocesses it
        rather than silently losing its (possibly unfinished) work.
        """
        with self._lock:
            self._journal_done(item)

    def __len__(self) -> int:
        return len(self._q)

    @property
    def pending(self) -> int:
        return len(self._q)

    def seen(self, sha: str) -> bool:
        return sha in self._seen

    def close(self) -> None:
        with self._lock:
            if self._state_fh is not None and not self._state_fh.closed:
                self._state_fh.close()

    # -- state journal (resume) -----------------------------------------
    def _journal_add(self, item: Item, extracted: bool) -> None:
        if self._state_fh is None:
            return
        # Store an absolute path: a resume may run from a different working
        # directory, where the original relative path would not resolve and the
        # pending item would be silently dropped.
        try:
            abs_path = str(Path(item.path).resolve())
        except OSError:
            abs_path = str(item.path)
        rec = {
            "op": "a", "sha": item.sha256, "path": abs_path, "kind": item.kind,
            "depth": item.depth, "parent": item.parent_sha, "prov": item.provenance,
            "size": item.size, "ext": bool(extracted),
        }
        self._state_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self._state_fh.flush()

    def _journal_done(self, item: Item) -> None:
        if self._state_fh is None:
            return
        self._state_fh.write(json.dumps({"op": "d", "sha": item.sha256}) + "\n")
        self._state_fh.flush()


def resume_queue(
    state_path: Path,
    max_depth: int = 6,
    max_files: int = 50000,
    max_extracted_size: int = 4 * 1024**3,
) -> WorkQueue:
    """Rebuild a queue from a prior run's state journal.

    The dedupe set is every sha ever added (so nothing is re-extracted and
    reprocessed). Pending items are those added but not marked done, replayed in
    their original order. The cap counters are restored from the recorded sizes
    so the resumed run keeps honoring the same zip-bomb / file-count limits.
    Items whose file is gone (e.g. a case dir partially cleaned) are skipped.
    """
    state_path = Path(state_path)
    added: dict[str, dict] = {}
    order: list[str] = []
    done: set[str] = set()
    if state_path.is_file():
        for line in state_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("op") == "a" and "sha" in rec:
                if rec["sha"] not in added:
                    order.append(rec["sha"])
                added[rec["sha"]] = rec
            elif rec.get("op") == "d" and "sha" in rec:
                done.add(rec["sha"])

    q = WorkQueue(max_depth, max_files, max_extracted_size, state_path=state_path)
    with q._lock:
        q._seen = set(added.keys())
        for sha in order:
            rec = added[sha]
            if rec.get("ext"):
                q.extracted_count += 1
                q.extracted_bytes += int(rec.get("size", 0))
            if sha in done:
                q.done_count += 1
                continue
            path = Path(rec.get("path", ""))
            if not path.is_file():
                # the file no longer exists; treat as done so we don't stall.
                q.done_count += 1
                continue
            q._q.append(Item(
                sha256=sha, path=path, kind=rec.get("kind", "other"),
                depth=int(rec.get("depth", 0)), parent_sha=rec.get("parent"),
                provenance=list(rec.get("prov", [])), size=int(rec.get("size", 0)),
            ))
    return q
