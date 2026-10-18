"""The deduplicating work queue with depth/file/size caps (spec section 4, 12).

The engine is a queue, not a script: pop an item, identify it, dispatch to
handlers, which may push extracted children back with depth+1. Dedup is by
sha256 so re-extracted identical blobs are processed once. Caps are enforced at
enqueue time as the zip-bomb / carve-recursion / binwalk-loop guard: an item
rejected by a cap is counted and dropped, never processed.
"""

from __future__ import annotations

import collections
import dataclasses
import hashlib
from pathlib import Path


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
        return True

    def pop(self) -> Item | None:
        if not self._q:
            return None
        item = self._q.popleft()
        self.done_count += 1
        return item

    def __len__(self) -> int:
        return len(self._q)

    @property
    def pending(self) -> int:
        return len(self._q)

    def seen(self, sha: str) -> bool:
        return sha in self._seen
