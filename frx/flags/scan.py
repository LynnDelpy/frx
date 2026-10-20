"""Scan a byte buffer for flag matches and for encoded-prefix needle hits.

These are pure functions over bytes so they work uniformly on raw file content,
on `strings` output, and on decoder windows. Large-file scanning is driven by
the binary handler (piping `strings` into ripgrep); this module is the matcher
those paths feed into, and the fallback for in-memory buffers.
"""

from __future__ import annotations

import dataclasses

from .formats import FlagFormat
from .needles import Needle

WINDOW = 4096  # bytes kept around a needle hit for the decoder
MAX_NEEDLE_HITS = 4000  # total windows kept, so a needle that matches millions
MAX_NEEDLE_WINDOW_BYTES = 64 * 1024**2  # of times cannot exhaust memory


@dataclasses.dataclass(frozen=True)
class FlagHit:
    value: bytes
    offset: int
    confirmed: bool
    source: str  # the format source/pattern that matched


@dataclasses.dataclass(frozen=True)
class NeedleHit:
    label: str
    offset: int
    needle: bytes
    window: bytes  # slice of the buffer around the hit, for the decoder


def scan_flags(data: bytes, formats: list[FlagFormat]) -> list[FlagHit]:
    """Return all flag matches, deduplicated by (value, offset).

    A confirmed format yields a confirmed hit; the generic pattern yields
    candidates. Overlapping matches from different formats are all reported.
    """
    hits: list[FlagHit] = []
    seen: set[tuple[bytes, int]] = set()
    for fmt in formats:
        for m in fmt.regex.finditer(data):
            key = (m.group(), m.start())
            if key in seen:
                continue
            seen.add(key)
            hits.append(FlagHit(m.group(), m.start(), fmt.confirmed, fmt.source))
    hits.sort(key=lambda h: (h.offset, not h.confirmed))
    return hits


def scan_needles(data: bytes, needles: list[Needle], window: int = WINDOW) -> list[NeedleHit]:
    """Locate needle occurrences and capture a window around each.

    Windows let the decoder re-examine a localized region instead of the whole
    item. Overlapping windows for nearby hits are expected and harmless. The
    total number of windows and their combined size are capped: a short needle
    that matches millions of times would otherwise allocate windows without
    bound and exhaust memory.
    """
    hits: list[NeedleHit] = []
    budget = MAX_NEEDLE_WINDOW_BYTES
    for n in needles:
        start = 0
        while True:
            idx = data.find(n.value, start)
            if idx == -1:
                break
            lo = max(0, idx - window // 2)
            hi = min(len(data), idx + len(n.value) + window // 2)
            win = data[lo:hi]
            hits.append(NeedleHit(n.label, idx, n.value, win))
            budget -= len(win)
            if len(hits) >= MAX_NEEDLE_HITS or budget <= 0:
                return hits
            start = idx + 1
    return hits
