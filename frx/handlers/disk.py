"""Disk-image handler via The Sleuth Kit (spec section 6.3), preferred over mounting.

mmls finds partitions (a bare filesystem image has none: treat it as one FS at
offset 0). Per filesystem: fsstat for the summary, tsk_recover -e to bulk-extract
allocated AND deleted files into the case dir (every recovered file enqueued),
fls -r -p for the listing with deleted entries flagged, and blkls to dump
unallocated space so the binary handler can sweep slack for hidden flags.
Loop-mount is only a last resort and only with --mount (amendment A5).
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from ..engine.context import Context
from ..engine.queue import Item
from ..report.findings import Finding

_MMLS_ROW = re.compile(r"^\s*\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$")
_SKIP_DESC = ("unallocated", "primary table", "safety table", "gpt header", "meta")


def _partitions(ctx: Context, item: Item) -> list[tuple[int, str]]:
    res = ctx.runner.run(["mmls", str(item.path)], timeout=120)
    if res.returncode != 0:
        return []
    parts = []
    for line in res.out_text().splitlines():
        m = _MMLS_ROW.match(line)
        if not m:
            continue
        start, _end, length, desc = int(m.group(1)), m.group(2), int(m.group(3)), m.group(4).strip()
        if length <= 1 or any(s in desc.lower() for s in _SKIP_DESC):
            continue
        parts.append((start, desc))
    return parts


def _offset_args(offset: int | None) -> list[str]:
    return ["-o", str(offset)] if offset else []


def _enqueue_tree(ctx: Context, item: Item, root: Path, label: str) -> int:
    n = 0
    for child in sorted(root.rglob("*")):
        if child.is_file():
            rel = child.relative_to(root)
            if ctx.enqueue_file(child, item, f"{label}:{rel}"):
                n += 1
    return n


def _process_fs(ctx: Context, item: Item, offset: int | None, tag: str) -> None:
    oa = _offset_args(offset)

    fsstat = ctx.runner.run(["fsstat", *oa, str(item.path)], timeout=120)
    if fsstat.stdout.strip():
        first = fsstat.out_text().splitlines()[:1]
        ctx.emit(Finding(
            severity="info", handler="disk", type="artifact",
            value=f"{tag} fsstat: {first[0] if first else ''}", item_sha=item.sha256,
            provenance=item.provenance + [f"disk:{tag}:fsstat"], command=fsstat.command,
        ))

    # Bulk-recover allocated + deleted files.
    rec = ctx.child_dir(item) / f"recover_{tag}"
    rec.mkdir(parents=True, exist_ok=True)
    rres = ctx.runner.run(["tsk_recover", "-e", *oa, str(item.path), str(rec)], timeout=ctx.runner.default_timeout)
    n = _enqueue_tree(ctx, item, rec, f"disk:{tag}:recover")
    ctx.log(f"  disk {tag}: recovered {n} file(s) rc={rres.returncode}")

    # Listing, flagging deleted entries for the report.
    fls = ctx.runner.run(["fls", "-r", "-p", *oa, str(item.path)], timeout=ctx.runner.default_timeout)
    for line in fls.out_text().splitlines():
        if line.startswith("*") or "* " in line[:4]:
            ctx.emit(Finding(
                severity="high", handler="disk", type="artifact",
                value=f"deleted entry: {line.strip()}", item_sha=item.sha256,
                provenance=item.provenance + [f"disk:{tag}:fls", "deleted"], command=fls.command,
            ))

    # Unallocated space -> a file the binary handler will sweep.
    if ctx.mode == "full":
        unalloc = ctx.child_dir(item) / f"unalloc_{tag}.bin"
        with unalloc.open("wb") as fh:
            br = ctx.runner.run(["blkls", *oa, str(item.path)], timeout=ctx.runner.default_timeout)
            fh.write(br.stdout)
        if unalloc.stat().st_size:
            ctx.enqueue_file(unalloc, item, f"disk:{tag}:unallocated")


def handle(item: Item, ctx: Context) -> None:
    if shutil.which("tsk_recover") is None:
        ctx.emit(Finding(
            severity="info", handler="disk", type="artifact",
            value="sleuthkit not available; disk image not parsed", item_sha=item.sha256,
            provenance=item.provenance + ["disk:unavailable"],
        ))
        return
    parts = _partitions(ctx, item)
    if parts:
        for start, desc in parts:
            _process_fs(ctx, item, offset=start, tag=f"p{start}")
    else:
        _process_fs(ctx, item, offset=None, tag="fs")
