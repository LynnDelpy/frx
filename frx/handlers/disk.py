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
_SKIP_DESC = ("unallocated", "primary table", "safety table", "gpt header",
              "partition table", "meta")


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
        # Never follow a symlink out of the extraction dir: a crafted image can
        # plant one pointing at /etc/passwd, and we would read/scan it.
        if child.is_file() and not child.is_symlink():
            rel = child.relative_to(root)
            if ctx.enqueue_file(child, item, f"{label}:{rel}"):
                n += 1
    return n


def _process_fs(ctx: Context, item: Item, offset: int | None, tag: str) -> bool:
    """Process one filesystem via TSK. Returns True if TSK understood it."""
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
        # fls marks a deleted entry with a standalone '*' after the type field,
        # e.g. "r/r * 13-128-2:\tname"; a live entry has the inode token there.
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[1] == "*":
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

    return bool(fsstat.stdout.strip()) or n > 0


def _mount_fallback(item: Item, ctx: Context) -> bool:
    """Last-resort read-only loop mount (amendment A5): TSK then 7z are preferred,
    so this only runs when TSK understood nothing AND the user passed --mount with
    --no-sandbox (a loop mount cannot happen inside the unshare -rn sandbox).

    udisksctl mounts the image read-only; files are copied into the case dir (so
    they survive the immediate unmount) and enqueued. The copy is bounded by the
    same total-size cap as any extraction, and the mount is always torn down.
    """
    from ..engine import sandbox

    if not sandbox.can_loop_mount(ctx.enforce_offline, ctx.mount):
        return False
    try:
        mounted = sandbox.loop_mount_ro(item.path, runner=ctx.runner)
    except Exception as e:  # noqa: BLE001 - never let a mount tool kill the run
        ctx.emit(Finding(
            severity="info", handler="disk", type="artifact",
            value=f"loop mount error: {type(e).__name__}: {e}", item_sha=item.sha256,
            provenance=item.provenance + ["disk:mount:error"],
        ))
        return False
    if not mounted:
        ctx.emit(Finding(
            severity="info", handler="disk", type="artifact",
            value="loop mount failed; nothing mounted", item_sha=item.sha256,
            provenance=item.provenance + ["disk:mount:failed"],
        ))
        return False

    dev, mp = mounted
    ctx.emit(Finding(
        severity="high", handler="disk", type="artifact",
        value=f"mounted read-only at {mp}", item_sha=item.sha256,
        provenance=item.provenance + ["disk:mount"],
    ))
    dest_root = ctx.child_dir(item) / "mount"
    dest_root.mkdir(parents=True, exist_ok=True)
    budget = ctx.queue.max_extracted_size
    copied = 0
    n = skipped = 0
    try:
        for child in sorted(mp.rglob("*")):
            if not child.is_file() or child.is_symlink():
                continue
            if child.is_symlink():
                continue  # don't copy a symlink target out of the mount
            try:
                sz = child.stat().st_size
            except OSError:
                continue
            # Count what the rest of the run already extracted, so the mount copy
            # cannot blow past --max-extracted-size on its own.
            if ctx.queue.extracted_bytes + copied + sz > budget:
                skipped += 1
                continue
            rel = child.relative_to(mp)
            out = dest_root / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(child, out)
            except OSError:
                continue
            copied += sz
            if ctx.enqueue_file(out, item, f"disk:mount:{rel}"):
                n += 1
    finally:
        sandbox.loop_unmount(dev, runner=ctx.runner)
    ctx.log(f"  disk mount: enqueued {n} file(s) from {mp}, skipped {skipped} over size budget")
    if skipped:
        ctx.emit(Finding(
            severity="info", handler="disk", type="artifact",
            value=f"mount copy stopped at size budget; {skipped} file(s) skipped",
            item_sha=item.sha256, provenance=item.provenance + ["disk:mount:truncated"],
        ))
    return True


def handle(item: Item, ctx: Context) -> None:
    has_tsk = shutil.which("tsk_recover") is not None
    produced = False
    if has_tsk:
        parts = _partitions(ctx, item)
        if parts:
            for start, desc in parts:
                produced = _process_fs(ctx, item, offset=start, tag=f"p{start}") or produced
        else:
            produced = _process_fs(ctx, item, offset=None, tag="fs") or produced

    if not produced:
        # TSK absent or could not parse the filesystem: try the mount fallback.
        if _mount_fallback(item, ctx):
            return
        if not has_tsk:
            ctx.emit(Finding(
                severity="info", handler="disk", type="artifact",
                value="sleuthkit not available; disk image not parsed", item_sha=item.sha256,
                provenance=item.provenance + ["disk:unavailable"],
            ))
