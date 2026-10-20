"""The universal fallback handler (spec section 6.7).

Runs on every item regardless of kind, so nothing is skipped: file type, three
`strings` passes (ASCII, UTF-16LE, UTF-16BE), flag-regex and needle scanning,
and (full mode) carving via binwalk/foremost. Needle windows and raw candidate
blobs are handed to the decode engine when one is wired into the context.
"""

from __future__ import annotations

import shutil

from ..flags.scan import scan_flags, scan_needles
from ..engine.context import Context
from ..engine.queue import Item
from ..report.findings import Finding

STRINGS_PASSES = (
    ("ascii", ["-a"]),
    ("utf-16le", ["-a", "-e", "l"]),
    ("utf-16be", ["-a", "-e", "b"]),
)
MAX_STRINGS_BYTES = 256 * 1024**2  # cap captured strings output
MIN_CARVE_SIZE = 64  # nothing to carve out of a handful of bytes


def _emit_flag_hits(ctx: Context, item: Item, data: bytes, via: str, command: str | None, offset_known: bool) -> None:
    for hit in scan_flags(data, ctx.formats):
        value = hit.value.decode("utf-8", "replace")
        prov = item.provenance + [via, value]
        off = hit.offset if offset_known else None
        if hit.confirmed:
            ctx.emit(Finding(
                severity="flag", handler="binary", type="flag", value=value,
                item_sha=item.sha256, flag=True, confidence=1.0,
                provenance=prov, command=command, offset=off,
            ))
        else:
            ctx.emit(Finding(
                severity="info", handler="binary", type="flag_candidate", value=value,
                item_sha=item.sha256, confidence=0.3,
                provenance=prov, command=command, offset=off,
            ))


def _feed_decoder(ctx: Context, item: Item, data: bytes, via: str) -> None:
    if ctx.decoder is None:
        return
    # Targeted: a decode window around each needle hit, with precise provenance.
    seen_windows: set[bytes] = set()
    for nh in scan_needles(data, ctx.needles):
        if nh.window in seen_windows:
            continue
        seen_windows.add(nh.window)
        ctx.decoder.decode_candidate(
            nh.window, item, base_provenance=item.provenance + [f"{via}:needle={nh.label}@{nh.offset}"],
        )
    # Comprehensive (full mode): hand the whole buffer to the decoder so long
    # high-purity runs (nested encodings no single needle matches) are tried.
    if ctx.mode == "full":
        ctx.decoder.decode_candidate(data, item, base_provenance=item.provenance + [via])


def _enqueue_carved(ctx: Context, item: Item, root, tool: str) -> int:
    if not root.is_dir():
        return 0
    n = 0
    for child in sorted(root.rglob("*")):
        if child.is_file() and not child.is_symlink() and child.stat().st_size:
            rel = child.relative_to(root)
            if ctx.enqueue_file(child, item, f"binary:{tool}:{rel}"):
                n += 1
    if n:
        ctx.log(f"  binary {item.short}: {tool} carved {n} file(s)")
    return n


def _bulk_extractor_features(ctx: Context, item: Item, root) -> None:
    """Scan bulk_extractor feature files for flags and feed base64 to the decoder."""
    if not root.is_dir():
        return
    for feat in sorted(root.glob("*.txt")):
        try:
            data = feat.read_bytes()
        except OSError:
            continue
        if not data.strip():
            continue
        for hit in scan_flags(data, ctx.formats):
            if hit.confirmed:
                v = hit.value.decode("utf-8", "replace")
                ctx.emit(Finding(
                    severity="flag", handler="binary", type="flag", value=v, item_sha=item.sha256,
                    flag=True, confidence=1.0,
                    provenance=item.provenance + [f"binary:bulk_extractor:{feat.name}", v],
                ))
        if ctx.decoder is not None and feat.name.startswith("base64"):
            ctx.decoder.decode_candidate(data, item, item.provenance + [f"binary:bulk_extractor:{feat.name}"])


def _carve(item: Item, ctx: Context) -> None:
    """Full-mode carving (spec section 6.7, amendment A1): binwalk extraction,
    foremost, and (optional) bulk_extractor. Carved files are enqueued as
    children, so the queue's depth/file/size caps bound the recursion."""
    if item.size < MIN_CARVE_SIZE:
        return
    carve = ctx.child_dir(item) / "carve"
    carve.mkdir(parents=True, exist_ok=True)
    if shutil.which("binwalk"):
        bdir = carve / "binwalk"
        bdir.mkdir(parents=True, exist_ok=True)
        # -e -C <dir> is the extraction form on both binwalk 2.x and the 3.x
        # Rust rewrite (which dropped --dd); we parse the carved tree, not a log.
        ctx.runner.run(["binwalk", "-e", "-C", str(bdir), str(item.path)],
                       timeout=ctx.runner.default_timeout)
        _enqueue_carved(ctx, item, bdir, "binwalk")
    if shutil.which("foremost"):
        fdir = carve / "foremost"  # foremost creates this; do not pre-make it
        ctx.runner.run(["foremost", "-t", "all", "-o", str(fdir), str(item.path)],
                       timeout=ctx.runner.default_timeout)
        _enqueue_carved(ctx, item, fdir, "foremost")
    if shutil.which("bulk_extractor"):  # optional (amendment A8)
        edir = carve / "bulk_extractor"
        ctx.runner.run(["bulk_extractor", "-o", str(edir), str(item.path)],
                       timeout=ctx.runner.default_timeout)
        _bulk_extractor_features(ctx, item, edir)


def handle(item: Item, ctx: Context) -> None:
    # file(1) description as an artifact.
    res = ctx.runner.run(["file", "-b", str(item.path)], timeout=60)
    if res.stdout.strip():
        ctx.emit(Finding(
            severity="info", handler="binary", type="artifact",
            value=res.out_text().strip(), item_sha=item.sha256,
            provenance=item.provenance + ["file"], command=res.command,
        ))

    # Direct scan of raw bytes (real offsets) for small-enough items.
    if item.size <= ctx.max_inmem:
        try:
            data = item.path.read_bytes()
        except OSError:
            data = b""
        if data:
            _emit_flag_hits(ctx, item, data, "raw", None, offset_known=True)
            _feed_decoder(ctx, item, data, "raw")

    # Three strings passes, scanned for flags and needles. strings output can be
    # image-sized, so stream it to a temp file (bounded RAM) and scan a capped
    # prefix rather than buffering it all through a pipe.
    for label, extra in STRINGS_PASSES:
        sfile = ctx.child_dir(item) / f"strings_{label}.txt"
        with sfile.open("wb") as fh:
            res = ctx.runner.run_to_file(["strings", *extra, str(item.path)], fh,
                                         timeout=ctx.runner.default_timeout)
        try:
            size = sfile.stat().st_size
        except OSError:
            size = 0
        if not size:
            sfile.unlink(missing_ok=True)
            continue
        with sfile.open("rb") as fh:
            data = fh.read(MAX_STRINGS_BYTES)
        sfile.unlink(missing_ok=True)
        via = f"strings:{label}"
        _emit_flag_hits(ctx, item, data, via, res.command, offset_known=False)
        _feed_decoder(ctx, item, data, via)

    # Carving + feature extraction (full mode only).
    if ctx.mode == "full":
        _carve(item, ctx)
