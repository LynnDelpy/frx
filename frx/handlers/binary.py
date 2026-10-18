"""The universal fallback handler (spec section 6.7).

Runs on every item regardless of kind, so nothing is skipped: file type, three
`strings` passes (ASCII, UTF-16LE, UTF-16BE), flag-regex and needle scanning,
and (full mode) carving via binwalk/foremost. Needle windows and raw candidate
blobs are handed to the decode engine when one is wired into the context.
"""

from __future__ import annotations

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


def _decode_needle_windows(ctx: Context, item: Item, data: bytes, via: str) -> None:
    if ctx.decoder is None:
        return
    seen_windows: set[bytes] = set()
    for nh in scan_needles(data, ctx.needles):
        if nh.window in seen_windows:
            continue
        seen_windows.add(nh.window)
        ctx.decoder.decode_candidate(
            nh.window, item, base_provenance=item.provenance + [f"{via}:needle={nh.label}@{nh.offset}"],
        )


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
            _decode_needle_windows(ctx, item, data, "raw")

    # Three strings passes, scanned for flags and needles.
    for label, extra in STRINGS_PASSES:
        res = ctx.runner.run(["strings", *extra, str(item.path)], timeout=ctx.runner.default_timeout)
        if not res.stdout:
            continue
        data = res.stdout[:MAX_STRINGS_BYTES]
        via = f"strings:{label}"
        _emit_flag_hits(ctx, item, data, via, res.command, offset_known=False)
        _decode_needle_windows(ctx, item, data, via)
