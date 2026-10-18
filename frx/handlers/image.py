"""Image/stego handler (spec section 6.5).

exiftool metadata (comments/GPS/XMP), structural checks (pngcheck/jpeginfo),
zsteg LSB analysis on PNG/BMP, and steghide brute via stegseek plus steghide
extract with empty/wordlist passphrases, and an outguess attempt. Recovered
payloads are enqueued; metadata and zsteg text are scanned for flags and fed to
the decoder. Appended-archive/trailing data is handled by the binary handler
(binwalk/foremost) which also runs on every image.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from ..engine.context import Context
from ..engine.queue import Item
from ..flags.scan import scan_flags
from ..report.findings import Finding


def _subtype(item: Item) -> str:
    try:
        head = item.path.open("rb").read(16)
    except OSError:
        return "other"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if head[:3] == b"\xff\xd8\xff":
        return "jpg"
    if head[:2] == b"BM":
        return "bmp"
    if head[:4] in (b"GIF8",):
        return "gif"
    return "other"


def _scan_and_decode(ctx: Context, item: Item, data: bytes, via: str, command: str | None = None) -> None:
    for hit in scan_flags(data, ctx.formats):
        if hit.confirmed:
            v = hit.value.decode("utf-8", "replace")
            ctx.emit(Finding(
                severity="flag", handler="image", type="flag", value=v, item_sha=item.sha256,
                flag=True, confidence=1.0, provenance=item.provenance + [via, v], command=command,
            ))
    if ctx.decoder is not None:
        ctx.decoder.decode_candidate(data, item, item.provenance + [via])


def _exiftool(ctx: Context, item: Item) -> None:
    res = ctx.runner.run(["exiftool", "-a", "-u", "-g1", str(item.path)], timeout=120)
    if res.stdout.strip():
        _scan_and_decode(ctx, item, res.stdout, "image:exiftool", res.command)


def _structural(ctx: Context, item: Item, sub: str) -> None:
    if sub == "png" and shutil.which("pngcheck"):
        res = ctx.runner.run(["pngcheck", "-v", str(item.path)], timeout=60)
        if res.stdout.strip():
            ctx.emit(Finding(
                severity="info", handler="image", type="artifact",
                value=f"pngcheck: {res.out_text().strip()[:500]}", item_sha=item.sha256,
                provenance=item.provenance + ["image:pngcheck"], command=res.command,
            ))
    if sub == "jpg" and shutil.which("jpeginfo"):
        res = ctx.runner.run(["jpeginfo", "-c", str(item.path)], timeout=60)
        if res.stdout.strip():
            ctx.emit(Finding(
                severity="info", handler="image", type="artifact",
                value=f"jpeginfo: {res.out_text().strip()[:300]}", item_sha=item.sha256,
                provenance=item.provenance + ["image:jpeginfo"], command=res.command,
            ))


def _zsteg(ctx: Context, item: Item, sub: str) -> None:
    if sub not in ("png", "bmp") or shutil.which("zsteg") is None:
        return
    res = ctx.runner.run(["zsteg", "-a", str(item.path)], timeout=ctx.runner.default_timeout)
    if res.stdout.strip():
        _scan_and_decode(ctx, item, res.stdout, "image:zsteg", res.command)


def _steghide(ctx: Context, item: Item, sub: str) -> None:
    if sub not in ("jpg", "bmp"):
        return
    out = ctx.child_dir(item) / f"steg_{item.short}"

    # stegseek: fast steghide passphrase brute using the wordlist.
    if ctx.wordlist and Path(ctx.wordlist).is_file() and shutil.which("stegseek"):
        payload = out.with_suffix(".stegseek")
        res = ctx.runner.run(
            ["stegseek", "--crack", "-sf", str(item.path), "-wl", ctx.wordlist, "-xf", str(payload)],
            timeout=ctx.runner.default_timeout,
        )
        text = res.out_text() + res.stderr.decode("utf-8", "replace")
        if payload.is_file() and payload.stat().st_size:
            ctx.emit(Finding(
                severity="high", handler="image", type="artifact",
                value=f"stegseek cracked passphrase: {_passphrase(text)}", item_sha=item.sha256,
                provenance=item.provenance + ["image:stegseek"], command=res.command,
            ))
            ctx.enqueue_file(payload, item, "image:stegseek-payload")

    # steghide extract with empty passphrase as a cheap fallback.
    if shutil.which("steghide"):
        empty = out.with_suffix(".empty")
        ctx.runner.run(["steghide", "extract", "-sf", str(item.path), "-p", "", "-xf", str(empty), "-f"], timeout=60)
        if empty.is_file() and empty.stat().st_size:
            ctx.enqueue_file(empty, item, "image:steghide-empty")


def _passphrase(text: str) -> str:
    for line in text.splitlines():
        if "passphrase" in line.lower() and '"' in line:
            return line.split('"')[1]
    return "(see log)"


def _outguess(ctx: Context, item: Item, sub: str) -> None:
    if sub != "jpg" or shutil.which("outguess") is None:
        return
    out = ctx.child_dir(item) / f"outguess_{item.short}.bin"
    res = ctx.runner.run(["outguess", "-r", str(item.path), str(out)], timeout=120)
    if out.is_file() and out.stat().st_size:
        ctx.enqueue_file(out, item, "image:outguess")
    _ = res


def handle(item: Item, ctx: Context) -> None:
    sub = _subtype(item)
    _exiftool(ctx, item)
    if ctx.mode != "full":
        return
    _structural(ctx, item, sub)
    _zsteg(ctx, item, sub)
    _steghide(ctx, item, sub)
    _outguess(ctx, item, sub)
