"""Document handler: PDF and Office (spec section 6.6).

PDF: pdfid / pdf-parser surface streams, /JS, /OpenAction; pdfdetach saves
attachments; qpdf decompresses object streams; pdftotext extracts text. Office:
olevba/oleid surface and dump macros. Attachments and decompressed streams are
enqueued; extracted text and macro source are scanned for flags and fed to the
decoder. pdfid/pdf-parser are Didier Stevens scripts installed by setup
(amendment A8); each tool is optional and skipped cleanly when absent.
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
        head = item.path.open("rb").read(8)
    except OSError:
        return "other"
    if head[:4] == b"%PDF":
        return "pdf"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if head[:4] in (b"PK\x03\x04",):
        return "ooxml"
    return "other"


def _scan_and_decode(ctx: Context, item: Item, data: bytes, via: str, command: str | None = None) -> None:
    for hit in scan_flags(data, ctx.formats):
        if hit.confirmed:
            v = hit.value.decode("utf-8", "replace")
            ctx.emit(Finding(
                severity="flag", handler="document", type="flag", value=v, item_sha=item.sha256,
                flag=True, confidence=1.0, provenance=item.provenance + [via, v], command=command,
            ))
    if ctx.decoder is not None:
        ctx.decoder.decode_candidate(data, item, item.provenance + [via])


def _resolve(name: str) -> list[str] | None:
    """Resolve a Didier Stevens tool to an argv prefix (binary or .py)."""
    for cand in (name, f"{name}.py"):
        p = shutil.which(cand)
        if p:
            return [p] if p.endswith(".py") is False else ["python3", p]
    tools = Path.home() / ".local/share/frx/tools" / f"{name}.py"
    if tools.is_file():
        return ["python3", str(tools)]
    return None


def _pdf(ctx: Context, item: Item) -> None:
    pdftotext = shutil.which("pdftotext")
    if pdftotext:
        txt = ctx.child_dir(item) / f"{item.short}.txt"
        ctx.runner.run([pdftotext, "-q", str(item.path), str(txt)], timeout=120)
        if txt.is_file() and txt.stat().st_size:
            _scan_and_decode(ctx, item, txt.read_bytes(), "document:pdftotext")

    if shutil.which("pdfdetach"):
        attach = ctx.child_dir(item) / "attachments"
        attach.mkdir(parents=True, exist_ok=True)
        ctx.runner.run(["pdfdetach", "-saveall", "-o", str(attach), str(item.path)], timeout=120)
        for child in sorted(attach.rglob("*")):
            if child.is_file() and child.stat().st_size:
                ctx.enqueue_file(child, item, f"document:pdf-attachment:{child.name}")

    pdfid = _resolve("pdfid")
    if pdfid:
        res = ctx.runner.run([*pdfid, str(item.path)], timeout=60)
        if res.stdout.strip():
            ctx.emit(Finding(
                severity="info", handler="document", type="artifact",
                value=f"pdfid: {res.out_text().strip()[:500]}", item_sha=item.sha256,
                provenance=item.provenance + ["document:pdfid"], command=res.command,
            ))

    # qpdf: decompress object streams so flags hidden in compressed streams surface.
    if shutil.which("qpdf"):
        decompressed = ctx.child_dir(item) / f"{item.short}.qpdf.pdf"
        ctx.runner.run(["qpdf", "--qdf", "--object-streams=disable", str(item.path), str(decompressed)], timeout=120)
        if decompressed.is_file() and decompressed.stat().st_size:
            ctx.enqueue_file(decompressed, item, "document:qpdf-decompressed")


def _office(ctx: Context, item: Item) -> None:
    if shutil.which("olevba"):
        res = ctx.runner.run(["olevba", "--decode", str(item.path)], timeout=120)
        if res.stdout.strip():
            _scan_and_decode(ctx, item, res.stdout, "document:olevba", res.command)
    if shutil.which("oleid"):
        res = ctx.runner.run(["oleid", str(item.path)], timeout=60)
        if res.stdout.strip():
            ctx.emit(Finding(
                severity="info", handler="document", type="artifact",
                value=f"oleid: {res.out_text().strip()[:400]}", item_sha=item.sha256,
                provenance=item.provenance + ["document:oleid"], command=res.command,
            ))


def handle(item: Item, ctx: Context) -> None:
    sub = _subtype(item)
    if sub == "pdf":
        _pdf(ctx, item)
    elif sub in ("ole", "ooxml"):
        _office(ctx, item)
