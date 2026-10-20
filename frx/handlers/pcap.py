"""PCAP handler via tshark (spec section 6.2).

Recon: protocol hierarchy and conversation stats as artifacts. Full: export
transferred objects (HTTP/SMB/TFTP/IMF/DICOM) and enqueue them, reassemble DNS
exfil (concatenate subdomain labels per zone, hand to the decoder for
hex/base32/base64), dump credentials, follow TCP/UDP streams (capped), and feed
high-value fields (http.file_data, data.data) to the flag/decode engine.
"""

from __future__ import annotations

from pathlib import Path

from ..engine.context import Context
from ..engine.queue import Item
from ..flags.scan import scan_flags
from ..report.findings import Finding

OBJECT_PROTOCOLS = ("http", "smb", "tftp", "imf", "dicom")
MAX_STREAMS = 500
RECON_STATS = (
    ("protocol-hierarchy", ["-z", "io,phs", "-q"]),
    ("tcp-conversations", ["-z", "conv,tcp", "-q"]),
    ("udp-conversations", ["-z", "conv,udp", "-q"]),
    ("ip-endpoints", ["-z", "endpoints,ip", "-q"]),
    ("http-tree", ["-z", "http,tree", "-q"]),  # spec section 6.2
)


def _tshark(ctx: Context, item: Item, args: list[str], timeout: float | None = None):
    return ctx.runner.run(["tshark", "-r", str(item.path), *args], timeout=timeout or ctx.runner.default_timeout)


def _recon_stats(ctx: Context, item: Item) -> None:
    for label, args in RECON_STATS:
        res = _tshark(ctx, item, args, timeout=120)
        if res.stdout.strip():
            ctx.emit(Finding(
                severity="info", handler="pcap", type="artifact",
                value=f"{label}:\n{res.out_text().strip()[:2000]}", item_sha=item.sha256,
                provenance=item.provenance + [f"pcap:{label}"], command=res.command,
            ))


def _export_one(ctx: Context, item: Item, proto: str) -> None:
    out = ctx.child_dir(item) / f"objects_{proto}"
    out.mkdir(parents=True, exist_ok=True)
    _tshark(ctx, item, ["--export-objects", f"{proto},{out}", "-q"])
    n = 0
    for child in sorted(out.rglob("*")):
        if child.is_file() and not child.is_symlink() and child.stat().st_size:
            if ctx.enqueue_file(child, item, f"pcap:{proto}-object:{child.name}"):
                n += 1
    if n:
        ctx.log(f"  pcap {item.short}: exported {n} {proto} object(s)")


def _export_objects(ctx: Context, item: Item) -> None:
    ctx.parallel([(lambda p=proto: _export_one(ctx, item, p)) for proto in OBJECT_PROTOCOLS])


def _dns_exfil(ctx: Context, item: Item) -> None:
    res = _tshark(ctx, item, ["-Y", "dns.flags.response==0", "-T", "fields", "-e", "dns.qry.name"], timeout=120)
    names = [n.strip() for n in res.out_text().splitlines() if n.strip()]
    if not names:
        return
    # Group by the registrable zone (last two labels); concatenate ALL preceding
    # labels of each name, in capture order, as that name's data. This keeps
    # multi-label-per-query exfil (c1.c2.c3.zone.tld) instead of only the first
    # label, while a single-data-label query (chunk.zone.tld) still reassembles.
    zones: dict[str, list[str]] = {}
    for name in names:
        labels = name.split(".")
        if len(labels) < 3:
            continue
        zone = ".".join(labels[-2:])
        zones.setdefault(zone, []).append("".join(labels[:-2]))
    for zone, chunks in zones.items():
        reassembled = "".join(chunks).encode()
        if len(reassembled) < 4:
            continue
        ctx.emit(Finding(
            severity="info", handler="pcap", type="artifact",
            value=f"dns reassembled ({zone}): {reassembled[:120].decode('latin-1')}",
            item_sha=item.sha256, provenance=item.provenance + [f"pcap:dns:{zone}"], command=res.command,
        ))
        for hit in scan_flags(reassembled, ctx.formats):
            if hit.confirmed:
                ctx.emit(Finding(
                    severity="flag", handler="pcap", type="flag", value=hit.value.decode("utf-8", "replace"),
                    item_sha=item.sha256, flag=True, confidence=1.0,
                    provenance=item.provenance + [f"pcap:dns:{zone}", hit.value.decode("utf-8", "replace")],
                ))
        if ctx.decoder is not None:
            ctx.decoder.decode_candidate(reassembled, item, item.provenance + [f"pcap:dns:{zone}"])
    # DNS TXT answers too.
    txt = _tshark(ctx, item, ["-T", "fields", "-e", "dns.txt"], timeout=120)
    for line in txt.out_text().splitlines():
        line = line.strip()
        if line and ctx.decoder is not None:
            ctx.decoder.decode_candidate(line.encode(), item, item.provenance + ["pcap:dns.txt"])


def _credentials(ctx: Context, item: Item) -> None:
    res = _tshark(ctx, item, ["-z", "credentials", "-q"], timeout=120)
    # tshark always prints a header/separator; only a real data row (which starts
    # with a packet number) means credentials were actually found.
    rows = [l for l in res.out_text().splitlines() if l.split() and l.split()[0].isdigit()]
    if rows:
        ctx.emit(Finding(
            severity="high", handler="pcap", type="artifact",
            value="credentials:\n" + "\n".join(rows)[:1500], item_sha=item.sha256,
            provenance=item.provenance + ["pcap:credentials"], command=res.command,
        ))


def _fields(ctx: Context, item: Item) -> None:
    for field, label in (("http.file_data", "http.file_data"), ("data.data", "data.data"), ("ftp-data.data", "ftp-data")):
        res = _tshark(ctx, item, ["-T", "fields", "-e", field], timeout=180)
        for line in res.out_text().splitlines():
            line = line.strip().replace(":", "")
            if len(line) < 8:
                continue
            try:
                raw = bytes.fromhex(line)
            except ValueError:
                raw = line.encode()
            for hit in scan_flags(raw, ctx.formats):
                if hit.confirmed:
                    v = hit.value.decode("utf-8", "replace")
                    ctx.emit(Finding(
                        severity="flag", handler="pcap", type="flag", value=v, item_sha=item.sha256,
                        flag=True, confidence=1.0, provenance=item.provenance + [f"pcap:{label}", v],
                    ))
            if ctx.decoder is not None:
                ctx.decoder.decode_candidate(raw, item, item.provenance + [f"pcap:{label}"])


def _follow_one(ctx: Context, item: Item, n: int) -> None:
    fr = _tshark(ctx, item, ["-q", "-z", f"follow,tcp,raw,{n}"], timeout=60)
    hexdata = "".join(
        line.strip() for line in fr.out_text().splitlines()
        if line.strip() and all(c in "0123456789abcdefABCDEF" for c in line.strip())
    )
    if len(hexdata) < 8:
        return
    try:
        raw = bytes.fromhex(hexdata)
    except ValueError:
        return
    dump = ctx.child_dir(item) / f"tcp_stream_{n}.bin"
    dump.write_bytes(raw)
    ctx.enqueue_file(dump, item, f"pcap:tcp-stream-{n}")


def _follow_streams(ctx: Context, item: Item) -> None:
    res = _tshark(ctx, item, ["-T", "fields", "-e", "tcp.stream"], timeout=120)
    streams = sorted({int(s) for s in res.out_text().split() if s.isdigit()})[:MAX_STREAMS]
    # Each stream follow is an independent read-only tshark call; fan them out.
    ctx.parallel([(lambda k=n: _follow_one(ctx, item, k)) for n in streams])


def handle(item: Item, ctx: Context) -> None:
    _recon_stats(ctx, item)
    if ctx.mode != "full":
        return
    _export_objects(ctx, item)
    _dns_exfil(ctx, item)
    _credentials(ctx, item)
    _fields(ctx, item)
    _follow_streams(ctx, item)
