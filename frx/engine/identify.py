"""Magic-based kind detection: the routing table (spec section 5).

Input type is detected from content, never from extension. A small signature
table handles what libmagic is weak on (LiME 'EMiL', E01 'EVF', ISO9660, raw
memory heuristics); libmagic (or the `file` command as fallback, amendment A11)
covers the rest. 'other' is the universal fallback so nothing is skipped.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# Kind constants (values match the routing table / finding handler names).
MEMORY_RAW = "memory_raw"
MEMORY_WIN = "memory_win"
PCAP = "pcap"
DISK_IMAGE = "disk_image"
ISO = "iso"
ARCHIVE = "archive"
IMAGE = "image"
DOCUMENT = "document"
OTHER = "other"

_OVERRIDE_MAP = {
    "memory": MEMORY_RAW,
    "memory_raw": MEMORY_RAW,
    "memory_win": MEMORY_WIN,
    "pcap": PCAP,
    "disk": DISK_IMAGE,
    "disk_image": DISK_IMAGE,
    "iso": ISO,
    "archive": ARCHIVE,
    "image": IMAGE,
    "document": DOCUMENT,
    "other": OTHER,
}


def _sniff_signatures(head: bytes, path: Path) -> str | None:
    """Content signatures for the cases libmagic gets wrong or misses."""
    if head[:4] == b"EMiL":  # LiME header magic, little-endian "LiME"
        return MEMORY_RAW
    if head[:3] == b"EVF" or head[:8] == b"EVF2\x0d\x0a\x81\x00":
        return DISK_IMAGE  # EWF/E01 forensic image
    if head[:4] == b"\x89PNG" or head[:3] == b"\xff\xd8\xff" or head[:4] in (b"GIF8",) or head[:2] == b"BM":
        return IMAGE
    if head[:4] == b"%PDF":
        return DOCUMENT
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return DOCUMENT  # OLE compound (legacy Office)
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return ARCHIVE  # zip (ooxml refined later by the document handler)
    if head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:2] == b"\x1f\x8b" or head[:6] == b"\xfd7zXZ\x00" or head[:3] == b"BZh" or head[:4] == b"Rar!":
        return ARCHIVE
    if head[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        return PCAP  # classic pcap (either endianness, us/ns)
    if head[:4] == b"\x0a\x0d\x0d\x0a":
        return PCAP  # pcapng
    # ISO9660: "CD001" at one of the volume-descriptor offsets.
    try:
        with path.open("rb") as fh:
            for off in (0x8001, 0x8801, 0x9001):
                fh.seek(off)
                if fh.read(5) == b"CD001":
                    return ISO
    except OSError:
        pass
    # GPT/MBR partition table.
    if len(head) >= 512 and head[510:512] == b"\x55\xaa":
        try:
            with path.open("rb") as fh:
                fh.seek(512)
                if fh.read(8) == b"EFI PART":
                    return DISK_IMAGE
        except OSError:
            pass
        return DISK_IMAGE
    return None


def _libmagic_kind(path: Path) -> str | None:
    try:
        import magic  # type: ignore
    except Exception:
        return _file_cmd_kind(path)
    try:
        desc = magic.from_file(str(path)).lower()
    except Exception:
        return None
    return _kind_from_desc(desc)


def _file_cmd_kind(path: Path) -> str | None:
    try:
        out = subprocess.run(
            ["file", "-b", str(path)], capture_output=True, timeout=30
        ).stdout.decode("utf-8", "replace").lower()
    except (OSError, subprocess.SubprocessError):
        return None
    return _kind_from_desc(out)


def _kind_from_desc(desc: str) -> str | None:
    if "pcap" in desc or "tcpdump" in desc:
        return PCAP
    if "iso 9660" in desc or "udf filesystem" in desc:
        return ISO
    if any(w in desc for w in ("filesystem", "partition", "boot sector", "mbr", "ext2", "ext3", "ext4", "ntfs", "fat ")):
        return DISK_IMAGE
    if any(w in desc for w in ("zip archive", "7-zip", "gzip", "xz compressed", "bzip2", "tar archive", "rar archive", "cpio")):
        return ARCHIVE
    if any(w in desc for w in ("image data", "bitmap", "png", "jpeg", "gif")):
        return IMAGE
    if "pdf document" in desc or "composite document" in desc or "word" in desc or "excel" in desc:
        return DOCUMENT
    return None


def identify(path, override: str | None = None, probe_memory: bool = False) -> str:
    """Return the kind for a path. `override` forces a kind (from --kind)."""
    p = Path(path)
    if override:
        ov = _OVERRIDE_MAP.get(override.lower())
        if ov:
            return ov
    try:
        with p.open("rb") as fh:
            head = fh.read(4096)
    except OSError:
        return OTHER
    if not head:
        return OTHER
    sig = _sniff_signatures(head, p)
    if sig:
        return sig
    mk = _libmagic_kind(p)
    if mk:
        return mk
    return OTHER
