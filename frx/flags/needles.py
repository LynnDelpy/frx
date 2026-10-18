"""Encoded-prefix needle generation (spec section 7.2).

Blind-decoding everything is noise. Instead we take the literal flag prefix
(e.g. 'CTF{') and precompute how it would look after each common single
encoding, then search those byte needles across every item. A hit localizes the
flag so the full decoder can be pointed at a small window.

Each needle is a stable substring: for block encodings (base64/base32) the edges
depend on surrounding bytes, so we trim the contaminated leading/trailing chars
and keep the stable middle. Needles shorter than MIN_LEN are dropped as noisy.
"""

from __future__ import annotations

import base64
import dataclasses
import math
import urllib.parse

MIN_LEN = 3


@dataclasses.dataclass(frozen=True)
class Needle:
    label: str  # the encoding, for provenance (e.g. "base64", "rot13")
    value: bytes


def _rot_n(data: bytes, n: int) -> bytes:
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:
            out.append((b - 65 + n) % 26 + 65)
        elif 97 <= b <= 122:
            out.append((b - 97 + n) % 26 + 97)
        else:
            out.append(b)
    return bytes(out)


def _rot47(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if 33 <= b <= 126:
            out.append((b - 33 + 47) % 94 + 33)
        else:
            out.append(b)
    return bytes(out)


def _b64_middle(prefix: bytes) -> list[Needle]:
    out: list[Needle] = []
    for i in range(3):  # three phase alignments
        raw = (b"\x00" * i) + prefix
        enc = base64.b64encode(raw).rstrip(b"=")
        lead = math.ceil(8 * i / 6)
        mid = enc[lead : len(enc) - 2] if len(enc) > lead + 2 else b""
        if len(mid) >= MIN_LEN:
            out.append(Needle("base64", mid))
    return out


def _b32_middle(prefix: bytes) -> list[Needle]:
    out: list[Needle] = []
    for i in range(5):  # base32 block is 5 bytes
        raw = (b"\x00" * i) + prefix
        enc = base64.b32encode(raw).rstrip(b"=")
        lead = math.ceil(8 * i / 5)
        mid = enc[lead : len(enc) - 2] if len(enc) > lead + 2 else b""
        if len(mid) >= MIN_LEN:
            out.append(Needle("base32", mid))
    return out


def _b85_middle(prefix: bytes) -> list[Needle]:
    try:
        enc = base64.b85encode(prefix)
    except Exception:
        return []
    mid = enc[1 : len(enc) - 1] if len(enc) > 2 else b""
    return [Needle("base85", mid)] if len(mid) >= MIN_LEN else []


def _b58(prefix: bytes) -> list[Needle]:
    # base58 is big-integer based: a prefix of the input is not a prefix of the
    # output, so this is only a best-effort whole-string needle.
    alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(prefix, "big")
    if num == 0:
        return []
    enc = bytearray()
    while num:
        num, rem = divmod(num, 58)
        enc.append(alphabet[rem])
    enc.reverse()
    return [Needle("base58", bytes(enc))] if len(enc) >= MIN_LEN else []


def generate_needles(prefix: str) -> list[Needle]:
    """All encoded forms of the flag prefix worth searching for."""
    p = prefix.encode()
    needles: list[Needle] = []

    # Plaintext prefix itself (the direct, most common case).
    if len(p) >= MIN_LEN:
        needles.append(Needle("plain", p))

    needles.extend(_b64_middle(p))
    needles.extend(_b32_middle(p))

    # hex, both cases
    needles.append(Needle("hex", p.hex().encode()))
    needles.append(Needle("hex", p.hex().upper().encode()))

    # reversed
    needles.append(Needle("reversed", p[::-1]))

    # rot-n and rot47
    for n in range(1, 26):
        needles.append(Needle(f"rot{n}", _rot_n(p, n)))
    needles.append(Needle("rot47", _rot47(p)))

    # UTF-16LE (interleaved nulls), the Windows/.NET wide-string case
    needles.append(Needle("utf16le", p.decode("latin-1").encode("utf-16-le")))

    # URL-encoded (percent-escape everything non-safe)
    url = urllib.parse.quote(prefix, safe="").encode()
    if url != p:
        needles.append(Needle("url", url))

    needles.extend(_b85_middle(p))
    needles.extend(_b58(p))

    # Dedup on (label, value), drop empties and sub-MIN_LEN.
    seen: set[tuple[str, bytes]] = set()
    out: list[Needle] = []
    for n in needles:
        if len(n.value) < MIN_LEN:
            continue
        key = (n.label, n.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out
