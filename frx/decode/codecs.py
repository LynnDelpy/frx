"""Reducing codecs: each turns an encoded token into (usually shorter) bytes.

Every function takes bytes and returns decoded bytes, or None when the input is
not valid for that codec. These are "reducing" transforms (spec/A3): the engine
recurses on them whenever the result scores above threshold, unlike the
charset-preserving transforms in classic.py which need stronger evidence.
"""

from __future__ import annotations

import base64
import binascii
import codecs as _py_codecs
import re
import urllib.parse

_WS = b" \t\r\n"

_MORSE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _strip_ws(data: bytes) -> bytes:
    return bytes(b for b in data if b not in _WS)


def decode_hex(data: bytes) -> bytes | None:
    s = _strip_ws(data)
    if len(s) < 4 or len(s) % 2 != 0:
        return None
    try:
        return binascii.unhexlify(s)
    except (binascii.Error, ValueError):
        return None


def decode_base64(data: bytes) -> bytes | None:
    s = _strip_ws(data)
    if len(s) < 8:
        return None
    pad = (-len(s)) % 4
    try:
        out = base64.b64decode(s + b"=" * pad, validate=True)
    except (binascii.Error, ValueError):
        return None
    return out or None


def decode_base32(data: bytes) -> bytes | None:
    s = _strip_ws(data).upper()
    if len(s) < 8:
        return None
    pad = (-len(s)) % 8
    try:
        return base64.b32decode(s + b"=" * pad) or None
    except (binascii.Error, ValueError):
        return None


def decode_base85(data: bytes) -> bytes | None:
    s = _strip_ws(data)
    if len(s) < 5:
        return None
    for fn in (base64.b85decode, base64.a85decode):
        try:
            out = fn(s)
            if out:
                return out
        except Exception:
            continue
    return None


def decode_base58(data: bytes) -> bytes | None:
    s = _strip_ws(data)
    if len(s) < 4 or any(b not in _B58_ALPHABET for b in s):
        return None
    num = 0
    for b in s:
        num = num * 58 + _B58_ALPHABET.index(b)
    out = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip(b"1"))
    return (b"\x00" * pad + out) or None


def decode_decimal(data: bytes) -> bytes | None:
    toks = re.split(rb"[\s,]+", data.strip())
    toks = [t for t in toks if t]
    if len(toks) < 2 or any(not t.isdigit() for t in toks):
        return None
    vals = [int(t) for t in toks]
    if any(v > 255 for v in vals):
        return None
    return bytes(vals)


def decode_binary(data: bytes) -> bytes | None:
    s = _strip_ws(data)
    if len(s) < 8 or len(s) % 8 != 0 or any(b not in (48, 49) for b in s):
        return None
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def decode_morse(data: bytes) -> bytes | None:
    text = data.decode("ascii", "ignore").strip()
    if not text or any(c not in ".-/ \t\n" for c in text):
        return None
    words = re.split(r"\s*/\s*|\s{2,}", text)
    out = []
    for word in words:
        for sym in word.split():
            ch = _MORSE.get(sym)
            if ch is None:
                return None
            out.append(ch)
        out.append(" ")
    res = "".join(out).strip()
    return res.encode() if res else None


def decode_url(data: bytes) -> bytes | None:
    if b"%" not in data:
        return None
    try:
        out = urllib.parse.unquote_to_bytes(data)
    except Exception:
        return None
    return out if out != data else None


def decode_utf16(data: bytes) -> bytes | None:
    if len(data) < 4 or 0 not in data:
        return None
    for enc in ("utf-16-le", "utf-16-be"):
        try:
            text = data.decode(enc)
        except (UnicodeDecodeError, ValueError):
            continue
        out = text.encode("utf-8", "replace")
        if out and out != data:
            return out
    return None


def decode_quoted_printable(data: bytes) -> bytes | None:
    if b"=" not in data:
        return None
    try:
        out = _py_codecs.decode(data, "quopri_codec")
    except Exception:
        return None
    return out if out != data else None


# name -> decoder. Order matters only for presentation; the engine gates by
# detect.applicable_codecs so non-matching codecs are not attempted.
REDUCING = {
    "base64": decode_base64,
    "base32": decode_base32,
    "hex": decode_hex,
    "base85": decode_base85,
    "base58": decode_base58,
    "decimal": decode_decimal,
    "binary": decode_binary,
    "morse": decode_morse,
    "url": decode_url,
    "utf16": decode_utf16,
    "quopri": decode_quoted_printable,
}
