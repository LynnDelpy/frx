"""Charset classification and candidate-token extraction (spec section 8).

Two jobs. (1) classes(token) names the stricter charset families a token fits
(hex, base64, base32, base58, binary) so the engine can tell when a
charset-preserving transform lands in a stricter class and is worth recursing
(amendment A3). (2) extract_tokens pulls the long high-purity runs out of a
noisy window, which are the decoder's candidate sources besides needle hits.
"""

from __future__ import annotations

import re

_HEX = re.compile(rb"^[0-9a-fA-F]+$")
_B64 = re.compile(rb"^[A-Za-z0-9+/]+=*$")
_B32 = re.compile(rb"^[A-Z2-7]+=*$")
_B58 = re.compile(rb"^[1-9A-HJ-NP-Za-km-z]+$")
_BIN = re.compile(rb"^[01]+$")

# Maximal runs of base64/hex/base32/base58-ish characters.
_RUN = re.compile(rb"[A-Za-z0-9+/=]{%d,}")


_WS = b" \t\r\n\v\f"


def _strip_ws(data: bytes) -> bytes:
    # C-speed whitespace strip: classes() runs this on every candidate variant
    # the decoder considers, so a per-byte Python loop here dominated a full pass.
    return data.translate(None, _WS)


def classes(token: bytes) -> set[str]:
    """The stricter charset families this token belongs to."""
    s = _strip_ws(token)
    out: set[str] = set()
    if not s:
        return out
    body = s.rstrip(b"=")
    if len(s) >= 4 and len(s) % 2 == 0 and _HEX.match(s):
        out.add("hex")
    if len(body) >= 8 and len(s) % 4 == 0 and _B64.match(s):
        out.add("base64")
    if len(body) >= 8 and len(s) % 8 == 0 and _B32.match(s):
        out.add("base32")
    if len(s) >= 4 and _B58.match(s):
        out.add("base58")
    if len(s) >= 8 and len(s) % 8 == 0 and _BIN.match(s):
        out.add("binary")
    return out


def token_codecs(token: bytes) -> list[str]:
    """Reducing codecs worth trying on a single high-purity token."""
    cls = classes(token)
    order = ["hex", "base64", "base32", "base58", "binary"]
    return [c for c in order if c in cls]


def blob_codecs(blob: bytes) -> list[str]:
    """Reducing codecs that operate on a whole blob (need delimiters/structure)."""
    out: list[str] = []
    if b"%" in blob:
        out.append("url")
    if b"=" in blob and re.search(rb"=[0-9A-Fa-f]{2}", blob):
        out.append("quopri")
    if 0 in blob:
        out.append("utf16")
    text = blob.strip()
    if text and all(c in b".-/ \t\n" for c in text):
        out.append("morse")
    toks = re.split(rb"[\s,]+", blob.strip())
    if len(toks) >= 2 and all(t.isdigit() for t in toks if t):
        out.append("decimal")
    s = _strip_ws(blob)
    if len(s) >= 8 and len(s) % 8 == 0 and _BIN.match(s):
        out.append("binary")
    return out


def extract_tokens(blob: bytes, min_len: int = 12, max_tokens: int = 4000) -> list[bytes]:
    """Distinct high-purity runs in a (possibly noisy) blob, longest first."""
    runs = re.compile(rb"[A-Za-z0-9+/=]{%d,}" % min_len).findall(blob)
    seen: set[bytes] = set()
    out: list[bytes] = []
    for r in sorted(runs, key=len, reverse=True):
        if r in seen:
            continue
        seen.add(r)
        out.append(r)
        if len(out) >= max_tokens:
            break
    return out
