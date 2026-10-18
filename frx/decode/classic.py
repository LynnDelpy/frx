"""Classic ciphers: Caesar rotations, rot47, atbash, single-byte XOR brute.

These are the "conditional" transforms (amendment A3): unlike reducing codecs,
they preserve length and mostly charset, so the engine only recurses on their
output when there is real evidence (flag match, flag prefix, a clear English
improvement, or a jump into a stricter charset class). Each yields labelled
variants so provenance can name the exact transform (e.g. "rot13", "xor:0x2a").
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass(frozen=True)
class Variant:
    label: str
    data: bytes


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


def rot47(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if 33 <= b <= 126:
            out.append((b - 33 + 47) % 94 + 33)
        else:
            out.append(b)
    return bytes(out)


def atbash(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if 65 <= b <= 90:
            out.append(90 - (b - 65))
        elif 97 <= b <= 122:
            out.append(122 - (b - 97))
        else:
            out.append(b)
    return bytes(out)


def rotations(data: bytes) -> list[Variant]:
    return [Variant(f"rot{n}", _rot_n(data, n)) for n in range(1, 26)]


def xor_brute(data: bytes) -> list[Variant]:
    out = []
    for key in range(1, 256):
        out.append(Variant(f"xor:0x{key:02x}", bytes(b ^ key for b in data)))
    return out


def conditional_variants(data: bytes, xor_max_len: int = 2048) -> list[Variant]:
    """All charset-preserving / conditional transform outputs for a token.

    Single-byte XOR brute is skipped for long tokens: a flag defeated by only a
    one-byte XOR is short, and brute-forcing 255 keys over a long high-entropy
    run is pure cost (amendment A3 keeps XOR, this just bounds it).
    """
    variants: list[Variant] = []
    variants.extend(rotations(data))
    variants.append(Variant("rot47", rot47(data)))
    variants.append(Variant("atbash", atbash(data)))
    variants.append(Variant("reversed", data[::-1]))
    if len(data) <= xor_max_len:
        variants.extend(xor_brute(data))
    return variants
