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


# Every transform here is a fixed byte->byte mapping, so each is precomputed once
# as a 256-byte translation table and applied with bytes.translate() (a C-speed
# loop). This matters: the decoder runs these over thousands of candidate tokens,
# and a per-byte Python loop made that the dominant cost of a full pass.

def _build_rot_table(n: int) -> bytes:
    t = bytearray(range(256))
    for b in range(65, 91):
        t[b] = (b - 65 + n) % 26 + 65
    for b in range(97, 123):
        t[b] = (b - 97 + n) % 26 + 97
    return bytes(t)


_ROT_TABLES = [_build_rot_table(n) for n in range(26)]


def _build_rot47_table() -> bytes:
    t = bytearray(range(256))
    for b in range(33, 127):
        t[b] = (b - 33 + 47) % 94 + 33
    return bytes(t)


_ROT47_TABLE = _build_rot47_table()


def _build_atbash_table() -> bytes:
    t = bytearray(range(256))
    for b in range(65, 91):
        t[b] = 90 - (b - 65)
    for b in range(97, 123):
        t[b] = 122 - (b - 97)
    return bytes(t)


_ATBASH_TABLE = _build_atbash_table()

# One translation table per XOR key (key 0 is identity and unused by xor_brute).
_XOR_TABLES = [bytes(i ^ k for i in range(256)) for k in range(256)]


def _rot_n(data: bytes, n: int) -> bytes:
    return data.translate(_ROT_TABLES[n % 26])


def rot47(data: bytes) -> bytes:
    return data.translate(_ROT47_TABLE)


def atbash(data: bytes) -> bytes:
    return data.translate(_ATBASH_TABLE)


def rotations(data: bytes) -> list[Variant]:
    return [Variant(f"rot{n}", data.translate(_ROT_TABLES[n])) for n in range(1, 26)]


def xor_brute(data: bytes) -> list[Variant]:
    return [Variant(f"xor:0x{key:02x}", data.translate(_XOR_TABLES[key])) for key in range(1, 256)]


COND_MAX_LEN = 8192  # a Caesar/XOR-wrapped flag is short; skip these on long runs


def conditional_variants(data: bytes, xor_max_len: int = 2048) -> list[Variant]:
    """All charset-preserving / conditional transform outputs for a token.

    A flag defeated by only a rotation or single-byte XOR is short, so these
    length-preserving transforms are skipped entirely above COND_MAX_LEN (each
    one copies the whole token, and brute-forcing them over a long high-entropy
    run is pure cost). XOR brute is bounded tighter still (amendment A3 keeps the
    transforms; this only bounds them).
    """
    if len(data) > COND_MAX_LEN:
        return []
    variants: list[Variant] = []
    variants.extend(rotations(data))
    variants.append(Variant("rot47", rot47(data)))
    variants.append(Variant("atbash", atbash(data)))
    variants.append(Variant("reversed", data[::-1]))
    if len(data) <= xor_max_len:
        variants.extend(xor_brute(data))
    return variants
