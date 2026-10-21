"""Decode engine performance + quality guards.

These lock in the milestone-7 follow-up work: the classic transforms and the
scorer were rewritten to run at C speed (bytes.translate / bytes.count) and must
stay byte-for-byte identical; the recursive decoder gained a hard per-item op
budget so base64 noise can no longer blow up a pass; and single-byte-XOR brute
matches are demoted to candidates so FLAGS.txt is not flooded with coincidences.
"""

import base64
import random
import time

from frx.decode import classic
from frx.decode.engine import MAX_OPS_PER_ITEM, DecodeEngine
from frx.decode.score import english_score, printable_ratio
from frx.flags.formats import build_formats


# -- the C-speed rewrites must match the obvious reference implementations ----

def test_classic_transforms_match_reference():
    data = bytes(range(256)) * 3
    for n in range(26):
        ref = bytes(
            (b - 65 + n) % 26 + 65 if 65 <= b <= 90
            else (b - 97 + n) % 26 + 97 if 97 <= b <= 122
            else b
            for b in data
        )
        assert classic._rot_n(data, n) == ref
    assert classic.atbash(data) == bytes(
        90 - (b - 65) if 65 <= b <= 90 else 122 - (b - 97) if 97 <= b <= 122 else b for b in data
    )
    assert classic.rot47(data) == bytes((b - 33 + 47) % 94 + 33 if 33 <= b <= 126 else b for b in data)
    xs = classic.xor_brute(data)
    assert len(xs) == 255
    assert xs[0].label == "xor:0x01" and xs[0].data == bytes(b ^ 1 for b in data)
    assert xs[-1].label == "xor:0xff" and xs[-1].data == bytes(b ^ 0xFF for b in data)


def test_printable_ratio_matches_reference():
    printable = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
    for data in [b"hello", b"\x00\x01\x02", bytes(range(256)), b"The quick brown fox", b""]:
        ref = (sum(1 for b in data if b in printable) / len(data)) if data else 0.0
        assert abs(printable_ratio(data) - ref) < 1e-9


def test_english_score_still_separates_text_from_noise():
    assert english_score(b"the quick brown fox jumps over") > english_score(b"zzzzxxxxqqqq")
    assert english_score(b"abc") == 0.0  # below the 4-letter floor


# -- a fake context just captures emitted findings ---------------------------

class _Ctx:
    def __init__(self):
        self.formats = build_formats(flag_formats=["CTF{...}"])
        self.emitted = []

    def emit(self, f):
        self.emitted.append(f)

    def log(self, msg):
        pass


class _Item:
    sha256 = "ab" * 32
    provenance = ["x"]
    short = "abcdef012345"


def _flags(ctx):
    return [f for f in ctx.emitted if getattr(f, "flag", False)]


def _candidates(ctx):
    return [f for f in ctx.emitted if f.type == "flag_candidate"]


# -- XOR-brute matches are leads, not confirmations ---------------------------

def test_xor_terminal_match_is_candidate_not_confirmed():
    ctx = _Ctx()
    eng = DecodeEngine(ctx)
    eng._emit_flags(b"CTF{looks_real}", _Item(), ["raw", "xor:0x2a"])
    assert not _flags(ctx)  # not written to FLAGS.txt
    assert any("CTF{looks_real}" in f.value for f in _candidates(ctx))


def test_reducing_chain_match_is_confirmed():
    ctx = _Ctx()
    eng = DecodeEngine(ctx)
    eng._emit_flags(b"CTF{real}", _Item(), ["raw", "base64"])
    assert any("CTF{real}" in f.value for f in _flags(ctx))


def test_direct_presence_still_confirmed():
    ctx = _Ctx()
    eng = DecodeEngine(ctx)
    eng._emit_flags(b"CTF{right_here}", _Item(), ["raw"])
    assert any("CTF{right_here}" in f.value for f in _flags(ctx))


# -- the decoder is bounded on a wall of base64 noise -------------------------

def test_decode_is_bounded_on_base64_noise():
    ctx = _Ctx()
    eng = DecodeEngine(ctx)
    rng = random.Random(1234)  # deterministic noise so the assertion is stable
    noise = b"\n".join(
        base64.b64encode(bytes(rng.randrange(256) for _ in range(300))) for _ in range(3000)
    )  # ~1.6 MB
    t0 = time.monotonic()
    eng.decode_candidate(noise, _Item(), ["raw"])
    elapsed = time.monotonic() - t0
    assert eng._ops.get(_Item.sha256, 0) <= MAX_OPS_PER_ITEM  # the hard ceiling held
    assert elapsed < 45  # bounded, not the former >120s blow-up
    assert not _flags(ctx)  # pure noise yields no confirmed flags
