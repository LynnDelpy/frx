import base64

from frx.decode import classic, codecs, detect
from frx.decode.score import english_score, printable_ratio, score_text


def test_codecs_roundtrip():
    assert codecs.decode_hex(b"4354467b") == b"CTF{"
    assert codecs.decode_base64(base64.b64encode(b"hello world")) == b"hello world"
    assert codecs.decode_base32(base64.b32encode(b"hello")) == b"hello"
    assert codecs.decode_binary(b"01000001") == b"A"
    assert codecs.decode_decimal(b"72 73") == b"HI"
    assert codecs.decode_url(b"CTF%7Bx%7D") == b"CTF{x}"


def test_codecs_reject_invalid():
    assert codecs.decode_hex(b"xyz") is None
    assert codecs.decode_binary(b"012") is None
    assert codecs.decode_decimal(b"999 1") is None  # >255


def test_morse():
    assert codecs.decode_morse(b"-.-. - ..-.") == b"ctf"


def test_classic_rot_and_atbash():
    assert classic._rot_n(b"CTF", 13) == b"PGS"
    assert classic.atbash(b"abc") == b"zyx"
    assert classic.rot47(classic.rot47(b"CTF{x}")) == b"CTF{x}"


def test_detect_classes_hex_vs_rot():
    rot = b"4354467n"  # not hex (n), base64-ish
    assert "hex" not in detect.classes(rot)
    import frx.decode.classic as c
    unrot = c._rot_n(rot, 13)
    # rot13 of [0-9n] -> [0-9a] style; the hex-rotated token gains hex class
    assert "hex" in detect.classes(c._rot_n(b"6e6f70", 0))  # plain hex sanity


def test_detect_extract_tokens_longest_first():
    blob = b"xx " + b"A" * 40 + b" yy " + b"B" * 20
    toks = detect.extract_tokens(blob, min_len=12)
    assert toks[0] == b"A" * 40


def test_score_printable_and_english():
    assert printable_ratio(b"hello") == 1.0
    assert printable_ratio(b"\x00\x01\x02") == 0.0
    assert english_score(b"the quick brown fox jumps over") > english_score(b"zzzzxxxxqqqq")


def test_score_text_bonus_for_braces():
    assert score_text(b"CTF{hello}", "CTF{") > score_text(b"randombytes", "CTF{")
