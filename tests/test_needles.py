import base64

from frx.flags.needles import generate_needles


def _labels(needles):
    return {n.label for n in needles}


def test_plain_prefix_present():
    ns = generate_needles("CTF{")
    assert any(n.label == "plain" and n.value == b"CTF{" for n in ns)


def test_base64_needle_matches_embedded_flag_any_alignment():
    ns = [n for n in generate_needles("CTF{") if n.label == "base64"]
    assert ns
    # Embed CTF{...} at each of three byte offsets, b64-encode the whole blob,
    # and require at least one base64 needle to appear.
    for pad in (b"", b"x", b"xy"):
        blob = pad + b"CTF{needle_hunt}" + b"zzzz"
        enc = base64.b64encode(blob)
        assert any(n.value in enc for n in ns), pad


def test_hex_needle_both_cases():
    ns = generate_needles("CTF{")
    hexes = {n.value for n in ns if n.label == "hex"}
    assert b"4354467b" in hexes and b"4354467B" in hexes


def test_rot13_needle_matches():
    ns = {n.label: n.value for n in generate_needles("CTF{")}
    assert ns["rot13"] == b"PGS{"


def test_utf16le_needle():
    ns = {n.label: n.value for n in generate_needles("CTF{")}
    assert ns["utf16le"] == b"C\x00T\x00F\x00{\x00"


def test_url_needle():
    ns = {n.label: n.value for n in generate_needles("CTF{")}
    assert ns["url"] == b"CTF%7B"


def test_reversed_needle():
    ns = {n.label: n.value for n in generate_needles("CTF{")}
    assert ns["reversed"] == b"{FTC"


def test_all_needles_meet_min_length():
    for n in generate_needles("CTF{"):
        assert len(n.value) >= 3
