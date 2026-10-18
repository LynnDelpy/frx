from frx.flags.formats import build_formats
from frx.flags.needles import generate_needles
from frx.flags.scan import scan_flags, scan_needles


def test_scan_flags_finds_confirmed_and_records_offset():
    fmts = build_formats(flag_formats=["CTF{...}"])
    data = b"noise noise CTF{found_it} trailing"
    hits = scan_flags(data, fmts)
    confirmed = [h for h in hits if h.confirmed and h.value == b"CTF{found_it}"]
    assert confirmed and confirmed[0].offset == data.index(b"CTF{")


def test_scan_flags_generic_is_candidate_only():
    fmts = build_formats(flag_formats=[], include_defaults=True)
    data = b"weird12{some_body_here}"
    hits = scan_flags(data, fmts)
    assert all(not h.confirmed for h in hits if h.value == b"weird12{some_body_here}")


def test_scan_needles_locates_and_windows():
    needles = [n for n in generate_needles("CTF{") if n.label == "plain"]
    data = b"x" * 5000 + b"CTF{" + b"y" * 5000
    hits = scan_needles(data, needles)
    assert hits
    h = hits[0]
    assert h.offset == 5000
    assert b"CTF{" in h.window
    assert len(h.window) <= 4096 + len(b"CTF{")


def test_scan_needles_multiple_occurrences():
    needles = [n for n in generate_needles("CTF{") if n.label == "plain"]
    data = b"CTF{a} and CTF{b}"
    hits = scan_needles(data, needles)
    offsets = sorted(h.offset for h in hits)
    assert offsets == [0, 11]
