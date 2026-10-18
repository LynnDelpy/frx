"""Milestone 2 end-to-end: the recursive decoder on a nested encoding."""

import base64
import codecs as _c

from frx.cli import main


def _nest(flag: bytes) -> bytes:
    b64 = base64.b64encode(flag)  # no trailing newline, unlike the shell fixture
    hexed = b64.hex().encode()
    return _c.encode(hexed.decode(), "rot13").encode()


def test_nested_base64_hex_rot13(tmp_path):
    token = _nest(b"CTF{nested_pipeline_works}")
    blob = b"A" * 200 + b"\n" + token + b"\n" + b"B" * 200
    inp = tmp_path / "nested.txt"
    inp.write_bytes(blob)
    case = tmp_path / "case"
    rc = main(["run", str(inp), "--mode", "full", "--flag-format", "CTF{...}", "--case", str(case)])
    assert rc == 0
    flags = (case / "FLAGS.txt").read_text()
    assert "CTF{nested_pipeline_works}" in flags
    # the provenance records the decode chain
    assert "rot13 -> hex -> base64" in flags
