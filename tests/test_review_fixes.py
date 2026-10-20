"""Guards for the cross-cutting fixes from the full-codebase review."""

import json

import pytest

from frx.config import parse_duration, parse_size
from frx.engine.context import Context
from frx.engine.queue import WorkQueue
from frx.engine.runner import Runner
from frx.flags.formats import build_formats
from frx.report.findings import FindingWriter


class _It:
    sha256 = "ab" * 32
    provenance = ["x"]
    short = "abcdef012345"


def _ctx(tmp_path):
    return Context(
        runner=None, findings=FindingWriter(tmp_path), queue=WorkQueue(),
        formats=build_formats(flag_formats=["CTF{...}"]), needles=[],
        case_dir=tmp_path, mode="full",
    )


def test_run_to_file_streams_stdout_not_memory(tmp_path):
    r = Runner(tmp_path, nice=False)
    out = tmp_path / "o.bin"
    with out.open("wb") as fh:
        res = r.run_to_file(["printf", "hello-stream"], fh, timeout=30)
    assert res.stdout == b""              # not held in memory
    assert out.read_bytes() == b"hello-stream"


def test_scan_and_decode_emits_confirmed_and_candidates(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.scan_and_decode(_It(), b"noise foo{bar} then CTF{real}", "image:exiftool", "image")
    ctx.findings.close()
    rows = [json.loads(l) for l in (tmp_path / "findings.jsonl").read_text().splitlines() if l.strip()]
    pairs = {(r["type"], r["value"]) for r in rows}
    assert ("flag", "CTF{real}") in pairs                 # confirmed
    assert any(t == "flag_candidate" for t, _ in pairs)   # foo{bar} -> candidate, not dropped


def test_parse_size_and_duration_reject_bad_values():
    assert parse_size("4G") == 4 * 1024**3
    assert parse_duration("40m") == 2400
    with pytest.raises(ValueError):
        parse_size("4X")
    with pytest.raises(ValueError):
        parse_duration("abc")


def test_cli_bad_size_exits_cleanly_not_traceback(tmp_path, capsys):
    from frx.cli import main

    rc = main(["run", str(tmp_path), "--max-extracted-size", "4X",
               "--flag-format", "CTF{...}", "--case", str(tmp_path / "case"), "--no-sandbox"])
    assert rc == 2
    assert "invalid size" in capsys.readouterr().err
