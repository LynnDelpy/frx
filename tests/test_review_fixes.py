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


def test_parallel_runs_concurrently_and_preserves_order(tmp_path):
    import threading
    import time

    ctx = Context(
        runner=None, findings=FindingWriter(tmp_path), queue=WorkQueue(),
        formats=build_formats(flag_formats=["CTF{...}"]), needles=[],
        case_dir=tmp_path, mode="full", jobs=4,
    )
    peak = [0]
    cur = [0]
    lock = threading.Lock()

    def work(i):
        with lock:
            cur[0] += 1
            peak[0] = max(peak[0], cur[0])
        time.sleep(0.05)
        with lock:
            cur[0] -= 1
        if i == 3:
            raise RuntimeError("boom")  # a failing task yields None, others continue
        return i * i

    res = ctx.parallel([(lambda k=i: work(k)) for i in range(8)])
    ctx.findings.close()
    assert res[0] == 0 and res[2] == 4 and res[7] == 49  # order preserved
    assert res[3] is None                                # failure -> None, not a crash
    assert peak[0] >= 2                                  # genuinely ran in parallel


def test_runner_semaphore_caps_concurrent_tools(tmp_path):
    import threading
    import time

    sem = threading.BoundedSemaphore(2)
    r = Runner(tmp_path, nice=False, concurrency=sem)

    def call():
        r.run(["sleep", "0.3"], timeout=10)

    threads = [threading.Thread(target=call) for _ in range(4)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - t0
    # 4 x 0.3s sleeps, 2 at a time => ~0.6s; unbounded would be ~0.3s.
    assert elapsed >= 0.5


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


def test_identify_memory_probe_is_gated(tmp_path, monkeypatch):
    from frx.engine import identify as idf

    calls = {"n": 0}

    def fake_run(argv, **kw):
        calls["n"] += 1

        class R:
            stdout = b'{"Banner": "Linux version 7.2"}\n'
        return R()

    monkeypatch.setattr(idf.shutil, "which", lambda n: "/usr/bin/vol")
    monkeypatch.setattr(idf.subprocess, "run", fake_run)

    small = tmp_path / "s.bin"
    small.write_bytes(b"\x00" * 100)
    assert idf.identify(small, probe_memory=True) == idf.OTHER
    assert calls["n"] == 0  # too small to spawn the vol probe

    big = tmp_path / "b.raw"
    big.write_bytes(b"\x00" * (17 * 1024 * 1024))
    assert idf.identify(big, probe_memory=True) == idf.MEMORY_RAW  # banner -> raw memory
    assert calls["n"] == 1

    calls["n"] = 0
    assert idf.identify(big, probe_memory=False) == idf.OTHER  # children never probed
    assert calls["n"] == 0


def test_cli_bad_size_exits_cleanly_not_traceback(tmp_path, capsys):
    from frx.cli import main

    rc = main(["run", str(tmp_path), "--max-extracted-size", "4X",
               "--flag-format", "CTF{...}", "--case", str(tmp_path / "case"), "--no-sandbox"])
    assert rc == 2
    assert "invalid size" in capsys.readouterr().err
