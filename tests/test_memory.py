"""Milestone 6: memory handler logic with a scripted vol (no real dump needed)."""

import shutil

import pytest

from frx.engine.context import Context
from frx.engine.queue import WorkQueue
from frx.engine.runner import RunResult
from frx.flags.formats import build_formats
from frx.handlers import memory, vol
from frx.report.findings import FindingWriter


class FakeRunner:
    def __init__(self, case_dir, script):
        self.default_timeout = 300.0
        self.case_dir = case_dir
        self._script = script
        self.calls = []

    def run(self, argv, timeout=None, **kw):
        self.calls.append(argv)
        out = self._script(argv)
        return RunResult(argv, 0, out, b"", 0.01)


def _ctx(tmp_path, runner):
    fw = FindingWriter(tmp_path)
    return Context(
        runner=runner, findings=fw, queue=WorkQueue(), formats=build_formats(flag_formats=["CTF{...}"]),
        needles=[], case_dir=tmp_path, mode="full", vol_plugin_timeout=300.0,
    )


def _findings(tmp_path):
    import json
    return [json.loads(l) for l in (tmp_path / "findings.jsonl").read_text().splitlines() if l.strip()]


def test_parse_jsonl_skips_noise():
    rows = vol.parse_jsonl('garbage\n{"a": 1}\n{"b": 2}\nnotjson')
    assert rows == [{"a": 1}, {"b": 2}]


def test_run_plugin_argv_is_offline_jsonl(tmp_path):
    captured = {}

    def script(argv):
        captured["argv"] = argv
        return b""

    runner = FakeRunner(tmp_path, script)
    ctx = _ctx(tmp_path, runner)

    class It:
        sha256 = "ab" * 32
        path = tmp_path / "mem.raw"
        provenance = ["mem.raw"]
        short = "abcdef012345"
    (tmp_path / "mem.raw").write_bytes(b"x")
    vol.run_plugin(ctx, It(), "banners.Banners")
    a = captured["argv"]
    assert a[0] == "vol" and "--offline" in a
    assert a[a.index("-r") + 1] == "jsonl"
    assert "--cache-path" in a and "-s" in a and "-f" in a
    assert a[-1] == "banners.Banners"


def test_honest_limit_when_no_symbols(tmp_path):
    (tmp_path / "mem.raw").write_bytes(b"EMiL" + b"\x00" * 100)

    def script(argv):
        if argv[-1] == "banners.Banners":
            return b'{"Banner": "Linux version 7.2.9-2-cachyos"}\n'
        if argv == ["vol", "-h"]:
            return b"  windows.info.Info  x\n  linux.pslist.PsList  x\n"
        return b""  # info/pslist probes return nothing -> no symbols

    runner = FakeRunner(tmp_path, script)
    ctx = _ctx(tmp_path, runner)

    class It:
        sha256 = "ab" * 32
        path = tmp_path / "mem.raw"
        provenance = ["mem.raw"]
        short = "abcdef012345"
        depth = 0
    memory.handle(It(), ctx)
    ctx.findings.close()
    vals = [f["value"] for f in _findings(tmp_path)]
    assert any("not analyzable past banners" in v for v in vals)
    assert any("7.2.9-2-cachyos" in v for v in vals)


def test_flag_in_plugin_output_is_found(tmp_path):
    (tmp_path / "mem.raw").write_bytes(b"EMiL" + b"\x00" * 100)

    def script(argv):
        if argv[-1] == "banners.Banners":
            return b'{"Banner": "Linux version 7.2.9"}\n'
        if argv == ["vol", "-h"]:
            return b"  linux.pslist.PsList  x\n  linux.bash.Bash  x\n"
        if argv[-1] == "linux.pslist.PsList":
            return b'{"PID": 1337, "COMM": "CTF{memory_flag_here}"}\n'
        if argv[-1] == "linux.bash.Bash":
            return b'{"Command": "echo done"}\n'
        return b""

    runner = FakeRunner(tmp_path, script)
    ctx = _ctx(tmp_path, runner)

    class It:
        sha256 = "cd" * 32
        path = tmp_path / "mem.raw"
        provenance = ["mem.raw"]
        short = "abcdef012345"
        depth = 0
    memory.handle(It(), ctx)
    ctx.findings.close()
    flags = [f["value"] for f in _findings(tmp_path) if f.get("flag")]
    assert "CTF{memory_flag_here}" in flags


@pytest.mark.skipif(not vol.vol_available(), reason="needs volatility3")
def test_list_plugins_real_vol(tmp_path):
    from frx.engine.runner import Runner

    ctx = _ctx(tmp_path, Runner(tmp_path, nice=False))
    plugins = vol.list_plugins(ctx)
    assert "banners.Banners" in plugins
    assert "windows.info.Info" in plugins
    assert "linux.pslist.PsList" in plugins
