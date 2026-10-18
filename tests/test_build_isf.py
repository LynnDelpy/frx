"""Milestone 6: the ISF build path against the real dwarf2json binary.

A live Linux memory analysis also needs a kernel dump whose exact DWARF vmlinux
is downloadable; for the running CachyOS kernel that debug package is purged
from the mirror (the very limitation the handler surfaces at runtime). This test
proves the novel code: build_isf drives dwarf2json over a DWARF ELF and writes a
valid xz-compressed ISF into the symbols dir where vol3 would find it.
"""

import json
import lzma
import shutil
import subprocess

import pytest

from frx.engine.context import Context
from frx.engine.queue import WorkQueue
from frx.engine.runner import Runner
from frx.flags.formats import build_formats
from frx.handlers import vol
from frx.report.findings import FindingWriter

_HAS = shutil.which("dwarf2json") and shutil.which("gcc")


@pytest.mark.skipif(not _HAS, reason="needs dwarf2json + gcc")
def test_build_isf_writes_valid_xz_isf(tmp_path):
    src = tmp_path / "t.c"
    src.write_text(
        "struct task_like { int pid; char comm[16]; };\n"
        "struct task_like the_task = { .pid = 1, .comm = \"init\" };\n"
        "unsigned long linux_banner = 0xdeadbeef;\n"
        "int main(void){ return the_task.pid; }\n"
    )
    elf = tmp_path / "vmlinux_test"
    subprocess.run(["gcc", "-g", "-gdwarf-4", "-O0", "-o", str(elf), str(src)], check=True)

    symbols = tmp_path / "symbols"
    fw = FindingWriter(tmp_path)
    ctx = Context(
        runner=Runner(tmp_path, nice=False), findings=fw, queue=WorkQueue(),
        formats=build_formats(flag_formats=["CTF{...}"]), needles=[], case_dir=tmp_path,
        vol_symbols=str(symbols),
    )
    dest = vol.build_isf(ctx, str(elf), None)
    assert dest is not None and dest.exists()
    assert dest.parent == symbols / "linux"
    assert dest.suffix == ".xz"

    with lzma.open(dest, "rb") as fh:
        isf = json.loads(fh.read())
    assert "metadata" in isf and "symbols" in isf
    assert "linux_banner" in isf["symbols"]  # our symbol made it into the ISF
    assert "task_like" in isf.get("user_types", {})  # DWARF struct type captured
