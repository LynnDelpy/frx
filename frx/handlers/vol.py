"""Volatility 3 interface: argv construction, plugin discovery, ISF build.

vol3 lives in its own Python 3.12 venv, so it is driven as a subprocess with the
JSONL renderer (amendment A2), always --offline with a case-private cache. This
module keeps the vol-specific mechanics out of the handler flow in memory.py.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from ..engine.context import Context
from ..engine.queue import Item

_PLUGIN_RE = re.compile(r"^\s{2,}([a-z][a-z0-9_]*(?:\.[A-Za-z0-9_]+)+)\b")


def vol_available() -> bool:
    return shutil.which("vol") is not None


def symbols_dir(ctx: Context) -> Path:
    base = ctx.vol_symbols or "~/.local/share/frx/symbols"
    return Path(base).expanduser()


def _cache_dir(ctx: Context) -> Path:
    d = ctx.case_dir / "vol-cache"
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_plugins(ctx: Context) -> set[str]:
    res = ctx.runner.run(["vol", "-h"], timeout=120)
    plugins: set[str] = set()
    for line in res.out_text().splitlines():
        m = _PLUGIN_RE.match(line)
        if m:
            plugins.add(m.group(1))
    return plugins


def run_plugin(ctx: Context, item: Item, plugin: str, extra: list[str] | None = None,
               dump_dir: Path | None = None, timeout: float | None = None):
    argv = [
        "vol", "-q", "-r", "jsonl", "--offline",
        "--cache-path", str(_cache_dir(ctx)),
        "-s", str(symbols_dir(ctx)),
    ]
    if dump_dir is not None:
        dump_dir.mkdir(parents=True, exist_ok=True)
        argv += ["-o", str(dump_dir)]
    argv += ["-f", str(item.path), plugin]
    if extra:
        argv += extra
    return ctx.runner.run(argv, timeout=timeout or ctx.vol_plugin_timeout)


def parse_jsonl(text: str) -> list[dict]:
    import json

    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def build_isf(ctx: Context, vmlinux: str, system_map: str | None) -> Path | None:
    """Build a Linux ISF from a vmlinux via dwarf2json, xz it into symbols/linux.

    Returns the written .json.xz path, or None if dwarf2json is unavailable or
    fails. vol3 discovers the ISF by banner match on the next plugin run.
    """
    if shutil.which("dwarf2json") is None:
        return None
    out_dir = symbols_dir(ctx) / "linux"
    out_dir.mkdir(parents=True, exist_ok=True)
    name = Path(vmlinux).stem or "kernel"
    argv = ["dwarf2json", "linux", "--elf", str(vmlinux)]
    if system_map:
        argv += ["--system-map", str(system_map)]
    res = ctx.runner.run(argv, timeout=ctx.runner.default_timeout)
    if res.returncode != 0 or not res.stdout:
        return None
    # xz-compress into the symbols dir (vol3 reads .json.xz). Write to a unique
    # temp and atomically rename so two dumps built in parallel for the same
    # vmlinux cannot interleave their writes into a corrupt ISF.
    import lzma
    import os
    import threading

    dest = out_dir / f"{name}.json.xz"
    tmp = out_dir / f".{name}.{os.getpid()}.{threading.get_ident()}.tmp"
    try:
        with lzma.open(tmp, "wb") as fh:
            fh.write(res.stdout)
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)
    return dest
