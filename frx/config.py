"""Configuration: defaults, TOML file, size/duration parsing.

Precedence (low to high): built-in defaults, ~/.config/frx/config.toml, then
CLI flags (applied by cli.py). Sizes accept K/M/G suffixes; durations accept
s/m/h. Kept dependency-free (tomllib is stdlib on 3.11+).
"""

from __future__ import annotations

import dataclasses
import os
import tomllib
from pathlib import Path

CONFIG_PATH = Path(os.path.expanduser("~/.config/frx/config.toml"))

_SIZE_UNITS = {"": 1, "b": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def parse_size(v) -> int:
    if isinstance(v, int):
        return v
    s = str(v).strip().lower()
    if not s:
        return 0
    unit = s[-1]
    try:
        if unit.isdigit():
            return int(s)
        mult = _SIZE_UNITS.get(unit)
        if mult is None:
            raise ValueError
        return int(float(s[:-1]) * mult)
    except ValueError:
        raise ValueError(f"invalid size {v!r} (use e.g. 4G, 500M, 1024)")


_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600}


def parse_duration(v) -> float:
    """Return seconds. Accepts '40m', '90s', '1h', or a bare number (seconds)."""
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip().lower()
    if not s:
        return 0.0
    unit = s[-1]
    try:
        if unit.isdigit():
            return float(s)
        mult = _DURATION_UNITS.get(unit)
        if mult is None:
            raise ValueError
        return float(s[:-1]) * mult
    except ValueError:
        raise ValueError(f"invalid duration {v!r} (use e.g. 40m, 90s, 1h)")


# Where a rockyou-style wordlist usually lives; the first that exists becomes
# the default, so archive-password / stego cracking runs without --wordlist.
_WORDLIST_PATHS = (
    "~/.local/share/frx/wordlists/rockyou.txt",  # where `frx setup --with-wordlists` puts it
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",        # noted below; gz is not used directly
)


def default_wordlist() -> str | None:
    """First existing rockyou-style wordlist, or None. Used as the default so
    encrypted archives and stego are brute-forced automatically when a wordlist
    is present (no --wordlist needed)."""
    for p in _WORDLIST_PATHS:
        q = Path(p).expanduser()
        if q.is_file() and not q.name.endswith(".gz"):
            return str(q)
    return None


@dataclasses.dataclass
class Config:
    flag_formats: list[str] = dataclasses.field(default_factory=lambda: ["CTF{...}", "flag{...}"])
    flag_regexes: list[str] = dataclasses.field(default_factory=list)
    wordlist: str | None = None
    jobs: int = max(1, (os.cpu_count() or 2) - 1)
    per_tool_timeout: float = 300.0
    vol_plugin_timeout: float = 300.0
    max_depth: int = 6
    max_files: int = 50000
    max_extracted_size: int = 4 * 1024**3
    vol_symbols: str = "~/.local/share/frx/symbols"

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        cfg = cls()
        path = path or CONFIG_PATH
        if path.is_file():
            data = tomllib.loads(path.read_text())
            if "flag_formats" in data:
                cfg.flag_formats = list(data["flag_formats"])
            if "wordlist" in data:
                cfg.wordlist = data["wordlist"]
            if "jobs" in data:
                cfg.jobs = int(data["jobs"])
            t = data.get("timeouts", {})
            if "per_tool" in t:
                cfg.per_tool_timeout = parse_duration(t["per_tool"])
            if "vol_plugin" in t:
                cfg.vol_plugin_timeout = parse_duration(t["vol_plugin"])
            lim = data.get("limits", {})
            if "max_depth" in lim:
                cfg.max_depth = int(lim["max_depth"])
            if "max_files" in lim:
                cfg.max_files = int(lim["max_files"])
            if "max_extracted_size" in lim:
                cfg.max_extracted_size = parse_size(lim["max_extracted_size"])
            paths = data.get("paths", {})
            if "vol_symbols" in paths:
                cfg.vol_symbols = paths["vol_symbols"]
        # Auto-select a rockyou wordlist if none was configured, so cracking is
        # automatic when one is installed.
        if cfg.wordlist is None:
            cfg.wordlist = default_wordlist()
        return cfg
