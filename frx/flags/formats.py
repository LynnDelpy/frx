"""Flag format parsing and the default flag patterns.

A --flag-format like 'CTF{...}' is split into a literal prefix ('CTF{') and a
closing delimiter ('}'), from which a regex is built. A --flag-regex is used
verbatim. The generic prefix pattern yields candidates, not confirmations
(spec section 7.1, amendment A4).

Byte scans need a body that excludes binary noise, so the default patterns bound
the body to printable ASCII without '}' rather than [^}\\n].
"""

from __future__ import annotations

import dataclasses
import re

# Printable ASCII except '}' and newline, for the flag body in byte scans.
_BODY = r"[ -\|~]{1,256}"  # 0x20..0x7e minus '}' (0x7d) handled below

# Build an explicit class: space (0x20) .. '|' (0x7c), and '~' (0x7e); omit '}'.
_BODY = r"[\x20-\x7c~]{1,256}"

DEFAULT_PATTERNS: tuple[str, ...] = (
    r"flag\{" + _BODY + r"\}",
    r"CTF\{" + _BODY + r"\}",
    r"[A-Za-z0-9_]{2,16}\{" + _BODY + r"\}",  # generic prefix{...}: candidates only
)


@dataclasses.dataclass(frozen=True)
class FlagFormat:
    """A parsed flag format.

    prefix is the literal lead-in (e.g. 'CTF{') used to seed needle generation.
    regex matches a full flag. confirmed marks whether a hit is a terminal flag
    (True for user-supplied formats/regexes) or only a candidate (the generic
    default pattern).
    """

    prefix: str
    regex: re.Pattern
    confirmed: bool = True
    source: str = ""


def parse_flag_format(fmt: str) -> FlagFormat:
    """Parse 'PREFIX{...}' style input into a FlagFormat.

    The wildcard marker is '...' if present, else the first '{'. Everything up
    to and including the opening delimiter is the literal prefix; the trailing
    character(s) after the wildcard are the closing delimiter.
    """
    marker = fmt.find("...")
    if marker != -1:
        prefix = fmt[:marker]
        suffix = fmt[marker + 3:]
    else:
        brace = fmt.find("{")
        if brace == -1:
            # No structure: treat the whole thing as a literal prefix word.
            prefix = fmt
            suffix = ""
        else:
            prefix = fmt[: brace + 1]
            suffix = fmt[brace + 1:]
    body = _BODY if suffix else r"[\x20-\x7e]{1,256}"
    pattern = re.escape(prefix) + body + (re.escape(suffix) if suffix else "")
    return FlagFormat(
        prefix=prefix,
        regex=re.compile(pattern.encode(), re.IGNORECASE),
        confirmed=True,
        source=fmt,
    )


def compile_flag_regex(pattern: str) -> FlagFormat:
    """Wrap a user-supplied --flag-regex. Confirmed, prefix taken up to '{'."""
    brace = pattern.find("{")
    prefix = pattern[: brace + 1] if brace != -1 else pattern
    prefix = re.sub(r"\\(.)", r"\1", prefix)  # unescape for needle seeding
    return FlagFormat(
        prefix=prefix,
        regex=re.compile(pattern.encode(), re.IGNORECASE),
        confirmed=True,
        source=pattern,
    )


def default_formats() -> list[FlagFormat]:
    """The shipped patterns, scanned alongside any user format.

    The generic prefix{...} pattern is marked unconfirmed (candidates only).
    """
    out: list[FlagFormat] = []
    for i, pat in enumerate(DEFAULT_PATTERNS):
        confirmed = i < 2  # flag{...} and CTF{...} confirm; generic does not
        prefix = {0: "flag{", 1: "CTF{"}.get(i, "")
        out.append(
            FlagFormat(prefix=prefix, regex=re.compile(pat.encode(), re.IGNORECASE),
                       confirmed=confirmed, source=pat)
        )
    return out


def build_formats(
    flag_formats: list[str] | None = None,
    flag_regexes: list[str] | None = None,
    include_defaults: bool = True,
) -> list[FlagFormat]:
    """Assemble the active FlagFormat list from CLI/config inputs."""
    formats: list[FlagFormat] = []
    for fmt in flag_formats or []:
        formats.append(parse_flag_format(fmt))
    for rx in flag_regexes or []:
        formats.append(compile_flag_regex(rx))
    if include_defaults:
        formats.extend(default_formats())
    # Deduplicate by compiled pattern, keeping the first (user formats win).
    seen: set[bytes] = set()
    unique: list[FlagFormat] = []
    for f in formats:
        key = f.regex.pattern
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
