"""Render findings.jsonl into report.md.

Order (spec section 11): confirmed flags with full provenance and the exact
reproduction command first, then high-signal artifacts, then decoded candidates,
then the extracted-file tree, then per-handler sections. Reproducibility is the
point: every claim carries the command that produced it.
"""

from __future__ import annotations

import json
from pathlib import Path


def _load(case_dir: Path) -> list[dict]:
    jsonl = case_dir / "findings.jsonl"
    if not jsonl.is_file():
        return []
    out = []
    for line in jsonl.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _prov(f: dict) -> str:
    return " -> ".join(f.get("provenance", []))


def render(case_dir: Path) -> str:
    case_dir = Path(case_dir)
    findings = _load(case_dir)
    flags = [f for f in findings if f.get("flag")]
    candidates = [f for f in findings if f.get("type") == "flag_candidate"]
    decoded = [f for f in findings if f.get("type") == "decoded"]
    extracted = [f for f in findings if f.get("type") == "extracted_file"]
    artifacts = [f for f in findings if f.get("type") == "artifact" and f.get("severity") == "high"]

    lines: list[str] = []
    lines.append(f"# frx report: {case_dir.name}")
    lines.append("")

    # Confirmed flags, deduped by value, first hit wins.
    lines.append("## Confirmed flags")
    seen: set[str] = set()
    uniq_flags = [f for f in flags if not (f["value"] in seen or seen.add(f["value"]))]
    if not uniq_flags:
        lines.append("")
        lines.append("_None._")
    for f in uniq_flags:
        lines.append("")
        lines.append(f"### `{f['value']}`")
        lines.append(f"- provenance: `{_prov(f)}`")
        if f.get("command"):
            lines.append(f"- command: `{f['command']}`")
        if f.get("offset") is not None:
            lines.append(f"- offset: {f['offset']}")
        lines.append(f"- item: `{f.get('item_sha', '')[:12]}`")
    lines.append("")

    lines.append("## High-signal artifacts")
    if not artifacts:
        lines.append("")
        lines.append("_None._")
    for f in artifacts:
        lines.append(f"- {f['value']}  ·  `{_prov(f)}`")
    lines.append("")

    lines.append("## Decoded candidates")
    if not decoded:
        lines.append("")
        lines.append("_None._")
    for f in decoded[:200]:
        lines.append(f"- `{f['value']}`  (conf {f.get('confidence', 0):.2f})  ·  `{_prov(f)}`")
    lines.append("")

    lines.append("## Flag candidates (unconfirmed)")
    if not candidates:
        lines.append("")
        lines.append("_None._")
    cseen: set[str] = set()
    for f in candidates:
        if f["value"] in cseen:
            continue
        cseen.add(f["value"])
        lines.append(f"- `{f['value']}`  ·  `{_prov(f)}`")
    lines.append("")

    lines.append("## Extracted files")
    lines.append("")
    lines.append(f"{len(extracted)} file(s) extracted.")
    for f in extracted[:500]:
        lines.append(f"- `{f['value']}`  ·  `{_prov(f)}`")
    lines.append("")

    # Per-handler counts.
    lines.append("## Per-handler summary")
    lines.append("")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.get("handler", "?")] = counts.get(f.get("handler", "?"), 0) + 1
    for h, n in sorted(counts.items()):
        lines.append(f"- {h}: {n} finding(s)")
    lines.append("")

    return "\n".join(lines)


def write_report(case_dir: Path) -> Path:
    case_dir = Path(case_dir)
    out = case_dir / "report.md"
    out.write_text(render(case_dir), encoding="utf-8")
    return out
