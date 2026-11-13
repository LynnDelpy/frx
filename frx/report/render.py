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


def _dedupe(items: list[dict]) -> list[dict]:
    """Drop findings identical in value + provenance, preserving first order.

    A resume reprocesses any item that was interrupted before it was marked
    done, so its handlers re-emit the same findings into findings.jsonl. Only
    flags are deduped at write time; this keeps the other report sections from
    listing the same artifact/decode/extracted entry twice.
    """
    seen: set = set()
    out: list[dict] = []
    for f in items:
        key = (f.get("type"), f.get("value"), tuple(f.get("provenance", [])))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _read_meta(case_dir: Path) -> dict:
    p = case_dir / "run-meta.json"
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


# A finding is a "limit" (something not fully analyzed, i.e. a next-step signal)
# when its provenance or value says a tool was missing, symbols were absent, an
# archive was encrypted, a cap was hit, or a handler errored.
_LIMIT_PROV = ("unavailable", "no-symbols", "build-isf:failed", "mount:failed",
               "mount:error", "encrypted", "too-large", ":error", "mount:truncated")
_LIMIT_VAL = ("not available", "not analyzed", "not analyzable", "not parsed",
              "not on path", "no matching symbols")


def _is_limit(f: dict) -> bool:
    if f.get("flag"):
        return False
    prov = " ".join(f.get("provenance", []))
    if any(m in prov for m in _LIMIT_PROV):
        return True
    val = (f.get("value") or "").lower()
    return any(w in val for w in _LIMIT_VAL)


def _suggest(meta: dict, candidates, decoded, limits) -> list[str]:
    out: list[str] = []
    text = " ".join(((l.get("value") or "") + " " + " ".join(l.get("provenance", [])))
                    for l in limits).lower()
    if (meta or {}).get("mode") == "recon":
        out.append("re-run with `--mode full` for carving, decoding, stego and the memory sweep")
    if "no-symbols" in text or "build-isf" in text or "not analyzable past banners" in text:
        out.append("a Linux memory dump needs its symbols: re-run with "
                   "`--build-isf <vmlinux> [--system-map <map>]`")
    if "encrypted" in text:
        out.append("an encrypted archive was found: run `frx setup --with-wordlists`, "
                   "then re-run to auto-crack it")
    if "not on path" in text or "unavailable" in text or "not parsed" in text or "not available" in text:
        out.append("some tools are missing: run `frx check`, then `frx setup` to install them")
    if ":error" in text:
        out.append("a handler errored on an item: see the per-handler section and run.log")
    if candidates or decoded:
        out.append("eyeball the flag candidates / decoded strings below; they are leads "
                   "frx could not confirm")
    out.append("if the flag has a different shape, add `--flag-format 'PREFIX{...}'` "
               "or `--flag-regex '...'`")
    return out


def summarize(case_dir: Path) -> dict:
    """Bucket the findings for both the report and the terminal summary."""
    case_dir = Path(case_dir)
    findings = _load(case_dir)
    seen: set[str] = set()
    uniq_flags = [f for f in findings
                  if f.get("flag") and not (f["value"] in seen or seen.add(f["value"]))]
    candidates = _dedupe([f for f in findings if f.get("type") == "flag_candidate"])
    decoded = _dedupe([f for f in findings if f.get("type") == "decoded"])
    artifacts = _dedupe([f for f in findings if f.get("type") == "artifact" and f.get("severity") == "high"])
    extracted = _dedupe([f for f in findings if f.get("type") == "extracted_file"])
    limits = _dedupe([f for f in findings if _is_limit(f)])
    items = len({f.get("item_sha") for f in findings
                 if f.get("item_sha") and f.get("item_sha") != "0" * 64})
    meta = _read_meta(case_dir)
    return {
        "meta": meta, "flags": uniq_flags, "candidates": candidates, "decoded": decoded,
        "artifacts": artifacts, "extracted": extracted, "limits": limits,
        "items": items, "findings_total": len(findings),
        "suggestions": _suggest(meta, candidates, decoded, limits),
    }


def render(case_dir: Path) -> str:
    case_dir = Path(case_dir)
    findings = _load(case_dir)
    s = summarize(case_dir)
    uniq_flags = s["flags"]
    candidates = s["candidates"]
    decoded = s["decoded"]
    extracted = s["extracted"]
    artifacts = s["artifacts"]
    limits = s["limits"]

    lines: list[str] = []
    lines.append(f"# frx report: {case_dir.name}")
    lines.append("")

    # When nothing confirmed, lead with leads + limits + next steps instead of
    # a page of "_None._": a miss is exactly when the analyst needs direction.
    if not uniq_flags:
        fmts = ", ".join((s["meta"] or {}).get("flag_formats", [])) or "the configured format"
        lines.append("## No flags confirmed")
        lines.append("")
        lines.append(f"frx matched no flag for `{fmts}` across {s['items']} item(s). "
                     "Leads and next steps:")
        lines.append("")
        lines.append(f"**Leads:** {len(candidates)} flag candidate(s), {len(decoded)} decoded "
                     f"string(s), {len(artifacts)} high-signal artifact(s), "
                     f"{len(extracted)} extracted file(s) (detailed below).")
        for f in candidates[:5]:
            lines.append(f"- candidate `{f['value']}`  ·  `{_prov(f)}`")
        for f in decoded[:5]:
            lines.append(f"- decoded `{f['value']}`  ·  `{_prov(f)}`")
        if not candidates and not decoded and not artifacts and not extracted:
            lines.append("- (nothing of note surfaced; the input may be clean, or see 'Try next')")
        lines.append("")
        if limits:
            lines.append("**Not fully analyzed:**")
            for f in limits[:20]:
                lines.append(f"- {f['value']}  ·  `{_prov(f)}`")
            lines.append("")
        lines.append("**Try next:**")
        for i, sug in enumerate(s["suggestions"], 1):
            lines.append(f"{i}. {sug}")
        lines.append("")

    # Confirmed flags, deduped by value, first hit wins.
    lines.append("## Confirmed flags")
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

    lines.append("## Not fully analyzed")
    if not limits:
        lines.append("")
        lines.append("_None._")
    for f in limits[:50]:
        lines.append(f"- {f['value']}  ·  `{_prov(f)}`")
    lines.append("")

    lines.append("## Extracted files")
    lines.append("")
    lines.append(f"{len(extracted)} file(s) extracted.")
    for f in extracted[:500]:
        lines.append(f"- `{f['value']}`  ·  `{_prov(f)}`")
    lines.append("")

    # Per-handler counts, over deduped findings so a resumed/reprocessed item
    # (whose handlers re-emit) does not inflate the totals.
    lines.append("## Per-handler summary")
    lines.append("")
    counts: dict[str, int] = {}
    cseen_all: set = set()
    for f in findings:
        key = (f.get("handler", "?"), f.get("type"), f.get("value"), tuple(f.get("provenance", [])))
        if key in cseen_all:
            continue
        cseen_all.add(key)
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
