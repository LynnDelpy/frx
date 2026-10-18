"""Command-line entry point: argparse -> config -> engine.

Subcommands: `run` (analyze inputs), `check` (verify dependencies), `setup`
(install, later milestone). Sandbox enforcement, budget and parallelism are
layered on in later milestones; this wires the core pass end to end.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path

from .config import Config, parse_duration, parse_size
from .engine.context import Context
from .engine.engine import Engine
from .engine.queue import WorkQueue
from .engine.runner import Runner
from .flags.formats import build_formats
from .flags.needles import generate_needles
from .progress.log import RunLog
from .report.findings import Finding, FindingWriter
from .report.render import write_report


def _default_case() -> Path:
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path("cases") / ts


def _collect_needles(formats):
    seen_prefix = set()
    needles = []
    for f in formats:
        if f.prefix and f.prefix not in seen_prefix:
            seen_prefix.add(f.prefix)
            needles.extend(generate_needles(f.prefix))
    # dedup across prefixes
    uniq = {}
    for n in needles:
        uniq[(n.label, n.value)] = n
    return list(uniq.values())


def cmd_run(args) -> int:
    cfg = Config.load()
    if args.jobs:
        cfg.jobs = args.jobs
    if args.max_depth is not None:
        cfg.max_depth = args.max_depth
    if args.max_files is not None:
        cfg.max_files = args.max_files
    if args.max_extracted_size:
        cfg.max_extracted_size = parse_size(args.max_extracted_size)
    if args.max_runtime:
        parse_duration(args.max_runtime)  # validated; budget enforced later
    if args.wordlist:
        cfg.wordlist = args.wordlist

    formats = build_formats(
        flag_formats=args.flag_format or cfg.flag_formats,
        flag_regexes=args.flag_regex or cfg.flag_regexes,
    )
    needles = _collect_needles(formats)

    case_dir = Path(args.case) if args.case else _default_case()
    case_dir.mkdir(parents=True, exist_ok=True)

    runlog = RunLog(case_dir)
    with FindingWriter(case_dir) as findings:
        findings.add_listener(lambda f: _on_finding(f, runlog))
        runner = Runner(case_dir, default_timeout=cfg.per_tool_timeout, logfn=runlog.line)
        queue = WorkQueue(cfg.max_depth, cfg.max_files, cfg.max_extracted_size)
        ctx = Context(
            runner=runner, findings=findings, queue=queue, formats=formats,
            needles=needles, case_dir=case_dir, mode=args.mode, wordlist=cfg.wordlist,
            logfn=runlog.line,
        )
        _wire_decoder(ctx)
        engine = Engine(ctx)
        runlog.line(f"seeding {len(args.input)} input(s), mode={args.mode}")
        engine.seed(args.input, kind_override=args.kind)
        engine.run()

    report = write_report(case_dir)
    flags_txt = case_dir / "FLAGS.txt"
    print(f"\nreport: {report}")
    if flags_txt.is_file() and flags_txt.stat().st_size:
        print(f"flags:  {flags_txt}")
        print(flags_txt.read_text().rstrip())
    else:
        print("flags:  none confirmed")
    return 0


def _wire_decoder(ctx: Context) -> None:
    try:
        from .decode.engine import DecodeEngine
    except Exception:
        return
    ctx.decoder = DecodeEngine(ctx)


def _on_finding(f: Finding, runlog: RunLog) -> None:
    if f.flag:
        runlog.line(f"FLAG {f.value}  [{' -> '.join(f.provenance)}]")
        print(f"[FLAG] {f.value}")


def cmd_check(args) -> int:
    from .setupcheck import run_check

    return run_check()


def cmd_setup(args) -> int:
    from .setupcheck import run_setup

    return run_setup(with_wordlists=args.with_wordlists, isf_only=args.isf_only, yes=args.yes)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="frx", description="Offline CTF forensics orchestrator")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="analyze inputs")
    r.add_argument("input", nargs="+")
    r.add_argument("--mode", choices=["recon", "full"], default="recon")
    r.add_argument("--flag-format", action="append", help="e.g. 'CTF{...}' (repeatable)")
    r.add_argument("--flag-regex", action="append", help="raw regex (repeatable)")
    r.add_argument("--kind", help="force input kind (memory, pcap, disk, ...)")
    r.add_argument("--wordlist", help="wordlist for archive/stego brute force")
    r.add_argument("--case", help="case dir (default cases/<timestamp>)")
    r.add_argument("--max-runtime", help="soft budget, e.g. 40m")
    r.add_argument("--max-depth", type=int)
    r.add_argument("--max-files", type=int)
    r.add_argument("--max-extracted-size", help="e.g. 4G")
    r.add_argument("--jobs", type=int)
    r.add_argument("--enforce-offline", dest="enforce_offline", action="store_true", default=True)
    r.add_argument("--no-sandbox", dest="enforce_offline", action="store_false")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("check", help="verify dependencies")
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("setup", help="install dependencies")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--with-wordlists", action="store_true")
    s.add_argument("--isf-only", action="store_true")
    s.set_defaults(func=cmd_setup)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
