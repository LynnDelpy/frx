"""Command-line entry point: argparse -> config -> engine.

Subcommands: `run` (analyze inputs), `check` (verify dependencies), `setup`
(print install commands). `run` wires together the whole milestone-7 pass:
the offline sandbox wraps the process, a runtime budget and Ctrl-C both end it
gracefully with a finalized report, a live display tracks parallel item workers,
and --resume continues an interrupted case from its state journal.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

from .config import Config, parse_duration, parse_size
from .engine.budget import Budget
from .engine.context import Context
from .engine.engine import Engine
from .engine.queue import WorkQueue, resume_queue
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
    uniq = {}
    for n in needles:
        uniq[(n.label, n.value)] = n
    return list(uniq.values())


def _make_ui(args, mode, budget, queue):
    """A live display only when attached to a real terminal and not suppressed."""
    if getattr(args, "no_progress", False):
        return None, None
    try:
        from rich.console import Console

        from .progress.ui import ProgressUI
    except Exception:
        return None, None
    console = Console()
    if not console.is_terminal:
        return None, None
    return ProgressUI(mode, budget=budget, queue=queue, console=console), console


def _make_listener(runlog: RunLog, ui):
    def listener(f: Finding) -> None:
        if f.flag:
            runlog.line(f"FLAG {f.value}  [{' -> '.join(f.provenance)}]")
            if ui is not None:
                ui.print_flag(f.value)
            else:
                print(f"[FLAG] {f.value}")
        if ui is not None:
            ui.on_finding(f)
    return listener


def cmd_run(args) -> int:
    programmatic = getattr(args, "_programmatic", False)

    # Offline sandbox: wrap the entire pass in `unshare -rn` by re-execing once
    # (spec section 2). Real CLI only -- a programmatic/embedded caller owns its
    # own process and must not be replaced out from under its runtime.
    if not programmatic:
        from .engine.sandbox import reexec_under_sandbox
        reexec_under_sandbox(args.enforce_offline)  # may replace the process or exit

    cfg = Config.load()
    if args.jobs:
        cfg.jobs = args.jobs
    if args.max_depth is not None:
        cfg.max_depth = args.max_depth
    if args.max_files is not None:
        cfg.max_files = args.max_files
    if args.max_extracted_size:
        cfg.max_extracted_size = parse_size(args.max_extracted_size)
    if args.wordlist:
        cfg.wordlist = args.wordlist

    max_runtime = parse_duration(args.max_runtime) if args.max_runtime else None

    resuming = bool(args.resume)
    case_dir = Path(args.resume) if resuming else (Path(args.case) if args.case else _default_case())
    case_dir.mkdir(parents=True, exist_ok=True)
    state_path = case_dir / "queue-state.jsonl"
    meta_path = case_dir / "run-meta.json"

    # Resume restores the run-level parameters the journal does not hold (mode,
    # flag formats, wordlist), so a resumed --mode full run does not silently
    # revert to recon. An explicit CLI flag still overrides the saved value.
    meta = {}
    if resuming and meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}

    mode = args.mode or meta.get("mode") or "recon"
    flag_formats = args.flag_format or meta.get("flag_formats") or cfg.flag_formats
    flag_regexes = args.flag_regex or meta.get("flag_regexes") or cfg.flag_regexes
    if resuming and not args.wordlist and meta.get("wordlist"):
        cfg.wordlist = meta["wordlist"]
    # Restore the original run's caps on resume (the journal holds only counters,
    # not the limits), unless the resume command overrides them explicitly.
    if resuming:
        lim = meta.get("limits", {})
        if args.max_depth is None and "max_depth" in lim:
            cfg.max_depth = int(lim["max_depth"])
        if args.max_files is None and "max_files" in lim:
            cfg.max_files = int(lim["max_files"])
        if not args.max_extracted_size and "max_extracted_size" in lim:
            cfg.max_extracted_size = int(lim["max_extracted_size"])

    formats = build_formats(flag_formats=flag_formats, flag_regexes=flag_regexes)
    needles = _collect_needles(formats)

    if not resuming:
        try:
            meta_path.write_text(json.dumps({
                "mode": mode, "flag_formats": flag_formats, "flag_regexes": flag_regexes,
                "wordlist": cfg.wordlist, "kind": args.kind,
                "limits": {
                    "max_depth": cfg.max_depth, "max_files": cfg.max_files,
                    "max_extracted_size": cfg.max_extracted_size,
                },
            }, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    runlog = RunLog(case_dir)
    from .engine.sandbox import already_sandboxed
    if already_sandboxed():
        runlog.line("offline sandbox: active (unshare -rn, no network egress)")
    elif not args.enforce_offline:
        runlog.line("offline sandbox: DISABLED (--no-sandbox); tools trusted to stay offline")
    budget = Budget(max_runtime)
    rc = 0
    with FindingWriter(case_dir) as findings:
        if resuming:
            queue = resume_queue(state_path, cfg.max_depth, cfg.max_files, cfg.max_extracted_size)
        else:
            queue = WorkQueue(cfg.max_depth, cfg.max_files, cfg.max_extracted_size, state_path=state_path)

        ui, console = _make_ui(args, mode, budget, queue)
        findings.add_listener(_make_listener(runlog, ui))
        runner = Runner(case_dir, default_timeout=cfg.per_tool_timeout, logfn=runlog.line, observer=ui)
        ctx = Context(
            runner=runner, findings=findings, queue=queue, formats=formats,
            needles=needles, case_dir=case_dir, mode=mode, wordlist=cfg.wordlist,
            vol_symbols=cfg.vol_symbols, build_isf=args.build_isf, system_map=args.system_map,
            vol_plugin_timeout=cfg.vol_plugin_timeout, logfn=runlog.line,
            jobs=cfg.jobs, budget=budget, ui=ui,
            enforce_offline=args.enforce_offline, mount=args.mount,
        )
        _wire_decoder(ctx)
        engine = Engine(ctx)

        if not programmatic:
            budget.install_sigint()
        try:
            if resuming:
                runlog.line(f"resuming case {case_dir} with {queue.pending} pending item(s), mode={mode}")
            else:
                runlog.line(f"seeding {len(args.input)} input(s), mode={mode}, jobs={cfg.jobs}")
                engine.seed(args.input, kind_override=args.kind)
            try:
                _drive(engine, ui, console)
            except KeyboardInterrupt:
                # A hard abort that escaped the sequential drain: stop, kill any
                # lingering tool, and still finalize the report below.
                budget.stop("signal")
                runlog.line("hard abort (second interrupt): finalizing with work so far")
                killer = getattr(runner, "kill_all", None)
                if killer is not None:
                    killer()
        finally:
            budget.restore_sigint()
            queue.close()
        if budget.stopped:
            rc = 130 if budget.reason == "signal" else 0

    report = write_report(case_dir)
    flags_txt = case_dir / "FLAGS.txt"
    print(f"\nreport: {report}")
    if flags_txt.is_file() and flags_txt.stat().st_size:
        print(f"flags:  {flags_txt}")
        print(flags_txt.read_text().rstrip())
    else:
        print("flags:  none confirmed")
    return rc


def _drive(engine: Engine, ui, console) -> None:
    """Run the pass, driving the live display when one is attached."""
    if ui is None or console is None:
        engine.run()
        return
    from rich.live import Live

    with Live(ui, console=console, refresh_per_second=4, screen=False, transient=False) as live:
        ui.set_live(live)
        engine.run()


def _wire_decoder(ctx: Context) -> None:
    try:
        from .decode.engine import DecodeEngine
    except Exception:
        return
    ctx.decoder = DecodeEngine(ctx)


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
    r.add_argument("input", nargs="*")
    r.add_argument("--mode", choices=["recon", "full"], default=None,
                   help="recon (fast, read-only) or full (default recon; restored from the case on --resume)")
    r.add_argument("--flag-format", action="append", help="e.g. 'CTF{...}' (repeatable)")
    r.add_argument("--flag-regex", action="append", help="raw regex (repeatable)")
    r.add_argument("--kind", help="force input kind (memory, pcap, disk, ...)")
    r.add_argument("--wordlist", help="wordlist for archive/stego brute force")
    r.add_argument("--build-isf", dest="build_isf", metavar="VMLINUX",
                   help="build a vol3 Linux ISF from this vmlinux via dwarf2json, then analyze")
    r.add_argument("--system-map", dest="system_map", help="System.map for --build-isf")
    r.add_argument("--case", help="case dir (default cases/<timestamp>)")
    r.add_argument("--resume", metavar="CASE", help="continue an interrupted case dir")
    r.add_argument("--max-runtime", help="soft budget, e.g. 40m; finalize on hit")
    r.add_argument("--max-depth", type=int)
    r.add_argument("--max-files", type=int)
    r.add_argument("--max-extracted-size", help="e.g. 4G")
    r.add_argument("--jobs", type=int, help="parallel item workers (default ncpu-1)")
    r.add_argument("--enforce-offline", dest="enforce_offline", action="store_true", default=True,
                   help="wrap the pass in unshare -rn (default)")
    r.add_argument("--no-sandbox", dest="enforce_offline", action="store_false",
                   help="do not network-isolate the pass (required for --mount)")
    r.add_argument("--mount", dest="mount", action="store_true", default=False,
                   help="allow a read-only loop mount as a last resort (needs --no-sandbox)")
    r.add_argument("--no-mount", dest="mount", action="store_false",
                   help="never mount; use TSK/7z only (default)")
    r.add_argument("--no-progress", dest="no_progress", action="store_true",
                   help="suppress the live display (log heartbeat only)")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("check", help="verify dependencies")
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("setup", help="print install commands")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--with-wordlists", action="store_true")
    s.add_argument("--isf-only", action="store_true")
    s.set_defaults(func=cmd_setup)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # A None argv is the real CLI entry (reads sys.argv); an explicit list is a
    # programmatic/test call. Only the real CLI re-execs into the sandbox.
    args._programmatic = argv is not None
    if getattr(args, "cmd", None) == "run" and not args.resume and not args.input:
        parser.error("run: provide at least one input, or --resume <case>")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
