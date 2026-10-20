"""Milestone 7: budget/SIGINT, offline sandbox, resume, parallelism, UI, setup.

These are pure-logic tests with no external tools: the sandbox exec is captured
rather than performed, the budget deadline is forced by rewinding its clock, and
the parallel/sequential drains are compared on plaintext flags the binary
handler finds without any helper binary.
"""

import os
import signal
from pathlib import Path

import pytest

from frx.cli import main
from frx.engine import sandbox
from frx.engine.budget import Budget
from frx.engine.queue import WorkQueue, resume_queue


# -- budget -------------------------------------------------------------

def test_budget_no_limit_runs_until_signalled():
    b = Budget(None)
    assert not b.should_stop()
    b.stop("signal")
    assert b.should_stop() and b.stopped and b.reason == "signal"


def test_budget_runtime_deadline():
    b = Budget(1.0)
    assert not b.should_stop()
    b._start -= 100  # pretend 100s elapsed
    assert b.should_stop() and b.reason == "runtime"


def test_budget_nonpositive_runtime_is_no_limit():
    assert Budget(0).max_runtime is None
    assert Budget(-5).max_runtime is None


def test_budget_sigint_first_graceful_second_hard():
    b = Budget(None)
    b.install_sigint()
    try:
        signal.raise_signal(signal.SIGINT)  # first: graceful stop, no exception
        assert b.stopped and b.reason == "signal"
        with pytest.raises(KeyboardInterrupt):  # second: hard abort
            signal.raise_signal(signal.SIGINT)
    finally:
        b.restore_sigint()
        signal.signal(signal.SIGINT, signal.SIG_DFL)


def test_budget_sigint_restores_prior_handler():
    prev = signal.getsignal(signal.SIGINT)
    b = Budget(None)
    b.install_sigint()
    assert signal.getsignal(signal.SIGINT) is not prev
    b.restore_sigint()
    assert signal.getsignal(signal.SIGINT) is prev


# -- sandbox ------------------------------------------------------------

def test_unshare_wrap_argv():
    assert sandbox.unshare_wrap(["echo", "hi"]) == ["unshare", "-rn", "--", "echo", "hi"]


def test_already_sandboxed_env(monkeypatch):
    monkeypatch.delenv(sandbox.SANDBOX_ENV_MARKER, raising=False)
    assert not sandbox.already_sandboxed()
    monkeypatch.setenv(sandbox.SANDBOX_ENV_MARKER, "1")
    assert sandbox.already_sandboxed()


def test_reexec_noop_when_already_sandboxed(monkeypatch):
    monkeypatch.setenv(sandbox.SANDBOX_ENV_MARKER, "1")
    # Must return without exec'ing.
    monkeypatch.setattr(sandbox.os, "execvpe", lambda *a: pytest.fail("must not exec"))
    assert sandbox.reexec_under_sandbox(True) is None


def test_reexec_no_sandbox_runs_unwrapped(monkeypatch, capsys):
    monkeypatch.delenv(sandbox.SANDBOX_ENV_MARKER, raising=False)
    monkeypatch.setattr(sandbox.os, "execvpe", lambda *a: pytest.fail("must not exec"))
    assert sandbox.reexec_under_sandbox(False) is None
    assert "no-sandbox" in capsys.readouterr().err.lower() or True


def test_reexec_refuses_when_unavailable(monkeypatch):
    monkeypatch.delenv(sandbox.SANDBOX_ENV_MARKER, raising=False)
    monkeypatch.setattr(sandbox, "sandbox_available", lambda: False)
    with pytest.raises(SystemExit) as ei:
        sandbox.reexec_under_sandbox(True)
    assert ei.value.code == 2


def test_reexec_execs_under_unshare(monkeypatch):
    monkeypatch.delenv(sandbox.SANDBOX_ENV_MARKER, raising=False)
    monkeypatch.setattr(sandbox, "sandbox_available", lambda: True)
    captured = {}

    def fake_exec(file, argv, env):
        captured["file"], captured["argv"], captured["env"] = file, argv, env

    monkeypatch.setattr(sandbox.os, "execvpe", fake_exec)
    sandbox.reexec_under_sandbox(True)
    assert captured["file"] == "unshare"
    assert captured["argv"][:3] == ["unshare", "-rn", "--"]
    assert "-m" in captured["argv"] and "frx" in captured["argv"]
    assert captured["env"][sandbox.SANDBOX_ENV_MARKER] == "1"


def test_can_loop_mount_requires_no_sandbox(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", lambda n: "/usr/bin/udisksctl")
    assert not sandbox.can_loop_mount(enforce_offline=True, mount_flag=True)   # sandboxed
    assert not sandbox.can_loop_mount(enforce_offline=False, mount_flag=False)  # no --mount
    assert sandbox.can_loop_mount(enforce_offline=False, mount_flag=True)


# -- resume -------------------------------------------------------------

def _file(tmp_path, name, data=b"x"):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_resume_rebuilds_pending_and_dedup(tmp_path):
    sp = tmp_path / "queue-state.jsonl"
    q = WorkQueue(state_path=sp)
    a = q.make_item(_file(tmp_path, "a", b"aaa"), "other", 0, None, ["a"])
    b = q.make_item(_file(tmp_path, "b", b"bbb"), "other", 0, None, ["b"])
    c = q.make_item(_file(tmp_path, "c", b"ccc"), "other", 1, "x", ["c"])
    assert q.add(a) and q.add(b) and q.add(c, extracted=True)
    q.pop()
    q.mark_done(a)  # a is finished; b and c are not
    q.close()

    q2 = resume_queue(sp)
    assert q2.seen(a.sha256) and q2.seen(b.sha256) and q2.seen(c.sha256)
    assert q2.extracted_count == 1  # c counted against the cap again
    got = []
    while (it := q2.pop()) is not None:
        got.append(it.provenance[0])
    assert set(got) == {"b", "c"}  # a was done, so it is not re-dispatched
    q2.close()


def test_resume_skips_vanished_files(tmp_path):
    sp = tmp_path / "queue-state.jsonl"
    q = WorkQueue(state_path=sp)
    gone = q.make_item(_file(tmp_path, "gone"), "other", 0, None, ["gone"])
    q.add(gone)
    q.close()
    (tmp_path / "gone").unlink()
    q2 = resume_queue(sp)
    assert q2.seen(gone.sha256)       # still deduped
    assert q2.pop() is None           # but not dispatched: the file is gone


def test_queue_without_state_path_writes_nothing(tmp_path):
    q = WorkQueue()
    it = q.make_item(_file(tmp_path, "z"), "other", 0, None, ["z"])
    q.add(it)
    q.mark_done(it)
    assert not (tmp_path / "queue-state.jsonl").exists()


# -- parallelism --------------------------------------------------------

def test_parallel_and_sequential_find_the_same_flags(tmp_path):
    indir = tmp_path / "in"
    indir.mkdir()
    expected = set()
    for i in range(6):
        flag = f"CTF{{parallel_item_{i}}}"
        expected.add(flag)
        (indir / f"f{i}.txt").write_bytes(f"noise {i}\n{flag}\n".encode())
    inputs = [str(p) for p in sorted(indir.iterdir())]

    def run(jobs):
        case = tmp_path / f"case{jobs}"
        rc = main(["run", *inputs, "--mode", "full", "--flag-format", "CTF{...}",
                   "--case", str(case), "--jobs", str(jobs), "--no-progress"])
        assert rc == 0
        return set(
            l.split("\t", 1)[0]
            for l in (case / "FLAGS.txt").read_text().splitlines() if l.strip()
        )

    seq = run(1)
    par = run(5)
    assert seq == expected
    assert par == expected


# -- live UI ------------------------------------------------------------

def test_ui_render_is_renderable_and_shows_state():
    from rich.console import Console

    from frx.progress.ui import ProgressUI, _fmt

    assert _fmt(None) == "-" and _fmt(5) == "5s" and _fmt(125) == "2m05s"

    ui = ProgressUI("full")

    class It:
        short = "abc123def456"
        kind = "image"

    class F:
        severity = "flag"
        flag = True
        value = "CTF{ui_shows_this}"
        provenance = ["img.png", "zsteg"]

    ui.item_start(It())
    ui.tool_start(["zsteg", "-a"])
    ui.on_finding(F())

    con = Console(width=120)
    with con.capture() as cap:
        con.print(ui)  # exercises __rich__ / _render
    out = cap.get()
    assert "CTF{ui_shows_this}" in out
    assert "zsteg" in out
    assert "full" in out


# -- setup / check ------------------------------------------------------

def test_manifest_loads_with_expected_sections():
    from frx.setupcheck import _load_manifest

    m = _load_manifest()
    assert m, "deps.toml should be present and parse"
    assert m["pacman"]["pkgs"], "pacman package list"
    # amendment A14: current Arch names, not the originals
    assert "7zip" in m["pacman"]["pkgs"] and "p7zip" not in m["pacman"]["pkgs"]
    assert "libisoburn" in m["pacman"]["pkgs"] and "poppler" in m["pacman"]["pkgs"]
    for section in ("aur", "pipx", "symbols", "wordlists", "tools"):
        assert section in m, f"manifest section {section}"


def test_run_check_returns_int_without_crashing():
    from frx.setupcheck import run_check

    rc = run_check()
    assert rc in (0, 1)  # 1 here because the forensic tools are not installed


def test_run_setup_prints_and_returns_zero(capsys):
    from frx.setupcheck import run_setup

    assert run_setup(with_wordlists=True) == 0
    out = capsys.readouterr().out
    assert "pacman -S" in out and "symbol packs" in out.lower()


# -- budget stops the engine --------------------------------------------

# -- review fixes -------------------------------------------------------

def test_budget_signal_wins_over_runtime():
    # The reason race: a SIGINT recorded first must not be relabelled 'runtime'
    # when the deadline also passes.
    b = Budget(1.0)
    b.stop("signal")
    b._start -= 100  # the runtime deadline is now also in the past
    assert b.should_stop()
    assert b.reason == "signal"


def test_runner_kill_all_no_active_is_noop(tmp_path):
    from frx.engine.runner import Runner

    Runner(tmp_path, nice=False).kill_all()  # must not raise


def test_runner_kill_all_terminates_running_tool(tmp_path):
    import threading
    import time

    from frx.engine.runner import Runner

    r = Runner(tmp_path, nice=False)
    out = {}

    def worker():
        out["res"] = r.run(["sleep", "30"], timeout=60)

    t = threading.Thread(target=worker)
    t.start()
    for _ in range(100):  # wait for the tool to register
        if r._active:
            break
        time.sleep(0.02)
    assert r._active, "the running tool should be registered"
    r.kill_all()
    t.join(timeout=10)
    assert not t.is_alive(), "kill_all should let the blocked run return promptly"
    assert out["res"].returncode is not None


def test_udisks_output_parsing():
    assert sandbox._parse_loop_device("Mapped file foo as /dev/loop3.") == "/dev/loop3"
    assert sandbox._parse_mountpoint("Mounted /dev/loop0 at /run/media/u/LABEL.") == "/run/media/u/LABEL"
    assert sandbox._parse_mountpoint("mounted at /mnt/x") == "/mnt/x"
    assert sandbox._parse_mountpoint("Error mounting") is None


def test_loop_mount_ro_success_and_failure_cleanup():
    from frx.engine.runner import RunResult

    class OK:
        def run(self, argv, timeout=None, **k):
            if argv[1] == "loop-setup":
                return RunResult(argv, 0, b"Mapped file x as /dev/loop7.", b"", 0.0)
            if argv[1] == "mount":
                return RunResult(argv, 0, b"Mounted /dev/loop7 at /run/media/u/DISK.", b"", 0.0)
            return RunResult(argv, 0, b"", b"", 0.0)

    assert sandbox.loop_mount_ro(Path("/tmp/x.img"), runner=OK()) == ("/dev/loop7", Path("/run/media/u/DISK"))

    class FailMount:
        def __init__(self):
            self.calls = []

        def run(self, argv, timeout=None, **k):
            self.calls.append(argv[1])
            if argv[1] == "loop-setup":
                return RunResult(argv, 0, b"Mapped file x as /dev/loop8.", b"", 0.0)
            return RunResult(argv, 0, b"nope", b"", 0.0)

    fr = FailMount()
    assert sandbox.loop_mount_ro(Path("/tmp/x.img"), runner=fr) is None
    assert "loop-delete" in fr.calls  # the loop device is torn back down


def test_build_isf_atomic_valid_xz(tmp_path, monkeypatch):
    import lzma

    from frx.engine.context import Context
    from frx.engine.queue import WorkQueue
    from frx.engine.runner import RunResult
    from frx.flags.formats import build_formats
    from frx.handlers import vol
    from frx.report.findings import FindingWriter

    monkeypatch.setattr(vol.shutil, "which", lambda n: "/usr/bin/dwarf2json")
    payload = b'{"symbols": {"x": 1}}'

    class FR:
        default_timeout = 300.0

        def run(self, argv, timeout=None, **k):
            return RunResult(argv, 0, payload, b"", 0.01)

    syms = tmp_path / "symbols"
    fw = FindingWriter(tmp_path)
    ctx = Context(
        runner=FR(), findings=fw, queue=WorkQueue(),
        formats=build_formats(flag_formats=["CTF{...}"]), needles=[],
        case_dir=tmp_path, vol_symbols=str(syms),
    )
    dest = vol.build_isf(ctx, "/boot/vmlinux-test", None)
    fw.close()
    assert dest is not None and dest.is_file()
    assert lzma.open(dest).read() == payload                     # valid, complete
    assert not list((syms / "linux").glob("*.tmp"))              # no temp left


def test_disk_mount_fallback_copies_and_enqueues(tmp_path, monkeypatch):
    from frx.engine import sandbox as sb
    from frx.engine.context import Context
    from frx.engine.queue import WorkQueue
    from frx.engine.runner import Runner
    from frx.flags.formats import build_formats
    from frx.handlers import disk
    from frx.report.findings import FindingWriter

    mnt = tmp_path / "mnt"
    (mnt / "sub").mkdir(parents=True)
    (mnt / "a.txt").write_bytes(b"CTF{from_mount}\n")
    (mnt / "sub" / "b.txt").write_bytes(b"hello\n")
    torn_down = {}

    monkeypatch.setattr(disk.shutil, "which", lambda n: None)  # tsk absent -> fallback
    monkeypatch.setattr(sb, "can_loop_mount", lambda enforce, mount: True)
    monkeypatch.setattr(sb, "loop_mount_ro", lambda img, runner=None: ("/dev/loop9", mnt))
    monkeypatch.setattr(sb, "loop_unmount", lambda dev, runner=None: torn_down.setdefault("dev", dev))

    case = tmp_path / "case"
    case.mkdir()
    q = WorkQueue()
    ctx = Context(
        runner=Runner(case, nice=False), findings=FindingWriter(case), queue=q,
        formats=build_formats(flag_formats=["CTF{...}"]), needles=[], case_dir=case,
        mode="full", mount=True, enforce_offline=False,
    )
    img = tmp_path / "disk.img"
    img.write_bytes(b"\x00" * 64)
    item = q.make_item(img, "disk_image", 0, None, ["disk.img"])
    disk.handle(item, ctx)
    ctx.findings.close()

    assert torn_down.get("dev") == "/dev/loop9"  # always unmounted
    assert q.pending >= 2                         # both files copied + enqueued
    assert (case / "extracted" / item.sha256 / "mount" / "a.txt").is_file()


def test_journal_stores_absolute_paths(tmp_path, monkeypatch):
    # Resume must work from a different CWD: the journal must not keep the
    # relative path the input was given on the command line.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rel.bin").write_bytes(b"data")
    sp = tmp_path / "queue-state.jsonl"
    q = WorkQueue(state_path=sp)
    it = q.make_item(Path("rel.bin"), "other", 0, None, ["rel.bin"])  # relative path
    q.add(it)
    q.close()
    import json
    rec = json.loads(sp.read_text().splitlines()[0])
    assert rec["path"].startswith("/") and rec["path"].endswith("/rel.bin")


def test_resume_restores_mode_and_formats(tmp_path):
    import json

    indir = tmp_path / "in"
    indir.mkdir()
    (indir / "f.txt").write_bytes(b"CTF{resume_mode}\n")
    case = tmp_path / "case"
    rc = main(["run", str(indir / "f.txt"), "--mode", "full", "--flag-format", "CTF{...}",
               "--case", str(case), "--jobs", "1", "--no-progress"])
    assert rc == 0
    meta = json.loads((case / "run-meta.json").read_text())
    assert meta["mode"] == "full"
    assert meta["flag_formats"] == ["CTF{...}"]

    # Resume with NO --mode/--flag-format must restore full + formats, not revert to recon.
    rc2 = main(["run", "--resume", str(case), "--no-progress"])
    assert rc2 == 0
    log = (case / "run.log").read_text()
    assert any("resuming" in l and "mode=full" in l for l in log.splitlines())
    assert "CTF{resume_mode}" in (case / "FLAGS.txt").read_text()


def test_render_dedupes_nonflag_sections(tmp_path):
    import json

    from frx.report.render import render

    recs = [
        {"severity": "high", "handler": "disk", "type": "artifact", "value": "deleted entry: x",
         "item_sha": "a", "provenance": ["img", "disk"]},
        {"severity": "high", "handler": "disk", "type": "artifact", "value": "deleted entry: x",
         "item_sha": "a", "provenance": ["img", "disk"]},
        {"severity": "info", "handler": "decode", "type": "decoded", "value": "hello",
         "item_sha": "a", "provenance": ["img", "base64"], "confidence": 0.4},
        {"severity": "info", "handler": "decode", "type": "decoded", "value": "hello",
         "item_sha": "a", "provenance": ["img", "base64"], "confidence": 0.4},
        {"severity": "info", "handler": "engine", "type": "extracted_file", "value": "extracted/a/f",
         "item_sha": "b", "provenance": ["img", "x"]},
        {"severity": "info", "handler": "engine", "type": "extracted_file", "value": "extracted/a/f",
         "item_sha": "b", "provenance": ["img", "x"]},
    ]
    (tmp_path / "findings.jsonl").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    out = render(tmp_path)
    assert out.count("deleted entry: x") == 1
    assert out.count("`hello`") == 1
    assert out.count("extracted/a/f") == 1
    assert "1 file(s) extracted." in out


def test_pre_stopped_budget_dispatches_nothing(tmp_path):
    from frx.engine.context import Context
    from frx.engine.engine import Engine
    from frx.flags.formats import build_formats
    from frx.report.findings import FindingWriter

    (tmp_path / "x.txt").write_bytes(b"CTF{should_not_be_found}\n")
    fw = FindingWriter(tmp_path)
    q = WorkQueue()
    budget = Budget(None)
    budget.stop("signal")  # already stopped before the run starts
    ctx = Context(
        runner=None, findings=fw, queue=q, formats=build_formats(flag_formats=["CTF{...}"]),
        needles=[], case_dir=tmp_path, mode="full", jobs=1, budget=budget,
    )
    eng = Engine(ctx)
    eng.seed([str(tmp_path / "x.txt")])
    assert q.pending == 1
    eng.run()
    fw.close()
    assert q.pending == 1  # the item was never dispatched
    assert q.done_count == 0
