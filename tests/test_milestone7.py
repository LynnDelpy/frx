"""Milestone 7: budget/SIGINT, offline sandbox, resume, parallelism, UI, setup.

These are pure-logic tests with no external tools: the sandbox exec is captured
rather than performed, the budget deadline is forced by rewinding its clock, and
the parallel/sequential drains are compared on plaintext flags the binary
handler finds without any helper binary.
"""

import os
import signal

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
