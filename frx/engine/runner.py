"""Subprocess wrapper: explicit argv, timeout, captured output, provenance.

Every external tool is invoked through here. Rules (spec section 0, 12):
- never shell=True; argv is always an explicit list
- per-call timeout, killing the whole process group on expiry
- stdout/stderr captured as bytes (tools emit binary; decode lazily)
- the exact command string is recorded for finding provenance
- a controlled environment: TMPDIR inside the case dir, no .pyc litter
- optional nice/ionice wrapping so a long pass stays background-friendly

A failed or timed-out call returns a RunResult with ok=False rather than
raising, so one broken tool never kills the run (fail loud per item, continue).
"""

from __future__ import annotations

import dataclasses
import os
import shlex
import shutil
import signal
import subprocess
from pathlib import Path


@dataclasses.dataclass
class RunResult:
    argv: list[str]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    duration: float
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.error is None and self.returncode == 0

    @property
    def command(self) -> str:
        return " ".join(shlex.quote(a) for a in self.argv)

    def out_text(self, errors: str = "replace") -> str:
        return self.stdout.decode("utf-8", errors)


class Runner:
    """Runs external tools with a shared default timeout and case-scoped env."""

    def __init__(
        self,
        case_dir: Path,
        default_timeout: float = 300.0,
        nice: bool = True,
        logfn=None,
        observer=None,
    ):
        self.case_dir = Path(case_dir)
        self.default_timeout = default_timeout
        self.nice = nice and shutil.which("nice") is not None
        self.ionice = nice and shutil.which("ionice") is not None
        self._logfn = logfn
        # Optional live-UI hook: observer.tool_start(argv)/tool_end(argv) are
        # called around each spawn so the per-worker display can show the tool
        # that is running and for how long. Never allowed to break a run.
        self._observer = observer
        self._tmp = self.case_dir / "tmp"
        self._tmp.mkdir(parents=True, exist_ok=True)

    def _env(self, extra: dict | None = None) -> dict:
        env = dict(os.environ)
        env["TMPDIR"] = str(self._tmp)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        if extra:
            env.update(extra)
        return env

    def _wrap(self, argv: list[str]) -> list[str]:
        prefix: list[str] = []
        if self.ionice:
            prefix += ["ionice", "-c", "3"]
        if self.nice:
            prefix += ["nice", "-n", "15"]
        return prefix + argv

    def run(
        self,
        argv: list[str],
        timeout: float | None = None,
        cwd: Path | None = None,
        env: dict | None = None,
        input_bytes: bytes | None = None,
    ) -> RunResult:
        import time

        timeout = self.default_timeout if timeout is None else timeout
        wrapped = self._wrap(list(argv))
        if self._logfn:
            self._logfn("exec: " + " ".join(shlex.quote(a) for a in argv))
        self._notify("tool_start", argv)
        start = time.monotonic()
        try:
            try:
                proc = subprocess.Popen(
                    wrapped,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                    cwd=str(cwd) if cwd else None,
                    env=self._env(env),
                    start_new_session=True,  # own process group, for clean kill
                )
            except (FileNotFoundError, PermissionError) as e:
                return RunResult(list(argv), None, b"", b"", 0.0, error=str(e))
            try:
                out, err = proc.communicate(input=input_bytes, timeout=timeout)
                dur = time.monotonic() - start
                return RunResult(list(argv), proc.returncode, out, err, dur)
            except subprocess.TimeoutExpired:
                self._kill_group(proc)
                out, err = proc.communicate()
                dur = time.monotonic() - start
                return RunResult(list(argv), proc.returncode, out or b"", err or b"", dur, timed_out=True)
        finally:
            self._notify("tool_end", argv)

    def _notify(self, event: str, argv: list[str]) -> None:
        if self._observer is None:
            return
        fn = getattr(self._observer, event, None)
        if fn is None:
            return
        try:
            fn(argv)
        except Exception:
            pass

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
