"""Offline enforcement by the kernel, not by trust (spec section 2, amendment A5).

"Offline" means zero network egress during the analysis pass. We enforce it by
re-executing the whole `frx run` inside a user + network namespace
(`unshare -rn`): a process in a fresh network namespace with no configured
interfaces simply has nowhere to send a packet, so no tool it spawns can reach
the network, whatever it tries. This is stronger than hoping each wrapped tool
was invoked with its offline flag.

The wrap happens once, around the entire pass, by re-exec rather than per tool
call. A marker env var stops the re-exec from recursing. If `unshare -rn` is
unavailable or fails and offline is enforced (the default), we refuse to run and
tell the user to pass --no-sandbox explicitly, so the choice to go unsandboxed is
always deliberate and logged.

Mounting (amendment A5): an unprivileged user namespace cannot loop-mount, so a
mount can never happen inside `unshare -rn`. The disk handler therefore prefers
TSK then 7z, and only falls back to a udisksctl mount when the user passed
--mount *and* --no-sandbox. The read-only mount helper lives here; it is only
ever reached on that explicit, unsandboxed path.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

SANDBOX_ENV_MARKER = "FRX_SANDBOXED"


def already_sandboxed() -> bool:
    return os.environ.get(SANDBOX_ENV_MARKER) == "1"


def sandbox_available() -> bool:
    """True if `unshare -rn` can actually create the namespaces on this host."""
    if shutil.which("unshare") is None:
        return False
    try:
        r = subprocess.run(
            ["unshare", "-rn", "true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def unshare_wrap(cmd: list[str]) -> list[str]:
    """Wrap a command so it runs in a fresh user + network namespace.

    Pure argv construction (no side effects) so it can be unit-tested.
    """
    return ["unshare", "-rn", "--", *cmd]


def _inner_command() -> list[str]:
    """The command that re-runs this exact invocation inside the namespace.

    `python -m frx <args>` is robust to how frx was launched (console script,
    `python -m`, editable install) because it does not depend on the frx
    entry-point being resolvable on PATH inside the namespace.
    """
    return [sys.executable, "-m", "frx", *sys.argv[1:]]


def reexec_under_sandbox(enforce_offline: bool, logfn=None) -> None:
    """Re-exec the whole pass under `unshare -rn`, or refuse, or run as-is.

    Called once at the top of `frx run` on the real CLI path. Behavior:
    - already inside the namespace (marker set): return, run normally;
    - --no-sandbox (enforce_offline False): return, run unsandboxed, log it;
    - enforce + unshare works: exec the namespaced re-run (does not return);
    - enforce + unshare unavailable: print a refusal and exit nonzero.
    """
    def _log(msg: str) -> None:
        if logfn:
            logfn(msg)

    if already_sandboxed():
        _log("offline sandbox active (unshare -rn): no network egress")
        return

    if not enforce_offline:
        msg = ("WARNING: --no-sandbox given; the analysis pass is NOT network-isolated. "
               "Tools are trusted to stay offline.")
        print(msg, file=sys.stderr)
        _log(msg)
        return

    if not sandbox_available():
        print(
            "refusing to run: offline enforcement is on but `unshare -rn` is "
            "unavailable on this host (needs unprivileged user namespaces).\n"
            "Re-run with --no-sandbox to proceed without network isolation "
            "(and accept that tools are merely trusted to stay offline).",
            file=sys.stderr,
        )
        raise SystemExit(2)

    env = dict(os.environ)
    env[SANDBOX_ENV_MARKER] = "1"
    argv = unshare_wrap(_inner_command())
    _log("entering offline sandbox: " + " ".join(argv))
    # Replace this process; control never returns on success.
    os.execvpe(argv[0], argv, env)


# -- read-only mounting (only reached with --mount + --no-sandbox) --------

def can_loop_mount(enforce_offline: bool, mount_flag: bool) -> bool:
    """A loop mount is permitted only when the user opted out of the sandbox.

    Inside `unshare -rn` a loop mount cannot work (amendment A5), so mounting is
    gated on --no-sandbox, requires --mount, and needs udisksctl present.
    """
    return bool(mount_flag) and not enforce_offline and shutil.which("udisksctl") is not None


def _parse_loop_device(text: str) -> Optional[str]:
    # "Mapped file ... as /dev/loop0." -> the /dev/loop* token.
    for token in text.replace(".", " ").split():
        if token.startswith("/dev/loop"):
            return token
    return None


def _parse_mountpoint(text: str) -> Optional[str]:
    # "Mounted /dev/loop0 at /run/media/user/LABEL." -> the path after " at ".
    marker = " at "
    i = text.find(marker)
    if i != -1:
        mp = text[i + len(marker):].strip().rstrip(".").strip()
        if mp.startswith("/"):
            return mp
    # Fallback: the LAST path-like token (the mountpoint follows the device).
    cand = None
    for token in text.replace(".", " ").split():
        if token.startswith("/") and not token.startswith("/dev/"):
            cand = token
    return cand


def loop_mount_ro(image: Path, runner=None) -> Optional[tuple[str, Path]]:
    """Loop-set-up and read-only mount `image` via udisksctl.

    Returns (loop_device, mountpoint) on success, or None. Runs outside any
    namespace. Uses udisksctl so no root is needed. Read-only is requested at
    loop-setup (-r); udisksctl then mounts without exec/suid by default policy.
    The loop device is always torn back down if the mount step fails or raises,
    so a partial failure never leaks a /dev/loop* binding.
    """
    def _run(argv):
        if runner is not None:
            return runner.run(argv, timeout=60)
        return subprocess.run(argv, capture_output=True, timeout=60)

    def _out(res) -> str:
        data = getattr(res, "stdout", b"") or b""
        return data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)

    setup = _run(["udisksctl", "loop-setup", "-r", "-f", str(image)])
    dev = _parse_loop_device(_out(setup))
    if not dev:
        return None
    try:
        mnt = _run(["udisksctl", "mount", "-b", dev])
        mountpoint = _parse_mountpoint(_out(mnt))
    except Exception:
        loop_unmount(dev, runner=runner)
        raise
    if not mountpoint:
        loop_unmount(dev, runner=runner)
        return None
    return dev, Path(mountpoint)


def loop_unmount(device: str, runner=None) -> None:
    def _run(argv):
        if runner is not None:
            return runner.run(argv, timeout=60)
        return subprocess.run(argv, capture_output=True, timeout=60)

    _run(["udisksctl", "unmount", "-b", device])
    _run(["udisksctl", "loop-delete", "-b", device])
