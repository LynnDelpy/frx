"""Memory handler via Volatility 3 (spec section 6.1, amendments A2/A12).

banners.Banners always runs (it identifies Linux dumps and names the exact
kernel the ISF must match). --build-isf builds that ISF from a vmlinux first.
OS family is detected once (windows.info, else a linux plugin). The full sweep
runs the intersection of the configured plugin set with what this vol3 actually
has, per-plugin timeout, scanning every plugin's output for flags and feeding it
to the decoder; dumped regions are enqueued. A Linux dump with no matching
symbols and no --build-isf is reported honestly (naming the kernel), not
silently skipped.
"""

from __future__ import annotations

from pathlib import Path

from ..engine.context import Context
from ..engine.queue import Item
from ..report.findings import Finding
from . import vol

# Configured plugin sets, using vol3 2.28 names (amendment A2). The sweep runs
# only those this vol3 actually exposes; the rest are logged as skipped.
WINDOWS_PLUGINS = [
    "windows.info.Info", "windows.pslist.PsList", "windows.pstree.PsTree",
    "windows.psscan.PsScan", "windows.cmdline.CmdLine", "windows.cmdscan.CmdScan",
    "windows.consoles.Consoles", "windows.netscan.NetScan", "windows.netstat.NetStat",
    "windows.filescan.FileScan", "windows.malfind.Malfind", "windows.svcscan.SvcScan",
    "windows.getsids.GetSIDs", "windows.envars.Envars", "windows.hashdump.Hashdump",
    "windows.lsadump.Lsadump", "windows.cachedump.Cachedump",
    "windows.registry.hivelist.HiveList", "windows.registry.printkey.PrintKey",
]
LINUX_PLUGINS = [
    "linux.bash.Bash", "linux.pslist.PsList", "linux.psaux.PsAux", "linux.lsof.Lsof",
    "linux.lsmod.Lsmod", "linux.proc.Maps", "linux.envars.Envars",
    "linux.check_syscall.Check_syscall", "linux.malfind.Malfind",
]
MAC_PLUGINS = [
    "mac.bash.Bash", "mac.pslist.PsList", "mac.psaux.Psaux", "mac.lsof.Lsof",
    "mac.netstat.Netstat", "mac.malfind.Malfind",
]
DUMPING_PLUGINS = {"windows.malfind.Malfind", "linux.malfind.Malfind", "mac.malfind.Malfind"}


def _scan_output(ctx: Context, item: Item, text: str, plugin: str, command: str) -> None:
    ctx.scan_and_decode(item, text.encode("utf-8", "replace"), f"memory:{plugin}", "memory", command)


def _banners(ctx: Context, item: Item) -> str:
    res = vol.run_plugin(ctx, item, "banners.Banners", timeout=180)
    text = res.out_text()
    banner = ""
    for row in vol.parse_jsonl(text):
        b = row.get("Banner") or row.get("banner") or ""
        if b:
            banner = b
            break
    if banner:
        ctx.emit(Finding(
            severity="info", handler="memory", type="artifact", value=f"banner: {banner}",
            item_sha=item.sha256, provenance=item.provenance + ["memory:banners"], command=res.command,
        ))
    _scan_output(ctx, item, text, "banners.Banners", res.command)
    return banner


def _detect_os(ctx: Context, item: Item, installed: set[str]) -> str:
    if "windows.info.Info" in installed:
        res = vol.run_plugin(ctx, item, "windows.info.Info", timeout=180)
        if vol.parse_jsonl(res.out_text()):
            _scan_output(ctx, item, res.out_text(), "windows.info.Info", res.command)
            return "windows"
    for probe in ("linux.pslist.PsList", "mac.pslist.PsList"):
        if probe in installed:
            res = vol.run_plugin(ctx, item, probe, timeout=180)
            if vol.parse_jsonl(res.out_text()):
                return "linux" if probe.startswith("linux") else "mac"
    return "unknown"


def _sweep(ctx: Context, item: Item, plugins: list[str], installed: set[str]) -> None:
    dump_dir = ctx.child_dir(item) / "voldump"
    for plugin in plugins:
        if plugin not in installed:
            ctx.log(f"  memory: plugin not installed, skipped: {plugin}")
            continue
        dd = dump_dir if plugin in DUMPING_PLUGINS else None
        extra = ["--dump"] if plugin in DUMPING_PLUGINS else None
        res = vol.run_plugin(ctx, item, plugin, extra=extra, dump_dir=dd)
        if res.timed_out:
            ctx.log(f"  memory: plugin timed out, skipped: {plugin}")
            continue
        if res.stdout.strip():
            _scan_output(ctx, item, res.out_text(), plugin, res.command)
    # Enqueue any dumped regions/files.
    if dump_dir.is_dir():
        for child in sorted(dump_dir.rglob("*")):
            if child.is_file() and child.stat().st_size:
                ctx.enqueue_file(child, item, f"memory:dump:{child.name}")


def handle(item: Item, ctx: Context) -> None:
    if not vol.vol_available():
        ctx.emit(Finding(
            severity="info", handler="memory", type="artifact",
            value="volatility3 (vol) not on PATH; memory dump not analyzed",
            item_sha=item.sha256, provenance=item.provenance + ["memory:unavailable"],
        ))
        return

    banner = _banners(ctx, item)

    if ctx.build_isf:
        dest = vol.build_isf(ctx, ctx.build_isf, ctx.system_map)
        if dest:
            ctx.emit(Finding(
                severity="info", handler="memory", type="artifact",
                value=f"built Linux ISF: {dest.name}", item_sha=item.sha256,
                provenance=item.provenance + ["memory:build-isf"],
            ))
        else:
            ctx.emit(Finding(
                severity="info", handler="memory", type="artifact",
                value="ISF build failed (dwarf2json missing or error); see run.log",
                item_sha=item.sha256, provenance=item.provenance + ["memory:build-isf:failed"],
            ))

    installed = vol.list_plugins(ctx)
    os_family = _detect_os(ctx, item, installed)
    ctx.log(f"  memory {item.short}: os={os_family}")

    if os_family == "unknown":
        # Honest limit: name the exact kernel the user must supply symbols for.
        need = f" Kernel banner: {banner}" if banner else ""
        ctx.emit(Finding(
            severity="high", handler="memory", type="artifact",
            value=("memory dump not analyzable past banners: no matching symbols. "
                   "For Linux, supply --build-isf <vmlinux> for this kernel." + need),
            item_sha=item.sha256, provenance=item.provenance + ["memory:no-symbols"],
        ))
        return

    plugins = {"windows": WINDOWS_PLUGINS, "linux": LINUX_PLUGINS, "mac": MAC_PLUGINS}[os_family]
    if ctx.mode != "full":
        plugins = plugins[:2]  # recon: info/banner + pslist only
    _sweep(ctx, item, plugins, installed)
