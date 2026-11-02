"""`frx check` and `frx setup` (spec section 9).

check verifies every dependency is present before a run so a long pass never
dies partway through on a missing binary. It also probes the offline sandbox
(`unshare -rn`), the vol3 symbol packs, and the stego wordlist, because a run
that silently lacks any of those produces misleadingly empty results.

setup installs them (interactive; package installs need sudo, which the user
runs, amendment A11). The dependency manifest lives in frx/data/deps.toml.
"""

from __future__ import annotations

import shutil
import subprocess
import tomllib
from pathlib import Path

from .config import Config

DATA = Path(__file__).parent / "data"

# name -> required?  (optional tools are reported but never fail `check`)
REQUIRED_BINARIES = {
    "file": True, "strings": True, "rg": True, "7z": True, "binwalk": True,
    "foremost": True, "exiftool": True, "tshark": True,
    "mmls": True, "fls": True, "icat": True, "tsk_recover": True, "blkls": True,
    "pdftotext": True, "pdfdetach": True, "qpdf": True, "zsteg": True,
    "steghide": True, "stegseek": True, "pngcheck": True, "jpeginfo": True,
    "vol": True, "olevba": True, "john": True, "zip2john": True,
    "outguess": False, "bulk_extractor": False, "dwarf2json": False,
    "xorriso": False, "fcrackzip": False, "unar": False, "udisksctl": False,
}


def _present(name: str) -> bool:
    return shutil.which(name) is not None


def _check_binaries() -> int:
    """Print the binary table; return the count of missing *required* tools."""
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="frx dependency check")
        table.add_column("tool")
        table.add_column("status")
        table.add_column("required")
        missing = 0
        for name, required in REQUIRED_BINARIES.items():
            ok = _present(name)
            if required and not ok:
                missing += 1
            status = "[green]ok[/]" if ok else ("[red]MISSING[/]" if required else "[yellow]missing[/]")
            table.add_row(name, status, "yes" if required else "no")
        console.print(table)
        return missing
    except Exception:
        missing = 0
        for name, required in REQUIRED_BINARIES.items():
            ok = _present(name)
            if required and not ok:
                missing += 1
            mark = "ok" if ok else ("MISSING" if required else "missing")
            print(f"{name:16} {mark:8} {'required' if required else 'optional'}")
        return missing


def _check_sandbox() -> bool:
    try:
        r = subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10)
        ok = r.returncode == 0
    except Exception:
        ok = False
    print(f"unshare -rn (offline sandbox): {'ok' if ok else 'FAIL (run with --no-sandbox, or enable unprivileged user namespaces)'}")
    return ok


def _check_symbols(cfg: Config) -> None:
    base = Path(cfg.vol_symbols).expanduser()
    for family in ("windows", "mac"):
        d = base / family
        has = d.is_dir() and any(d.iterdir())
        note = "" if has else "  (needed only for that OS; fetch via `frx setup`)"
        print(f"vol symbols/{family}: {'present' if has else 'missing'}{note}")
    print("vol symbols/linux: built per dump via `frx run --build-isf <vmlinux>` (no pack)")


def _check_wordlist(cfg: Config) -> None:
    if not cfg.wordlist:
        print("wordlist: none configured (archive/stego brute force disabled)")
        return
    wl = Path(cfg.wordlist).expanduser()
    print(f"wordlist: {'ok' if wl.is_file() else 'MISSING'} ({cfg.wordlist})")


def _check_gpu() -> None:
    try:
        from .decode.gpu import probe
        ok, detail = probe()
    except Exception as e:  # noqa: BLE001
        ok, detail = False, f"{type(e).__name__}: {e}"
    print(f"gpu (--gpu, optional): {'ok, ' + detail if ok else 'not available (' + detail + ')'}")


def run_check() -> int:
    cfg = Config.load()
    missing_required = _check_binaries()
    print()
    _check_sandbox()
    _check_symbols(cfg)
    _check_wordlist(cfg)
    _check_gpu()

    if missing_required:
        print(f"\n{missing_required} required tool(s) missing. Run `frx setup` or install them.")
        return 1
    print("\nAll required tools present.")
    return 0


def _load_manifest() -> dict:
    mf = DATA / "deps.toml"
    if mf.is_file():
        return tomllib.loads(mf.read_text())
    return {}


def _run_cmd(argv: list[str], dry_run: bool, require: str | None = None):
    """Print a command, then (unless dry_run) run it with the terminal attached
    so sudo/pacman can prompt. Returns True ok, False failed, None skipped."""
    print("  $ " + " ".join(argv))
    if dry_run:
        return None
    if require and shutil.which(require) is None:
        print(f"    skipped: {require} not found")
        return None
    try:
        return subprocess.run(argv).returncode == 0
    except (OSError, subprocess.SubprocessError) as e:
        print(f"    failed: {e}")
        return False


def run_setup(with_wordlists: bool = False, isf_only: bool = False,
              yes: bool = False, dry_run: bool = False) -> int:
    """Install frx's external dependencies. Runs the commands directly (package
    installs use sudo and will prompt); --dry-run only prints them, --yes passes
    --noconfirm to the package managers for an unattended install."""
    manifest = _load_manifest()
    nc = ["--noconfirm"] if yes else []
    if dry_run:
        print("frx setup (dry run): the commands below would run; nothing is executed.\n")
    else:
        print("frx setup: installing dependencies. Package installs use sudo and may prompt.\n")

    if isf_only:
        _setup_tools(manifest, dry_run)
        return 0 if dry_run else run_check()

    pac = manifest.get("pacman", {}).get("pkgs", [])
    if pac:
        if dry_run or shutil.which("pacman"):
            _run_cmd(["sudo", "pacman", "-S", "--needed", *nc, *pac], dry_run, require="pacman")
        else:
            print("  pacman not found (not an Arch host); install equivalently: " + " ".join(pac))

    aur = manifest.get("aur", {}).get("pkgs", [])
    if aur:
        helper = shutil.which("paru") or shutil.which("yay")
        if dry_run:
            print("  $ paru -S --needed " + " ".join(nc + aur))
        elif helper:
            _run_cmd([Path(helper).name, "-S", "--needed", *nc, *aur], dry_run)
        else:
            print("  no AUR helper (paru/yay); install from the AUR yourself: " + " ".join(aur))

    for p in manifest.get("pipx", {}).get("pkgs", []):
        _run_cmd(["pipx", "install", p], dry_run, require="pipx")
    for g in manifest.get("gem", {}).get("pkgs", []):
        _run_cmd(["gem", "install", "--user-install", g], dry_run, require="gem")

    _setup_tools(manifest, dry_run)
    _setup_symbols(manifest, dry_run)
    if with_wordlists:
        _setup_wordlists(manifest, dry_run)
    else:
        print("\nwordlists: re-run `frx setup --with-wordlists` to fetch rockyou (enables auto-cracking).")

    if dry_run:
        print("\n(dry run complete; re-run without --dry-run to install.)")
        return 0
    print("\nVerifying with `frx check`:\n")
    return run_check()


def _symbols_dir() -> Path:
    return Path(Config().vol_symbols).expanduser()


def _setup_tools(manifest: dict, dry_run: bool) -> None:
    tools = manifest.get("tools", {})
    if not tools:
        return
    dest = Path("~/.local/share/frx/tools").expanduser()
    if not dry_run:
        dest.mkdir(parents=True, exist_ok=True)
    print(f"\nunpackaged tools -> {dest}:")
    for key in ("pdfid", "pdf_parser"):
        if key in tools:
            name = key.replace("_", "-") + ".py"
            _run_cmd(["curl", "-fsSL", "-o", str(dest / name), tools[key]], dry_run, require="curl")
    if "dwarf2json" in tools:
        print(f"  dwarf2json: download the release binary from {tools['dwarf2json']} and put it on "
              "PATH (choosing the right release asset is manual).")


def _setup_symbols(manifest: dict, dry_run: bool) -> None:
    sym = manifest.get("symbols", {})
    if not sym:
        return
    base = _symbols_dir()
    print(f"\nvol3 symbol packs -> {base}:")
    for family in ("windows", "mac"):
        if family not in sym:
            continue
        out = base / family
        zpath = base / f"{family}.zip"
        if not dry_run:
            out.mkdir(parents=True, exist_ok=True)
        ok = _run_cmd(["curl", "-fsSL", "-o", str(zpath), sym[family]], dry_run, require="curl")
        if dry_run or ok:
            _run_cmd(["7z", "x", "-y", f"-o{out}", str(zpath)], dry_run, require="7z")


def _setup_wordlists(manifest: dict, dry_run: bool) -> None:
    wl = manifest.get("wordlists", {})
    if not wl:
        return
    dest = Path("~/.local/share/frx/wordlists").expanduser()
    if not dry_run:
        dest.mkdir(parents=True, exist_ok=True)
    print(f"\nwordlists -> {dest}:")
    for name, url in wl.items():
        _run_cmd(["curl", "-fsSL", "-o", str(dest / f"{name}.txt"), url], dry_run, require="curl")
