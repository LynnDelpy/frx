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


def run_check() -> int:
    cfg = Config.load()
    missing_required = _check_binaries()
    print()
    _check_sandbox()
    _check_symbols(cfg)
    _check_wordlist(cfg)

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


def run_setup(with_wordlists: bool = False, isf_only: bool = False, yes: bool = False) -> int:
    manifest = _load_manifest()
    print("frx setup prints the commands to run; package installs need sudo (run them yourself).\n")

    if isf_only:
        _print_tools(manifest)
        print("\n(--isf-only: skipping packages, symbol packs, and wordlists.)")
        return 0

    pac = manifest.get("pacman", {}).get("pkgs", [])
    aur = manifest.get("aur", {}).get("pkgs", [])
    pipx = manifest.get("pipx", {}).get("pkgs", [])
    gem = manifest.get("gem", {}).get("pkgs", [])
    if pac:
        print("Official packages:\n  sudo pacman -S --needed " + " ".join(pac) + "\n")
    if aur:
        print("AUR packages (paru or yay):\n  paru -S --needed " + " ".join(aur) + "\n")
    if pipx:
        print("Python tools (vol/olevba on PATH; pipx or uv tool):\n  pipx install " + " && pipx install ".join(pipx) + "\n")
    if gem:
        print("Ruby gems (if not using the AUR build):\n  gem install --user-install " + " ".join(gem) + "\n")

    _print_tools(manifest)
    _print_symbols(manifest)
    if with_wordlists:
        _print_wordlists(manifest)
    else:
        print("\nWordlists: re-run `frx setup --with-wordlists` to print their download commands.")
    print("\nAfter installing, run `frx check` to verify everything resolves before a long pass.")
    return 0


def _symbols_dir() -> Path:
    return Path(Config().vol_symbols).expanduser()


def _print_tools(manifest: dict) -> None:
    tools = manifest.get("tools", {})
    if not tools:
        return
    dest = Path("~/.local/share/frx/tools").expanduser()
    print(f"Unpackaged tools -> {dest}:")
    if "dwarf2json" in tools:
        print(f"  dwarf2json: download the release binary from {tools['dwarf2json']} and put it on PATH")
    for key in ("pdfid", "pdf_parser"):
        if key in tools:
            print(f"  {key.replace('_', '-')}.py: curl -L {tools[key]} -o {dest}/{key.replace('_', '-')}.py")


def _print_symbols(manifest: dict) -> None:
    sym = manifest.get("symbols", {})
    if not sym:
        return
    base = _symbols_dir()
    print(f"\nvol3 symbol packs -> {base}:")
    for family in ("windows", "mac"):
        if family in sym:
            print(f"  {family}: curl -L {sym[family]} -o /tmp/{family}.zip && "
                  f"unzip -o /tmp/{family}.zip -d {base}/{family}")


def _print_wordlists(manifest: dict) -> None:
    wl = manifest.get("wordlists", {})
    if not wl:
        return
    print("\nWordlists:")
    for name, url in wl.items():
        print(f"  {name}: curl -L {url} -o ~/.local/share/frx/wordlists/{name}.txt")
