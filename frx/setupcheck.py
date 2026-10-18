"""`frx check` and `frx setup` (spec section 9).

check verifies every dependency is present before a run so a long pass never
dies partway through on a missing binary. setup installs them (interactive;
package installs need sudo, which the user runs, amendment A11). The dependency
manifest lives in frx/data/deps.toml. This is the minimal check that other
milestones extend (symbol packs, wordlists, unshare probe).
"""

from __future__ import annotations

import shutil
import tomllib
from pathlib import Path

DATA = Path(__file__).parent / "data"

# name -> (how to get it, required?)
REQUIRED_BINARIES = {
    "file": True, "strings": True, "rg": True, "7z": True, "binwalk": True,
    "foremost": True, "exiftool": True, "tshark": True, "unzip": True,
    "mmls": True, "fls": True, "icat": True, "tsk_recover": True, "blkls": True,
    "pdftotext": True, "pdfdetach": True, "qpdf": True, "zsteg": True,
    "steghide": True, "stegseek": True, "pngcheck": True, "jpeginfo": True,
    "vol": True, "olevba": True, "john": True, "zip2john": True,
    "outguess": False, "bulk_extractor": False, "dwarf2json": False,
    "xorriso": False, "fcrackzip": False, "unar": False, "udisksctl": False,
}


def _present(name: str) -> bool:
    return shutil.which(name) is not None


def run_check() -> int:
    try:
        from rich.console import Console
        from rich.table import Table

        console = Console()
        table = Table(title="frx dependency check")
        table.add_column("tool")
        table.add_column("status")
        table.add_column("required")
        missing_required = 0
        for name, required in REQUIRED_BINARIES.items():
            ok = _present(name)
            if required and not ok:
                missing_required += 1
            status = "[green]ok[/]" if ok else ("[red]MISSING[/]" if required else "[yellow]missing[/]")
            table.add_row(name, status, "yes" if required else "no")
        console.print(table)
    except Exception:
        missing_required = 0
        for name, required in REQUIRED_BINARIES.items():
            ok = _present(name)
            mark = "ok" if ok else ("MISSING" if required else "missing")
            if required and not ok:
                missing_required += 1
            print(f"{name:16} {mark:8} {'required' if required else 'optional'}")

    # unshare -rn probe (offline sandbox).
    import subprocess

    try:
        r = subprocess.run(["unshare", "-rn", "true"], capture_output=True, timeout=10)
        print(f"unshare -rn: {'ok' if r.returncode == 0 else 'FAIL'}")
    except Exception:
        print("unshare -rn: FAIL")

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
    pac = manifest.get("pacman", {}).get("pkgs", [])
    aur = manifest.get("aur", {}).get("pkgs", [])
    if pac:
        print("Official packages:\n  sudo pacman -S --needed " + " ".join(pac) + "\n")
    if aur:
        print("AUR packages:\n  paru -S --needed " + " ".join(aur) + "\n")
    print("See docs/spec.md section 9 for symbol packs, pipx/gem tools, and wordlists.")
    return 0
