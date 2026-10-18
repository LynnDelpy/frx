"""Capstone acceptance test (spec section 14).

Generate every local fixture with tests/make-fixtures.sh, run a single full pass
over all of them, and assert every flag in tests/expected.txt lands in
FLAGS.txt. Individual fixtures that need a missing tool simply won't be built;
their flags are skipped rather than failing the suite.
"""

import subprocess
from pathlib import Path

import pytest

from frx.cli import main

ROOT = Path(__file__).resolve().parent


@pytest.mark.slow
def test_all_fixtures_yield_flags(tmp_path):
    out = tmp_path / "out"
    subprocess.run(["bash", str(ROOT / "make-fixtures.sh"), str(out)], check=True, capture_output=True)

    inputs = [str(p) for p in sorted(out.iterdir()) if p.is_file() and p.name != "words.txt"]
    assert inputs, "no fixtures were generated"
    wordlist = out / "words.txt"

    case = tmp_path / "case"
    argv = ["run", *inputs, "--mode", "full", "--flag-format", "CTF{...}", "--case", str(case)]
    if wordlist.is_file():
        argv += ["--wordlist", str(wordlist)]
    assert main(argv) == 0

    found = (case / "FLAGS.txt").read_text() if (case / "FLAGS.txt").is_file() else ""
    expected = (ROOT / "expected.txt").read_text().split()
    # A flag counts if its fixture was built; a fixture that needs a missing tool
    # leaves no trace, so only assert flags whose inputs exist.
    built_markers = {
        "CTF{nested_pipeline_works}": (out / "nested.txt").exists(),
        "CTF{utf16_wide_string}": (out / "wide.bin").exists(),
        "CTF{deep_in_the_archive}": (out / "nested3.zip").exists(),
        "CTF{exif_comment_flag}": (out / "appended.png").exists(),
        "CTF{stegseek_cracked_it}": (out / "cover.jpg").exists(),
        "CTF{recovered_from_slack}": (out / "disk.img").exists(),
        "CTF{iso_contents_read}": (out / "data.iso").exists(),
        "CTF{http_object_export}": (out / "traffic.pcap").exists(),
        "CTF{dns_exfil_reassembled}": (out / "traffic.pcap").exists(),
    }
    missing = [fl for fl in expected if built_markers.get(fl, True) and fl not in found]
    assert not missing, f"missing flags: {missing}"
