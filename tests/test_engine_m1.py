"""Milestone 1 end-to-end: queue + identify + binary handler + findings + report."""

import subprocess

from frx.cli import main


def test_run_finds_plaintext_and_utf16_flags(tmp_path):
    indir = tmp_path / "in"
    indir.mkdir()
    (indir / "plain.txt").write_bytes(b"noise\nCTF{plaintext_flag_works}\nmore\n")
    subprocess.run(
        ["iconv", "-t", "UTF-16LE"],
        input=b"CTF{utf16_wide_string}",
        stdout=(indir / "wide.bin").open("wb"),
        check=True,
    )
    case = tmp_path / "case"
    rc = main([
        "run", str(indir / "plain.txt"), str(indir / "wide.bin"),
        "--mode", "full", "--flag-format", "CTF{...}", "--case", str(case),
    ])
    assert rc == 0
    flags = (case / "FLAGS.txt").read_text()
    assert "CTF{plaintext_flag_works}" in flags
    assert "CTF{utf16_wide_string}" in flags
    assert (case / "report.md").is_file()
    assert (case / "findings.jsonl").is_file()
