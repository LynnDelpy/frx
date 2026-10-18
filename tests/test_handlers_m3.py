"""Milestone 3: archive (nested, compressed) and disk (deleted-file) handlers."""

import shutil
import subprocess
import zipfile

import pytest

from frx.cli import main


def _flag_prov(case, value):
    for line in (case / "FLAGS.txt").read_text().splitlines():
        if line.startswith(value + "\t"):
            return line.split("\t", 1)[1]
    return None


def test_nested_compressed_zip_requires_extraction(tmp_path):
    # Compressible payload so deflate hides the flag from a raw byte scan:
    # only real extraction can surface it.
    flag = b"CTF{deep_in_the_archive}"
    payload = flag + b"\n" + b"A" * 20000
    inner = tmp_path / "flag.txt"
    inner.write_bytes(payload)
    a = tmp_path / "a.zip"
    b = tmp_path / "b.zip"
    n = tmp_path / "nested3.zip"
    with zipfile.ZipFile(a, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(inner, "flag.txt")
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(a, "a.zip")
    with zipfile.ZipFile(n, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(b, "b.zip")
    assert flag not in n.read_bytes()  # raw scan cannot find it

    case = tmp_path / "case"
    rc = main(["run", str(n), "--mode", "full", "--flag-format", "CTF{...}", "--case", str(case)])
    assert rc == 0
    prov = _flag_prov(case, flag.decode())
    assert prov is not None
    assert "archive" in prov  # found through extraction, not raw


@pytest.mark.skipif(
    shutil.which("mkfs.ext4") is None or shutil.which("debugfs") is None or shutil.which("tsk_recover") is None,
    reason="needs e2fsprogs + sleuthkit",
)
def test_ext4_deleted_file_recovered(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "secret.txt").write_bytes(b"CTF{recovered_from_slack}")
    img = tmp_path / "disk.img"
    subprocess.run(["dd", "if=/dev/zero", f"of={img}", "bs=1M", "count=20", "status=none"], check=True)
    subprocess.run(["mkfs.ext4", "-q", "-d", str(d), str(img)], check=True, capture_output=True)
    subprocess.run(["debugfs", "-w", "-R", "rm /secret.txt", str(img)], check=True, capture_output=True)

    case = tmp_path / "case"
    rc = main(["run", str(img), "--mode", "full", "--flag-format", "CTF{...}", "--case", str(case)])
    assert rc == 0
    flags = (case / "FLAGS.txt").read_text()
    assert "CTF{recovered_from_slack}" in flags
    # the disk handler recovered or dumped it (not just a raw scan of the image)
    fj = (case / "findings.jsonl").read_text()
    assert "disk:fs:recover" in fj or "disk:fs:unallocated" in fj
