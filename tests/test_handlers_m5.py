"""Milestone 5: image stego (exif, stegseek) and document (PDF stream) handlers."""

import shutil
import subprocess
import zipfile
import zlib

import pytest

from frx.cli import main


def _flags(case):
    p = case / "FLAGS.txt"
    return p.read_text() if p.is_file() else ""


@pytest.mark.skipif(shutil.which("exiftool") is None or shutil.which("convert") is None, reason="needs exiftool + imagemagick")
def test_png_exif_comment(tmp_path):
    png = tmp_path / "base.png"
    subprocess.run(["convert", "-size", "32x32", "xc:navy", str(png)], check=True, capture_output=True)
    subprocess.run(["exiftool", "-q", "-overwrite_original", "-Comment=CTF{exif_comment_flag}", str(png)], check=True, capture_output=True)
    case = tmp_path / "case"
    assert main(["run", str(png), "--mode", "full", "--flag-format", "CTF{...}", "--case", str(case)]) == 0
    assert "CTF{exif_comment_flag}" in _flags(case)


@pytest.mark.skipif(
    shutil.which("steghide") is None or shutil.which("stegseek") is None or shutil.which("convert") is None,
    reason="needs steghide + stegseek + imagemagick",
)
def test_steghide_cracked_by_stegseek(tmp_path):
    cover = tmp_path / "cover.jpg"
    subprocess.run(["convert", "-size", "128x128", "plasma:", str(cover)], check=True, capture_output=True)
    secret = tmp_path / "s.txt"
    secret.write_bytes(b"CTF{stegseek_cracked_it}")
    subprocess.run(["steghide", "embed", "-cf", str(cover), "-ef", str(secret), "-p", "password123", "-q"], check=True, capture_output=True)
    wl = tmp_path / "words.txt"
    wl.write_text("password123\nhunter2\nletmein\n")
    case = tmp_path / "case"
    assert main(["run", str(cover), "--mode", "full", "--flag-format", "CTF{...}", "--wordlist", str(wl), "--case", str(case)]) == 0
    assert "CTF{stegseek_cracked_it}" in _flags(case)


def test_pdf_compressed_stream(tmp_path):
    flag = b"CTF{pdf_stream_decoded}"
    content = b"BT /F1 24 Tf 72 720 Td (" + flag + b") Tj ET"
    comp = zlib.compress(content)
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(comp) + comp + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    pdf = b"%PDF-1.5\n"
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(pdf))
        pdf += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(pdf)
    pdf += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offs:
        pdf += b"%010d 00000 n \n" % off
    pdf += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF" % (len(objs) + 1, xref)
    assert flag not in pdf  # hidden in the compressed stream
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(pdf)
    case = tmp_path / "case"
    assert main(["run", str(doc), "--mode", "full", "--flag-format", "CTF{...}", "--case", str(case)]) == 0
    assert "CTF{pdf_stream_decoded}" in _flags(case)
