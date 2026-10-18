import gzip
import struct
import zipfile

from frx.engine import identify as idf


def test_override_wins(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"\x00\x01\x02")
    assert idf.identify(p, override="memory") == idf.MEMORY_RAW


def test_lime_header(tmp_path):
    p = tmp_path / "mem.lime"
    p.write_bytes(b"EMiL" + b"\x00" * 100)
    assert idf.identify(p) == idf.MEMORY_RAW


def test_png_signature(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
    assert idf.identify(p) == idf.IMAGE


def test_pdf_signature(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"%PDF-1.7\n..." + b"\x00" * 50)
    assert idf.identify(p) == idf.DOCUMENT


def test_zip_signature(tmp_path):
    p = tmp_path / "a.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("f.txt", "hi")
    assert idf.identify(p) == idf.ARCHIVE


def test_gzip_signature(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(gzip.compress(b"hello"))
    assert idf.identify(p) == idf.ARCHIVE


def test_pcap_classic_magic(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(struct.pack("<I", 0xA1B2C3D4) + b"\x00" * 50)
    assert idf.identify(p) == idf.PCAP


def test_iso9660_volume_descriptor(tmp_path):
    p = tmp_path / "a.iso"
    buf = bytearray(0x8006)
    buf[0x8001:0x8006] = b"CD001"
    p.write_bytes(bytes(buf))
    assert idf.identify(p) == idf.ISO


def test_empty_file_is_other(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    assert idf.identify(p) == idf.OTHER


def test_plain_text_is_other(tmp_path):
    p = tmp_path / "t.txt"
    p.write_bytes(b"just some ascii text here\n")
    assert idf.identify(p) == idf.OTHER
