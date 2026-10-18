import json

from frx.report.findings import Finding, FindingWriter


def test_finding_rejects_bad_severity():
    import pytest

    with pytest.raises(ValueError):
        Finding(severity="wat", handler="x", type="info", value="v", item_sha="ab")


def test_finding_to_dict_drops_null_optionals():
    f = Finding(severity="info", handler="binary", type="artifact", value="v", item_sha="ab")
    d = f.to_dict()
    assert "offset" not in d and "command" not in d
    assert d["flag"] is False and d["ts"].endswith("Z")


def test_writer_appends_jsonl_and_flushes(tmp_path):
    with FindingWriter(tmp_path) as w:
        w.emit(Finding(severity="info", handler="binary", type="artifact", value="v", item_sha="ab"))
        # readable before close: per-finding flush
        lines = (tmp_path / "findings.jsonl").read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["value"] == "v"


def test_confirmed_flag_mirrored_to_flags_txt_once(tmp_path):
    with FindingWriter(tmp_path) as w:
        for _ in range(2):
            w.emit(
                Finding(
                    severity="flag", handler="pcap", type="flag", value="CTF{x}",
                    item_sha="ab", flag=True, confidence=1.0,
                    provenance=["input.pcap", "base64", "CTF{x}"],
                )
            )
    flags = (tmp_path / "FLAGS.txt").read_text().splitlines()
    assert flags == ["CTF{x}\tinput.pcap -> base64 -> CTF{x}"]


def test_listener_receives_finding(tmp_path):
    seen = []
    with FindingWriter(tmp_path) as w:
        w.add_listener(seen.append)
        w.emit(Finding(severity="info", handler="binary", type="artifact", value="v", item_sha="ab"))
    assert seen and seen[0].value == "v"
