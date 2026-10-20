"""Unit guards for the review fixes in the container handlers.

These drive the pure parsing/budget logic with a scripted runner, so they do not
need the real forensic tools the full integration fixtures require.
"""

from frx.engine.context import Context
from frx.engine.queue import WorkQueue
from frx.engine.runner import RunResult
from frx.flags.formats import build_formats
from frx.handlers import archive, pcap
from frx.report.findings import FindingWriter


class FakeRunner:
    default_timeout = 300.0

    def __init__(self, fn):
        self.fn = fn
        self.calls = []

    def run(self, argv, timeout=None, **kw):
        self.calls.append(argv)
        return self.fn(argv)


def _ctx(tmp_path, runner, **kw):
    return Context(
        runner=runner, findings=FindingWriter(tmp_path), queue=WorkQueue(),
        formats=build_formats(flag_formats=["CTF{...}"]), needles=[],
        case_dir=tmp_path, mode="full", **kw,
    )


class _It:
    def __init__(self, tmp_path, name="x"):
        self.path = tmp_path / name
        self.path.write_bytes(b"x")
        self.short = "abcdef012345"
        self.sha256 = "ab" * 32
        self.provenance = [name]
        self.depth = 0


def test_archive_uncompressed_size_sums_only_size_lines(tmp_path):
    def fn(argv):
        out = b"Path = a\nSize = 100\nPacked Size = 40\nPath = b\nSize = 250\n"
        return RunResult(argv, 0, out, b"", 0.0)

    ctx = _ctx(tmp_path, FakeRunner(fn))
    assert archive._uncompressed_size(ctx, _It(tmp_path, "a.zip")) == 350  # not the Packed sizes
    ctx.findings.close()


def test_capped_wordlist_enforces_limit(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("\n".join(f"w{i}" for i in range(50)) + "\n")
    ctx = _ctx(tmp_path, FakeRunner(lambda a: RunResult(a, 0, b"", b"", 0.0)), wordlist=str(wl))
    capped = archive._capped_wordlist(ctx, _It(tmp_path), 10)
    assert capped is not None and len(capped.read_text().splitlines()) == 10
    ctx.findings.close()


def test_archive_refuses_zip_bomb_before_extracting(tmp_path):
    calls = []

    def fn(argv):
        calls.append(argv[1] if len(argv) > 1 else argv[0])
        if argv[:2] == ["7z", "l"]:
            return RunResult(argv, 0, b"Size = 999999999999\n", b"", 0.0)  # huge
        return RunResult(argv, 0, b"", b"", 0.0)

    ctx = _ctx(tmp_path, FakeRunner(fn))
    ctx.queue.max_extracted_size = 1024  # tiny budget
    archive.handle(_It(tmp_path, "bomb.zip"), ctx)
    ctx.findings.close()
    import json
    vals = [json.loads(l)["value"] for l in (tmp_path / "findings.jsonl").read_text().splitlines() if l.strip()]
    assert any("not extracted" in v for v in vals)
    assert "x" not in calls  # never reached `7z x` (extraction)


def test_dns_exfil_concatenates_multiple_labels(tmp_path):
    h = b"CTF{dns}".hex()
    mid = len(h) // 2
    name = f"{h[:mid]}.{h[mid:]}.exfil.example"  # two data labels + 2-label zone

    def fn(argv):
        if "dns.qry.name" in argv:
            return RunResult(argv, 0, (name + "\n").encode(), b"", 0.0)
        return RunResult(argv, 0, b"", b"", 0.0)

    ctx = _ctx(tmp_path, FakeRunner(fn))
    captured = []

    class Dec:
        def decode_candidate(self, data, item, prov):
            captured.append(bytes(data))

    ctx.decoder = Dec()
    pcap._dns_exfil(ctx, _It(tmp_path, "t.pcap"))
    ctx.findings.close()
    assert any(h.encode() in c for c in captured)  # full hex reassembled, not just first label


def test_pcap_credentials_no_false_positive_on_header_only(tmp_path):
    def fn(argv):
        if "credentials" in argv:
            # header + separator, but no data row
            return RunResult(argv, 0, b"Packet  Protocol  Username\n--------\n", b"", 0.0)
        return RunResult(argv, 0, b"", b"", 0.0)

    ctx = _ctx(tmp_path, FakeRunner(fn))
    pcap._credentials(ctx, _It(tmp_path, "t.pcap"))
    ctx.findings.close()
    body = (tmp_path / "findings.jsonl").read_text()
    assert "credentials" not in body  # nothing emitted without a real row
