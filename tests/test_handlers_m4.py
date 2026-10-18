"""Milestone 4: pcap handler (HTTP object export + DNS exfil reassembly)."""

import subprocess
import textwrap

import pytest

from frx.cli import main

_HAS_SCAPY = subprocess.run(["python3", "-c", "import scapy"], capture_output=True).returncode == 0

_BUILD = textwrap.dedent(
    """
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
    import base64, sys
    out = sys.argv[1]
    pkts = []
    body = b"<html>" + base64.b64encode(b"CTF{http_object_export}") + b"</html>"
    resp = (b"HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n"
            b"Content-Length: %d\\r\\n\\r\\n" % len(body)) + body
    pkts.append(IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=40000, flags="PA", seq=1) / Raw(resp))
    h = "CTF{dns_exfil_reassembled}".encode().hex()
    for i in range(0, len(h), 12):
        q = "%s.exfil.example" % h[i:i+12]
        pkts.append(IP(src="10.0.0.1", dst="10.0.0.53") / UDP(sport=50000, dport=53) / DNS(rd=1, qd=DNSQR(qname=q)))
    wrpcap(out, pkts)
    """
)


@pytest.mark.skipif(not _HAS_SCAPY, reason="needs scapy to build the fixture")
def test_pcap_http_object_and_dns_exfil(tmp_path):
    pcap = tmp_path / "traffic.pcap"
    subprocess.run(["python3", "-c", _BUILD, str(pcap)], check=True, capture_output=True)
    case = tmp_path / "case"
    rc = main(["run", str(pcap), "--mode", "full", "--flag-format", "CTF{...}", "--case", str(case)])
    assert rc == 0
    flags = (case / "FLAGS.txt").read_text()
    assert "CTF{http_object_export}" in flags
    assert "CTF{dns_exfil_reassembled}" in flags
    assert "pcap:dns" in flags  # the DNS channel was reassembled, not raw-scanned
