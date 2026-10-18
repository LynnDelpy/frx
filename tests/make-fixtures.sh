#!/usr/bin/env bash
# Generate local CTF fixtures for frx (spec section 14). No network needed.
# Each fixture hides one flag; tests/expected.txt lists them. The disk image is
# built without root (amendment A6): mkfs.ext4 -d populates it, debugfs deletes.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here/out}"
rm -rf "$out"; mkdir -p "$out"; cd "$out"

need() { command -v "$1" >/dev/null 2>&1 || { echo "SKIP: missing $1 (some fixtures not built)"; return 1; }; }

# 1. nested encoding: CTF{...} -> base64 -> hex -> rot13, buried in base64 junk.
f='CTF{nested_pipeline_works}'
enc=$(printf '%s' "$f" | base64 | xxd -p | tr -d '\n' | tr 'A-Za-z' 'N-ZA-Mn-za-m')
{ head -c 2000 /dev/urandom | base64; echo "$enc"; head -c 2000 /dev/urandom | base64; } > nested.txt

# 2. UTF-16LE flag (strings -el path).
printf 'CTF{utf16_wide_string}' | iconv -t UTF-16LE > wide.bin

# 3. triple-nested zip (recursion + depth caps).
printf 'CTF{deep_in_the_archive}' > flag.txt
zip -q a.zip flag.txt; zip -q b.zip a.zip; zip -q nested3.zip b.zip
rm -f flag.txt a.zip b.zip

# 4. PNG exif comment + appended archive.
if need convert && need exiftool; then
  convert -size 64x64 xc:navy base.png
  exiftool -q -overwrite_original -Comment='CTF{exif_comment_flag}' base.png
  printf 'CTF{exif_comment_flag}' > e.txt; zip -q e.zip e.txt
  cat base.png e.zip > appended.png; rm -f e.txt e.zip base.png
fi

# 5. steghide + stegseek (weak password that lives in the test wordlist).
printf 'password123\nhunter2\nletmein\n' > words.txt
if need convert && need steghide; then
  convert -size 128x128 plasma: cover.jpg
  printf 'CTF{stegseek_cracked_it}' > s.txt
  steghide embed -cf cover.jpg -ef s.txt -p password123 -q
  rm -f s.txt
fi

# 6. disk image with a DELETED file, no root (TSK recovery / slack).
if need mkfs.ext4 && need debugfs; then
  d=$(mktemp -d); printf 'CTF{recovered_from_slack}' > "$d/secret.txt"
  dd if=/dev/zero of=disk.img bs=1M count=20 status=none
  mkfs.ext4 -q -d "$d" disk.img
  debugfs -w -R 'rm /secret.txt' disk.img >/dev/null 2>&1
  rm -rf "$d"
fi

# 7. ISO with a flag file.
printf 'CTF{iso_contents_read}' > iso_flag.txt
if command -v xorriso >/dev/null 2>&1; then
  xorriso -as mkisofs -quiet -o data.iso iso_flag.txt 2>/dev/null
elif command -v mkisofs >/dev/null 2>&1; then
  mkisofs -quiet -o data.iso iso_flag.txt
fi
rm -f iso_flag.txt

# 8. pcap: HTTP base64 body + DNS exfil of a hex-chunked flag.
if command -v python3 >/dev/null 2>&1 && python3 -c 'import scapy' 2>/dev/null; then
python3 - <<'PY'
from scapy.all import IP,TCP,UDP,DNS,DNSQR,Raw,wrpcap
import base64
pkts=[]
body=b"<html>"+base64.b64encode(b"CTF{http_object_export}")+b"</html>"
resp=(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
      b"Content-Length: %d\r\n\r\n"%len(body))+body
pkts.append(IP(src="10.0.0.2",dst="10.0.0.1")/TCP(sport=80,dport=40000,flags="PA",seq=1)/Raw(resp))
h="CTF{dns_exfil_reassembled}".encode().hex()
for i in range(0,len(h),12):
    q="%s.exfil.example"%h[i:i+12]
    pkts.append(IP(src="10.0.0.1",dst="10.0.0.53")/UDP(sport=50000,dport=53)/DNS(rd=1,qd=DNSQR(qname=q)))
wrpcap("traffic.pcap",pkts)
PY
fi

echo "fixtures written to $out"
ls -1 "$out"
