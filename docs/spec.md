# frx: offline CTF forensics CLI (build spec)

Target host: CachyOS (Arch). Language: Python 3.11+. Personal single user
tool: no multi user, no server, no AI at runtime.

Sections 0 to 15 are the original brief. Section 16 lists the amendments
approved on 2026-10-18; where they conflict with earlier sections, the
amendments win.

## 0. Design rules for the implementer

- One responsibility per file. Keep modules small and focused (aim ~100 lines,
  split when a file grows a second job). No god objects.
- Wrap external tools via `subprocess` with explicit argv lists (never
  `shell=True`), per call timeout, captured stdout/stderr, and record the exact
  command in the finding provenance.
- Never execute extracted/carved files. Never write outside the case dir.
- Fail loud per item, continue the run. One broken input must not kill the pass.
- Every nontrivial action emits a finding with a provenance chain. A flag you
  cannot explain how you found is useless in a CTF.

## 1. Goals / non goals

Goals:
- Two modes against one input set: `recon` (fast, read only, minutes) and
  `full` (recursive carving + decode + stego + memory sweep, 20 to 40+ min).
- Wrap existing tools (vol3, tshark, sleuthkit, binwalk, strings, stego tools,
  decoders). frx is an orchestrator, not a reimplementation.
- Take the CTF flag format as input, search for it directly and through common
  encodings, and recursively decode candidates offline.
- Build a vol3 Linux ISF when given matching kernel symbols; use `--offline` for
  Windows so no runtime network fetch happens.
- Mount or unpack container inputs (ISO, disk image, archive) on demand, read only.
- Real progress reporting and a graceful stop that still produces a report.

Non goals:
- No cracking of strong crypto, no keyless Vigenere, no bespoke ciphers.
- No cloud, no telemetry, no model calls.
- Not a replacement for manual analysis: it surfaces leads, it does not "win".

## 2. Offline semantics (precise)

"Offline" means zero network egress during analysis, not air gapped overall.

- `setup` phase MAY use network (package install, symbol packs, wordlists).
- `run` phase MUST make no network requests. Enforce with the kernel, not trust:
  wrap the entire analysis pass in `unshare -rn` (user + network namespace) when
  `--enforce-offline` is set (default on). If `unshare` is unavailable or fails,
  refuse to run unless `--no-sandbox` is passed explicitly, and log that choice.
- vol3 always invoked with `--offline`. Its symbol dir is pre-populated in setup.
- `check` verifies every dependency and symbol pack is present before a run so a
  40 minute pass never dies 30 minutes in on a missing binary.

## 3. CLI

```
frx setup [--yes] [--with-wordlists] [--isf-only]
frx check
frx run <input...> \
    --mode {recon,full} \
    --flag-format 'CTF{...}'            # repeatable; or --flag-regex
    --flag-regex 'CTF\{[^}]+\}'         # repeatable; overrides parsed format
    --case <dir>                        # default ./cases/<timestamp>
    --max-runtime 40m                   # soft global budget, finalize on hit
    --max-depth 6                       # recursion cap on extracted items
    --max-extracted-size 4G             # zip bomb guard, total
    --max-files 50000                   # extracted item cap
    --build-isf <vmlinux> [--system-map <map>]   # generate Linux ISF then run
    --mount / --no-mount                # default no-mount, prefer TSK/7z
    --enforce-offline / --no-sandbox    # default enforce
    --jobs N                            # parallel item workers, default ncpu-1
    --resume <case>                     # continue an interrupted case
```

`<input>` may be: raw/lime memory dump, pcap/pcapng, disk image (dd/E01),
iso, archive (zip/7z/tar/...), any single file, or a directory.

Input type is detected, not inferred from extension (section 5).

## 4. Architecture: a work queue, not a script

Core is a deduplicating work queue. Each queue item:

```
Item(sha256, path, kind, depth, parent_sha, provenance[list[str]])
```

Loop: pop item -> identify kind -> dispatch to handler(s) for that kind ->
handler may (a) emit findings, (b) extract child files, pushed back as new items
with depth+1 and extended provenance. Dedupe by sha256 before enqueue. Stop
enqueue at `--max-depth`, `--max-files`, or `--max-extracted-size`.

Module layout:

```
frx/
  cli.py            # argparse, wires config -> engine
  config.py         # TOML load/merge, defaults, flag format parsing
  engine/
    queue.py        # dedup queue, depth/size/file caps
    identify.py     # magic based kind detection (routing table)
    dispatch.py     # kind -> [handler] map, per item timeout, parallelism
    runner.py       # subprocess wrapper: argv, timeout, capture, provenance
    sandbox.py      # unshare -rn wrapping, mount helpers (ro,noexec,...)
    budget.py       # global runtime budget, SIGINT -> graceful finalize
  handlers/
    memory.py       # vol3 (+ISF build), banners, plugin sweep
    pcap.py         # tshark stats, object export, stream follow, dns
    disk.py         # sleuthkit: mmls/fsstat/fls/icat/tsk_recover/blkls
    archive.py      # 7z/tar/unzip, iso via 7z, nested
    image.py        # exiftool, zsteg, stegseek, steghide, outguess, pngcheck
    document.py     # pdfid/pdf-parser/pdfdetach, oletools
    binary.py       # file, strings (ascii/-el/-eb), binwalk, foremost, bulk_extractor, entropy
  flags/
    formats.py      # default formats + regex compile
    needles.py      # encoded prefix needle generation
    scan.py         # ripgrep needles over strings + raw across all items
  decode/
    detect.py       # charset detection of candidate blobs
    codecs.py       # base64/32/58/85, hex, bin, dec, morse, url, utf16
    classic.py      # rot-n, rot47, atbash, xor single byte brute
    score.py        # printable ratio, chi-square English, flag regex terminal
    engine.py       # recursive decode with depth cap + scoring
  report/
    findings.py     # Finding dataclass + JSONL writer (append, flush per hit)
    render.py       # report.md renderer
  progress/
    ui.py           # rich live display (phases, queue depth, ETA, live hits)
    log.py          # heartbeat line to run.log for tail -f / headless
```

## 5. Identification + routing

Use `python-magic` (libmagic) plus a small signature table for things libmagic
is weak on (LiME header `EMiL`, raw memory heuristics, E01 `EVF`).

| kind       | detect                                            | handlers            |
|------------|---------------------------------------------------|---------------------|
| memory_raw | LiME `EMiL`, or `--kind memory`, or vol3 probe    | memory              |
| memory_win | banners/KDBG probe                                | memory              |
| pcap       | libmagic pcap/pcapng                              | pcap                |
| disk_image | MBR/GPT via `mmls`, filesystem magic, E01         | disk                |
| iso        | ISO9660/UDF                                       | archive (7z)        |
| archive    | zip/7z/tar/gz/xz/bz2/rar                          | archive             |
| image      | png/jpg/bmp/gif                                   | image, binary       |
| document   | pdf, ole/ooxml                                    | document, binary    |
| other/bin  | fallback                                          | binary              |

Every item, regardless of kind, also goes through: sha256, `file`, `exiftool`,
entropy, and the flag needle scan (section 7). The binary handler is the
universal fallback so nothing is skipped.

## 6. Handlers

Recon mode runs the read only subset. Full mode runs everything and feeds
extracted files back into the queue.

### 6.1 memory.py (vol3)

Setup prerequisites (section 9): Windows/Mac symbol packs in
`$VOL_SYMBOLS/windows|mac`, dwarf2json present for Linux ISF build.

Flow:
1. `banners.Banners` always (both OS families). Record kernel/OS string. This is
   how Linux dumps get identified and how you know which ISF you need.
2. If `--build-isf <vmlinux>` given: run
   `dwarf2json linux --elf <vmlinux> [--system-map <map>]` and write the JSON to
   `$VOL_SYMBOLS/linux/<name>.json.xz` (xz compressed, vol3 reads it). Then
   verify by re-running a cheap linux plugin. If banner version and supplied
   vmlinux version disagree, warn and continue (user's call).
3. OS detection: try `windows.info`; on failure try a linux plugin. Cache the
   chosen context so the sweep does not re-probe.

Recon: `banners`, `windows.info` or linux banner, pslist only.

Full sweep (per plugin timeout, e.g. 300s, skip on timeout and log):
- Windows: info, pslist, pstree, psscan, cmdline, cmdscan, consoles, netscan,
  netstat, filescan, malfind, svcscan, getsids, envars, clipboard, hashdump,
  lsadump, cachedump, registry.hivelist, registry.printkey (Run keys),
  dumpfiles (targeted on suspicious filescan hits only, not all).
- Linux: banner, bash, pslist, psaux, lsof, lsmod, proc.Maps, envars,
  check_syscall, malfind if available.
- Mac: analogous mac.* set.

All plugin text output is scanned for flag needles. Dumped files (malfind
regions, dumpfiles) are enqueued as child items. vol3 invoked with `--offline`
and a private `--cache-path` inside the case dir.

Honest limit to surface in the report: a Linux dump with no matching debug
symbols and no `--build-isf` cannot be analyzed past `banners`. Say so, name the
exact kernel string needed, do not silently produce nothing.

### 6.2 pcap.py (tshark)

Recon: `-z io,phs` (protocol hierarchy), `-z conv,tcp`, `-z conv,udp`,
`-z endpoints,ip`, `-z http,tree`. Summarize top talkers and odd protocols.

Full:
- Export objects: `--export-objects http,<dir>`, `smb`, `tftp`, `imf`, `dicom`.
  Enqueue every exported object.
- Follow streams: enumerate tcp/udp streams, `-z follow,tcp,raw,<n>` for each,
  dump raw to files, enqueue. Cap stream count (e.g. 500) and size.
- Credentials: `-z credentials`.
- DNS exfil: extract all `dns.qry.name`, strip the zone, concat subdomain labels
  in order, try hex/base32/base64 decode of the reassembled string. Classic
  channel, high value. Also check `dns.txt`.
- ICMP/other payload bytes dumped and enqueued.
- Fields of interest grepped for needles: `http.file_data`, `data.data`,
  `ftp-data`, usernames/passwords.

### 6.3 disk.py (sleuthkit), preferred over mounting

- `mmls` for partition table, `fsstat` per partition.
- `fls -r -p` full recursive listing including deleted (deleted entries flagged
  `*`), parse into a tree.
- `icat` each file (and allocated but interesting deleted inodes) and enqueue.
  `tsk_recover -e` to bulk extract allocated + deleted into a dir, enqueue tree.
- `blkls` unallocated space, then run the binary handler + needle scan (slack
  space hides flags).
- Only fall back to loop mount if TSK cannot parse the FS and `--mount` is set.

### 6.4 archive.py

- `7z x` handles zip/7z/tar/gz/xz/iso/udf/wim. `unar` as fallback for odd rar.
- Password: if an archive is encrypted, try the configured wordlist
  (`7z` + password list, or `fcrackzip`/`john zip2john` for zip). Cap attempts.
- Every extracted entry enqueued with depth+1. Zip bomb guard via the global
  size/file/depth caps in queue.py.

### 6.5 image.py (stego)

- `exiftool` full dump (comments, GPS, XMP), then needle scan.
- `pngcheck -v` / `jpeginfo` for structural anomalies and trailing data.
- `zsteg -a` on png/bmp (LSB, many channels). Enqueue any extracted payloads.
- `stegseek <jpg> <wordlist>` (fast steghide brute). On success enqueue the
  recovered file. `steghide extract` with empty + wordlist passphrases.
- `outguess -r` attempt.
- Trailing data / appended archive check via binwalk (handled in binary too).

### 6.6 document.py

- PDF: `pdfid`, `pdf-parser` (streams, /JS, /OpenAction), `pdfdetach -saveall`.
  Enqueue attachments and decompressed streams. `pdftotext`, then needle scan.
- Office: `olevba` (macros), `oleid`, `oledump`. Macro source, then needle scan.

### 6.7 binary.py (universal fallback)

- `file`, `exiftool`, sha256, entropy (flag high entropy regions).
- `strings` three passes: default ASCII, `strings -el` (UTF-16LE, essential for
  Windows memory and .NET), `strings -eb` (UTF-16BE). Needle scan all three.
- `binwalk` signature scan (recon) and binwalk extraction (full), enqueue output.
- `foremost -t all` carve, enqueue output.
- `bulk_extractor` (emails, urls, base64, ccn, etc.) into a feature dir, needle
  scan and feed base64 features into the decoder.

## 7. Flag engine

### 7.1 Formats (flags/formats.py)

Input `--flag-format 'CTF{...}'`: everything before the first `...`/`{` wildcard
is the literal prefix, the surrounding `{ }` (or whatever) are delimiters. From
that build a regex. Users may instead pass `--flag-regex` directly (repeatable).

Ship defaults (case insensitive prefix, greedy bounded body), scanned alongside
any user format:

```
flag\{[^}\n]{1,256}\}
CTF\{[^}\n]{1,256}\}
[A-Za-z0-9_]{2,16}\{[^}\n]{1,256}\}   # generic prefix{...}, catches custom
```

A `--flag-regex` match is a terminal, confirmed flag (highest severity). The
generic pattern produces candidates, not confirmations.

### 7.2 Encoded prefix needle search (flags/needles.py), the fast path

Blind decoding everything is noise. Instead, take the literal prefix (e.g.
`CTF{`) and precompute how it would look after common single encodings, then
ripgrep those needles across every item's raw bytes and all three strings
passes. A hit localizes the flag; point the full decoder at that window.

Needles to generate from prefix `P`:
- base64 of `P` at 3 phase alignments (prepend 0/1/2 filler bytes), drop the
  last 1 to 2 chars that depend on the body. Keep the stable middle substring.
- base32 of `P` at its alignments, same edge trim.
- hex of `P`, both cases.
- `P` reversed.
- rot-n of `P` for n in 1..25, and rot47.
- UTF-16LE of `P`: `C\x00T\x00F\x00{\x00`.
- URL encoded: `{` becomes `%7B`, etc.
- base58/base85 middle substrings (best effort).

Use `rg -a -o --byte-offset -f needles.txt` for speed; map byte offset back to
the item and extract a window (e.g. 4 KiB around the hit) for the decoder.

## 8. Decoder engine (decode/)

No AI. Pure structure + statistics.

- detect.py: classify a candidate blob by charset, which picks the codecs to try
  (base64/32/58/85, hex, binary string, decimal, morse, url, utf16, quoted
  printable). Length/charset gates reduce false starts.
- engine.py: recursive. Decode, score, and if the flag regex matches, terminal
  success. Else if the score passes the threshold and depth < 5, re-feed the
  output as a new candidate. Track the decode chain in provenance
  (`base64 -> hex -> rot13 -> flag`).
- classic.py: all 25 Caesar rotations, rot47, atbash, single byte XOR brute
  (256 keys), each result scored.
- score.py:
  - flag regex match => 1.0 terminal.
  - else `0.6*printable_ratio + 0.4*english_chi2_score` (chi2 against English
    letter frequency, normalized). Bonus if result contains the flag prefix
    chars or `{`/`}`.
  - threshold ~0.5 to continue recursion; keep top N candidates per item.

Candidate sources: needle hit windows (primary), bulk_extractor base64 features,
any long high charset purity run found in strings output.

## 9. setup / check (dependency manifest)

`setup` detects distro (Arch first), installs, verifies. Manifest in
`frx/data/deps.toml`:

```
[pacman]
pkgs = ["python","python-rich","wireshark-cli","sleuthkit","binwalk",
        "foremost","perl-image-exiftool","p7zip","unar","ripgrep",
        "steghide","outguess","pngcheck","qpdf","go"]
[aur]            # paru/yay; prompt if neither present
pkgs = ["stegseek","bulk_extractor","dwarf2json-git"]
[pipx]
pkgs = ["volatility3","oletools"]
[gem]
pkgs = ["zsteg"]
[python-magic]   # libmagic binding for identify.py
pkgs = ["python-magic"]

[symbols]
# vol3 symbol packs -> $VOL_SYMBOLS (default ~/.local/share/frx/symbols)
windows = "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip"
mac     = "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip"
# linux: NO pack. Built per dump via dwarf2json (--build-isf).

[wordlists]      # only with --with-wordlists
rockyou = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
```

`check` (run before every analysis): each binary resolves on PATH, vol3 imports,
Windows/Mac symbol packs present, wordlist present if stego brute enabled,
`unshare -rn true` works. Print a table, exit nonzero if anything required is
missing. This is what makes a 40 minute run safe to start.

## 10. Progress + long run UX

- `rich` live display, refreshed ~4/s:
  - current phase, mode, elapsed / budget remaining (ETA from budget).
  - queue: pending / done / extracted so far, current depth.
  - per worker line: item short sha + handler + running tool + its elapsed.
  - a pinned "FLAGS" panel that appends confirmed hits the instant they land.
  - findings counters by severity.
- Also write a one line heartbeat every ~10s to `<case>/run.log` so a headless
  or tmux run is followable with `tail -f` (no TTY dependency).
- Confirmed flags also printed to stdout immediately and to `<case>/FLAGS.txt`.
- `budget.py`: on `--max-runtime` reached or SIGINT, stop dispatching new items,
  let in-flight tool calls finish or time out, then finalize findings.jsonl and
  render report.md. Never lose collected work. `--resume <case>` reloads the
  dedupe set and queue state and continues.

## 11. Output

Case dir:
```
cases/<ts>/
  FLAGS.txt              # confirmed flags, one per line, with provenance
  findings.jsonl         # append only, flushed per finding
  report.md
  run.log                # heartbeat + command log
  extracted/<sha>/...    # extracted/carved file tree, namespaced by parent sha
  vol-cache/             # vol3 cache, isolated
```

Finding schema (one JSON object per line):
```json
{
  "ts": "2026-10-18T12:00:00Z",
  "severity": "flag|high|info",
  "handler": "pcap",
  "type": "flag|flag_candidate|extracted_file|artifact|decoded",
  "value": "CTF{...}",
  "flag": true,
  "confidence": 1.0,
  "item_sha": "ab12...",
  "offset": 40960,
  "provenance": ["input.pcap","http-object-3","base64","CTF{...}"],
  "command": "tshark -r input.pcap --export-objects http,..."
}
```

report.md order: confirmed flags (with full provenance chain + the exact command
to reproduce) first, then high signal artifacts (creds, suspicious procs,
decoded candidates), then extracted file tree summary, then per handler
sections, then timing table and full command log. Reproducibility is the point:
every claim carries the command that produced it.

## 12. Safety / robustness caps

- per tool timeout (default 300s, vol3 plugins own value), per item timeout.
- depth/file count/total size caps enforced at enqueue (zip bomb, binwalk loop,
  carve recursion guards).
- sha256 dedupe so re-extracted identical blobs are not reprocessed.
- never exec extracted files; mounts always `ro,noexec,nosuid,nodev` and only if
  `--mount`; prefer TSK/7z.
- `nice`/`ionice` the workers.
- analysis pass inside `unshare -rn` (section 2).

## 13. Build order (milestones, each testable)

1. queue + identify + runner + findings + a minimal binary handler (file,
   strings 3x, needle scan) + report. Run end to end on a text fixture.
2. flag engine (formats + needles + scan) and decoder engine. Verify on the
   nested encoding and utf16 fixtures.
3. archive + disk handlers. Verify on nested zip, iso, deleted file image.
4. pcap handler. Verify on the crafted pcap (http object + dns exfil).
5. image/document stego handlers. Verify on exif + zsteg + stegseek fixtures.
6. memory handler incl. `--build-isf`. Verify on a self made LiME dump + ISF.
7. progress UI, budget/SIGINT/resume, sandbox enforcement, setup/check.

## 14. Test fixtures

`tests/make-fixtures.sh` generates inputs locally (no downloads except the
memory case) and `tests/expected.txt` lists the flag each must yield. Running
`frx run tests/out/* --mode full --flag-format 'CTF{...}'` must put every
expected flag in FLAGS.txt.

Fixtures (see amendment A6 for the root free disk image):
1. nested encoding: `CTF{nested_pipeline_works}` through base64, hex, rot13,
   buried in random base64 junk.
2. UTF-16LE flag `CTF{utf16_wide_string}` (strings -el path).
3. triple nested zip with `CTF{deep_in_the_archive}` (recursion + depth caps).
4. PNG with exif comment `CTF{exif_comment_flag}` plus an appended zip.
5. steghide JPEG with weak password `password123` from a test wordlist,
   payload `CTF{stegseek_cracked_it}`.
6. ext4 image with a DELETED file holding `CTF{recovered_from_slack}`.
7. ISO with a flag file `CTF{iso_contents_read}`.
8. pcap: HTTP body with base64 of `CTF{http_object_export}` plus DNS exfil of
   hex chunks of `CTF{dns_exfil_reassembled}` across A query labels.

Memory test (needs more setup, proves the ISF path end to end): see amendment
A12.

## 15. Config file (TOML)

`~/.config/frx/config.toml`, overridden by CLI flags:

```toml
flag_formats = ["CTF{...}", "flag{...}"]
wordlist = "/usr/share/wordlists/rockyou.txt"
jobs = 7
[timeouts]
per_tool = 300
vol_plugin = 300
[limits]
max_depth = 6
max_files = 50000
max_extracted_size = "4G"
[paths]
vol_symbols = "~/.local/share/frx/symbols"
```

## 16. Amendments (approved 2026-10-18)

These were found while checking the brief against the actual host.

A1. binwalk 3.x. The host has binwalk 3.1 (the Rust rewrite), where `--dd` no
longer exists. binary.py runs `binwalk -l <json>` for the signature scan and
`binwalk -e -C <dir> -l <json>` for extraction, then parses the JSON log. A 2.x
binwalk is detected and gets the old flags.

A2. The vol3 plugin set is discovered, not assumed. vol3 2.28 has no
`linux.banner` (`banners.Banners` covers it) and no `windows.clipboard`.
Several plugins moved under `windows.malware.*` and `windows.registry.*`, with
deprecated aliases at the old paths. memory.py lists the installed plugins once,
prefers the new path, runs the intersection with the configured set, and logs
every configured plugin that is missing. vol3 lives in its own Python 3.12 venv,
so library import is not possible: it runs as a subprocess with `-r jsonl`
output for parsing.

A3. Decoder gating. With `0.6*printable + 0.4*chi2` and a 0.5 threshold, every
Caesar rotation of printable text passes and recursion explodes. Charset
preserving transforms (rot-n, rot47, atbash, reverse) and single byte XOR only
recurse when the output matches the flag regex, contains the flag prefix, scores
clearly better on English than its input, or lands in a stricter charset class
(for example rot13 turning `[0-9n-s]` into valid hex). Reducing codecs
(base64/32/58/85, hex, binary, decimal, morse, url, quoted printable, utf16)
recurse on the spec score.

A4. Generic flag pattern. `[A-Za-z0-9_]{2,16}\{...\}` stays but only produces
`flag_candidate` findings, deduplicated and capped per item. In byte scans the
default patterns restrict the body to printable ASCII without `}` instead of
`[^}\n]`, so binary noise between braces does not match. User `--flag-regex`
patterns are used exactly as given.

A5. Mounting. Unprivileged user namespaces cannot loop mount, so a mount cannot
happen inside `unshare -rn`. The disk fallback chain is TSK, then 7z (it reads
ext, NTFS, FAT, HFS+, APFS, VMDK, VHD and QCOW2), then a `udisksctl` mount
(read only, noexec, nosuid, nodev), which only runs with `--mount` plus
`--no-sandbox`.

A6. Fixtures. Fixture 6 is built without root: `mkfs.ext4 -d` populates the
image and `debugfs -w -R 'rm secret.txt'` deletes the file. Fixture 7 needs
xorriso (package `libisoburn`). The pcap fixture uses scapy, which is installed.

A7. Writes outside the case dir. Every subprocess gets `TMPDIR=<case>/tmp` and
`PYTHONDONTWRITEBYTECODE=1`. john gets `--pot` and `--session` inside the case
dir. vol3 gets `--cache-path <case>/vol-cache`.

A8. Unpackaged tools. bulk_extractor is in neither the repos nor the AUR, so it
is optional and `check` reports it as such. pdfid and pdf-parser are not
packaged: `setup` downloads Didier Stevens' scripts into
`~/.local/share/frx/tools`. qpdf decompresses PDF streams either way.

A9. Archive passwords. 7z tests about 100 passwords per second, so encrypted
zips go through `zip2john` plus `john --wordlist` (capped), and 7z with a short
list is the fallback for other formats.

A10. Strings on large inputs. The three strings passes are piped straight into
rg instead of being written to disk. Only hits and their windows are kept.

A11. Install and runtime. frx installs with `uv tool install --editable .`,
which gives it its own venv with rich and python-magic. identify.py falls back
to the `file` command when python-magic is missing. Package installs need sudo,
which the user runs; `setup` prints the commands and runs them interactively.

A12. Memory fixture. `tests/make-memory-fixture.sh` boots the host CachyOS
kernel under QEMU/KVM with a static initramfs that plants flags in a process
environment and argv, dumps guest RAM through the QEMU monitor (`pmemsave`),
and wraps it as LiME. The ISF is built from the `linux-cachyos-dbg` vmlinux
(downloaded and unpacked in user space, nothing installed) with the dwarf2json
GitHub release binary.

A13. Version control. The repo is local git on `main`, with one commit per
milestone.

A14. Package names. The shipped manifest uses current Arch names (`7zip`
instead of `p7zip`, `unarchiver` for `unar`, `libisoburn` for xorriso), adds
`poppler` (pdftotext, pdfdetach), and takes dwarf2json from its GitHub release
binary instead of building `dwarf2json-git` with Go. volatility3 and oletools
are accepted from any install that puts `vol` and `olevba` on PATH (pipx, uv
tool, or an existing venv).
