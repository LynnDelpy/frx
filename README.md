# frx

Offline CTF forensics orchestrator. It wraps the tools you already use (vol3,
tshark, sleuthkit, 7z, binwalk, foremost, exiftool, stego tools, decoders),
feeds extracted files back through a deduplicating work queue, searches
everything for your flag format and its common encodings, and recursively
decodes the candidates. It surfaces leads with a full provenance chain; it does
not try to "win" the challenge for you.

It is a personal, single-user, offline tool. During a run it makes zero network
requests (enforced by the kernel, see [Offline sandbox](#offline-sandbox)).

Target host: CachyOS / Arch, Python 3.11+.

## Install

frx is an orchestrator, so most of the setup is installing the external tools
it drives. `frx setup` prints the exact commands and `frx check` verifies them,
so you never start a 40-minute run only to die on a missing binary.

```bash
# 1. get frx itself (its own venv, with rich + python-magic)
uv tool install --editable .
#    (or, without uv:)
#    python -m venv .venv && . .venv/bin/activate && pip install -e .

# 2. see what external tools/symbols/wordlists are needed, and the commands
frx setup                 # prints pacman / AUR / pipx / gem install lines
frx setup --with-wordlists   # also prints the wordlist download commands

# 3. install those (they need sudo, so you run them), then verify
frx check                 # table of every tool + the offline sandbox + GPU
```

`frx check` exits non-zero if a required tool is missing. Optional tools
(bulk_extractor, outguess, udisksctl, the `--gpu` stack) are reported but do not
fail the check.

## Quick start

```bash
# fast, read-only recon (minutes)
frx run suspicious.pcap --mode recon --flag-format 'CTF{...}'

# full recursive sweep (carving + decode + stego + memory), uses all cores
frx run ./challenge_files/ --mode full --flag-format 'CTF{...}' --jobs 20
```

Confirmed flags are printed the instant they are found, written to
`FLAGS.txt`, and explained with the exact command that produced them in
`report.md`.

`<input>` can be a memory dump, pcap/pcapng, disk image (dd/E01), ISO, archive,
any single file, or a directory. The type is detected from content, not the
extension.

## Flag formats

Give the literal flag shape; frx builds the regex and the encoded-prefix
needles (base64/32, hex, rot-n, utf16, url, ...) from it:

```bash
frx run mem.raw --flag-format 'CTF{...}'                 # prefix + braces
frx run dump.bin --flag-format 'flag{...}' --flag-format 'HTB{...}'   # repeatable
frx run dump.bin --flag-regex 'picoCTF\{[a-z0-9_]+\}'    # exact regex, repeatable
```

## Modes

| mode    | what it does                                                        |
|---------|---------------------------------------------------------------------|
| `recon` | fast, read-only: identify, metadata, protocol/partition summaries   |
| `full`  | everything: carve, extract, follow streams, stego, vol3 sweep, recurse |

## Common options

| option | meaning |
|--------|---------|
| `--mode {recon,full}` | analysis depth (default `recon`) |
| `--flag-format 'CTF{...}'` | flag shape, repeatable |
| `--flag-regex '...'` | exact flag regex, repeatable |
| `--jobs N` | parallel workers and max concurrent tools (default: CPUs - 1) |
| `--case DIR` | output dir (default `cases/<timestamp>`) |
| `--resume CASE` | continue an interrupted case (restores mode, formats, caps) |
| `--max-runtime 40m` | soft budget; on hit, finish in-flight and finalize the report |
| `--max-depth N` / `--max-files N` / `--max-extracted-size 4G` | zip-bomb / recursion guards |
| `--build-isf vmlinux [--system-map map]` | build a vol3 Linux ISF, then analyze |
| `--kind memory\|pcap\|disk\|...` | force the input type instead of detecting it |
| `--wordlist FILE` | wordlist for archive-password / stego brute force |
| `--no-sandbox` | do not network-isolate the pass (required for `--mount`) |
| `--mount` | last-resort read-only loop mount (needs `--no-sandbox`) |
| `--gpu` | experimental OpenCL XOR acceleration (see [Performance](#performance)) |
| `--no-progress` | no live display, just the `run.log` heartbeat |

Press Ctrl-C once to stop gracefully (in-flight tools finish, the report is
finalized). Press it twice to hard-abort (running tools are killed); the report
is still written from what was found.

## Output

A run writes a self-contained case directory:

```
cases/<timestamp>/
  FLAGS.txt           # confirmed flags, one per line, with provenance
  report.md           # flags (with the exact reproduction command) + leads + summary
  findings.jsonl      # every finding, append-only, flushed as it lands
  run.log             # timestamped heartbeat + command log (tail -f this)
  run-meta.json       # run parameters, for --resume
  queue-state.jsonl   # work-queue journal, for --resume
  extracted/<sha>/... # carved / extracted files, namespaced by parent
  vol-cache/          # vol3 cache, isolated to this case
```

## Offline sandbox

By default the entire `run` is re-executed inside a user + network namespace
(`unshare -rn`), so no tool it spawns can reach the network, whatever it tries.
If unprivileged user namespaces are unavailable, frx refuses to run rather than
go unisolated; pass `--no-sandbox` to accept that and run without isolation (it
is logged). `setup` and `check` may use the network; `run` never does.

A loop mount cannot happen inside the namespace, so `--mount` requires
`--no-sandbox`; otherwise the disk handler prefers TSK then 7z.

## Performance

frx is built for GB-scale inputs on a multi-core laptop:

- **Parallelism.** `--jobs` fans work across cores, and within a single large
  input the independent tool calls (pcap stream follows, vol3 plugins, disk
  partitions) run concurrently too, bounded so they never oversubscribe. Set
  `--jobs` to your thread count for the biggest effect.
- **Streaming.** `strings` and `blkls` output is streamed to disk, never
  buffered whole in RAM, so a GB input will not blow up memory.
- **`--gpu` (experimental).** Accelerates only the decoder's single-byte XOR
  brute via OpenCL (AMD or Intel, through pyopencl), falling back to the CPU
  when no device is present. Honest expectation: for pcap/disk/memory the
  runtime is dominated by the external tools and I/O, not the XOR brute, so the
  real-world gain is usually small. The CPU parallelism above is the bigger win.
  To try it: install an OpenCL runtime (`opencl-mesa` / `rocm-opencl-runtime`
  for AMD, `intel-compute-runtime` for Intel) plus `pyopencl numpy`, confirm
  with `frx check`, then add `--gpu`.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e . pytest
python -m pytest            # unit + logic tests (external-tool tests skip/fail without the tools)
bash tests/make-fixtures.sh tests/out   # build the end-to-end fixtures (needs the tools)
```

The full design and the approved amendments are in
[`docs/spec.md`](docs/spec.md).
