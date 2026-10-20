"""Archive handler (spec section 6.4).

7z extracts zip/7z/tar/gz/xz/iso/udf/wim; unar is the fallback for odd rar.
Every extracted entry is enqueued at depth+1, so nested archives unwind through
the queue and the global caps are the zip-bomb guard. Encrypted archives are
cracked (full mode) with the configured wordlist: zip2john+john for zips
(amendment A9), a capped 7z password list otherwise.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from ..engine.context import Context
from ..engine.queue import Item
from ..report.findings import Finding

MAX_CRACK_WORDS = 100000  # cap for zip2john+john (fast)
MAX_7Z_WORDS = 2000       # cap for the per-word 7z brute (slow: ~100 pw/s, A9)


def _enqueue_tree(ctx: Context, item: Item, root: Path, label: str) -> int:
    n = 0
    for child in sorted(root.rglob("*")):
        # Skip symlinks: a crafted archive can plant one pointing outside the
        # extraction dir, and we would read/scan the target.
        if child.is_file() and not child.is_symlink():
            rel = child.relative_to(root)
            if ctx.enqueue_file(child, item, f"{label}:{rel}"):
                n += 1
    return n


def _capped_wordlist(ctx: Context, item: Item, limit: int) -> Path | None:
    """Write the first `limit` words of the configured wordlist to a case-local
    file, so the brute force honors the attempt cap (amendment A9)."""
    if not ctx.wordlist or not Path(ctx.wordlist).is_file():
        return None
    dst = ctx.case_dir / "tmp" / f"{item.short}.wl{limit}"
    dst.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with Path(ctx.wordlist).open("r", encoding="utf-8", errors="ignore") as src, \
            dst.open("w", encoding="utf-8") as out:
        for line in src:
            out.write(line)
            n += 1
            if n >= limit:
                break
    return dst if n else None


def _uncompressed_size(ctx: Context, item: Item) -> int | None:
    """Total uncompressed size from `7z l -slt`, or None if it cannot be read
    (e.g. an encrypted header). Used to refuse a zip bomb before extracting it."""
    res = ctx.runner.run(["7z", "l", "-slt", "-p", "-y", str(item.path)], timeout=120)
    if res.returncode != 0:
        return None
    total = 0
    found = False
    for line in res.out_text().splitlines():
        if line.startswith("Size = "):
            try:
                total += int(line[7:].strip())
                found = True
            except ValueError:
                pass
    return total if found else None


def _try_extract(ctx: Context, item: Item, out: Path, password: str | None) -> tuple[bool, str]:
    argv = ["7z", "x", "-y", "-bd", f"-p{password or ''}", f"-o{out}", str(item.path)]
    res = ctx.runner.run(argv, timeout=ctx.runner.default_timeout)
    text = res.out_text() + res.stderr.decode("utf-8", "replace")
    return res.returncode == 0, text


def _is_encrypted(text: str) -> bool:
    low = text.lower()
    return "wrong password" in low or "enter password" in low or "cannot open encrypted" in low


def _crack_zip(ctx: Context, item: Item) -> str | None:
    if shutil.which("zip2john") is None or shutil.which("john") is None:
        return None
    wordlist = _capped_wordlist(ctx, item, MAX_CRACK_WORDS)
    if wordlist is None:
        return None
    case_tmp = ctx.case_dir / "tmp"
    hashfile = case_tmp / f"{item.short}.ziphash"
    res = ctx.runner.run(["zip2john", str(item.path)], timeout=120)
    if not res.stdout:
        return None
    hashfile.write_bytes(res.stdout)
    pot = case_tmp / f"{item.short}.pot"
    session = case_tmp / f"{item.short}.john"
    ctx.runner.run([
        "john", f"--wordlist={wordlist}", f"--pot={pot}",
        f"--session={session}", str(hashfile),
    ], timeout=ctx.runner.default_timeout)
    show = ctx.runner.run(["john", f"--pot={pot}", "--show", str(hashfile)], timeout=60)
    for line in show.out_text().splitlines():
        if ":" in line and not line.endswith("password hashes cracked, 0 left"):
            parts = line.split(":")
            if len(parts) >= 2 and parts[1]:
                return parts[1]
    return None


def _crack_7z(ctx: Context, item: Item) -> str | None:
    """Capped per-word 7z brute for non-zip encrypted archives (amendment A9)."""
    wordlist = _capped_wordlist(ctx, item, MAX_7Z_WORDS)
    if wordlist is None:
        return None
    for word in wordlist.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not word:
            continue
        res = ctx.runner.run(["7z", "t", f"-p{word}", "-y", str(item.path)], timeout=60)
        if res.returncode == 0:
            return word
    return None


def handle(item: Item, ctx: Context) -> None:
    out = ctx.child_dir(item) / f"arc_{item.short}"
    out.mkdir(parents=True, exist_ok=True)

    # Zip-bomb guard: refuse before writing if the uncompressed total would blow
    # past the remaining global extraction budget (caps also apply at enqueue).
    budget_left = ctx.queue.max_extracted_size - ctx.queue.extracted_bytes
    size = _uncompressed_size(ctx, item)
    if size is not None and size > budget_left:
        ctx.emit(Finding(
            severity="high", handler="archive", type="artifact",
            value=f"archive not extracted: uncompressed {size} bytes exceeds remaining budget {budget_left}",
            item_sha=item.sha256, provenance=item.provenance + ["archive:too-large"],
        ))
        return

    ok, text = _try_extract(ctx, item, out, password=None)
    password = None
    if not ok and _is_encrypted(text):
        ctx.emit(Finding(
            severity="high", handler="archive", type="artifact",
            value=f"encrypted archive: {item.path.name}", item_sha=item.sha256,
            provenance=item.provenance + ["archive:encrypted"],
        ))
        if ctx.mode == "full":
            password = _crack_zip(ctx, item) or _crack_7z(ctx, item)
            if password:
                ctx.emit(Finding(
                    severity="high", handler="archive", type="artifact",
                    value=f"archive password: {password}", item_sha=item.sha256,
                    provenance=item.provenance + ["archive:cracked", password],
                ))
                ok, text = _try_extract(ctx, item, out, password=password)

    if not ok:
        # Fallback: unar for formats 7z struggles with (some rar).
        if shutil.which("unar"):
            ctx.runner.run(["unar", "-f", "-o", str(out), str(item.path)], timeout=ctx.runner.default_timeout)

    n = _enqueue_tree(ctx, item, out, "archive")
    ctx.log(f"  archive {item.short}: extracted {n} file(s)")
