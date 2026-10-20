"""Recursive decode engine (spec section 8, amendment A3).

Given a candidate blob (a needle-hit window, a bulk_extractor feature, or a long
high-purity run), try the applicable reducing codecs and the conditional
transforms, score each result, and recurse on the promising ones until a flag
regex matches (terminal success) or the depth/op budget runs out. The decode
chain is recorded in provenance, e.g. base64 -> hex -> rot13 -> CTF{...}.

Gating keeps recursion from exploding:
- reducing codecs (base64/hex/...) recurse when the result scores >= threshold;
- conditional transforms (rot-n/rot47/atbash/reverse/xor) recurse only on real
  evidence: a flag prefix appears, the English score clearly improves, or the
  output enters a stricter charset class (e.g. rot13 turning [0-9n-s] into hex).
"""

from __future__ import annotations

import dataclasses

from ..flags.scan import scan_flags
from ..report.findings import Finding
from . import classic, codecs, detect
from .score import english_score, score_text

MAX_DEPTH = 5
THRESHOLD = 0.5
PER_CALL_OPS = 8000
ENGLISH_MARGIN = 0.15
ENGLISH_FLOOR = 0.40  # a conditional transform recurses on English only above this
MAX_CANDIDATES_PER_ITEM = 50
MAX_OPS_PER_ITEM = 400_000  # hard ceiling on decode attempts per item (backstop)
MIN_DIVERSITY = 4  # a blob with fewer distinct bytes cannot hold a flag
XOR_MAX_LEN = 2048  # single-byte XOR brute only on short tokens
# Total high-purity tokens brute-decoded per item across every whole-blob pass.
# The targeted needle-window decodes are cheap and always run; this only bounds
# the comprehensive net, so a multi-megabyte wall of base64 noise cannot turn the
# decoder into the slowest part of a pass. The truncation is logged, not silent.
MAX_TOKENS_PER_ITEM = 1500


def _too_dull(data: bytes) -> bool:
    return len(set(data)) < MIN_DIVERSITY


@dataclasses.dataclass
class _State:
    ops: int = 0
    visited: set = dataclasses.field(default_factory=set)


class DecodeEngine:
    def __init__(self, ctx, max_depth: int = MAX_DEPTH, threshold: float = THRESHOLD):
        self.ctx = ctx
        self.max_depth = max_depth
        self.threshold = threshold
        self._prefixes = [f.prefix.encode() for f in ctx.formats if f.prefix]
        self._cand_counts: dict[str, int] = {}
        self._cand_seen: dict[str, set] = {}
        self._tok_seen: dict[str, set] = {}
        self._tok_count: dict[str, int] = {}
        self._tok_capped: set = set()
        self._ops: dict[str, int] = {}
        self._ops_capped: set = set()

    # -- public entry ---------------------------------------------------
    def decode_candidate(self, blob: bytes, item, base_provenance: list[str]) -> None:
        """Decode a candidate blob.

        Each top-level high-purity token gets its own op budget so a pile of
        junk tokens cannot starve a real (possibly last) one. Whole-blob
        structural codecs and the recursion they spawn share one budget.
        """
        if not blob:
            return
        # A flag may already be literally present.
        self._emit_flags(blob, item, base_provenance)
        # Whole-blob structural codecs (url/quopri/utf16/morse/decimal/binary).
        self._structural(blob, item, base_provenance, depth=0, state=_State())
        # Each high-purity run with a fresh budget, skipping tokens already tried
        # for this item: the binary handler feeds the raw bytes, three strings
        # passes and the needle windows, which overlap heavily, so without this
        # the same token is brute-decoded several times over.
        seen = self._tok_seen.setdefault(item.sha256, set())
        for token in detect.extract_tokens(blob):
            h = hash(token)
            if h in seen:
                continue
            seen.add(h)
            if self._tok_count.get(item.sha256, 0) >= MAX_TOKENS_PER_ITEM:
                if item.sha256 not in self._tok_capped:
                    self._tok_capped.add(item.sha256)
                    self.ctx.log(
                        f"  decode: token budget ({MAX_TOKENS_PER_ITEM}) reached for {item.short}; "
                        "further high-purity runs not brute-decoded (needle windows still covered)"
                    )
                break
            self._tok_count[item.sha256] = self._tok_count.get(item.sha256, 0) + 1
            self._token(token, item, base_provenance, depth=0, state=_State())

    # -- flag detection -------------------------------------------------
    @staticmethod
    def _is_brute(step: str) -> bool:
        # Single-byte XOR brute tries 255 keys per token, so over high-entropy
        # data it coincidentally spells flag-shaped matches ("CTF{EMgV}"). A
        # format match reachable only this way is a lead, not a confirmation.
        return step.startswith("xor:")

    @staticmethod
    def _plausible_flag(value: str) -> bool:
        """A decoded flag body of mostly punctuation is a brute-decode
        coincidence, not a real flag. Real CTF bodies are word-like."""
        i, j = value.find("{"), value.rfind("}")
        if i == -1 or j <= i:
            return True  # no clear body to judge; don't second-guess
        body = value[i + 1:j]
        if not body:
            return True
        wordish = sum(1 for c in body if c.isalnum() or c in "_-")
        return wordish / len(body) >= 0.6

    def _emit_flags(self, data: bytes, item, prov: list[str]) -> bool:
        brute = bool(prov) and self._is_brute(prov[-1])
        confirmed_found = False
        for hit in scan_flags(data, self.ctx.formats):
            if not hit.confirmed:
                continue
            value = hit.value.decode("utf-8", "replace")
            # XOR-brute matches, and matches whose body is punctuation soup, are
            # decode coincidences: surface them as leads, not confirmed flags.
            if brute or not self._plausible_flag(value):
                self._emit_brute_candidate(value, item, prov)
                continue
            confirmed_found = True
            self.ctx.emit(Finding(
                severity="flag", handler="decode", type="flag", value=value,
                item_sha=item.sha256, flag=True, confidence=1.0,
                provenance=prov + [value],
            ))
        return confirmed_found

    def _emit_brute_candidate(self, value: str, item, prov: list[str]) -> None:
        seen = self._cand_seen.setdefault(item.sha256, set())
        if value in seen or self._cand_counts.get(item.sha256, 0) >= MAX_CANDIDATES_PER_ITEM:
            return
        seen.add(value)
        self._cand_counts[item.sha256] = self._cand_counts.get(item.sha256, 0) + 1
        self.ctx.emit(Finding(
            severity="info", handler="decode", type="flag_candidate", value=value,
            item_sha=item.sha256, confidence=0.3, provenance=prov + [value],
        ))

    def _emit_candidates(self, data: bytes, item, prov: list[str], score: float) -> None:
        """Emit a decoded finding only for a generic flag-shaped match.

        This keeps the report's lead list meaningful: a random rot/xor output is
        not reported just for scoring high or containing stray braces. Capped
        per item so a noisy input cannot flood findings.jsonl.
        """
        seen = self._cand_seen.setdefault(item.sha256, set())
        for hit in scan_flags(data, self.ctx.formats):
            if hit.confirmed:
                continue  # confirmed flags are emitted by _emit_flags
            value = hit.value.decode("utf-8", "replace")
            if value in seen:
                continue
            if self._cand_counts.get(item.sha256, 0) >= MAX_CANDIDATES_PER_ITEM:
                return
            seen.add(value)
            self._cand_counts[item.sha256] = self._cand_counts.get(item.sha256, 0) + 1
            self.ctx.emit(Finding(
                severity="info", handler="decode", type="flag_candidate", value=value,
                item_sha=item.sha256, confidence=round(min(score, 0.5), 3),
                provenance=prov + [value],
            ))

    # -- recursion ------------------------------------------------------
    def _blob(self, blob: bytes, item, prov: list[str], depth: int, state: _State) -> None:
        """Recursion target for a decoded output: structural codecs + tokens."""
        if state.ops >= PER_CALL_OPS or depth > self.max_depth:
            return
        key = (depth, hash(blob))
        if key in state.visited:
            return
        state.visited.add(key)

        # A flag may already be visible in this blob (after a prior decode).
        if self._emit_flags(blob, item, prov):
            return

        self._structural(blob, item, prov, depth, state)
        for token in detect.extract_tokens(blob):
            if state.ops >= PER_CALL_OPS:
                return
            self._token(token, item, prov, depth, state)

    def _structural(self, blob: bytes, item, prov: list[str], depth: int, state: _State) -> None:
        """Whole-blob codecs that need delimiters/structure."""
        for name in detect.blob_codecs(blob):
            state.ops += 1
            fn = codecs.REDUCING.get(name)
            out = fn(blob) if fn else None
            if out:
                self._result(out, name, True, blob, item, prov, depth, state)

    def _token(self, token: bytes, item, prov: list[str], depth: int, state: _State) -> None:
        # Reducing codecs applicable to this token's charset.
        for name in detect.token_codecs(token):
            state.ops += 1
            out = codecs.REDUCING[name](token)
            if out:
                self._result(out, name, True, token, item, prov, depth, state)

        # Conditional transforms, gated hard (they preserve length/charset).
        if depth + 1 > self.max_depth:
            return
        for variant in classic.conditional_variants(token, xor_max_len=XOR_MAX_LEN):
            state.ops += 1
            if state.ops >= PER_CALL_OPS:
                return
            self._result(variant.data, variant.label, False, token, item, prov, depth, state)

    def _result(self, decoded: bytes, name: str, reducing: bool, src: bytes,
                item, prov: list[str], depth: int, state: _State) -> None:
        n = self._ops.get(item.sha256, 0)
        if n >= MAX_OPS_PER_ITEM:
            if item.sha256 not in self._ops_capped:
                self._ops_capped.add(item.sha256)
                self.ctx.log(
                    f"  decode: op budget ({MAX_OPS_PER_ITEM}) reached for {item.short}; "
                    "comprehensive decode truncated (needle windows still covered)"
                )
            return
        self._ops[item.sha256] = n + 1
        if not decoded or decoded == src:
            return
        new_prov = prov + [name]

        # Terminal: a confirmed flag in the decoded output.
        if self._emit_flags(decoded, item, new_prov):
            return

        # A near-constant blob cannot contain a flag; never recurse into it.
        if _too_dull(decoded):
            return

        score = score_text(decoded, self._prefix_str())
        self._emit_candidates(decoded, item, new_prov, score)

        if depth + 1 > self.max_depth:
            return

        if reducing:
            if score >= self.threshold:
                self._blob(decoded, item, new_prov, depth + 1, state)
        else:
            if self._conditional_recurse(decoded, src):
                self._blob(decoded, item, new_prov, depth + 1, state)

    def _conditional_recurse(self, decoded: bytes, src: bytes) -> bool:
        if any(p in decoded for p in self._prefixes):
            return True
        if detect.classes(decoded) - detect.classes(src):
            return True
        # English-improvement gate: require a real absolute English score, not
        # just a relative bump. Rotations/XORs of high-entropy base64 noise jitter
        # the score enough to clear a pure margin test, which was the main driver
        # of runaway recursion; genuine Caesar/XOR-of-text clears the floor.
        ds = english_score(decoded)
        if ds >= ENGLISH_FLOOR and ds >= english_score(src) + ENGLISH_MARGIN:
            return True
        return False

    def _prefix_str(self) -> str:
        return self._prefixes[0].decode("latin-1") if self._prefixes else ""
