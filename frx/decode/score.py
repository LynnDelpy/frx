"""Scoring candidate decodings (spec section 8, amendment A3).

No AI: pure structure and statistics. A flag-regex match is a terminal 1.0. For
everything else, score = 0.6*printable_ratio + 0.4*english_score, with a small
bonus for flag-ish characters. english_score is a normalized chi-square against
English letter frequencies (1.0 = very English, 0.0 = uniform/random).
"""

from __future__ import annotations

# Relative English letter frequencies (a-z), percentages.
_ENGLISH = {
    "a": 8.17, "b": 1.49, "c": 2.78, "d": 4.25, "e": 12.70, "f": 2.23,
    "g": 2.02, "h": 6.09, "i": 6.97, "j": 0.15, "k": 0.77, "l": 4.03,
    "m": 2.41, "n": 6.75, "o": 7.51, "p": 1.93, "q": 0.10, "r": 5.99,
    "s": 6.33, "t": 9.06, "u": 2.76, "v": 0.98, "w": 2.36, "x": 0.15,
    "y": 1.97, "z": 0.07,
}
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if b in _PRINTABLE)
    return good / len(data)


def english_score(data: bytes) -> float:
    """Normalized chi-square fit to English letter frequencies, 0..1."""
    letters = [chr(b).lower() for b in data if 65 <= b <= 90 or 97 <= b <= 122]
    n = len(letters)
    if n < 4:
        return 0.0
    counts: dict[str, int] = {}
    for c in letters:
        counts[c] = counts.get(c, 0) + 1
    chi2 = 0.0
    for c, pct in _ENGLISH.items():
        expected = pct / 100.0 * n
        observed = counts.get(c, 0)
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    # Map chi2 (0=perfect) to (0..1]; divide by n to make it length-independent.
    norm = chi2 / n
    return 1.0 / (1.0 + norm)


def score_text(data: bytes, prefix_chars: str = "") -> float:
    base = 0.6 * printable_ratio(data) + 0.4 * english_score(data)
    bonus = 0.0
    if b"{" in data and b"}" in data:
        bonus += 0.1
    if prefix_chars and prefix_chars.encode() in data:
        bonus += 0.2
    return min(1.0, base + bonus)
