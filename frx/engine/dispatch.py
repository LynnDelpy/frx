"""Kind -> handler routing (spec section 5 table).

The binary handler is universal: it runs on every item so nothing is skipped.
Kind-specific handlers run first (they understand structure and extract
children), then the binary fallback sweeps the same bytes. Handler modules are
imported lazily so a run that never sees a memory dump never imports vol3.
"""

from __future__ import annotations

import importlib

# kind -> specialist handler module names (binary is appended to all).
ROUTING: dict[str, list[str]] = {
    # populated as handlers land: "pcap": ["pcap"], "disk_image": ["disk"], ...
}
UNIVERSAL = ["binary"]


def handler_names(kind: str) -> list[str]:
    names = list(ROUTING.get(kind, []))
    for u in UNIVERSAL:
        if u not in names:
            names.append(u)
    return names


def load_handler(name: str):
    mod = importlib.import_module(f"frx.handlers.{name}")
    return mod.handle


def handlers_for(kind: str):
    out = []
    for name in handler_names(kind):
        try:
            out.append((name, load_handler(name)))
        except Exception:
            continue
    return out
