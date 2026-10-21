"""Optional GPU acceleration for the decoder's single-byte XOR brute.

This is the one piece of frx's own work that is genuinely data-parallel: for a
candidate token, trying all 255 single-byte XOR keys and scoring each is a wide,
regular, arithmetic workload. Everything else frx does is either an external
tool or I/O/bandwidth-bound byte scanning the CPU already handles at memory
speed, so only this step gets a GPU path.

Design and honesty:
- It is OPT-IN (`frx run --gpu`) and defaults off. With it off, or when no
  OpenCL device / pyopencl is present, the decoder runs exactly as before.
- Cross-vendor via OpenCL (pyopencl), so it runs on AMD or Intel GPUs (and CPUs
  that expose an OpenCL device).
- It does not replace the CPU logic; it PREFILTERS, and it does so exactly for
  prefix-based flag formats. The kernel XORs each token by all 255 keys and
  marks the keys whose output contains the flag prefix (e.g. "ctf{"), case
  insensitively. The CPU then runs the real flag regex + recursion on only those
  keys (usually zero for noise, one for a genuine single-byte-XOR'd flag). The
  correct key is the one that makes the prefix appear, so it is always marked:
  no prefix-confirmed flag is ever missed (verified: wrong keys do not spell the
  prefix; the CPU still validates the full match, so there are no false flags).
- The win only materializes when there are many/large tokens to batch (the GPU
  transfer and launch cost is fixed); for small inputs the CPU path is used.

Tradeoff (documented): with --gpu, XOR matches that rely on the generic
prefixless pattern are not surfaced (those are only ever candidate leads, and
they are demoted to candidates anyway); formats with no literal prefix fall back
to the CPU trying all keys. Correctness of confirmed flags never depends on the
GPU, and --gpu is off by default with the CPU path as the fallback.
"""

from __future__ import annotations

import importlib

# OpenCL C: one work-item per (token, key). Mark the key if token^key contains
# the (pre-lowercased) flag prefix, compared case-insensitively.
_KERNEL = r"""
__kernel void xor_find_prefix(
    __global const uchar* data,
    __global const uint*  offsets,
    __global const uint*  lengths,
    __global const uchar* prefix,
    const uint            plen,
    __global uchar*       found)       // [num_tokens * 255]
{
    uint gid = get_global_id(0);
    uint tok = gid / 255u;
    uint key = (gid % 255u) + 1u;      // keys 1..255 (0 is identity, skipped)
    uint off = offsets[tok];
    uint len = lengths[tok];
    uchar f = 0u;
    if (plen > 0u && len >= plen) {
        for (uint i = 0u; i + plen <= len && f == 0u; i++) {
            uchar m = 1u;
            for (uint j = 0u; j < plen; j++) {
                uchar b = data[off + i + j] ^ (uchar)key;
                if (b >= 65u && b <= 90u) b += 32u;   // ASCII lowercase
                if (b != prefix[j]) { m = 0u; break; }
            }
            if (m) f = 1u;
        }
    }
    found[tok * 255u + (key - 1u)] = f;
}
"""


def probe() -> tuple[bool, str]:
    """Return (available, detail) describing OpenCL GPU support."""
    try:
        cl = importlib.import_module("pyopencl")
    except Exception:
        return False, "pyopencl not installed (pip install pyopencl numpy)"
    try:
        importlib.import_module("numpy")
    except Exception:
        return False, "numpy not installed"
    try:
        devices = []
        for plat in cl.get_platforms():
            for dev in plat.get_devices():
                devices.append(dev)
        gpus = [d for d in devices if d.type & cl.device_type.GPU]
        chosen = gpus or devices
        if not chosen:
            return False, "no OpenCL devices found"
        names = ", ".join(sorted({d.name.strip() for d in chosen}))
        return True, ("GPU: " if gpus else "OpenCL device: ") + names
    except Exception as e:  # noqa: BLE001 - any driver hiccup => unavailable
        return False, f"OpenCL probe failed: {type(e).__name__}: {e}"


class GpuAccelerator:
    """Lazily-built OpenCL context + XOR-printable kernel. Any failure disables it."""

    MAX_TOKEN = 65536  # tokens larger than this skip the GPU (and XOR anyway)

    def __init__(self):
        self.ok = False
        self.detail = ""
        self._cl = None
        self._np = None
        self._ctx = None
        self._queue = None
        self._prog = None
        try:
            self._cl = importlib.import_module("pyopencl")
            self._np = importlib.import_module("numpy")
            devices = [d for p in self._cl.get_platforms() for d in p.get_devices()]
            gpus = [d for d in devices if d.type & self._cl.device_type.GPU]
            chosen = (gpus or devices)[:1]
            if not chosen:
                self.detail = "no OpenCL devices"
                return
            self._ctx = self._cl.Context(devices=chosen)
            self._queue = self._cl.CommandQueue(self._ctx)
            self._prog = self._cl.Program(self._ctx, _KERNEL).build()
            self.detail = chosen[0].name.strip()
            self.ok = True
        except Exception as e:  # noqa: BLE001
            self.detail = f"{type(e).__name__}: {e}"
            self.ok = False

    def xor_prefilter(self, tokens: list[bytes], prefixes: list[bytes]) -> list[list[int]] | None:
        """For each token, return the XOR keys whose output contains any flag
        prefix (case-insensitive). Aligned to `tokens` ([] = no key matched, so
        no XOR'd prefix-flag is present). Returns None (caller tries all keys on
        the CPU) when there is no usable prefix or the GPU run fails.
        """
        if not self.ok:
            return None
        pfxs = [p.lower() for p in prefixes if p]
        if not pfxs:
            return None  # no literal prefix to key on -> CPU tries all keys
        cl, np = self._cl, self._np
        idx = [i for i, t in enumerate(tokens) if 0 < len(t) <= self.MAX_TOKEN]
        result: list[list[int]] = [[] for _ in tokens]
        if not idx:
            return result
        try:
            blob = b"".join(tokens[i] for i in idx)
            data = np.frombuffer(blob, dtype=np.uint8)
            offsets = np.empty(len(idx), dtype=np.uint32)
            lengths = np.empty(len(idx), dtype=np.uint32)
            pos = 0
            for j, i in enumerate(idx):
                offsets[j] = pos
                lengths[j] = len(tokens[i])
                pos += len(tokens[i])

            mf = cl.mem_flags
            d_data = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data)
            d_off = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=offsets)
            d_len = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=lengths)
            marked = [set() for _ in idx]
            for pfx in pfxs:
                pbuf = np.frombuffer(pfx, dtype=np.uint8)
                found = np.zeros(len(idx) * 255, dtype=np.uint8)
                d_pfx = cl.Buffer(self._ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pbuf)
                d_found = cl.Buffer(self._ctx, mf.WRITE_ONLY, found.nbytes)
                self._prog.xor_find_prefix(self._queue, (len(idx) * 255,), None,
                                           d_data, d_off, d_len, d_pfx, np.uint32(len(pfx)), d_found)
                cl.enqueue_copy(self._queue, found, d_found)
                self._queue.finish()
                found = found.reshape(len(idx), 255)
                for j in range(len(idx)):
                    for k in np.nonzero(found[j])[0]:
                        marked[j].add(int(k) + 1)  # key = index + 1
            for j, i in enumerate(idx):
                result[i] = sorted(marked[j])
            return result
        except Exception:  # noqa: BLE001 - any failure => CPU fallback
            return None
