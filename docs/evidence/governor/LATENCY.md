# LATENCY — REJECTED, moved to quarantine

This document ("QNX 61 µs WCET vs Linux 143 ms CFS") is **withdrawn**.
Both numbers were unsupported: the QNX figure came from a generator that
inserted fixed values, and no reproducible source samples exist for the
Linux comparison.

- Rejected copy: `docs/evidence/quarantine/REJECTED-governor-LATENCY.md`
- Rejection record: `docs/evidence/quarantine/README.txt`
- What to quote instead: `governor/governor-qemu-verify.txt` —
  `run max 80,911 cyc ≈ 1.29 ms`, labelled a **TCG observation, not a WCET**.

A fresh, honest measurement (N ≥ 10⁶ ticks, p50/p99/max, TCG caveat) is
tracked as U11 in the update plan; until it exists, this archive makes no
WCET claim at all.
