LATCH -- on-target defect resolution
=====================================

This file is part of the resolution record: each defect below was found by
running the built IFS under QEMU AArch64 `virt` and reading the supervisor's
own counters and the evidence tape, and each fix was proven by the same
counters moving.

The four defects were INDEPENDENT. Fixing any one of them alone still left
the on-target signature wrong, which is why the bring-up needed eight runs.


The summary table
-----------------

| # | Defect | Symptom | Fix | Before -> After |
|---|---|---|---|---|
| 1 | PSCI never reached the guest FDT | the Linux guest hung for tens of minutes after `cacheinfo` | `set psci-supported on` | >30 min -> **8.1 s** to `/init` |
| 2 | QNX 8.0 `cpu` syntax | the 7.1 one-line form is *rejected*; a bare block leaves the vCPU **floating** on every core | indented `cpu` / `cluster _cpu-N` / `sched 8r` block, one cluster per block | vCPU floating -> **pinned** (`cy-guest-qemu-virt/0`, `/1`) |
| 3 | `on -C`/`-R` cannot express "CPUs 2+3" | `Invalid cluster runmask specified` | start `qvm` with an **unconstrained** runmask; the qvmconf pins do the isolating | boot refused -> **boots** |
| 4 | The transport starved the supervisor | 51 envelope vetoes, last seq 25 | vdev `sched 60`; no artificial pacing in the bridge; the guest produces 4 frames / 200 us in 128-byte writes; the guest's markers go to `/dev/kmsg` | 51 -> 27 -> **7** vetoes, seq 25 -> 35 -> 57 -> **80** |

The measured progression
------------------------

| Run | What changed | frames | wire | envelope | last seq | VERIFY_RC |
|---|---|---|---|---|---|---|
| run1 | Run 1 -- guest's 40 ms phase pauses | 84 | 8 | 51 | 25 | 0 |
| run3 | Run 3 -- guest pauses removed entirely (IDENTICAL to run 2) | 84 | 8 | 48 | 35 | 0 |
| run4 | Run 4 -- vdev forwarding priority + unpaced bridge | 84 | 8 | 27 | 57 | 0 |
| run6 | Run 6 -- guest pacing fixed (suite now exactly right) | 84 | 12 | 7 | 80 | 1 |
| run7 | Run 7 -- latch_verify paced (all five invariants PASS) | 84 | 12 | 7 | 80 | 0 |
| final | FINAL -- the canonical session | 84 | 12 | 7 | 80 | 0 |

Each run differs from the one before it by exactly one fix. Run 3
is the pivot: removing the guest's pauses changed NOTHING (48 vetoes,
seq 35 -- identical to run 2), which proved the guest was not the
variable and the transport was.

The starvation signature, measured on the tapes
----------------------------------------------

| tape log | envelope vetoes | wire faults | last seq | starvation stalls | longest stall |
|---|---|---|---|---|---|
| `latch_tape` | 51 | 8 | 25 | 9 | 63 ticks |
| `latch_tape2` | 27 | 8 | 57 | 8 | 27 ticks |
| `latch_tape4` | 27 | 8 | 57 | 8 | 21 ticks |
| `latch_tape5` | 27 | 8 | 57 | 9 | 23 ticks |
| `latch_tape6` | 7 | 12 | 80 | 1 | 3 ticks |

A *starvation stall* is a run of supervisor ticks during which no
new frame was consumed. The supervisor's 2-tick watchdog fires
inside a stall, fails closed into HA-HOLD, and retracts theta --
which turns every later frame into a spurious RATE veto. The
correct run has one 3-tick stall; the broken runs have stalls of
21 to 63 ticks.

The rejected experiment
----------------------

A second `vdev virtio-console` was added at `0x1c0b0000`, reserved
for the guest's human-readable phase markers, so that they would
not have to travel over the slow PL011 console.

Measured result: **26 frames delivered instead of 84, and 26 wire faults instead of 8.**
The second vdev corrupted the frame channel. It was removed, the
single-virtio-console design was restored, and the markers were
routed to `/dev/kmsg` (non-blocking) instead. The guest's console
markers are cosmetic and may be dropped by the slow PL011 under
load; the HOST's evidence tape is the artefact that carries the
safety story, and it is complete.
