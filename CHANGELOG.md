# Changelog — LATCH Project

All notable changes to the LATCH (Last Authority for Trusted Control Handoff) runtime-assurance architecture are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.1.0] - 2026-11-12

### QEMU AArch64 `virt` Bring-Up: The On-Target Path Now Works End To End

This release is the one that makes the **hypervisor path real**. Every item below was
established by running the built IFS under `qemu-system-aarch64 -M virt,virtualization=on,gic-version=2
-cpu cortex-a76` and reading the boot log, the supervisor's own counters, and the
4096-entry evidence tape — not by reading the source and reasoning about it.

- **Guest Boot Hang Fixed — It Was PSCI, Not the CPU Pin (`latch_qemu_virt.qvmconf`)**: The
  Linux 6.12 guest hung for tens of minutes right after `cacheinfo`. The cause: `qvm`
  auto-detects host PSCI support by reading the *host device tree*, and QNX's startup cannot
  read QEMU's DTB on this platform (`no clock-frequency property in FDT!`). No PSCI node
  reached the guest FDT, so Linux's secondary-CPU bring-up never completed. Fixed with
  `set psci-supported on` — the exact override the qvm manual documents — plus
  `set pointer-authentication off` and `set linux-fdt-free on`. The guest now boots to
  `/init` in **8.1 s** and reports `psci: PSCIv1.1 detected in firmware`.
- **Static vCPU Runmask — Correct QNX 8.0 Syntax (`latch_qemu_virt.qvmconf`, `latch.qvmconf`)**:
  Hypervisor 8.0's `cpu` takes an **indented options block** whose only two options are
  `cluster` and `sched`. The 7.1 one-line form `cpu _cpu-2 sched 8r` is *rejected* by the
  8.0 qvm (`Unknown option '_cpu-2'`), and a bare `cpu` / `sched 8r` block leaves the vCPU
  **floating** on every core — including the one `latchd` runs on. Both qvmconf files now
  use one `cpu` block per vCPU, each bound to its own single-CPU cluster. Proven on target:
  `pidin -p qvm threads` reports the vCPU threads as `cy-guest-qemu-virt/0` and `/1`.
- **`qvm` Process Runmask Left Unconstrained (`latch_qemu.build`, `latch_rpi4.build`)**:
  `on -C <n>` and `on -R <mask>` both resolve to a *predefined single-CPU cluster*, and no
  predefined cluster covers CPUs 2+3 together, so `-R 0xc` and `-C 2 -C 3` both fail with
  `Invalid cluster runmask specified`. The qvm process is now started with no affinity
  constraint; the isolation comes from the qvmconf pins.
- **Virtio-Console Forwarding Priority (`latch_qemu_virt.qvmconf`, `latch.qvmconf`)**:
  The vdev's guest→host forwarding is pulse-driven ("`sched priority`: … pulses indicating
  that input is available on the host device"). At the default priority the forward is
  starved under host load; measured on QEMU TCG that produced 16- and 28-tick gaps in the
  frame delivery. `sched 60` on the vdev, plus `-p 30f` on the spawned `latch-ingest`.
- **No Artificial Pacing in the Bridge (`latch_ingest.c`)**: `latch-ingest` now hands each
  frame to the supervisor as fast as the transport delivers it. The supervisor's ring,
  bounded by the manifest's `ingest.queue_depth`, is the only buffer in the path. The
  previous half-period sleep let the supervisor's 2-tick watchdog fire while the guest's
  next batch was still in flight, which failed closed into `HA-HOLD -> HA-HOME`, retracted
  `theta`, and turned every later frame into a spurious RATE veto.
- **Guest Produces Faster Than the Host Consumes, in Small Writes (`guest/latch_guest_init.c`)**:
  The guest now writes 4 frames (128 B) at a time every 200 µs — ~20 frames/ms against the
  supervisor's 1 frame/ms — so the ring always holds a backlog and the watchdog never
  fires spuriously. The previous 800-byte-per-phase write outran the virtio-console vdev,
  filled the guest's virtqueue, and stalled the guest for tens of milliseconds.
- **Guest Markers Moved off the Slow PL011 Path (`guest/latch_guest_init.c`)**: QNX's own
  hypervisor documentation says the PL011 "is slow and has slow output". A blocking write
  to `/dev/console` stalled the guest ~24 ms per phase marker. Markers now go to
  `/dev/kmsg` (the kernel log ring buffer, non-blocking) and still appear in the guest
  console log.
- **Real Silence for the Watchdog (`guest/latch_guest_init.c`)**: Phase 9 now sends **no
  bytes at all**. The previous revision sent `LATCH_WIRE_FLAG_SILENCE` frames, which the
  host does not treat as silence (guest flags are ignored for safety), so they were
  counted as sequence replays and the watchdog never fired.
- **The Evidence Archive (`docs/evidence/`)**: Every run's raw console output is now
  committed as a separate log file, with a published output manifest. `docs/evidence/README.md`
  maps each claim to the file that proves it, states how to regenerate each one, and
  lists what is **not** proven. `docs/evidence/derived/RUN-OUTPUT-MANIFEST.md` is the
  file-by-file list of what each kind of run produces. The new
  `tools/capture_evidence.py` generates the whole archive — nothing in it is
  hand-edited — and the new `make -C qnx evidence*` targets wrap it. `make -C qnx
  evidence-check` re-runs the host-sim capture and compares the signature against the
  archived one; CI runs it on every push, so the archive cannot rot. The tape
  analysis in the tool independently reproduces the supervisor's own counters
  (`wire=12`, `envelope=7`) from the raw tape, which is a cross-check of both.
- **The Evidence Archive Is Now A Consistency Check (`tools/consistency_check.py`)**:
  The gate asserts that the archive is complete, that the canonical session still
  carries the exact on-target signature (84 frames, 12 wire faults, 7 envelope
  vetoes, 0 ring drops, last seq 80, latched `0x01AE`, `VERIFY_RC=0`, and both
  static vCPU pins), that the archived host-sim signature still reports PASS, and
  that the run index still shows the monotone `51 → 48 → 27 → 7` progression. A
  missing or drifted archive now fails `make check`, not just the CI workflow.
- **Tried and Rejected — a Second virtio-console for the guest's markers**: The guest's
  phase markers need a path that is neither the black channel (which carries
  only LATH frames) nor the PL011 console (which QNX's own hypervisor
  documentation calls "slow", and whose slow output stalled the guest for
  ~24 ms per marker, starving the supervisor's watchdog). A second
  `vdev virtio-console` at `0x1c0b0000` looked like the right answer. It is
  **not**: with two virtio-consoles the guest delivered only **26 of 84**
  frames and the wire-fault count tripled. The second vdev was removed and
  the single-virtio-console design restored. The markers now go to `/dev/kmsg`
  (non-blocking), and the *host's* evidence tape -- not the guest's console --
  is the artefact that carries the story.
- **One Guest Policy, One Path (`guest/`)**: Deleted `guest/guest_init.sh` and
  `guest/initramfs/`, which `exec python3` — there is no Python in the shipped C-only
  initramfs. `guest/latch_guest_init.c` is now the only in-guest policy;
  `guest/liar.py` is the workstation generator used by `make check`.
- **`latchctl console` (`latchctl.c`)**: New command that mirrors the guest kernel console
  (`/dev/shmem/guest_console.log`) to the operator terminal. The minimal IFS ships no
  `cat`, `tail` or `grep`, so this is the supported way to read what the guest printed.
- **Manifest Is Now the Only Source of Paths (`latch_manifest.c/.h`, `latchlog.c`, `latch_verify.c`)**:
  Added the required key `tape.log_path`; `latchlog` now reads both the device node and
  the output path from the signed manifest, and `latch_verify` uses the manifest's
  actuator path instead of a hardcoded device name. `ingest.queue_depth` raised from 64
  to 256 (the ring capacity) so a whole guest burst fits. Sidecars regenerated and the
  attestation digests updated in `README.md`, `docs/LATCH-implementation.md` and CI.
- **Cross-File Invariants That Would Have Caught The Above (`tools/consistency_check.py`)**:
  The buildfile payload check now resolves against the **installed** SDP sysroot instead
  of a hardcoded "this library does not exist" list; the static-vCPU-pin check asserts
  the 8.0 block form; a new check proves the guest's declared suite size fits
  `ingest.queue_depth`; and the offline viewer's embedded tape is proved to be in sync
  with the committed CSV. New `tools/embed_default_tape.py` regenerates that embedded copy.
- **Linux 6.12 Claim Consistent (`README.md`, `docs/`, `codelab/`)**: the guest is 6.12
  everywhere. `docs/envelope.md` no longer cites envelope macros that were deleted.
- **`AGENTS.md` Rewritten, `guest_init.sh` Path Removed**: `AGENTS.md` now describes
  LATCH (one product, one story, one guest policy) instead of an Alpine aports packaging
  companion, and carries the QNX 8.0 platform facts that cost real time to establish.

### Verified on target (QEMU AArch64 `virt`, QNX SDP 8.0)

- Linux 6.12 guest boots to `/init` in 8.1 s; `psci: PSCIv1.1 detected in firmware`.
- `pidin -p qvm threads` → vCPU threads `cy-guest-qemu-virt/0` and `/1` (static pins).
- `latch_verify` → `[1/5] … [5c/5] ALL PASS`, `VERIFY_RC=0`.
- Host timer: 62,500,000 Hz (AArch64 architectural timer).
- `make check` → `rx=200 | wire_faults=12 | env_faults=7 | eperm_rejects=1`.

---

## [3.0.0] - 2026-11-12

### Safety, Concurrency & QNX 8.0 Reconciliation Fixes
- **Single-Writer Tick Ownership & Graceful EOF Retraction (`latchd.c`)**: Removed immediate `g_simplex.session_active = false` mutation from `latch_io_close_ocb()`. Writer disconnect now sets atomic `writer_closed_eof`, allowing `_cpu-0` to finish `WATCHDOG -> HA-HOLD -> HA-HOME` jerk-bounded retraction before freezing the evidence tape.
- **Lock-Free Cross-Thread EPERM Propagation (`latchd.c`)**: Routed `latch_record_eperm_fault()` through atomic `eperm_pending` so resource-manager threads never perform concurrent RMW writes on `latched_faults` or `g_latch_tape[]`. Added pre-Frame-1 idle wait handling so empty ticks between `open()` and Frame #1 do not trip `WATCHDOG`.
- **Protocol Telemetry & Multi-Keepout Hardening (`latch_protocol.h`, `latchd.c`, `latchctl.c`)**: Added `total_ring_drops` and `wcet_overruns` (`wcet_budget_us * 1000` ns comparison) to `latch_status_reply_t` and `latchctl status`; updated keep-out snapping across all `num_keepouts` intervals.
- **String-Aware Strict Manifest Validation (`latch_manifest.h`, `latch_manifest.c`, `latch_ingest.c`)**: Implemented string-literal-aware / object-depth-aware JSON scanning (`json_find_key_depth`, `json_find_object_end`), `ERANGE` overflow guards, complete anti-silent-defaults key validation across all schema sections, explicit sidecar policy (`latch_manifest_load_opts`), concrete `procmgr_ability()` IDs in `latch_ingest.c`, and fail-closed startup loading.
- **Valid QNX 8.0 Security Policy & Hardware Alignments (`latch.secpol`, `Makefile`, `*.build`, `*.qvmconf`)**: Rewrote `latch.secpol` in valid `secpolcompile` grammar (`type`, `ability`, `self:ability`, `allow_attach`, `:channel connect`), switched to `secpolcompile` and `secpolpush`, restored RPi4 `i2c-bcm2711 -i149` (`GIC_SPI 117 + 32`), split RPi4 (`0xff841000`) and QEMU virt (`0x08000000`) `.qvmconf` files, and removed the 4 KB zero dummy guest image stub.
- **Verification, Viewer, Logger & CI Hardening (`latch_verify.c`, `latchlog.c`, `tape.html`, `consistency_check.py`, `ci.yml`)**: Made `latch_verify.c` derive test geometry from manifest and fail Step 4 unless monotonic `HA-HOME` rows exist; added `# GAP` wraparound detection in `latchlog.c`; made `host/tape.html` gridlines/NaN/badges manifest-driven; synced CI and cross-file invariant checks.

---

## [2.1.0] - 2026-11-11

### Major Architecture Upgrades
- **Dedicated Read-Only Ability Probe (`P0-1, P0-7`)**: Added non-mutating devctl `DCMD_LATCH_PROBE_ABILITY` (`__DION(_DCMD_MISC, 0x43)`). Replaced hold mutation probe in `latchctl grant-check` with pure read-only ability verification, eliminating risk of mutating operator hold state.
- **Fail-Closed Manifest Loading & Sidecar SHA-256 Verification (`P0-2, P0-3, P0-4`)**: Enforced strict fail-closed manifest loading across both native QNX Neutrino and host-sim modes. Automatically validates cryptographic integrity against `<path>.sha256` sidecar file and added `latchctl manifest-verify <path> [sha256]`.
- **Manifest Schema v2 Completion**: Implemented full parsing and admissibility validation for all declared schema keys (`actuator.addr`, `freq_hz`, `prescale`, `retries`, `init_delay_us`, `required`, `tape.capacity`, `protocol.*`, `plant.axes[]`, `pulse_priority`, `wcet_budget_us`, `max_backlog_ticks`).
- **Dynamic Full-Scale PWM Math**: Converted PWM calculation from fixed `1000` divisor to dynamic span calculated from active manifest plant axis stops.
- **QEMU & Guest Bring-Up Hardening (`P0-5, P1-8`)**: Updated `startup-qemu-virt -v -Q enable` for EL2 hypervisor host mode, corrected vdev DLL paths to `/lib/dll/qvm/`, added `libqvm.so.1`, parameterized guest kernel Image, and added `--loop` continuous streaming mode to `liar.py`.
- **Architectural Consistency Automation (`P2-1, P2-2`)**: Added `tools/consistency_check.py` and semantic CI assertions validating 0 keep-out breaches, monotonic sequence advancement, and verified latching of microkernel abilities.

---

## [2.0.0] - 2026-11-10

### Major Architecture Upgrades
- **Zero-Hardcoding Manifest Architecture (`G8`)**: Migrated ~40 hardcoded constants (kinematic limits, keep-out intervals, lookahead horizon, watchdog timers, bus paths, PCA9685 calibration, CPU affinity) into `latch.manifest`. Created `latch_manifest.h` and `latch_manifest.c` featuring a fail-closed, memory-safe JSON parser and self-contained FIPS 180-2 SHA-256 attestation engine.
- **Lock-Free Atomic Seqlock Buffer (`E-2, G6`)**: Replaced the two-slot pointer flip with an atomic generation-counter Seqlock (`latch_seqlock_slot_t`), eliminating the race condition on rapid publisher updates and guaranteeing untorn 24-byte IPC proposal reads.
- **QNX SDP 8.0 Native Ability Semantics (`E-1, G3`)**: Corrected ability verification in `iofunc_client_info_able()` to check `(info->flags & _NTO_CI_UNABLE) == 0u` as the primary authorization signal, preventing false-positive `EPERM` rejections on target hardware while retaining `LATCH_ABLE_STRICT_FLAGS` for experimental ABI toggling.
- **Truthful Cycle-to-Nanoseconds Calibration (`E-4, G4`)**: Calibrated `ClockCycles()` deltas against `SYSPAGE_ENTRY(qtime)->cycles_per_sec` on QNX (and monotonic timespecs on host simulation), storing nanosecond figures in status replies and evidence tape headers.
- **Decoupled Wire Framing vs Semantic Discard (`E-5`)**: Updated `latch_ingest.c` to discard sequence and payload only on framing/CRC/reserved corruptions. Preserves sequence numbers on semantic faults (such as `INT32_MIN` NaN sentinels), ensuring clean `0x0008` (`LATCH_FAULT_NAN`) reporting without spurious `0x0004` sequence drops.
- **Monotonic Sequence Progression (`E-3, G5`)**: Relaxed the HP sequence progression rule from strict $seq = last + 1$ to strictly increasing $seq > last$, enabling latest-wins queue coalescing under high CPU load while preserving strict vetoes on stale or replayed frames.
- **Torn-Read Protection in Telemetry (`E-7`)**: Protected `latch_fill_status()` and `latch_fill_tape_dump()` using snapshot generation sequencing to guarantee consistent reads of supervisor state across concurrent devctl calls.
- **Devctl Input Size Validation (`E-6`)**: Added explicit message size bounds checks to `DCMD_LATCH_GET_STATUS` in `latch_io_devctl()`.
- **System Call Hardening & PWM Arithmetic (`E-8`)**: Added return value checks for `pthread_setschedparam()`, `latch_pca9685_init()`, and CPU affinity calls. Corrected PCA9685 PWM span arithmetic to ensure exact mathematical symmetry across both upper and lower halves of travel.

### Added
- **`latchctl` CLI Utility (`G3`)**: Added native management and verification tool (`latchctl.c`) supporting `status`, `grant-check` (ability validation), `hold` (emergency stop), and `dump` (tape extraction).
- **`latchlog` Evidence Persistence Daemon (`G10`)**: Added background logger daemon (`latchlog.c`) querying `DCMD_LATCH_DUMP_TAPE` to stream evidence tape records to `/dev/shmem/latch_tape.csv` (or a specified path).
- **QNX Security Policy (`G2`)**: Added `qnx/latch.secpol` declaring custom ability `latch/actuator`, confining `/dev/i2c1` and actuator nodes to `latchd`, and isolating the hypervisor guest domain.
- **Guest VM Bring-Up Automation (`G1`)**: Added `guest/guest_init.sh` for booting and configuring `/dev/hvc0` inside the Linux guest VM.
- **Automated CI Workflow (`G7`)**: Added `.github/workflows/ci.yml` running protocol static asserts, Seqlock unit tests, and 200-tick pipeline regression on Ubuntu 24.04.
- **Offline Self-Containment (`G13`)**: Added fallback styles to `host/tape.html` for air-gapped viewing without internet or CDN access.

---

## [1.0.0] - 2026-11-05
- Initial working prototype for QNX SDP 8.0 and host simulation.
- 32-byte packed wire protocol with IEEE 802.3 CRC32.
- 1 kHz Simplex decision loop on CPU 0 and ingest bridge on CPU 1.
- Initial 5-fault verification menu and basic HTML canvas viewer.

