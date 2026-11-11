# Changelog — LATCH Project

All notable changes to the LATCH (Last Authority for Trusted Control Handoff) runtime-assurance architecture are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **`latchlog` Evidence Persistence Daemon (`G10`)**: Added background logger daemon (`latchlog.c`) querying `DCMD_LATCH_DUMP_TAPE` to continuously stream evidence tape records to persistent flash storage (`/var/log/latch_tape.csv`).
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

