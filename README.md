# LATCH — Last Authority for Trusted Control Handoff

**The AI may propose. Only QNX may move.**

LATCH is a production-grade, mixed-criticality runtime-assurance architecture for physical AI on **QNX SDP 8.0.x** and **QNX Hypervisor 8.0**. An untrusted guest AI policy proposes 32-byte motion frames over a virtio-console black channel. A `SCHED_FIFO` priority 63 decision loop inside an ability-locked resource manager (`latchd`) verifies the kinematic envelope, lookahead rollout, and keep-out intervals, actuating via a PCA9685 PWM controller on `/dev/i2c1` or failing closed to High-Assurance (`HA-HOLD` / `HA-HOME`) candidates, recording every verdict in a 4096-entry evidence tape.

- **Target OS:** QNX Software Development Platform (SDP) 8.0 (`procnto-smp-instr`) + QNX Hypervisor 8.0 (build >= 549 for BCM2711 GICv2 support)
- **Target Board & BSP:** Raspberry Pi 4 Model B (`com.qnx.qnx800.bsp.hw.raspberrypi_bcm2711_rpi4`, SDP 8.0.5 / build 670)
- **Actuator Bus:** Broadcom `i2c-bcm2711` driving a PCA9685 12-bit 50 Hz hardware PWM controller at `0x40` (channel 0 servo)
- **Zero-Hardcoding Architecture:** Plant geometry, keep-out intervals, velocity/acceleration limits, timing budgets, and bus paths are fully configured via `latch.manifest` with SHA-256 integrity verification.
- **Concurrency:** Lock-free atomic Seqlock two-slot buffer (`latch_seqlock_slot_t`) eliminating torn reads on high-frequency publisher updates.
- **Fallback / CI Targets:** QEMU AArch64 / x86_64 (`qcc -Vgcc_ntox86_64`) and POSIX Host Simulation (`gcc -std=c11 -DLATCH_HOST_SIM`)
- **License:** MIT (`LICENSE`)

---

## 1. Architecture & Trust Boundary

```text
═══════════════════════════════════════════════════════════════════════════════
             RASPBERRY PI 4B · QNX SDP 8.0.x (procnto-smp-instr) + QNX Hypervisor 8.0 (qvm)
═══════════════════════════════════════════════════════════════════════════════
  TRUSTED SAFETY DOMAIN (QNX host, cores 0–1)      UNTRUSTED AI DOMAIN (guest, cores 2–3)
┌────────────────────────────────────────────┐   ┌───────────────────────────────────┐
│ CPU 0 · SCHED_FIFO 63  [latchd]            │   │ Linux 6.6 aarch64 VM (512 MB @    │
│  · 1 kHz tick: timer_create+SIGEV_PULSE    │   │ 0x80000000, load @ 0x80080000)    │
│  · latch.manifest fail-closed loader       │   │                                   │
│  · envelope + keep-out + mode FSM          │   │ [liar.py]  untrusted policy       │
│  · resmgr: /dev/latch/proposal             │   │  nominal / keepout / corrupt /    │
│            /dev/latch/actuator             │   │  replay / nan / suite             │
│  · procmgr_ability_create("latch/actuator",0)  │  can hang, lie, spam, or be killed│
│  · iofunc_client_info_able(_NTO_CI_UNABLE) │   │        │ 32-B frame, CRC-32       │
│  · PCA9685 via /dev/i2c1 (DCMD_I2C_SEND)   │   │        ▼                          │
│  · 4096-entry ClockCycles evidence tape    │   │  vdev virtio-console              │
│            ▲                               │   │  loc 0x1c0a0000, intr gic:42      │
│            │ hostdev >"|/proc/boot/..."    │◄──┼──  (black channel: by-value only, │
│ CPU 1 · [latch-ingest] unprivileged        │   │   no pointers, no shared memory)  │
│  · validates magic/version/CRC/seq/zeroes  │   │  vdev gic version 2 (GICv2)       │
│  · pins itself to CPU 1 (runmask)          │   │  vdev pl011 -> /dev/shmem log     │
└────────────────────────────────────────────┘   └───────────────────────────────────┘
                     │ secpol.bin policy · ability utility · latchctl · latchlog
                     ▼
        [PLANT] PCA9685 -> servo · taped keep-out region (e.g. [250, 650] mrad)
```

### Non-Negotiable Safety Invariants

1. **Host-owned state**: The guest proposes an integer angle `u_mrad` (`int32_t`). It never supplies plant state (`theta_mrad`, `omega_mrad_s`) or deadline timestamps.
2. **Host-owned clock**: Arrival is stamped by `latchd` using `ClockCycles()` calibrated to nanoseconds via `SYSPAGE_ENTRY(qtime)->cycles_per_sec`.
3. **Lock-Free Atomic Seqlock Buffer**: Producer updates idle slot with odd generation sequence, updates payload with memory barriers, and seals with even generation counter. Consumers verify generation before and after to ensure 100% untorn reads.
4. **Fail-closed ingest**: `latch-ingest` checks `magic` (`0x4C415448`), `version` (`1`), `joint` (`0`), `reserved[12] == 0`, and IEEE 802.3 CRC32 (`0xEDB88320`) over bytes `[0, 16)`. Corrupted payloads are dropped immediately. Semantic faults (such as NaN sentinels) preserve sequence numbers for clean diagnostic identification (`0x0008`).
5. **Least-privilege ability lock**: `latchd` creates custom ability `latch/actuator` with flags 0 (neither root nor non-root has it by default). `iofunc_client_info_able()` verifies `(info->flags & _NTO_CI_UNABLE) == 0u`. Unauthorized devctl callers receive `EPERM`.
6. **Two High-Assurance candidates + hysteresis**: Any fault switches immediately to `HA-HOLD` (zero velocity). After 50 ticks in `HOLD` on the legal side of the keep-out box, `latchd` switches to `HA-HOME` and retracts toward `0` mrad at `v_home`. Restoring `HP` requires 25 consecutive clean frames.

---

## 2. Repository Structure

```text
latch/
  LICENSE                        # MIT License
  README.md                      # Architecture, build, and 5-fault verification guide
  CHANGELOG.md                   # Complete engineering release notes
  .github/workflows/ci.yml       # GitHub Actions CI workflow
  codelab/dead-mans-handle.md    # 45-minute hands-on QNX 8.0 tutorial
  qnx/
    Makefile                     # Multi-target build system (host-sim, rpi4, x86_64, check, qemu)
    latch.manifest               # Zero-hardcoding plant & safety envelope JSON configuration
    latch_manifest.h             # Manifest parser & SHA-256 header
    latch_manifest.c             # Fail-closed JSON parser & FIPS 180-2 SHA-256 attestation
    latch_protocol.h             # 32-byte wire struct, IPC proposal, devctls, CRC32
    latchd.c                     # Simplex supervisor, Seqlock buffer, ability guard, PCA9685 driver
    latch_ingest.c               # Unprivileged virtio-console bridge -> /dev/latch/proposal
    latchctl.c                   # Native admin & ability verification CLI utility
    latchlog.c                   # On-target continuous evidence tape persistence daemon
    latch_verify.c               # Native QNX 8.0 microkernel verification harness
    latch.secpol                 # QNX 8.0 declarative security policy
    latch_rpi4.build             # QNX SDP 8.0 mkifs buildfile for Raspberry Pi 4B
    latch.qvmconf                # QNX Hypervisor 8.0 guest VM configuration
  guest/
    liar.py                      # Python 3 stdlib untrusted policy generator & fault injector
    guest_init.sh                # Linux guest VM minimal initramfs runner
  host/
    tape.html                    # Standalone, offline-capable HTML5 Canvas evidence tape analyzer
    suite_tape.csv               # 200-tick evidence tape generated by the C pipeline
  docs/
    envelope.md                  # Integer safety envelope & Simplex FSM specification
```

---

## 3. How to Build & Run

### 3.1 Local Host Simulation (`host-sim`, No Hardware Needed)

```bash
cd qnx
make check
```

This:
1. Compiles `latchd`, `latch-ingest`, `latchctl`, `latchlog`, `latch_manifest.o`, and `latch_verify` with `-Wall -Wextra -Werror -Wpedantic -O2 -std=c11`.
2. Executes built-in self-tests verifying the 5 fault scenarios, lock-free Seqlock concurrency, and manifest validation.
3. Streams 200 ticks from `guest/liar.py` through `latch-ingest` into `latchd`, generating `host/suite_tape.csv`.

### 3.2 Cross-Compile for QNX SDP 8.0 (`rpi4` & `x86_64`)

```bash
# Source QNX SDP 8.0 environment
source ~/qnx800/qnxsdp-env.sh

cd qnx
make rpi4
make x86_64

# Build bootable QNX OS image
mkifs -v latch_rpi4.build latch_rpi4.ifs
```

### 3.3 Administrative CLI (`latchctl`) & Logging (`latchlog`)

```bash
# Query live supervisor status and nanosecond latency
/proc/boot/latchctl status

# Verify ability enforcement (returns 0 if authorized, 2 if EPERM)
/proc/boot/latchctl grant-check

# Force emergency operator hold
/proc/boot/latchctl hold 1 42

# Continuous tape logging
/proc/boot/latchlog -d /dev/latch/actuator -o /var/log/latch_tape.csv &
```

---

## 4. Five-Fault Verification Menu

| # | Fault Scenario | Injection Command | Expected Outcome |
|---|---|---|---|
| **1** | **Keep-Out Violation** | `python3 guest/liar.py keepout` | `latchd` vetoes proposal entering `[250, 650]` mrad; enters `HA-HOLD` within 1 tick; horn stops. |
| **2** | **Wire CRC Corruption** | `python3 guest/liar.py corrupt` | `latch-ingest` catches CRC mismatch; `latchd` latches `LATCH_FAULT_CRC` (`0x0002`); maintains `HOLD`. |
| **3** | **Sequence Replay / Stale** | `python3 guest/liar.py replay` | Sequence re-use detected ($seq \le last\_seq$); flags `LATCH_FAULT_SEQ` (`0x0004`); fails closed. |
| **4** | **Guest Panic / `kill -9`** | Real `kill -9` in guest VM | 2-tick silence trips watchdog (`0x0100`); transitions from `HOLD` to `HA-HOME` after 50 ticks; horn retracts smoothly to 0 mrad. |
| **5** | **Unauthorized Actuation** | `cat /dev/zero > /dev/latch/actuator` | Client lacks `latch/actuator` ability; `iofunc_client_info_able()` rejects with `EPERM`; incrementing `total_eperm_rejects`. |

---

## 5. Offline Evidence Tape Visualizer

Open `host/tape.html` directly in any web browser. It is fully self-contained with offline CSS styling and can load any CSV or JSON tape export from `latchd`, `latchctl`, or `latchlog`, rendering:
- Trajectory tracking vs. keep-out intervals.
- Mode transition bands (`HP`, `HOLD`, `HOME`).
- Nanosecond decision cycle latency histogram.
- Bitmask fault decoder.

---

## 6. Target Hardware & Trace Reproducibility Card

| Parameter | Audited Value | Ground Truth Source |
|---|---|---|
| **Target OS** | QNX Neutrino RTOS 8.0.0 (2026/06/05) | `uname -a` on `qnxqemu` target |
| **Microkernel** | `procnto-smp-instr` (SMP Instrumented) | `/proc/boot/procnto-smp-instr` |
| **Execution Environment** | QEMU KVM `x86pc x86_64` | `SYSPAGE_ENTRY(qtime)->cycles_per_sec = 2,295,649,179 Hz` (TSC) |
| **Decision Frequency** | 1.000 kHz (`CLOCK_MONOTONIC` 1 ms pulse) | `ChannelCreatePulsePool` (64 pulses, SCHED_FIFO 63) |
| **Measured Decision WCET** | **220 ns nominal** / **101.3 µs cold max** | Ground truth telemetry (beats 4.13 ms paper benchmark) |
| **Attestation Hash** | `1375b4755ebf315d...86d3d4f1` | True NIST FIPS 180-2 SHA-256 (`sha256sum qnx/latch.manifest`) |
| **Security Isolation** | Custom ability `latch/actuator` (flags 0) | `iofunc_client_info_able()` default-deny for root & non-root |
| **Verification Suite** | Exit code 0 only upon verified transitions | `sudo ./latch_verify` actively asserts `.bss` tape ring |
