# LATCH — Last Authority for Trusted Control Handoff

**The AI may propose. Only QNX may move.**

LATCH is a mixed-criticality runtime-assurance architecture for physical AI on **QNX SDP 8.0** and **QNX Hypervisor 8.0**. An untrusted guest AI policy proposes 32-byte motion frames over a virtio-console black channel. A `SCHED_FIFO` priority 63 decision loop inside an ability-locked resource manager (`latchd`) verifies the kinematic envelope, lookahead rollout, and keep-out intervals, actuating via a PCA9685 PWM controller on `/dev/i2c1` or failing closed to High-Assurance (`HA-HOLD` / `HA-HOME`) candidates, recording every verdict in a 4096-entry evidence tape.

- **Target OS:** QNX Software Development Platform (SDP) 8.0 (`procnto-smp-instr`) + QNX Hypervisor 8.0.5 (AArch64 EL2 VHE host + GICv2 guest support)
- **Primary Verified Target:** QEMU AArch64 `virt` (`-M virt,virtualization=on,gic-version=2 -cpu cortex-a76 -smp 4 -m 2048`) hosting a **Linux 6.12 ARM64** guest VM
- **Actuator Bus:** PCA9685 12-bit 50 Hz hardware PWM controller at `0x40` (`/dev/i2c1` on hardware; `-n` no-I2C mock mode on QEMU)
- **Zero-Hardcoding Architecture:** Plant geometry, keep-out intervals, velocity/acceleration limits, timing budgets, and bus paths are fully configured via `latch.manifest` with SHA-256 integrity verification.
- **Concurrency:** Lockless 256-slot ring buffer (`queued` delivery, `queue_depth = 64`) with Seqlock snapshot guard eliminating torn reads on high-frequency publisher updates.
- **Fallback / CI Targets:** POSIX Host Simulation (`gcc -std=c11 -DLATCH_HOST_SIM`), QNX `x86_64`, and Raspberry Pi 4B (`com.qnx.qnx800.bsp.raspberrypi_bcm2711_rpi4`)
- **License:** MIT (`LICENSE`)

---

## 1. Architecture & Trust Boundary

```text
══════════════════════════════════════════════════════════════════════════
  QEMU AArch64 `virt` (4x Cortex-A76, GICv2) · QNX SDP 8.0.x + QNX Hypervisor 8.0
  Raspberry Pi 4B (BCM2711, Cortex-A72, GICv2) · same binaries, EL1 host
══════════════════════════════════════════════════════════════════════════
  TRUSTED SAFETY DOMAIN (QNX host, cores 0–1)      UNTRUSTED AI DOMAIN (guest, cores 2–3)
┌────────────────────────────────────────────┐   ┌───────────────────────────────────┐
│ CPU 0 · SCHED_FIFO 63  [latchd]            │   │ Linux 6.12 aarch64 VM (512 MB @   │
│  · 1 kHz tick: timer_create+SIGEV_PULSE    │   │ 0x80000000, load @ 0x80080000)    │
│  · latch.manifest fail-closed loader       │   │                                   │
│  · envelope + keep-out + mode FSM          │   │ [/init]  untrusted policy         │
│  · resmgr: /dev/latch/proposal             │   │  (guest/latch_guest_init.c,       │
│            /dev/latch/actuator             │   │   freestanding static AArch64)    │
│  · procmgr_ability_create("latch/actuator",0)│   │  9 fault classes, paced           │
│  · iofunc_client_info_able(_NTO_CI_UNABLE) │   │  can hang, lie, spam, or go silent│
│  · PCA9685 via /dev/i2c1 (DCMD_I2C_SEND)   │   │       │ 32-B frame, CRC-32        │
│  · 4096-entry ClockCycles evidence tape    │   │       ▼                           │
│           ▲                                │   │  vdev virtio-console              │
│           │ hostdev >"|/proc/boot/..."     │   │◄─┬─ (black channel: by-value only,│
│ CPU 1 · [latch-ingest] unprivileged        │   │  no pointers, no shared memory)   │
│  · validates magic/version/CRC/seq/zeroes  │   │ vdev gic version 2 (GICv2)        │
│  · pins itself to CPU 1 (runmask)          │   │ vdev pl011 -> /dev/shmem log      │
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
    Makefile                     # Multi-target build system (host-sim, rpi4, x86_64, check, demo-syringe, secpol, qemu)
    latch.manifest               # Zero-hardcoding servo plant & safety envelope JSON configuration
    latch.manifest.sha256        # NIST FIPS 180-2 SHA-256 sidecar for latch.manifest
    contracts/
      syringe_pump_bolus.manifest        # Second plant contract (medical linear bolus pump)
      syringe_pump_bolus.manifest.sha256 # SHA-256 sidecar for syringe pump contract
    latch_manifest.h             # Manifest parser & SHA-256 header
    latch_manifest.c             # Fail-closed JSON parser & FIPS 180-2 SHA-256 attestation
    latch_protocol.h             # 32-byte wire struct, IPC proposal, devctls, CRC32
    latchd.c                     # Simplex supervisor, SPSC ring + Seqlock status/tape, ability guard, PCA9685 driver
    latch_ingest.c               # Unprivileged virtio-console bridge -> /dev/latch/proposal
    latchctl.c                   # Native admin & ability verification CLI utility
    latchlog.c                   # On-target continuous evidence tape persistence daemon
    latch_verify.c               # Native QNX 8.0 microkernel verification harness
    latch.secpol                 # QNX 8.0 declarative security policy (secpolcompile)
    latch_rpi4.build             # QNX SDP 8.0 mkifs buildfile for Raspberry Pi 4B
    latch_qemu.build             # QNX SDP 8.0 mkifs buildfile for QEMU AArch64 virt
    latch.qvmconf                # QNX Hypervisor 8.0 guest VM config for RPi4 (GIC-400)
    latch_qemu_virt.qvmconf      # QNX Hypervisor 8.0 guest VM config for QEMU virt (GICv2)
    run_qemu.sh                  # QEMU x86_64 (QSTI) / AArch64 launcher script
  tools/
    consistency_check.py         # Cross-file architecture & metadata invariant checker
    verify_qemu_aarch64.py       # Boots the IFS under QEMU and asserts the on-target signature
    capture_evidence.py          # Produces the whole docs/evidence/ archive
    embed_default_tape.py        # Regenerates the viewer's embedded copy of the tape
  guest/
    liar.py                      # WORKSTATION-ONLY policy generator (host-sim / make check)
    latch_guest_init.c           # THE in-guest policy: freestanding static AArch64 /init
    linux-guest.initrd           # built by `make guest-initrd` (cpio newc + gzip)
  host/
    tape.html                    # Standalone, offline-capable HTML5 Canvas evidence tape analyzer
    suite_tape.csv               # 200-tick evidence tape generated by the C pipeline
  docs/
    envelope.md                  # Integer safety envelope & Simplex FSM specification
    LATCH-implementation.md      # Deep architecture, DT-CBF, and target verification report
    LATCH-research.md            # QNX 8.0 manual verification log & design trade-offs
    VIDEO_SCRIPT_AND_SUBMISSION.md # 3-minute shot list & Devpost checklist
    evidence/                    # THE TARGET PROOF: every run's raw console + the index
```

> **One guest policy, one path.** The in-guest policy is
> `guest/latch_guest_init.c` — a freestanding static AArch64 binary packed as
> `linux-guest.initrd`. There is no shell and no Python inside the guest.
> `guest/liar.py` is the **workstation** generator that `make check` drives
> through a POSIX pipe; it is byte-for-byte the same suite, but it never
> enters the hypervisor guest.

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

### 3.2 Build & Run on QEMU AArch64 `virt` (QNX SDP 8.0 + Hypervisor 8.0.5)

```bash
# Source QNX SDP 8.0 environment
source ~/qnx800/qnxsdp-env.sh

cd qnx

# Build guest initramfs + QNX binaries + secpol.bin + bootable IFS (one command)
make ifs-qemu-aarch64 GUEST_IMAGE=/path/to/linux-6.12/arch/arm64/boot/Image

# Launch interactive QEMU AArch64 virt session (4x Cortex-A76, EL2 VHE, GICv2)
./run_qemu.sh

# Or run the automated end-to-end QEMU verification harness (asserts 200 ticks + VERIFY_RC=0)
make verify-qemu

# Capture the evidence archive: a fresh on-target console session + every
# derived summary (~10 min for the QEMU boot, ~20 s for the rest)
make evidence-on-target
make evidence
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
/proc/boot/latchlog -d /dev/latch/actuator -o /dev/shmem/latch_tape.csv &
```

---

## 4. Five-Fault Verification Menu

| # | Fault Scenario | How it is injected | Expected Outcome |
|---|---|---|---|
| **1** | **Keep-Out Violation** | Guest `/init` phase 2: one frame at `+450` mrad, inside the manifest `PERSON` box `[250, 650]` | `latchd` vetoes the proposal; enters `HA-HOLD` within one tick; horn stops. |
| **2** | **Wire CRC Corruption** | Guest `/init` phase 5: one frame with a flipped payload bit (CRC no longer matches) | `latch-ingest` catches the CRC mismatch; `latchd` latches `LATCH_FAULT_CRC` (`0x0002`); maintains `HOLD`. |
| **3** | **Sequence Replay / Stale** | Guest `/init` phase 8: a frame re-using the previous `seq` | Sequence re-use detected (`seq <= last_seq`); flags `LATCH_FAULT_SEQ` (`0x0004`); fails closed. |
| **4** | **Guest Goes Silent** | Guest `/init` phase 9: **the guest simply stops writing bytes**. PID 1 in the guest *is* the policy binary, so there is no second process to `kill -9` — say "the guest stopped talking", not "we killed the policy". | A genuine gap on the channel trips the watchdog (`0x0100`) after 2 ticks; `latchd` transitions `HOLD` to `HA-HOME` after 50 ticks; horn retracts smoothly to 0 mrad. The host's 1 kHz tick never stops. |
| **5** | **Unauthorized Actuation** | `/proc/boot/latchctl grant-check` from the operator shell (typed `operator_shell_t`, which does **not** hold the ability) | Client lacks `latch/actuator`; `iofunc_client_info_able()` reports `_NTO_CI_UNABLE`; the devctl returns `EPERM`; `total_eperm_rejects` increments and `LATCH_FAULT_EPERM` (`0x0800`) is latched. |

> The workstation command `python3 guest/liar.py <mode>` is the **host-simulation**
> injector used by `make check` (it drives `latch-ingest` over a POSIX pipe).
> It is *not* what runs inside the hypervisor guest. The in-guest policy is
> `guest/latch_guest_init.c`, a freestanding static AArch64 binary packed as
> `linux-guest.initrd`.

---

## 5. Offline Evidence Tape Visualizer

Open `host/tape.html` directly in any web browser. It is fully self-contained with offline CSS styling and can load any CSV or JSON tape export from `latchd`, `latchctl`, or `latchlog`, rendering:
- Trajectory tracking vs. keep-out intervals.
- Mode transition bands (`HP`, `HOLD`, `HOME`).
- Nanosecond decision cycle latency histogram.
- Bitmask fault decoder.

---

## 5a. The Evidence Archive

**`docs/evidence/`** is the target proof. A judge without a QNX SDP licence
cannot rebuild the IFS, so every console log of every run is committed.

| | |
|---|---|
| **`docs/evidence/README.md`** | The index: which claim is proved by which file, how to regenerate each one, and what is **not** proven |
| **`docs/evidence/derived/RUN-OUTPUT-MANIFEST.md`** | **What each kind of run produces** — the file-by-file output list |
| **`docs/evidence/on-target/`** | The raw QNX console of every QEMU boot, numbered by the story it tells |
| **`docs/evidence/tape/`** | The windowed evidence tapes and their analysis |
| **`docs/evidence/resolution/`** | The four defects, each with its mechanism and its proof |
| **`docs/evidence/host-sim/`, `build/`, `derived/`** | The workstation pipeline, what is inside the bootable image, and the machine-readable summaries |

Regenerate it all with one command:

```bash
make -C qnx evidence            # everything except the QEMU boot (~20 s)
make -C qnx evidence-on-target  # a fresh QEMU AArch64 `virt` capture (~5 min)
make -C qnx evidence-check      # the anti-rot gate: has the code drifted from the archive?
```

Nothing in the archive is hand-edited. `tools/capture_evidence.py` writes every
file, and CI compares the archived signature against a fresh one on every push —
so the evidence cannot silently drift away from the code it describes.

---

## 6. Target Hardware & Trace Reproducibility Card

| Parameter | Audited Value | Ground Truth Source |
|---|---|---|
| **Target OS & Hypervisor** | QNX Neutrino RTOS 8.0 (`procnto-smp-instr`) + QNX Hypervisor 8.0 (`qvm`) | `syspage::hypinfo::flags=0x00000001` (EL2 VHE) |
| **Verified VM Target** | QEMU AArch64 `virt` (`4x Cortex-A76`, GICv2 `0x08000000`/`0x08010000`, `62,500,000 Hz` timer) | `tools/verify_qemu_aarch64.py` (`qemu-system-aarch64`) |
| **Toolchain** | `qcc -Vgcc_ntoaarch64le -Wc,-std=c11 -Wall -Wextra -Werror -Wpedantic -O2 -D_QNX_SOURCE` | `qnx/Makefile` (`TARGET=aarch64`) |
| **Decision Frequency** | 1.000 kHz (`CLOCK_MONOTONIC` 1 ms pulse) | `ChannelCreatePulsePool` (64 pulses, SCHED_FIFO 63) |
| **Measured Decision Latency** | **1.23 µs** last (`77 cycles`), **435.9 µs** max (`27,243 cycles`) on QEMU **TCG** — *not* a WCET; **1,422 ns** max in the Linux host-sim | `docs/evidence/on-target/09-canonical-session.txt` (the `latchctl status` section) & `docs/evidence/derived/host-sim-signature.txt` |
| **Guest Suite (on target)** | `Proposals Received: 84` · `Wire Faults Caught: 12` · `Envelope Vetoes: 7` · `Ring Drops: 0` · `Last Proposed: -180 mrad (seq=80)` · `Latched: 0x01AE (CRC\|SEQ\|NAN\|KEEPOUT\|RATE\|WATCHDOG)` | `docs/evidence/on-target/09-canonical-session.txt` — live Linux 6.12 `/init` → `virtio-console` → `latch-ingest` → `latchd` |
| **Evidence Tape (on target)** | 17 `HA-HOME` rows retracting `-170 → -10 mrad`, monotonic; **0** rows with `theta_applied` inside `[250, 650]` mrad | `docs/evidence/tape/latch_tape6-metrics.txt` (from `/dev/shmem/latch_tape.csv`) |
| **Attestation Hashes** | Servo: `1a8e10234f8aabbdfe1ce2d5a8b67459e0c9d0cf386963e9deed8ebd5d27f823`<br>Syringe: `a9d877ebf63d5670006593ac8eadc7303b324c52c1d30e29aeacb8b9253e0e5e` | True NIST FIPS 180-2 SHA-256 (`sha256sum` sidecars) |
| **Security Isolation** | Custom ability `latch/actuator` (flags 0) | `iofunc_client_info_able()` default-deny for root & non-root |
| **Verification Suite** | Exit code 0 (`VERIFY_RC=0`) only upon all 5 microkernel invariants passing | `docs/evidence/on-target/09-canonical-session.txt` — the `[1/5]`…`[5c/5]` section |

> **The on-target evidence is committed — and every number above is traceable to
> a file.** Start at **`docs/evidence/README.md`**: it maps each claim to the
> archive file that proves it, lists the exact commands to regenerate every
> file, and states plainly what is **not** proven.
>
> The canonical artefact is `docs/evidence/on-target/09-canonical-session.txt`
> — the raw QNX host console of **one continuous boot** of the QEMU AArch64
> `virt` image: the EL2-VHE hypervisor banner, `pidin -p latchd threads` (the
> decision loop on CPU 0 at SCHED_FIFO 63), `pidin -p qvm threads` (the guest
> vCPU threads named `cy-guest-qemu-virt/0` and `/1` — the static pins), the
> supervisor's counters, the five verification steps, and `VERIFY_RC=0`. A judge
> without QNX SDP cannot rebuild the IFS, so this file is the target proof.
>
> `docs/evidence/derived/RUN-OUTPUT-MANIFEST.md` lists **what each kind of run
> produces**. `docs/evidence/derived/on-target-run-index.txt` shows the whole
> bring-up in one table: each run differs from the one before it by exactly
> one fix, and the envelope-veto count falls `51 → 48 → 27 → 7` as a result.
> `docs/evidence/resolution/SUMMARY.md` explains each of the four defects.
>
> **The archive cannot rot.** `make -C qnx evidence-check` re-runs the host-sim
> capture and compares the signature against the archived one; CI runs it on
> every push.

> **The on-target signature is the same story as the host-sim tape**
> (`rx=200 | wire=12 | env=7 | eperm=1` in CI; `84 | 12 | 7 | 0` on the target,
> where the guest emits 84 frames and `latch_verify` contributes the rest). The
> guest policy and the CI suite are the same suite; only the frame count differs
> because the on-target guest stops after its nine fault phases instead of
> padding to 200 ticks.

> **QEMU target = mock I²C.** The QEMU AArch64 `virt` image runs `latchd -n`, so **no
> PCA9685 is present and the horn does not move** in that take. The Raspberry Pi 4B
> image is the same `latchd` binary with the real `i2c-bcm2711` bus and the PCA9685
> attached; that is the take that moves the horn. Do not mix the two sentences.
