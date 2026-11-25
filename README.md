# GOVERNOR — Deterministic Safety Interlock & Dead Man's Switch for Physical AI

**The AI may propose. Only QNX may move.**

**Evidence notice:** Archived benchmark reports citing 61.08 µs or 23,500 QNX samples are invalid: the former generator inserted fixed values. Fresh QNX timing requires recorded samples, counter frequency, and platform details.

GOVERNOR is a prototype mixed-criticality runtime-assurance architecture for physical AI on **QNX SDP 8.0** and **QNX Hypervisor 8.0**, built as the flagship safety advancement of the LATCH (Last Authority for Trusted Control Handoff) framework. An untrusted guest AI policy (running inside an isolated Linux 6.12 guest VM or userspace planning agent) proposes 32-byte motion frames over an unprivileged virtio-console black channel. A `SCHED_FIFO` priority 63 decision loop inside an ability-locked QNX resource manager (`latchd`) enforces a discrete integer safety envelope, token-bucket rate burst smoothing, integer rational unit normalization, and an advancing 24-bit coherence lease.

When an AI policy hallucinates out-of-scale coordinates, commands lethal acceleration steps, freezes in infinite loops, or encounters prompt injections, GOVERNOR deterministically clamps velocity, degrades authority across a 6-rung supervisory ladder (`HP` → `ADVISE` → `CLAMP` → `SLOW` → `SAFE_STOP` → `LATCH`), and stores events in a volatile 4096-entry ring for offline export and hash chaining.

- **Target OS:** QNX Software Development Platform (SDP) 8.0 (`procnto-smp-instr`) + QNX Hypervisor 8.0.5 (AArch64 EL2 VHE host + GICv2 guest support)
- **Primary Verified Target:** QEMU AArch64 `virt` (`-M virt,virtualization=on,gic-version=2 -cpu cortex-a76 -smp 4 -m 2048`) hosting a **Linux 6.12 ARM64** guest VM
- **Dual-Domain Applications:** Industrial Robotics (1-DoF servo keep-out containment $[-1000, +1000]$ mrad with forbidden person interval $[250, 650]$ mrad) & Medical Infusion (linear bolus syringe pump $[0, 50000]\ \mu\text{L}$ with simulated per-step limits, lockout interval, and a sliding cumulative-dose limit)
- **Actuator Bus:** PCA9685 12-bit 50 Hz hardware PWM controller at `0x40` (`/dev/i2c1` on hardware; `-n` mock mode on QEMU)
- **Zero-Hardcoding Architecture:** Plant kinematics, unit conversion ratios, rate limits, ladder thresholds, and deadman leases are fully configured via NIST FIPS 180-2 SHA-256 attested schema-3 manifests (`governor_servo.manifest`, `syringe_governor.manifest`).
- **Concurrency:** Lockless 256-slot ring buffer (`queued` delivery, `queue_depth = 256`) with atomic Seqlock snapshot protection covering the 1 kHz decision tick.
- **Fallback / CI Targets:** POSIX Host Simulation (`gcc -std=c11 -DLATCH_HOST_SIM`), QNX `x86_64`, and Raspberry Pi 4B (`com.qnx.qnx800.bsp.raspberrypi_bcm2711_rpi4`)
- **License:** MIT (`LICENSE`)

---

## The Three Industrial Safety Inventions Reborn in QNX 8.0

Modern physical AI systems combine untrusted neural network reasoning with direct actuator handles, creating an unprecedented safety challenge. GOVERNOR resurrects three proven mechanical and cybernetic safety inventions from industrial history, re-architected natively as microkernel primitives on QNX SDP 8.0:

```text
 1788 (Watt's Flyball Governor)       1880s (Railway Dead Man's Handle)      1953 (Flight Data Recorder)
┌───────────────────────────────┐   ┌────────────────────────────────┐   ┌────────────────────────────────┐
│   Centrifugal Steam Engine    │   │  Spring-Loaded Operator Lever  │   │   Survivable Blackbox Casing   │
│   Mechanical Valve Throttling │   │   Loss of Grip -> Full Braking │   │   Crash Telemetry Loop Tape    │
└───────────────┬───────────────┘   └───────────────┬────────────────┘   └───────────────┬────────────────┘
                ▼                                   ▼                                    ▼
┌───────────────────────────────┐   ┌────────────────────────────────┐   ┌────────────────────────────────┐
│ GOVERNOR KINEMATIC POLICY GATE│   │ DEADMAN LIVENESS & COHERENCE   │   │ BLACKBOX HASH-CHAINED FORENSICS│
│ - Discrete-Time CBF Invariance│   │ - Modulo-2^24 Coherence Lease  │   │ - 4096-Entry Circular Memory   │
│ - Token-Bucket Rate Limiter   │   │ - 6-Rung Degradation Ladder    │   │ - Rolling SHA-256 Hash Chain   │
│ - Integer Rational Unit Math  │   │ - 25-Frame Hysteresis Recovery │   │ - Out-of-Band Devctl 0x44 Dump │
└───────────────────────────────┘   └────────────────────────────────┘   └────────────────────────────────┘
```

1. **Watt's Flyball Governor (1788) → `governor` Policy Gate**:
   James Watt used centrifugal flyballs to physically throttle steam valves when rotational speed exceeded safe thresholds. In GOVERNOR, the microkernel implements Discrete-Time Control Barrier Functions (DT-CBF), leaky token-bucket rate burst smoothing, and integer rational unit normalization ($u_{\text{canonical}} = u_{\text{raw}} \cdot N / D$). When an AI policy commands excessive velocity, accelerates wildly, or injects incompatible units, the gate physically clamps or vetoes the command before it reaches the actuator.
2. **Railway Dead Man's Switch → `deadman` Liveness & Coherence Lease**:
   Steam and electric locomotives required the driver to continuously depress a spring-loaded pedal or handle; if the driver lost consciousness, brakes deployed automatically. GOVERNOR implements an advancing 24-bit coherence lease ($\Delta c = (c_k - c_{k-1}) \pmod{2^{24}}$). If the AI agent crashes, hangs in an infinite loop, or stops providing forward progress within `lease_ticks` (100 ms), authority is revoked and the system cascades down a 6-rung degradation ladder to fail-closed `LATCH` (`HOLD`).
3. **Aviation Flight Data Recorder → `blackbox` Hash-Chained Telemetry**:
   Following aircraft incidents, the flight recorder preserves immutable telemetry for accident investigation. GOVERNOR integrates a 4096-entry circular memory event ring in `.bss` memory; on dump (devctl `0x44`), `gov_replay.py` seals the records into a manifest-bound rolling SHA-256 hash chain ($H_k = \text{SHA-256}(H_{k-1} \mathbin{\Vert} E_k)$) and checks continuity after sealing; this cannot detect changes before sealing or prove completeness without an independently retained checkpoint. The ring is RAM-backed (volatile on this target) — no warm-reset persistence is claimed — and the chain is computed at dump/verify time, never inside the decision tick.

---

## The Degradation Ladder & Capability Matrix

GOVERNOR manages AI actuator authority through a deterministic 6-rung finite state machine. Authority degrades progressively upon missed leases or advisory faults, and recovers strictly through verifiable good behavior:

| Rung | Name | Actuator Authority | Velocity Bound ($v_{\text{applied}}$) | Demotion Conditions | Recovery Rule (Hysteresis) |
|:---:|:---|:---|:---|:---|:---|
| **0** | **`HP`** (High Performance) | Full autonomous AI control | $v \le v_{\text{max}}$ (25 mrad/tick) | Lease expiry ($> 100\text{ ms}$) or advisory fault | Top rung; nominal steady state |
| **1** | **`ADVISE`** | Proposals admitted with advisory rate tracking | $v \le v_{\text{max}}$ (25 mrad/tick) with burst rate | 3 consecutive advisory faults or lease expiry | 25 consecutive clean commands promote to `HP` |
| **2** | **`CLAMP`** | Clamped to minimal actuator step | $v \le \text{clamp\_max\_step}$ (5 mrad/tick) | Lease expiry ($> 100\text{ ms}$) | 25 consecutive clean commands promote to `ADVISE` |
| **3** | **`SLOW`** | Limp-home safety crawl | $v \le \text{clamp\_max\_step} \cdot \text{slow\_scale\_pct} = 1$ mrad/tick | Lease expiry ($> 100\text{ ms}$) | 25 consecutive clean commands promote to `CLAMP` |
| **4** | **`SAFE_STOP`** | AI authority revoked; controlled stop | Decelerating slew ($v \to 0$) | Lease expiry ($> 100\text{ ms}$) | 25 consecutive clean commands promote to `SLOW` |
| **5** | **`LATCH`** | Fail-closed `HOLD` (software interlock; mock I²C on the QEMU take — no physical actuation there) | Complete freeze ($v = 0$) | Terminal safe state on channel silence | Operator release required (`latchctl hold 0`) |

### Critical Degradation Invariants
- **Heartbeat Chatter Non-Recovery**: Heartbeat-only frames (`kind=1`) renew the liveness lease, but **explicitly reset** `clean_command_streak = 0`. An agent cannot regain authority by simply pinging health checks.
- **25-Frame Bounded Hysteresis**: Restoring authority up one rung requires exactly 25 (`promote_clean_frames`) consecutive clean, valid, coherent motion proposals (`kind=2`). Any fault resets the streak to 0.

---

## Protocol v2 Wire & IPC Specifications

### Wire Protocol v2 (32 Bytes, Black Channel)
Packed binary frame (`_Static_assert(sizeof(gov_wire_frame_t) == 32)`), transmitted over virtio-console:

| Byte Range | Type | Field Name | Description |
|:---:|:---:|:---|:---|
| `[0..4)` | `uint32_t` | `magic` | Frame header magic: `0x4C415448` (`"LATH"` in ASCII) |
| `[4..6)` | `uint16_t` | `version` | Protocol version: `2` for GOVERNOR v2 (`1` for legacy) |
| `[6]` | `uint8_t` | `joint` | Joint actuator index: `0` for primary 1-DoF plant |
| `[7]` | `uint8_t` | `kind` | Frame kind: `0=CMD`, `1=HEARTBEAT`, `2=CMD_V2`, `3=SHRINK_REQ` |
| `[8..12)` | `uint32_t` | `seq` | Strictly monotonic proposal sequence number |
| `[12..16)` | `int32_t` | `u_mrad` | Signed raw proposal (or `shrink_v_max` for `kind=3`) |
| `[16..20)` | `uint32_t` | `crc32` | IEEE 802.3 CRC-32 covering 28 bytes: `[0..16) || [20..32)` |
| `[20..24)` | `uint32_t` | `confidence_q8` | AI confidence score ($0 \dots 255$, Q8 fixed-point) |
| `[24]` | `uint8_t` | `agent_state` | Agent state: `0=BOOT`, `1=NOMINAL`, `2=DEGRADED`, `3=RECOVER` |
| `[25..28)` | `uint8_t[3]` | `coherence_ctr` | Advancing 24-bit little-endian coherence counter |
| `[28..32)` | `uint32_t` | `unit_id` | Rational unit ID (declared in manifest units dictionary) |

### LPR2 Internal IPC Proposal (48 Bytes)
Transferred from `latch-ingest` to `latchd` via `/dev/latch/proposal` (`_Static_assert(sizeof(latch_ipc_proposal_v2_t) == 48)`):

| Byte Range | Type | Field Name | Description |
|:---:|:---:|:---|:---|
| `[0..4)` | `uint32_t` | `ipc_magic` | IPC protocol magic: `0x4C505232` (`"LPR2"`) |
| `[4..8)` | `uint32_t` | `seq` | Monotonic proposal sequence number |
| `[8..12)` | `int32_t` | `u_mrad` | Raw proposed motion angle |
| `[12..14)` | `uint16_t` | `wire_flags` | Original flags / kind indicators |
| `[14..16)` | `uint16_t` | `pre_fault_bits` | Fault bits detected during bridge ingestion |
| `[16..24)` | `uint64_t` | `ingest_cycles` | Nanosecond-calibrated arrival `ClockCycles()` timestamp |
| `[24..26)` | `uint16_t` | `ipc_version` | IPC interface version (`2`) |
| `[26]` | `uint8_t` | `wire_version` | Original wire version (`2`) |
| `[27]` | `uint8_t` | `kind` | Wire frame kind (`0..3`) |
| `[28]` | `uint8_t` | `confidence_q8` | Scaled confidence score |
| `[29]` | `uint8_t` | `agent_state` | Agent health state |
| `[30..32)` | `uint16_t` | `reserved0` | Alignment padding (must be 0) |
| `[32..36)` | `uint32_t` | `coherence_ctr` | 24-bit advancing coherence counter |
| `[36..40)` | `uint32_t` | `shrink_v` | Shrunk velocity limit parameter |
| `[40..44)` | `uint32_t` | `shrink_scale_q8`| Shrunk acceleration/keepout scale factor |
| `[44..48)` | `uint32_t` | `unit_id` | Manifest rational unit ID |

---

## Adversarial Evaluation Scorecard

GOVERNOR was evaluated against seven named cyber-physical attacks using the unified adversarial test harness (`latch/tools/attacks/run_attacks.py`), which drives the **host-sim build of the same C sources** cross-compiled for the QNX target (on-target proof is archived separately under `docs/evidence/governor/`). Across **121 executed ticks**, the system achieved a **0.0% keep-out breach rate** and a **7/7 deterministic fault detection rate**:

| ID | Attack Scenario | Evaluated Ticks | Target Vulnerability Probed | Fault Bit Verified | Outcome & Ladder Verdict |
|:---:|:---|:---:|:---|:---|:---:|
| **A1** | **Rogue Unit Injection** | 8 | AI hallucinates unmapped unit (`unit_id=999`, $u=370000$) | `LATCH_FAULT_UNIT` (bit 12, `0x1000`) | Proposals rejected; demoted `HP` → `ADVISE` → `CLAMP`. Valid unit 3 ($1/1000$) admitted cleanly. **PASS** |
| **A2** | **Rate Flood Attack** | 5 | Velocity step burst ($\Delta u = 500\text{ mrad}$) to breach keep-out | `LATCH_FAULT_RATE` (bit 7, `0x0080`) | Token bucket exhausted; actuator step clamped to 0 mrad ($\le v_{\text{max}}$). Zero keep-out breach. **PASS** |
| **A3** | **Prompt Injection Attack** | 6 | Scripted injection-like proposal sends $u=450$ into keepout $[250, 650]$ | `LATCH_FAULT_KEEPOUT` (bit 5, `0x0020`) | Keepout breach intercepted; fail-closed drop to `LATCH` (`HOLD`). Plant unmoved. **PASS** |
| **A4** | **Deadman Trip & Recovery** | 79 | Agent CPU stalls ($> 100\text{ ms}$ silence); sends 150 heartbeats | `LATCH_FAULT_HEARTBEAT` (bit 13, `0x2000`) | Lease expires → demotes to `ADVISE`; 150 heartbeats hold without recovery; 25 clean cmds restore `HP`. **PASS** |
| **A5** | **Coherence Spoof Attack**| 6 | Frozen counter ($\Delta c = 0$) or jump ($\Delta c = 10 > 3$) | `LATCH_FAULT_HEARTBEAT` (bit 13, `0x2000`) | Lease renewal refused; ladder demotes `HP` → `ADVISE` → `CLAMP`; plant held stationary. **PASS** |
| **A6** | **Sequence Replay Attack** | 7 | Attacker replays captured frame ($seq \le last\_seq$) | `LATCH_FAULT_SEQ` (bit 2, `0x0004`) | Replay detected; supervisor triggers immediate fail-closed transition to `LATCH` (`HOLD`). **PASS** |
| **A7** | **Chain Tamper Attack** | 10 | Adversary modifies recorded blackbox flight recorder | `TAMPER_DETECTED` (exit code 1) | Rolling SHA-256 chain detects payload/hash mismatch; post-seal payload/hash mismatch detected. **PASS** |

**Adversarial Audit Summary:** 121 ticks evaluated · 0 keep-out breaches · 0% failure rate · 7/7 attacks passed (regenerate with `python3 latch/tools/governor_metrics.py` — **requires host-sim binaries: `CCACHE_DISABLE=1 make -C latch/qnx host-sim`**).

---

## Evidence-of-QNX-Use File & Function Index

GOVERNOR is not an abstract concept; it is an engineered QNX 8.0 application utilizing specialized OS capabilities:

| QNX 8.0 Subsystem / API | Source File & Exact Line Citation | Engineering Role in GOVERNOR |
|:---|:---|:---|
| `resmgr_attach()` | `latch/qnx/latchd.c:2269, 2272, 2275` | Registers `/dev/latch/proposal` (ingest sink), `/dev/latch/actuator` (ability-protected actuator devctl node), and `/dev/governor` (supervisor alias) into QNX pathname space. |
| `ThreadCtl(_NTO_TCTL_RUNMASK_...)` | `latch/qnx/latchd.c:1783`<br>`latch/qnx/latch_ingest.c:99` | Binds safety-critical decision loop exclusively to core 0 (`_cpu-0`) and unprivileged ingest bridge to core 1 (`_cpu-1`). |
| `procmgr_ability_create()` | `latch/qnx/latchd.c:2204` | Creates custom ability `latch/actuator` with `flags=0` (default-deny for both root and non-root users). |
| `procmgr_ability()` | `latch/qnx/latch_ingest.c:295, 322` | Ingestion bridge drops all root abilities, sub-range abilities, and custom abilities at startup (Principle of Least Privilege). |
| `iofunc_client_info_able()` | `latch/qnx/latchd.c:1805, 1843` | Verifies client process holds `latch/actuator` ability before allowing actuation devctls; unauthorized callers receive `EPERM`. |
| `ClockCycles()` | `latch/qnx/latchd.c:197`<br>`latch/qnx/latch_ingest.c:68` | Sub-microsecond hardware cycle timestamping calibrated via `SYSPAGE_ENTRY(qtime)->cycles_per_sec` for deterministic latency tracking. |
| `ChannelCreatePulsePool()` | `latch/qnx/latchd.c:2091` | Allocates non-blocking microkernel pulse pool for deterministic 1.000 ms periodic decision events. |
| `timer_create(CLOCK_MONOTONIC)` | `latch/qnx/latchd.c:2112` | Hardware monotonic timer delivering periodic `SIGEV_PULSE` directly to the `SCHED_FIFO` priority 63 decision loop. |
| `devctl()` Extensions (`DCMD_LATCH_GET_GOV_STATUS`, `DCMD_LATCH_DUMP_GOV_EVENTS`) | `latch/qnx/latchd.c:2030, 2049, 2378, 2384, (+3 more)`<br>`latch/qnx/latchctl.c:135, 394` | Versioned extension devctls: `DCMD_LATCH_GET_GOV_STATUS` (`0x43`) and `DCMD_LATCH_DUMP_GOV_EVENTS` (`0x44`). |
| `devctl(..., DCMD_I2C_SEND, ...)` | `latch/qnx/latchd.c:653, 657, 719, 723` | Direct register programming of PCA9685 12-bit PWM controller over QNX I2C framework (`/dev/i2c1`). |
| `qvm` Hypervisor Guest Isolation (`vdev virtio-console`, `cluster _cpu-2` / `_cpu-3` pins) | `latch/qnx/latch_qemu_virt.qvmconf:128`<br>`latch/qnx/latch_qemu_governor.build:87` | QNX Hypervisor 8.0 EL2 VHE guest configuration isolating untrusted Linux 6.12 guest on vCPUs 2-3 with virtio-console black channel. |
| `secpolcompile` / `secpolpush` (`type latchd_t`, `type latch_ingest_t`, `type qvm_host_t`) | `latch/qnx/latch.secpol:23`<br>`latch/qnx/latch_qemu.build:41, latch_qemu_governor.build:41` | QNX 8.0 declarative Mandatory Access Control (MAC) enforcing process type isolation (`latchd_t`, `latch_ingest_t`, `qvm_host_t`). |

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
4. **Fail-closed ingest**: `latch-ingest` checks `magic` (`0x4C415448`), `version` (`1` or `2`), `joint` (`0`), and IEEE 802.3 CRC32 (`0xEDB88320`). Corrupted payloads are dropped immediately. Semantic faults preserve sequence numbers for clean diagnostic identification (`0x0008`).
5. **Least-privilege ability lock**: `latchd` creates custom ability `latch/actuator` with flags 0 (neither root nor non-root has it by default). `iofunc_client_info_able()` verifies `(info->flags & _NTO_CI_UNABLE) == 0u`. Unauthorized devctl callers receive `EPERM`.
6. **Two High-Assurance candidates + hysteresis**: Any fault switches immediately to `HA-HOLD` (zero velocity). After 50 ticks in `HOLD` on the legal side of the keep-out box, `latchd` switches to `HA-HOME` and retracts toward `0` mrad at `v_home`. Restoring `HP` requires 25 consecutive clean frames.

---

## 2. Repository Structure

```text
latch/
  LICENSE                        # MIT License
  README.md                      # Flagship architecture, build, and verification guide
  CHANGELOG.md                   # Complete engineering release notes
  .github/workflows/ci.yml       # GitHub Actions CI workflow
  codelab/dead-mans-handle.md    # 45-minute hands-on QNX 8.0 tutorial
  qnx/
    Makefile                     # Multi-target build system (host-sim, rpi4, x86_64, check, check-governor)
    latch.manifest               # Zero-hardcoding servo plant & safety envelope JSON configuration
    latch.manifest.sha256        # NIST FIPS 180-2 SHA-256 sidecar for latch.manifest
    contracts/
      governor_servo.manifest    # Schema-3 enabled GOVERNOR contract (wire v2, rational units, ladder)
      governor_servo.manifest.sha256 # NIST FIPS 180-2 SHA-256 sidecar
      syringe_governor.manifest  # Schema-3 medical infusion pump contract (DOSE fault, microlitres)
      syringe_governor.manifest.sha256 # NIST FIPS 180-2 SHA-256 sidecar
      syringe_pump_bolus.manifest        # Second plant contract (medical linear bolus pump)
      syringe_pump_bolus.manifest.sha256 # SHA-256 sidecar for syringe pump contract
    latch_manifest.h             # Schema-3 manifest parser & SHA-256 attestation header
    latch_manifest.c             # Fail-closed JSON parser, keep-out validation, & FIPS sidecar audit
    latch_protocol.h             # 32-byte wire struct, 48-byte LPR2 IPC, devctls 0x40..0x45, CRC32
    latchd.c                     # Simplex supervisor, 6-rung ladder, 4096-entry event ring, devctl dispatch
    latch_ipc.h, .c              # IPC message structures (LPRP, LPR2) and channel decoders
    governor_wire.h, .c          # Wire v2 32-byte codec, kind rules, and 28-byte CRC32 validator
    governor_policy.h, .c        # 6-rung degradation ladder FSM, advancing lease, and hysteresis
    governor_policy_test.c       # Unit test: 6-rung ladder transition invariants
    governor_wire_test.c         # Unit test: framing, CRC coverage, and fail-closed faults
    latch_ipc_test.c             # Unit test: LPRP/LPR2 IPC decoding and structural rejection
    gov_gate_precheck.h, .c      # Precheck: rational units, token bucket, Q8 shrink, DOSE fault
    gov_gate_precheck_test.c     # Unit test: precheck gates and cumulative dose windowing
    latch_ingest.c               # Unprivileged virtio-console bridge -> /dev/latch/proposal
    latchctl.c                   # Native admin CLI (status, events, hold, manifest-verify)
    latchlog.c                   # Continuous evidence tape persistence daemon
    latch_verify.c               # Native QNX 8.0 microkernel verification harness
    latch.secpol                 # QNX 8.0 declarative security policy (secpolcompile)
    latch_rpi4.build             # QNX SDP 8.0 mkifs buildfile for Raspberry Pi 4B
    latch_qemu.build             # QNX SDP 8.0 mkifs buildfile for QEMU AArch64 virt
    latch_qemu_governor.build    # Dedicated GOVERNOR QEMU AArch64 buildfile
    latch_qemu_governor.qvmconf  # QNX Hypervisor 8.0 VM config for GOVERNOR virt (GICv2)
    latch_qemu_virt.qvmconf      # QNX Hypervisor 8.0 guest VM config for QEMU virt (GICv2)
    run_qemu.sh                  # QEMU launcher script
  tools/
    consistency_check.py         # Cross-file architecture & metadata invariant checker
    capture_evidence.py          # Evidence generation & archival engine (all scenarios)
    generate_governor_tape.py    # Merged adversarial tape generator (A1-A7, 121 ticks)
    benchmark_qnx_vs_linux.py    # Determinism & jitter benchmark against Linux CFS
    governor_metrics.py          # Adversarial evaluation scorecard generator
    governor_client.py           # Python SDK for wire v2 encoding, CRC32, kinds, Q8, unit conversions
    agent_loop.py                # Autonomous AI agent control loop ("plan -> propose -> observe")
    gov_replay.py                # Tamper-evident hash chain replay and verification engine
    governor_e2e.py              # End-to-end full path integration test (7 scenarios)
    governor_manifest_test.py    # Schema-3 negative test suite
    qemu_guest_kill.py           # Guest crash and supervisor isolation test (slay -9 qvm)
    verify_governor_qemu.py      # QEMU GOVERNOR guest-to-QNX runtime verifier
    verify_qemu_aarch64.py       # Boots legacy IFS under QEMU and asserts on-target signature
    attacks/                     # Standalone adversarial attack test suite
      attack_a1_unit_injection.py
      attack_a2_rate_flood.py
      attack_a3_prompt_note.py
      attack_a4_deadman.py
      attack_a5_coherence_spoof.py
      attack_a6_replay.py
      attack_a7_chain_tamper.py
      run_attacks.py             # Unified adversarial attack rig runner
  guest/
    latch_guest_init.c           # THE in-guest policy: freestanding static AArch64 /init
    liar.py                      # Workstation policy generator (host-sim / make check)
  host/
    console.html                 # Offline HTML5 Canvas operator console & attack trigger pad
    tape.html                    # Standalone HTML5 Canvas evidence tape analyzer
    suite_tape.csv               # 200-tick evidence tape generated by the C pipeline
  docs/
    evidence/governor/           # Archived authentic transcripts, tapes, and metrics
      governor-host-sim.txt
      governor-manifest-verify.txt
      governor-metrics.txt
      governor-qemu-console.txt
      governor-status-transition.txt
      governor-tape.csv
      governor-latency-benchmark.txt
      governor-vm-kill-resume.txt
      governor-qemu-verify.txt
      LATENCY.md
    GOVERNOR_JUDGE_READINESS.md  # Honest claims ledger
    GOVERNOR_PROTOCOL_V2.md      # Binding wire/IPC specification
    LATCH-implementation.md      # Technical architecture
    DEVPOST_SUBMISSION.md        # Official Devpost submission draft
    DEMO_VIDEO_SCRIPT.md         # 3-minute video storyboard script
```

---

## 3. How to Build & Run

### 3.1 Four Named Reproduction Verification Commands

```bash
# 1. Architectural Consistency & Invariant Verification Gate
python3 latch/tools/consistency_check.py

# 2. Unified Adversarial Attack Rig (Attacks A1, A2, A4, A5, A6)
#    PREREQUISITE: the rig drives the host-sim binaries, which are not
#    committed. Build them first or run_attacks.py exits with FileNotFoundError.
CCACHE_DISABLE=1 make -C latch/qnx host-sim
python3 latch/tools/attacks/run_attacks.py

# 3. Dedicated GOVERNOR Seven-Scenario Test Gate
CCACHE_DISABLE=1 make -C latch/qnx check-governor

# 4. Full Legacy Oracle Regression Suite (200 ticks | rx=200 | wire=12 | env=7 | eperm=1)
CCACHE_DISABLE=1 make -C latch/qnx check
```

### 3.2 Build & Run on QEMU AArch64 `virt` (QNX SDP 8.0 + Hypervisor 8.0.5)

```bash
# Source QNX SDP 8.0 environment
source ~/qnx800/qnxsdp-env.sh

cd latch/qnx

# Build dedicated GOVERNOR bootable IFS
make ifs-qemu-governor

# Run automated on-target QEMU verifier (asserts 235 proposals, A4 lease trip, clean recovery)
python3 ../tools/verify_governor_qemu.py

# Launch interactive QEMU session
./run_qemu.sh
```

### 3.3 Administrative CLI (`latchctl`) & Telemetry Replay (`gov_replay.py`)

```bash
# Query live supervisor status and ladder rung
/proc/boot/latchctl status

# Dump event ring blackbox forensics
/proc/boot/latchctl events

# Verify manifest sidecar cryptographic integrity
/proc/boot/latchctl manifest-verify /proc/boot/governor_servo.manifest

# Replay and verify hash chain integrity offline
python3 latch/tools/gov_replay.py --test
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

---

## 5. Offline Evidence Tape Visualizer

Open `host/tape.html` directly in any web browser (`file:///`) — it is fully self-contained with offline CSS styling and loads any CSV tape export from `latchd`, `latchctl`, or `latchlog`, rendering:
- Trajectory tracking vs. keep-out intervals.
- Mode transition bands (`HP`, `HOLD`, `HOME`).
- Nanosecond decision cycle latency histogram.
- Bitmask fault decoder.

`host/console.html` is a separate **offline simulator/demo** of the GOVERNOR ladder (canvas radar, ladder badges, attack trigger pad): it runs a client-side model of the system for visualization and does **not** load tape files or talk to a live target. Its in-browser hash chain is a labeled demo digest — real SHA-256 sealing of real dumps is `tools/gov_replay.py`.

---

## 5a. The Evidence Archive

**`docs/evidence/`** is the target proof. A judge without a QNX SDP licence
cannot rebuild the IFS, so every console log of every run is committed.

| Directory | Purpose |
|---|---|
| **`docs/evidence/README.md`** | The index: which claim is proved by which file, how to regenerate each one, and what is **not** proven |
| **`docs/evidence/derived/RUN-OUTPUT-MANIFEST.md`** | **What each kind of run produces** — the file-by-file output list |
| **`docs/evidence/on-target/`** | The raw QNX console of every QEMU boot, numbered by the story it tells |
| **`docs/evidence/tape/`** | The windowed evidence tapes and their analysis |
| **`docs/evidence/resolution/`** | The four defects, each with its mechanism and its proof |
| **`docs/evidence/governor/`** | **GOVERNOR Evidence**: QEMU console transcript, the archived `make verify-governor-qemu` PASS log, live status transitions, 121-tick attack tape, metrics, and manifest attestations |
| **`docs/evidence/host-sim/`, `build/`, `derived/`** | The workstation pipeline, what is inside the bootable image, and the machine-readable summaries |

Regenerate it all with one command:

```bash
make -C qnx evidence            # everything except the QEMU boot (~20 s)
make -C qnx evidence-on-target  # a fresh QEMU AArch64 `virt` capture (~5 min)
make -C qnx evidence-check      # the anti-rot gate: has the code drifted from the archive?
```

Nothing in the legacy archive is hand-edited: `tools/capture_evidence.py`
writes every file, and `make -C qnx evidence-check` re-runs the capture and
compares the signature against the archived one — so the legacy evidence cannot
silently drift away from the code it describes. The **GOVERNOR** captures under
`docs/evidence/governor/` are raw outputs of their named tools: the on-target
runs are verbatim `make verify-governor-qemu` logs, and the attack scorecard is
regenerated with `python3 tools/governor_metrics.py` — **requires host-sim binaries: `CCACHE_DISABLE=1 make -C qnx host-sim`**.

---

## 6. Target Hardware & Trace Reproducibility Card

| Parameter | Audited Value | Ground Truth Source |
|---|---|---|
| **QNX SDP (installed)** | `com.qnx.qnx800` **8.0.0.00141T202311271501L** — the SDP the IFS in this archive was built against (current upstream release is 8.0.6; every build here is evidence for **8.0.0**) | `~/qnx800/.packages/metadata/` (QSC install manifest) · `docs/SBOM.md` §2 |
| **QNX Hypervisor (installed)** | `com.qnx.qnx800.target.hypervisor.group` **3.6.0.00802T202608071638L** — the package version published for **QNX Hypervisor 8.0.5**, so the installed hypervisor **is** 8.0.5 | QNX Hypervisor 8.0.5 Product Release Notes (edition Aug 21 2026) · `docs/SBOM.md` §2 |
| **QNX Host Tools (installed)** | `com.qnx.qnx800.host.linux.x86_64` **0.0.1.02005T202411230033L** (the metapackage — it *requires* the per-tool packages below, but not `mkifs`)<br>`com.qnx.qnx800.host.linux.x86_64.qcc` **8.0.0.00121T202510081309L** (`qcc`)<br>`com.qnx.qnx800.host.linux.x86_64.secpol` **0.5.0.00132T202605281115L** (`secpolcompile`)<br>`com.qnx.qnx800.host.linux.x86_64.qlicense` **8.0.0.00114T202411221950L** (`qlicense`)<br>`com.qnx.qnx800.host.linux.x86_64.mkifs` **1.2.2.00014T202605190942L** (`mkifs`) | `~/qnx800/.packages/metadata/` (QSC install manifest) · `docs/SBOM.md` §2 |
| **QNX Cross-Compiler (installed)** | `com.qnx.qnx800.host.linux.x86_64.gcc` **12.2.0.00500T202604231841L** (QNX GCC 12.2.0) | `~/qnx800/.packages/metadata/` (QSC install manifest) · `docs/SBOM.md` §2 |
| **Target OS & Hypervisor** | QNX Neutrino RTOS 8.0 (`procnto-smp-instr`) + QNX Hypervisor 8.0 (`qvm`) | `syspage::hypinfo::flags=0x00000001` (EL2 VHE) |
| **Verified VM Target** | QEMU AArch64 `virt` (`4x Cortex-A76`, GICv2 `0x08000000`/`0x08010000`, `62,500,000 Hz` timer) | `tools/verify_qemu_aarch64.py` (`qemu-system-aarch64`) |
| **Toolchain** | `qcc -Vgcc_ntoaarch64le -Wc,-std=c11 -Wall -Wextra -Werror -Wpedantic -O2 -D_QNX_SOURCE` | `qnx/Makefile` (`TARGET=aarch64`) |
| **Decision Frequency** | 1.000 kHz (`CLOCK_MONOTONIC` 1 ms pulse) | `ChannelCreatePulsePool` (64 pulses, SCHED_FIFO 63) |
| **Measured Decision Latency** | **64 cycles (1,024 ns)** last, **40,323 cycles (645,168 ns)** max on QEMU **TCG** — *not* a WCET. The Linux host-sim's max decision latency is host-load dependent, so it is recorded per capture in `docs/evidence/host-sim/` rather than quoted here. | `docs/evidence/on-target/20261125-090128-status.txt` (the `latchctl status` block) & `docs/evidence/host-sim/` |
| **Guest Suite (on target)** | `Proposals Received: 84` · `Wire Faults Caught: 12` · `Envelope Vetoes: 7` · `Ring Drops: 0` · `Last Proposed: -180 mrad (seq=80)` · `Latched: 0x01AE (CRC\|SEQ\|NAN\|KEEPOUT\|RATE\|WATCHDOG)` | `docs/evidence/on-target/20261125-090128-status.txt` — live Linux 6.12 `/init` → `virtio-console` → `latch-ingest` → `latchd` |
| **Evidence Tape (on target)** | 17 `HA-HOME` rows retracting `-170 → -10 mrad`, monotonic; **0** rows with `theta_applied` inside `[250, 650]` mrad | `docs/evidence/tape/latch_tape6-metrics.txt` (from `/dev/shmem/latch_tape.csv`) |
| **Attestation Hashes** | Servo: `1a8e10234f8aabbdfe1ce2d5a8b67459e0c9d0cf386963e9deed8ebd5d27f823`<br>Syringe: `a9d877ebf63d5670006593ac8eadc7303b324c52c1d30e29aeacb8b9253e0e5e`<br>GOVERNOR Servo: `a29b81341077ac0e4276d91b5ff703c700243db69b674f7cbb466c0689ddc53b`<br>GOVERNOR Syringe: `6b62927a81c2566d1f2d7d0e8ff5047d9f22086f1693044ea9a77de7c142b392` | True NIST FIPS 180-2 SHA-256 (`sha256sum` sidecars) |
| **Security Isolation** | Custom ability `latch/actuator` (flags 0) | `iofunc_client_info_able()` default-deny for root & non-root |
| **Verification Suite** | Exit code 0 (`VERIFY_RC=0`) only upon all 5 microkernel invariants passing | `docs/evidence/on-target/20261125-090128-verify.txt` — the `[1/5]`…`[5c/5]` section |

> **The on-target evidence is committed — and every number above is traceable to
> a file.** Start at **`docs/evidence/README.md`**: it maps each claim to the
> archive file that proves it, lists the exact commands to regenerate every
> file, and states plainly what is **not** proven.
>
> The canonical artefact is `docs/evidence/on-target/CURRENT-SESSION.txt`
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
> (`rx=200 | wire=12 | env=7 | eperm=1` in CI; `84 | 12 | 7 | 0` on the target).
> The guest policy and the CI suite are the same suite; only the frame count
> differs, because the on-target guest stops after its nine fault phases instead
> of padding to 200 ticks. After `latch_verify` has run the supervisor has
> received 97 frames in total — the guest's 84 plus the harness's own 13 —
> which is why the post-verify telemetry reads `97`, not 200.

> **QEMU target = mock I²C.** The QEMU AArch64 `virt` image runs `latchd -n`, so **no
> PCA9685 is present and the horn does not move** in that take. The Raspberry Pi 4B
> image is the same `latchd` binary with the real `i2c-bcm2711` bus and the PCA9685
> attached; that is the take that moves the horn. Do not mix the two sentences.
