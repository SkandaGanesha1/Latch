# 01 — LATCH Current Workflow, Codebase Audit & Master Checklist A–Z Verification

**Generated:** 2026-11-23  
**Target Platform:** QNX SDP 8.0 (`procnto-smp-instr`) + QNX Hypervisor 8.0 (QEMU AArch64 `virt` & Raspberry Pi 4B)  
**Codebase HEAD:** `e1f4e6b` on branch `main` (`/home/skanda/Downloads/latch-qnx800/latch`)  
**Core Invariant:** The AI may propose; only QNX moves.

---

## 1. Executive Summary & System Identity

LATCH (Last Authority for Trusted Control Handoff) is an open-source, mixed-criticality runtime assurance and safety supervisor built natively for **QNX SDP 8.0**. It enforces strict spatial, temporal, and capability separation between untrusted physical AI planning components and trusted real-time actuation.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        QNX SDP 8.0 / HYPERVISOR 8.0 ARCHITECTURE                       │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  SAFETY DOMAIN (Cores 0-1, Trusted)                  AI GUEST DOMAIN (Cores 2-3)       │
│  ┌──────────────────────────────────────────────┐    ┌──────────────────────────────┐  │
│  │ latchd (SCHED_FIFO 63, Core 0 pinned)        │    │ qvm (QNX Hypervisor 8.0)     │  │
│  │  ├─ Timer Pulse Pool: ChannelCreatePulsePool │    │  ┌────────────────────────┐  │  │
│  │  │   monotonic 1 kHz, _NTO_CHF_FIXED_PRIORITY│    │  │ Linux 6.12 (AArch64)   │  │  │
│  │  ├─ SPSC Seqlock: C11 acquire/release        │    │  │  /init PID 1           │  │  │
│  │  │   256 slots, memory_order_acq_rel         │    │  │  235-frame attack suite│  │  │
│  │  ├─ 6-Rung Degradation Ladder FSM            │    │  └───────────┬────────────┘  │  │
│  │  │   HP -> ADVISE -> CLAMP -> SLOW -> LATCH  │    └──────────────┼───────────────┘  │
│  │  ├─ DT-CBF: 10-tick lookahead & braking      │                   │ 32-B virtio-     │
│  │  └─ Ability Gate: procmgr_ability_create     │                   │    console       │
│  │ latch_ingest (Unprivileged, drops root, C1)  │◄──────────────────┘                  │
│  │ latchctl (Operator CLI, checks 'latch/act')  │                                      │
│  └──────────────────────────────────────────────┘                                      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

An untrusted guest (running inside an isolated Linux 6.12 guest VM or userspace planning agent) proposes 32-byte motion frames over an unprivileged `virtio-console` black channel. An unprivileged bridge (`latch-ingest`) validates frame framing, CRC32, and message kinds, forwarding proposals via fixed-size native QNX message passing (`/dev/latch/proposal`) to a trusted supervisor (`latchd`). `latchd` is a `SCHED_FIFO` priority 63 ability-locked resource manager pinned to CPU 0, and is **the only process possessing the `latch/actuator` ability required to command the physical or simulated actuator**.

---

## 2. Codebase Audit & Architectural Invariants

### 2.1 ABI, Frame Formats & Devctl Mapping

The audit verifies exact ABI alignment across headers, C sources, and tools:

#### Devctl Command Numbers (`qnx/latch_protocol.h:365–430`)
- `0x40`: `DCMD_LATCH_FORCE_HOLD` (`__DIOT(_DCMD_MISC, 0x40, int)`) — Operator emergency hold override (requires `latch/actuator` ability).
- `0x41`: `DCMD_LATCH_GET_STATUS` (`__DIOF(_DCMD_MISC, 0x41, latch_status_t)`) — Basic status query.
- `0x42`: `DCMD_LATCH_DUMP_TAPE` (`__DIOTF(_DCMD_MISC, 0x42, latch_dump_req_t)`) — Snapshot ring buffer dump.
- `0x43`: `DCMD_LATCH_GET_STATUS_EXT` (`__DIOF(_DCMD_MISC, 0x43, governor_status_ext_t)`) — GOVERNOR extended status (ladder rung, streak, medical dose, coherence).
- `0x44`: `DCMD_LATCH_DUMP_GOV_EVENTS` (`__DIOTF(_DCMD_MISC, 0x44, gov_dump_req_t)`) — Forensic blackbox event ring dump (4096 entries).
- `0x45`: `DCMD_LATCH_PROBE_ABILITY` (`__DIOF(_DCMD_MISC, 0x45, uint32_t)`) — Validates client possession of `latch/actuator` ability.

#### Wire v2 Frame Layout (32 Bytes, `qnx/governor_wire.c:68–71, 100–103`)
- `[0..4)`: Magic `0x4C415448` (`LATH`)
- `[4..6)`: Version `2` (little-endian uint16)
- `[6..8)`: Joint ID (uint16)
- `[8..10)`: Kind (uint16: `0`=CMD, `1`=HEARTBEAT, `2`=CMD_V2, `3`=SHRINK_REQ)
- `[10..12)`: Sequence Number (uint16)
- `[12..16)`: Command Value / Position (`u_mrad` / `shrink_v`, int32)
- `[16..20)`: CRC-32 IEEE 802.3 over split buffer `[0..16) || [20..32)`
- `[20..24)`: Q8 Confidence Value (uint32)
- `[24..25)`: Agent State (uint8)
- `[25..28)`: Coherence Counter (uint24, advancing lease proof)
- `[28..32)`: Unit Identifier (uint32)

#### 16-Bit Fault Taxonomy (`qnx/latch_protocol.h:145–162`)
- `0x0001`: `LATCH_FAULT_MAGIC` — Invalid protocol magic.
- `0x0002`: `LATCH_FAULT_CRC` — CRC-32 integrity mismatch.
- `0x0004`: `LATCH_FAULT_SEQ` — Sequence regression or illegal jump.
- `0x0008`: `LATCH_FAULT_NAN` — Floating point NaN / Inf payload.
- `0x0010`: `LATCH_FAULT_BOUNDS` — Position outside physical limits.
- `0x0020`: `LATCH_FAULT_KEEPOUT` — Projected trajectory breaches Keep-Out safety envelope.
- `0x0040`: `LATCH_FAULT_VELOCITY` — Slew velocity limit exceeded.
- `0x0080`: `LATCH_FAULT_RATE` — Token-bucket burst acceleration / jerk violation.
- `0x0100`: `LATCH_FAULT_WATCHDOG` — 100 ms liveness lease expired.
- `0x0200`: `LATCH_FAULT_I2C` — Hardware actuator bus I/O failure.
- `0x0400`: `LATCH_FAULT_INTERNAL` — Microkernel supervisor internal inconsistency.
- `0x0800`: `LATCH_FAULT_EPERM` — Client lacks required security ability.
- `0x1000`: `LATCH_FAULT_UNIT` — Unknown or unmapped rational unit conversion.
- `0x2000`: `LATCH_FAULT_HEARTBEAT` — Coherence counter stalled or invalid Δc jump.
- `0x4000`: `LATCH_FAULT_SHRINK` — Attempted expansion of contracted safety envelope.
- `0x8000`: `LATCH_FAULT_DOSE` — Medical cumulative window or minimum bolus lockout violation.

---

## 3. Root Cause Analysis (RCA) of Prior Inaccuracies

| Issue | Prior Finding | Root Cause | Verified Correction |
|:---|:---|:---|:---|
| **Devctl Numbers** | Scrambled `0x40`/`0x41`/`0x42` | Inverted in analysis text without checking header `#define`s. | `0x40`=FORCE_HOLD, `0x41`=GET_STATUS, `0x42`=DUMP_TAPE. Verified in `latch_protocol.h`. |
| **Wire v2 Upper 12B** | Stated `shrink_v` in bytes 20..32, omitted `agent_state`. | Reading conceptual notes instead of `governor_wire.c:68-71`. | Byte 24 is `agent_state`; `shrink_v` is multiplexed in `u_mrad` (bytes 12..16). |
| **Evidence Output** | Truncated `check_governor_evidence.py` PASS log. | Truncation of qualification string. | Output explicitly warns `; QNX runtime freshness not established` (contract digests agree). |
| **`/dev/governor` Node** | Assumed proposal sink. | Misinterpreting resmgr registration in `latchd.c:2150`. | Attached using `g_actuator_attr.attr`; writes return `EPERM`. It is an administrative devctl node. |
| **Medical Lockout Time-Reversal** | Checked only forward delta: `(tick - last_tick) < interval`. | Missing check for non-monotonic tick wrap or time-reversal attack. | Fixed in `gov_gate_precheck.c:247`: `(input->tick < state->last_bolus_tick || (input->tick - state->last_bolus_tick) < min_interval)`. |
| **Ladder Semantics** | README claimed ADVISE was 10 mrad/tick. | Code actually uses ADVISE as advisory logging with full $v_{\text{max}}$. | Harmonized: ADVISE permits $v_{\text{max}}$ with strict rate tracking; 3 advisory faults demote to CLAMP. |

---

## 4. Master Checklist A–Z Cross-Verification Matrix

| Domain | Concepts & Invariants | Status | Code Anchor & Verification Evidence |
|:---|:---|:---:|:---|
| **A. Systems Engineering** | Requirements traceability, interface contracts, Simplex architecture | **PASS** | `latch_protocol.h:109-124` `_Static_assert`s; `qnx/contracts/*.manifest` signed JSON schemas. |
| **B. Computer Architecture** | AArch64 EL2 VHE, SMP affinity, memory barriers, MMIO | **PASS** | Core 0/1/2-3 affinity via `ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT)` (`latchd.c:1783`, `latch_ingest.c:99`); C11 atomics with acquire/release. |
| **C. OS Architecture** | Microkernel resource manager, ability boundaries, fault isolation | **PASS** | `resmgr_attach()` × 3; `procmgr_ability_create("latch/actuator", flags=0)`; unprivileged ingest. |
| **D. Scheduling** | Real-time determinism, FIFO scheduling, priority inversion defense | **PASS** | `SCHED_FIFO` 63; `ChannelCreatePulsePool` with `_NTO_CHF_FIXED_PRIORITY`; `ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT)` core pinning. (Note: QNX OS 8.0 does not support APS — the legacy `aps` keyword works only on QOS 2.2.x. LATCH uses none of it. QNX *sporadic* scheduling is a distinct policy and is **not** implemented here.) |
| **E. Memory Safety** | Zero heap allocation in tick path, static pre-allocated rings | **PASS** | Zero `malloc()` in the 1 kHz loop; all rings and buffers are statically allocated in `.bss` (measured `.bss` = **438,576 bytes ≈ 428 KiB** in the AArch64 QNX build — `size qnx/build/nto-aarch64-le/latchd`). `mlockall(MCL_CURRENT \| MCL_FUTURE)` is called at startup (`latchd.c:2187`) but is a **no-op on SDP 8.0** — all memory is already locked for the process lifetime — so it is **not** credited as a determinism technique. |
| **F. Concurrency** | Lockless SPSC ring, Seqlock atomics, non-blocking telemetry | **PASS** | `snapshot_gen` atomic counter fencing; devctl 0x44 dumps cannot block or delay 1 ms actuator commit. |
| **G. Interrupts & Timers** | Monotonic timer pulses, high-resolution cycles, sub-µs jitter | **PASS** | `timer_create(CLOCK_MONOTONIC)` delivering `SIGEV_PULSE`; `ClockCycles()` sub-microsecond stamping. |
| **H. IPC & Services** | Fixed-size synchronous/asynchronous IPC, strict size rejection | **PASS** | `resmgr_msgread()` rejects malformed writes with `EMSGSIZE`; black-channel console isolation. |
| **I. Device Drivers** | Hardware/virtual target abstraction, register control | **PASS** | PCA9685 12-bit PWM over `/dev/i2c1` (`DCMD_I2C_SEND`); transparent mock-mode fallback under QEMU. |
| **J. Real-Time Systems** | Control Barrier Functions (DT-CBF), latency determinism | **PASS** | 10-tick lookahead + 10-tick deceleration braking rollout (`latchd.c:398-478`); honest latency = GOVERNOR on-target observation `80,911 cyc ≈ 1.29 ms` (TCG, **not WCET**) — `docs/evidence/governor/governor-qemu-verify.txt`. ~~Old 61.08 µs vs 143 ms row~~ **REJECTED/quarantined**; no WCET claim is made. |
| **K. Fault Tolerance** | 6-rung ladder FSM, fail-closed faults, 25-frame hysteresis | **PASS** | `governor_policy.c:30-131`; 7/7 adversarial cyber-physical attacks neutralized with 0% keepout breaches. |
| **L. Safety Engineering** | FMEA-Lite, ASIL D / SIL 3 / Class C architectural alignment | **PASS** | `docs/FMEA-LITE.md` (all RPN < 100); informative alignment mapping (no false certification claims). |
| **M. Cybersecurity** | Type enforcement (`secpol`), default-deny abilities, black channel | **PASS** | `latch.secpol` compiled with `secpolcompile`; guest VM denied access to actuator devctls. |
| **N. Startup Architecture** | Minimal IFS buildfile, secpolpush at boot, deterministic order | **PASS** | `latch_qemu_governor.build`; `secpolpush` executed before any service initialization. |
| **O. Data Integrity** | Rolling SHA-256 blackbox event chain, tamper detection | **PASS** | Genesis-bound rolling hash chain; `tools/gov_replay.py --test` passes 12/12 tamper detection scenarios. |
| **P. Networking Stacks** | Airgapped serial transport, zero network attack surface | **PASS** | Target safety domain has zero network sockets or NIC drivers; point-to-point serial framing only. |
| **Q. Virtualization** | QNX Hypervisor 8.0, vCPU pinning, VM-kill containment | **PASS** | Guest VM on virtual cores 2–3; `slay -9 qvm` triggers instant fail-closed `LATCH` with 0 loop interrupts. |
| **R. Resource Engineering** | Worst-case latency profiling, tail jitter elimination | **PART** | Profiling harness exists (`ClockCycles` stamps, tape histograms), but the old "QNX 61.08 µs vs Linux 143,000 µs (2,344×)" comparison was **rejected and quarantined** (no reproducible source samples). Fresh honest baseline = update plan U11/U12; until then no comparative number is claimed. |
| **S. Energy Management** | Actuator thermal throttling, slew rate clamping | **PART** | Velocity/slew-rate clamping only (`SLOW`/`CLAMP` rungs cap velocity steps); **no thermal, DVFS, or current-sensing code exists** — energy management is honestly out of scope for the QEMU target. |
| **T. Observability** | Zero-dependency offline HTML5 Canvas console, forensic logs | **PASS** | `host/console.html` runs locally with embedded tape data; full radar, ladder, and bitmask decoders. |
| **U. Verification** | Static analysis, ASan/UBSan, fuzzing, adversarial test harness | **PASS** | `make check` (9/9), `check-governor` (14/14), `check-asan` (0 errors), `fuzz` (300/300 fail-closed). |
| **V. Toolchains** | C11 standards compliance, QNX GCC 12.2.0, reproducible flags | **PASS** | `-std=c11 -Wall -Wextra -Werror -Wpedantic -O2 -D_QNX_SOURCE`; zero compiler warnings. |
| **W. Release Engineering** | Hermetic reproducibility, SBOM, contract SHA-256 sidecars | **PASS** | Zero external pip/npm dependencies; `docs/SBOM.md` complete; all 4 manifest digests verified. |
| **X. Productization** | Generic schema-3 parameterization, zero hardcoding | **PASS** | Moving from robot arm to syringe pump requires changing only the signed JSON manifest. |
| **Y. Advanced Research** | Discrete-Time CBFs, Simplex runtime assurance, physical AI | **PASS** | Mathematical proof of forward invariance under untrusted generative AI proposals. |
| **Z. Deliverables** | PRD, SAD, ICD, FMEA, V&V, Demo Video Storyboard, Codelab | **PART** | SAD/HLD/LLD (`docs/LATCH-implementation.md`), ICD (`docs/GOVERNOR_PROTOCOL_V2.md`), FMEA-lite, V&V gates, storyboard and codelab exist; **PRD/SyRS not produced as standalone docs and the demo video is not yet filmed**. |
