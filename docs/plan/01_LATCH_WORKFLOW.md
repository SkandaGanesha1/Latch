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

#### Devctl Command Numbers (`qnx/latch_protocol.h:536–551, 622–623`)
Re-derived from the header on 2026-11-25; the previous revision of this table
stopped at `0x45` and named two of the payloads incorrectly.

- `0x40`: `DCMD_LATCH_FORCE_HOLD` (`__DIOT(_DCMD_MISC, 0x40, latch_force_hold_cmd_t)`) — Operator emergency hold/release command, 8 bytes (`lock_hold`, `reason_code`). Requires the `latch/actuator` ability.
- `0x41`: `DCMD_LATCH_GET_STATUS` (`__DIOF(_DCMD_MISC, 0x41, latch_status_reply_t)`) — Legacy status reply (byte-for-byte unchanged since v1).
- `0x42`: `DCMD_LATCH_DUMP_TAPE` (`__DIOTF(_DCMD_MISC, 0x42, latch_tape_dump_t)`) — Evidence tape ring dump; the cursor is 64-bit.
- `0x43`: `DCMD_LATCH_GET_GOV_STATUS` (`__DIOF(_DCMD_MISC, 0x43, latch_governor_status_reply_t)`) — Versioned GOVERNOR status (`extension_version` 6): ladder rung, streaks, lease owner, session epoch, HOMEOSTAT scale.
- `0x44`: `DCMD_LATCH_DUMP_GOV_EVENTS` (`__DIOTF(_DCMD_MISC, 0x44, latch_gov_event_dump_t)`) — Forensic blackbox event ring dump (4096 entries).
- `0x45`: `DCMD_LATCH_PROBE_ABILITY` (`__DION(_DCMD_MISC, 0x45)`) — Read-only probe of the caller's `latch/actuator` ability. It carries **no** payload and returns no data; it answers only "may this client mutate the actuator?".
- `0x46`: `DCMD_LATCH_GET_HOLD_STATUS` (`__DIOF(_DCMD_MISC, 0x46, latch_hold_status_t)`) — Operator-release acknowledgement (L-5): whether a release was deferred or armed. Output-only.
- `0x47`: `DCMD_LATCH_GET_SESSION_STATUS` (`__DIOF(_DCMD_MISC, 0x47, latch_session_status_t)`) — Writer-session handoff status (L-2): whether the exclusive proposal writer OCB is held, and the writer-session generation. Output-only; grants no authority.

`0x45` is declared at the end of the header rather than in the devctl block.
That is a source-order quirk, not a second numbering scheme: the numbers are
still unique and contiguous over `0x40..0x47`.

#### Wire v2 Frame Layout (32 Bytes, `qnx/governor_wire.c:61–71`)
Re-derived from the parser on 2026-11-25. The previous revision of this table
was wrong about four fields (it showed the joint ID, kind and sequence as
16-bit quantities at the wrong offsets).

- `[0..4)`: Magic `0x4C415448` (`LATH`), uint32 little-endian
- `[4..6)`: Version `2`, uint16 little-endian
- `[6]`: Joint ID, uint8 (must be the default joint `0`)
- `[7]`: Kind, uint8 (`0`=CMD, `1`=HEARTBEAT, `2`=CMD_V2, `3`=SHRINK_REQ)
- `[8..12)`: Sequence Number, uint32 little-endian
- `[12..16)`: Command Value / Position (`u_mrad`, or `shrink_v` for kind 3), int32 little-endian
- `[16..20)`: CRC-32 IEEE 802.3 over the split buffer `[0..16) || [20..32)`
- `[20..24)`: Q8 Confidence Value, uint32 (must be `<= 255`)
- `[24]`: Agent State, uint8 (`0`=BOOT … `4`; must be `<= 4`)
- `[25..28)`: Coherence Counter, 24-bit little-endian (the high byte is implicit zero)
- `[28..32)`: Unit Identifier, uint32

The CRC covers 28 bytes, skipping the 4 CRC bytes themselves. `shrink_v` and
`shrink_scale_q8` are **multiplexed** into `u_mrad` and `confidence_q8` for
kind 3 — they are not separate wire fields.

#### LPR2 Internal IPC Proposal (56 Bytes, `qnx/latch_protocol.h:210–286`)
The 32-byte wire frame above is what crosses the virtio-console boundary. The
`latch-ingest` → `latchd` message is a different, larger ABI
(`latch_ipc_proposal_v2_t`, magic `0x4C505232` "LPR2"), whose size and field
offsets are pinned by `_Static_assert`s:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 4 | `ipc_magic` |
| 4 | 4 | `seq` |
| 8 | 4 | `u_mrad` |
| 12 | 2 | `wire_flags` |
| 14 | 2 | `pre_fault_bits` |
| 16 | 8 | `ingest_cycles` |
| 24 | 2 | `ipc_version` |
| 26 | 1 | `wire_version` |
| 27 | 1 | `kind` |
| 28 | 1 | `confidence_q8` |
| 29 | 1 | `agent_state` |
| 30 | 2 | `producer_tag` (L-2; `0` is reserved and rejected) |
| 32 | 4 | `coherence_ctr` |
| 36 | 4 | `shrink_v` |
| 40 | 4 | `shrink_scale_q8` |
| 44 | 4 | `unit_id` |
| 48 | 4 | `session_epoch` (RT-02; `0` is reserved and rejected) |
| 52 | 4 | `reserved1` (must be `0`) |

The legacy LPRP v1 message remains 24 bytes. `latchd` accepts **exactly** 24
bytes with the LPRP magic or **exactly** 56 bytes with the LPR2 magic; every
other length, magic or version pair is rejected at the IPC boundary.

#### 16-Bit Fault Taxonomy (`qnx/latch_protocol.h:146–163`)
Re-derived from the header on 2026-11-25. The previous revision of this table
was wrong about six bits: it had no `RESERVED` bit, it had no `OPERATOR` bit,
it had no `WIDEN` bit, and it mislabelled `0x0040`, `0x0400` and `0x4000`
(which are `BOUNDS`, `OPERATOR` and `WIDEN`, not `VELOCITY`, `INTERNAL` and
`SHRINK`).

- `0x0001`: `LATCH_FAULT_MAGIC` — Bad magic, version, or joint.
- `0x0002`: `LATCH_FAULT_CRC` — IEEE 802.3 CRC-32 mismatch.
- `0x0004`: `LATCH_FAULT_SEQ` — Sequence gap or replay. **Also carries the RT-02 session-epoch rejection** (a frame naming another session, or an unscoped frame).
- `0x0008`: `LATCH_FAULT_NAN` — `u_mrad == INT32_MIN` (the NaN sentinel).
- `0x0010`: `LATCH_FAULT_RESERVED` — Non-zero reserved bytes or out-of-range metadata.
- `0x0020`: `LATCH_FAULT_KEEPOUT` — Enters or crosses the keep-out interval.
- `0x0040`: `LATCH_FAULT_BOUNDS` — Outside the manifest envelope stops.
- `0x0080`: `LATCH_FAULT_RATE` — Exceeds `v_max` / `a_max` / `j_max`.
- `0x0100`: `LATCH_FAULT_WATCHDOG` — Silent past `watchdog_ticks`.
- `0x0200`: `LATCH_FAULT_I2C` — PCA9685 I²C transfer error.
- `0x0400`: `LATCH_FAULT_OPERATOR` — Operator GPIO / devctl HOLD.
- `0x0800`: `LATCH_FAULT_EPERM` — Unauthorized actuator devctl.
- `0x1000`: `LATCH_FAULT_UNIT` — Unknown or invalid unit metadata.
- `0x2000`: `LATCH_FAULT_HEARTBEAT` — Guest lease / coherence fault.
- `0x4000`: `LATCH_FAULT_WIDEN` — Guest requested wider limits.
- `0x8000`: `LATCH_FAULT_DOSE` — Dose rate exceeds the ladder-rung limit or the envelope. Alias: `LATCH_FAULT_CONSIST`.

Two masks partition the taxonomy for the supervisor's own use:

- `LATCH_FAULT_WIRE_MASK` = `MAGIC | CRC | SEQ | NAN | RESERVED` — faults the ingest bridge can detect on the wire; they suppress the payload before it is forwarded.
- `LATCH_FAULT_ENVELOPE_MASK` = `KEEPOUT | BOUNDS | RATE` — faults the envelope gate raises.

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
| **J. Real-Time Systems** | Control Barrier Functions (DT-CBF), latency determinism | **PASS** | 10-tick lookahead + 10-tick deceleration braking rollout (`latchd.c:398-478`); honest latency = GOVERNOR on-target observation `80,911 cyc ≈ 1.29 ms` (TCG, **not WCET**) — `docs/evidence/governor/governor-status-transition.txt` (the file that carries the `Decision Latency` line; `governor-qemu-verify.txt` carries the *verify* transcript, not the latency), plus the **U-4 decision-latency DISTRIBUTION** — the supervisor's own per-tick decision latency, sampled once per tick for >10⁶ ticks and aggregated in a histogram on the target — in `docs/evidence/governor/LATENCY.md` (also **not a WCET**: its percentiles are bucket ranges and its maxima are the host's TCG noise). ~~Old 61.08 µs vs 143 ms row~~ **REJECTED/quarantined**; no WCET claim is made. |
| **K. Fault Tolerance** | 6-rung ladder FSM, fail-closed faults, 25-frame hysteresis | **PASS** | `governor_policy.c:30-131`; every adversarial cyber-physical attack neutralized with 0% keepout breaches (the scorecard is regenerated by `tools/governor_metrics.py`; the tick and attack counts live in `docs/evidence/governor/governor-metrics.txt`, not in this table). |
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
