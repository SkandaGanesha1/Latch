# LATCH v3.0 & GOVERNOR Implementation Architecture & Target Verification Report

**Author**: SkandaGanesha1 <skandaganesha16@gmail.com>  
**Target Environment**: QNX Neutrino RTOS 8.0.0 (`x86_64`, `aarch64le`)  
**Microkernel**: `procnto-smp-instr` (SMP Instrumented Kernel)  
**Security Model**: Microkernel Custom Ability (`latch/actuator`) with Default-Deny Policy  
**Flagship Safety Extension**: GOVERNOR Deterministic Safety Interlock & Dead Man's Switch for Physical AI  

---

## 1. End-to-End System Architecture

LATCH (**Last Authority for Trusted Control Handoff**) is a high-assurance Simplex Architecture supervisory framework engineered natively for QNX Neutrino RTOS 8.0.0. It provides mathematical and runtime safety guarantees for untrusted high-performance (HP) guest control policies operating under virtualization (e.g., Linux guest under QNX Hypervisor 8.0) or unprivileged POSIX userspace.

```text
+---------------------------------------------------------------------------------------+
|  UNTRUSTED GUEST / AGENT                                                              |
|  - Autonomous AI Policy (RL / DNN / LLM Agent / Heuristic)                            |
|  - Generates 32-byte wire frames (Protocol v2):                                       |
|    [MAGIC:4][VER:2][JOINT:1][KIND:1][SEQ:4][U:4][CRC:4][CONF:4][STATE:1][COH:3][UNIT:4]|
+---------------------------------------------------------------------------------------+
                                          |
                                          | (virtio-console / POSIX pipe)
                                          v
+---------------------------------------------------------------------------------------+
|  QNX 8.0 INGESTION BRIDGE (`latch-ingest`)                                            |
|  - Reads wire proposals from standard input                                           |
|  - Validates wire framing, kind codes (0..3), and 28-byte CRC-32                      |
|  - Performs zero-copy unbuffered writes to `/dev/latch/proposal`                      |
|  - Translates 32-byte wire v2 into 48-byte LPR2 IPC proposal structure                |
+---------------------------------------------------------------------------------------+
                                          |
                                          | (QNX Resource Manager `io_write`)
                                          v
+---------------------------------------------------------------------------------------+
|  LATCH & GOVERNOR SIMPLEX SUPERVISOR (`latchd`) - High-Criticality Domain             |
|                                                                                       |
|  +---------------------------------------------------------------------------------+  |
|  | Lockless 256-Slot Ring Buffer (`latch_ring_t`)                                  |  |
|  | - Power-of-2 indexed (`head & (N - 1)`), cache-line aligned (64-byte padding)     |  |
|  | - Single-producer (`io_write`), single-consumer (`decision_thread`)              |  |
|  | - Atomic session reset on ingest connect (`session_reset_pending`)               |  |
|  +---------------------------------------------------------------------------------+  |
|                                          |                                            |
|                                          v                                            |
|  +---------------------------------------------------------------------------------+  |
|  | 1 kHz Pulse-Driven Decision Thread (`latch_decision_thread`)                    |  |
|  | - Priority 63 (`SCHED_FIFO`), bound to dedicated safety core                     |  |
|  | - Monotonic 1 ms tick (`CLOCK_MONOTONIC`, `ChannelCreatePulsePool`)             |  |
|  | - Seqlock Protected State (`latch_seqlock_t`) with `atomic_thread_fence`        |  |
|  | - Discrete-Time Control Barrier Function (DT-CBF) Enforcer                     |  |
|  | - NIST FIPS 180-2 SHA-256 Attested Contract Manifest Integration                 |  |
|  | - GOVERNOR Precheck Gate: Rational Units, Token Bucket, Q8 Confidence Shrink   |  |
|  | - Deadman Liveness & Coherence Lease: Modulo-2^24 Bounded Forward Difference    |  |
|  | - 6-Rung Supervisory Degradation Ladder FSM (HP -> ADVISE -> CLAMP -> ...)       |  |
|  | - 4096-Entry Circular Event Ring with Rolling Tamper-Evident SHA-256 Blackbox   |  |
|  | - Fail-Closed Fallback: Tri-State Mode (HP -> HOLD -> HOME)                      |  |
|  +---------------------------------------------------------------------------------+  |
|                                          |                                            |
|                                          v                                            |
|  +---------------------------------------------------------------------------------+  |
|  | Actuator Gatekeeper (`/dev/latch/actuator`)                                     |  |
|  | - Protected by QNX Ability `procmgr_ability(PROCMGR_ADN_NONROOT, "latch/actuator")|  |
|  | - Restricts PWM / I2C physical actuation to authorized processes                 |  |
|  | - Unprivileged processes rejected with `EPERM`                                  |  |
|  +---------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------+
```

### Key Architectural Invariants
1. **Startup-Only Manifest Allocation & Zero Tick Heap Activity**: All ring buffers, state structs, and evidence tapes reside in pre-allocated `.bss` memory. `malloc` is used strictly once at process initialization inside `latch_manifest_load()` and freed before entering the tick loop; zero heap allocations occur during runtime decision ticks.
2. **Manifest Latency Budget (measured max, not a WCET)**: Pulse delivery directly unblocks the decision thread via microkernel pulse event handling (`_NTO_CHO_CUSTOM_EVENT`). Every decision tick measures its own latency and compares it against the manifest's `timing.wcet_budget_us` (100 µs in `latch.manifest`); an exceedance increments the reported `wcet_overruns` counter instead of being hidden. The measured maxima are archived per capture: the Linux host-sim's figures are in `docs/evidence/host-sim/`, and the demonstrated QEMU AArch64 `virt` session's are in `docs/evidence/derived/on-target-numbers.txt`. These are measured maxima on emulated hosts, never worst-case execution-time bounds; see the latency note in §7.1.
3. **Seqlock Consistency**: Telemetry snapshots use an atomic generation sequence guard (`snapshot_gen`). Readers (such as verification inspectors and telemetry reporters) execute optimistic lock-free retry loops without blocking the safety-critical decision loop.

---

## 2. Mathematical Formulation of Discrete-Time CBF (DT-CBF)

The safety envelope enforces kinematic invariance over the physical state space $\mathcal{X} = \{(\theta, v, a) \in \mathbb{R}^3\}$.

### 2.1 State Evolution
Given sampling period $\Delta t = 1\text{ ms}$:
$$
v_{k} = \frac{\theta_k - \theta_{k-1}}{\Delta t}, \quad a_k = \frac{v_k - v_{k-1}}{\Delta t}, \quad j_k = \frac{a_k - a_{k-1}}{\Delta t}
$$

### 2.2 Forward Invariance via Barrier Functions
Let the safe set be $\mathcal{C} = \{\theta \in \mathbb{R} \mid h(\theta) \ge 0\}$.
For a single-sided position limit $\theta_{\text{max}}$:
$$
h(\theta) = \theta_{\text{max}} - \theta
$$
Under discrete-time CBF with decay parameter $\alpha \in (0, 1]$:
$$
\Delta h(\theta_k, u_k) = h(\theta_{k+1}) - h(\theta_k) \ge -\alpha h(\theta_k)
$$
Substituting $\theta_{k+1} = \theta_k + v_k \Delta t + \frac{1}{2} u_k \Delta t^2$ guarantees that if $\theta_0 \in \mathcal{C}$, then $\theta_k \in \mathcal{C}$ for all $k \ge 0$.

### 2.3 Multi-Constraint Kinematic Clamping
At each decision tick $k$, proposal $u_k$ is accepted if and only if all the following conditions hold simultaneously:
1. **Position Bounds**: $\theta_{\text{min}} \le u_k \le \theta_{\text{max}}$
2. **Velocity Slew Limit**: $|u_k - \theta_{k-1}| \le v_{\text{max}} \Delta t$
3. **Acceleration Slew Limit**: $|(u_k - \theta_{k-1}) - (\theta_{k-1} - \theta_{k-2})| \le a_{\text{max}} \Delta t^2$
4. **Jerk Bounds**: $|a_k - a_{k-1}| \le j_{\text{max}} \Delta t$
5. **Keep-Out Interval Invariance**: For every forbidden region $[K_{\text{lo}}, K_{\text{hi}}]$, $u_k \notin (K_{\text{lo}}, K_{\text{hi}})$, and the trajectory cannot tunnel through the keep-out zone without triggering a barrier violation.

If any constraint is violated, the proposal is rejected (`veto`), the fault bitmask is updated, and the supervisor commands safe hold ($u_k = \theta_{k-1}$) or initiates a controlled, jerk-bounded return to `home_mrad`.

---

## 3. Dissection & Root-Cause Proof: Run 3 Telemetry Anomaly

### 3.1 Observed Symptom in Historical Run 3
During end-to-end telemetry streaming over a POSIX pipe, the supervisor recorded:
- Proposals received: 200
- Wire faults caught: 12 (expected injected CRC / SEQ / MAGIC corruption)
- Envelope vetoes: **76** (expected: **7**)
- Root Cause: 69 excess envelope vetoes!

### 3.2 Sequence of Events & Race Condition
1. **Unsynchronized Session Arming**: In historical revisions, `latch_io_open()` on `/dev/latch/proposal` immediately asserted:
   ```c
   g_simplex.session_active = true;
   g_simplex.last_rx_tick = g_simplex.tick;
   ```
2. **Ingest Bridge Startup Latency**:
   The ingest process (`python3 liar.py | ./latch-ingest`) opened `/dev/latch/proposal` before the first 32-byte frame was received from standard input.
3. **Watchdog Starvation**:
   The 1 kHz decision timer on `_cpu-0` fired continuously. Because `session_active == true` but no proposal was present in the ring buffer, `silent_ticks` incremented:
   $$\text{silent\_ticks} \ge W_{\text{budget}} \implies \text{FAULT\_WATCHDOG (0x0100)}$$
   The supervisor entered `LATCH_MODE_HOLD` with frozen position $\theta_{\text{applied}} = 0\text{ mrad}$.
4. **Cascading Slew Vetoes**:
   When Frame #1 finally arrived at $t \approx 10\text{ ms}$, the plant was frozen in `HOLD` at $\theta = 0$.
   Frames #2 through #25 (commanding smooth ramp from $-10$ to $-250$) were evaluated against $\theta = 0$. Because $|-20 - 0| > v_{\text{max}}$, the velocity slew check failed on every frame!
   - 24 slew vetoes on ramp
   - 7 keep-out vetoes
   - 44 slew vetoes on recovery and replay sequences
   Total: $1 + 24 + 7 + 44 = 76$ vetoes.

### 3.3 The v3.0 Mathematical & Concurrency Solution
The session lifecycle was refactored into a two-phase decoupled handshake:
1. **Phase 1: Arming**: `latch_io_open()` flushes stale ring slots and atomically sets `session_reset_pending = 1u`. `session_active` remains **FALSE**. The watchdog timer is disarmed.
2. **Phase 2: Activation on Frame #1**:
   When the first wire proposal is dequeued by `latch_simplex_tick()`:
   ```c
   if (atomic_exchange(&st->session_reset_pending, 0u) != 0u) {
       st->session_active = true;
       st->last_seq = 0;
       st->theta_mrad = g_manifest.envelope.home_mrad;
       st->v = 0;
       st->a = 0;
       st->last_rx_tick = st->tick;
       st->last_rx_cycles = cycles_in;
   }
   ```
3. **No artificial pacing in the bridge**: `latch_ingest.c` defers opening `/dev/latch/proposal` until the first valid 32-byte wire frame is read from `stdin`, and then hands each frame to the supervisor as fast as the transport delivers it. The supervisor's ring, bounded by the manifest's `ingest.queue_depth`, is the only buffer in the path.

### 3.4 Telemetry Proof
Under the new lifecycle:
- Proposals received: **200**
- Wire faults caught: **12**
- Envelope vetoes: **7** (exactly the 7 keep-out frames #26..#32)
- Unexpected rate faults: **0**
- Watchdog trips during streaming: **0**
- Max decision latency: host-load dependent — recorded per capture in `docs/evidence/host-sim/` rather than quoted here

---

## 4. GOVERNOR Subsystem Architecture

GOVERNOR extends LATCH with an industrial-grade safety supervisor, adding Wire Protocol v2, rational unit normalization, token-bucket rate shaping, a 24-bit advancing coherence lease, a 6-rung supervisory degradation ladder, and tamper-evident event ring blackbox forensics.

### 4.1 Wire Protocol v2 Ingest Pipeline & 28-Byte CRC-32 Math

The wire transport exchanges strictly packed 32-byte frames (`gov_wire_frame_t`).

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic: 0x4C415448                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Version (2)          |   Joint (0)   |   Kind (0..3) |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (seq)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Signed Payload u_mrad / shrink_v_max               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      IEEE 802.3 CRC-32                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Confidence Q8 (confidence_q8)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Agent State  |           Coherence Counter (24-bit)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Unit ID (unit_id)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### CRC-32 Split-Buffer Calculation
The CRC field covers all payload bytes except the checksum itself:
$$\text{CRC Coverage} = \text{Frame}[0..16) \mathbin{\Vert} \text{Frame}[20..32) \quad (\text{exactly } 28 \text{ bytes})$$
Calculated using the IEEE 802.3 reflected polynomial ($0xEDB88320$), initialized to $0xFFFFFFFF$ and final XOR $0xFFFFFFFF$:
```c
uint32_t expected_crc = latch_crc32_buf(0xFFFFFFFFu, (const uint8_t *)frame, 16u);
expected_crc = latch_crc32_buf(expected_crc, (const uint8_t *)frame + 20u, 12u) ^ 0xFFFFFFFFu;
```

#### Frame Kind Codes
- `0 = CMD`: Legacy command proposal (treated as unit_id=0).
- `1 = HEARTBEAT`: Deadman liveness lease renewal; carries zero payload; plant must not move.
- `2 = CMD_V2`: Version 2 motion command with explicit `unit_id`, `confidence_q8`, and `agent_state`.
- `3 = SHRINK_REQ`: AI dynamic envelope tightening request ($v_{\text{max}}' \le v_{\text{max}}$).

### 4.2 Precheck Gate Mathematical Formulation

#### 1. Rational Unit Normalization Arithmetic
To eliminate non-deterministic floating-point conversions inside the safety microkernel, GOVERNOR implements 64-bit integer rational normalization:
$$
u_{\text{canonical}} = \frac{u_{\text{raw}} \cdot N_i}{D_i}
$$
where $(N_i, D_i)$ is declared in the signed manifest's `governor.units` dictionary. If `unit_id` is unknown or undeclared, the proposal is rejected fail-closed with `LATCH_FAULT_UNIT` (bit 12, `0x1000`).

The two signed contracts declare these exact rationals — all conversion is exact 64-bit integer arithmetic, and a non-integral remainder, a zero denominator, or an overflow is rejected fail-closed with `LATCH_FAULT_UNIT` (proven by `gov_gate_precheck_test.c`: raw `100` under the servo's `1/57` scale has a remainder and is rejected; raw `37000` under `1/1000` converts to exactly `37`):

| Contract | `unit_id=1` (canonical) | `unit_id=2` | `unit_id=3` |
|---|---|---|---|
| `governor_servo.manifest` | `mrad` | ×1/57 — milli-degree-scale raw → `mrad` (1 mrad = 57.2958 mdeg; `57` is the declared integer stand-in) | ×1/1000 — µrad-scale raw → `mrad` (attack A1 phase 4: `37000 → 37`) |
| `syringe_governor.manifest` | `µL` | ×1000/1 — mL-scale raw → `µL` (raw `50` → `50000`) | ×1/1000 — nL-scale raw → `µL` |

Every ratio lives only in the signed manifest: no unit conversion factor is a C literal, and the command's magnitude is never used to guess a unit.

#### 2. Token-Bucket Rate Burst Smoother
To defend against velocity flood attacks ($A2$), the precheck gate maintains a discrete leaky token bucket:
$$
b_k = \min\left(B_{\max}, \; b_{k-1} + r \cdot \Delta t\right)
$$
$$
\text{Cost} = |u_k - \theta_{k-1}|
$$
If $\text{Cost} > b_k$, the burst exceeds available tokens. The proposal is clamped to $v_{\text{max}}$ and flags `LATCH_FAULT_RATE` (bit 7, `0x0080`).

#### 3. Confidence Contraction (Q8 Arithmetic)
When an agent reports lower certainty ($c_{Q8} < 255$), the precheck floors the reported value at the contract's `ladder.min_confidence_q8` (128 in both signed contracts — the historical Q8 half-scale floor; the key is required, range 1–255) and contracts the *motion* envelope:
$$
\text{scale} = \frac{\max(c_{Q8},\ \text{min\_confidence\_q8})}{256}
$$
$$
v_{\text{effective}} = \lfloor v_{\text{max}} \cdot \text{scale} \rfloor, \quad a_{\text{effective}} = \lfloor a_{\text{max}} \cdot \text{scale} \rfloor
$$
Maximum slew velocity and acceleration limits contract proportionally; an active `SHRINK_REQ` takes the minimum of its own value and the confidence-scaled value. **Keep-out intervals do not move** — they stay at their signed manifest bounds and are re-validated against every applied step, so a low-confidence proposal can never tunnel through them.

#### 4. Cumulative DOSE Limit Check (Medical Syringe Mode)
In infusion contracts, precheck computes the delivered volume step $\Delta V$:
If $\Delta V > \text{rung\_max\_step}$, `LATCH_FAULT_DOSE` (bit 15, `0x8000`) is asserted, preventing dangerous bolus over-infusion.

### 4.3 Modulo-$2^{24}$ Bounded Forward Difference Coherence Engine

To detect frozen control loops, infinite agent spins, and clock glitches, the deadman lease is governed by an advancing 24-bit counter $c_k \in [0, 2^{24}-1]$:
$$
\Delta c = (c_k - c_{k-1}) \pmod{2^{24}} = (c_k - c_{k-1}) \mathbin{\&} \text{0x00FFFFFF}
$$

**Lease Renewal Rules**:
1. **Admissible Advance**: $1 \le \Delta c \le \text{coherence\_max\_gap}$ (default 3). The lease timer is reloaded to `lease_ticks` (100 ms).
2. **Frozen Counter**: $\Delta c = 0$. Indicates stalled computation; lease is **NOT** renewed; trips `LATCH_FAULT_HEARTBEAT` (bit 13, `0x2000`).
3. **Discontinuous Jump**: $\Delta c > \text{coherence\_max\_gap}$. Counter desynchronization; lease is **NOT** renewed; trips `LATCH_FAULT_HEARTBEAT`.

### 4.4 6-Rung Degradation Ladder & 25-Frame Hysteresis Recovery FSM

The supervisor executes a deterministic 6-rung finite state machine:

| Rung | Name | Motion Authority | Velocity Bound | Fault/Lease Transition |
|---|---|---|---|---|
| **0** | `HP` (High Performance) | Full AI Proposal Authority | $v_{\text{applied}} \le v_{\text{max}}$ | Trips down to `ADVISE` on lease expiry or advisory fault |
| **1** | `ADVISE` | AI Proposals Subject to Strict Rate Clamps | $v_{\text{applied}} \le v_{\text{advise}}$ | Demotes to `CLAMP` after 3 consecutive faults or lease expiry |
| **2** | `CLAMP` | Actuator Step Clamped to Minimal Slew | $v_{\text{applied}} \le \text{clamp\_step}$ | Demotes to `SLOW` on repeated lease expiry |
| **3** | `SLOW` | Limp-Home Velocity Clamping | $v_{\text{applied}} \le 0.2 \cdot v_{\text{max}}$ | Demotes to `SAFE_STOP` on lease expiry |
| **4** | `SAFE_STOP` | AI Authority Revoked; Actuator Slew to Decelerate | $v_{\text{applied}} \to 0$ | Demotes to `LATCH` on lease expiry |
| **5** | `LATCH` | Software Interlock / Fail-Closed `HOLD` (mock I²C on the QEMU take — no physical actuation there) | Zero Movement ($v = 0$) | Operator Release Required (`latchctl hold 0`) |

#### Hysteresis & Recovery Invariants
- **Heartbeat Chatter Non-Recovery**: Heartbeat-only frames (`kind=1`) renew the liveness lease, but **explicitly reset** `clean_command_streak = 0`. An agent cannot regain authority simply by repeating health pings.
- **25-Frame Clean Command Recovery**: Promotion from a demoted rung up one level requires exactly $N = 25$ (`promote_clean_frames`) consecutive clean, valid, coherent motion proposals (`kind=2`). Any fault, CRC error, or sequence drop immediately resets the streak to 0.

---

## 5. Versioned Extension Devctls

GOVERNOR extends the native QNX resource manager interface with out-of-band diagnostic and forensic devctls while keeping legacy devctls byte-for-byte backward compatible.

### 5.1 `DCMD_LATCH_GET_GOV_STATUS` (0x43)

Queries real-time supervisory status, lease counters, rate tokens, and degradation rungs.

#### Binary Layout (228 Bytes)
```text
+---------------------------------------------------------------------------------------+
|  Legacy latch_status_reply_t (Bytes 0 .. 167)                                         |
|  - uint64_t tick, uint64_t cycles, uint32_t seq, int32_t theta, int32_t v, int32_t a  |
|  - uint16_t active_faults, uint16_t latched_faults, uint8_t mode, uint8_t reserved     |
|  - uint32_t telemetry counters (proposals, wire, env, eperm, drops, wcet, backlog)    |
|  - uint8_t  manifest_sha256[32]                                                       |
+---------------------------------------------------------------------------------------+
|  GOVERNOR Extension Payload (Bytes 168 .. 231)                                        |
|  - uint32_t extension_version        (Offset 168: ABI version = 3)                     |
|  - uint32_t enabled                  (Offset 172: 1 if governor active, 0 if disabled) |
|  - uint32_t rung                     (Offset 176: Active rung 0..5)                    |
|  - uint32_t v2_session               (Offset 180: 1 if v2 protocol active)             |
|  - uint32_t lease_ticks_remaining    (Offset 184: Remaining lease window ticks)        |
|  - uint32_t lease_age_ticks          (Offset 188: Ticks since last advancing renewal)  |
|  - uint32_t warmup_heartbeats_seen   (Offset 192: Count of valid warmup pings)         |
|  - uint32_t agent_state              (Offset 196: Reported agent status 0..4)          |
|  - uint32_t rate_tokens_remaining    (Offset 200: Token bucket fill level)             |
|  - uint32_t shrink_active            (Offset 204: 1 if dynamic envelope tightened)     |
|  - uint32_t shrink_v_max             (Offset 208: Active shrunk velocity limit)        |
|  - uint32_t shrink_scale_q8          (Offset 212: Active shrink scale 0..255)          |
|  - uint32_t coherence_ctr            (Offset 216: Last valid 24-bit coherence counter) |
|  - uint32_t coherence_valid          (Offset 220: 1 if coherence sequence healthy)     |
|  - uint32_t clean_command_streak     (Offset 224: Streak towards next promotion 0..25) |
|  - uint32_t deadline_misses          (Offset 228: Tick deadline overrun count)         |
+---------------------------------------------------------------------------------------+
```

### 5.2 `DCMD_LATCH_DUMP_GOV_EVENTS` (0x44)

Retrieves historical event telemetry from the 4096-entry circular buffer in `.bss` memory.

#### Data Structures
```c
typedef struct __attribute__((packed)) latch_gov_event {
    uint64_t event_index;          /* Monotonic global event index */
    uint64_t tick;                 /* Supervisor 1 kHz tick */
    uint64_t cycles;               /* Sub-microsecond ClockCycles timestamp */
    uint32_t seq;                  /* Proposal sequence number */
    int32_t  raw_u_mrad;           /* Unscaled proposal from wire */
    int32_t  normalized_u_mrad;    /* Canonicalized proposal */
    int32_t  theta_applied_mrad;   /* Final actuator command issued */
    uint32_t unit_id;              /* Manifest rational unit ID */
    uint32_t coherence_ctr;        /* 24-bit coherence counter */
    uint32_t lease_remaining;      /* Ticks remaining in lease */
    uint16_t fault_bits;           /* Instantaneous microkernel fault mask */
    uint8_t  mode;                 /* Simplex mode (HP, HOLD, HOME) */
    uint8_t  rung_before;          /* Ladder rung before evaluation */
    uint8_t  rung_after;           /* Ladder rung after evaluation */
    uint8_t  kind;                 /* Wire v2 frame kind (0..3) */
    uint8_t  verdict;              /* Decision verdict (ACCEPT, CLAMP, VETO) */
    uint8_t  agent_state;          /* Agent state reported in frame */
    uint8_t  confidence_q8;        /* Scaled confidence value */
    uint8_t  coherence_valid;      /* Coherence continuity boolean */
} latch_gov_event_t;
_Static_assert(sizeof(latch_gov_event_t) == 62u, "Packed event record must be 62 bytes");
```

#### Tamper-Evident SHA-256 Rolling Hash Chain
Each event emitted into the blackbox is linked into a cryptographic hash chain:
$$
H_0 = \text{SHA-256}(\text{manifest\_sha256})
$$
$$
H_k = \text{SHA-256}\left(H_{k-1} \mathbin{\Vert} \text{EventBytes}_k\right)
$$
Any post-incident tampering (event deletion, modification of actuator angles, or reordering) breaks the rolling hash chain. Offline verification via `gov_replay.py` instantly pinpoints the exact compromised record index.

---

## 6. Multi-Plant Contracts: Servo Gripper vs. Syringe Pump

LATCH enforces strict zero-hardcoding. All parameters, constraints, and hardware calibrations are loaded from signed, SHA-256 attested JSON manifests.

| Architectural Parameter | Robotic Servo (`qnx/latch.manifest`) | Syringe Infusion Pump (`qnx/contracts/syringe_pump_bolus.manifest`) |
| :--- | :--- | :--- |
| **Domain Type** | Angular (`mrad`, symmetric `[-1000, +1000]`) | Linear (`mm` scaled units, unidirectional `[0, 5000]`) |
| **$\theta_{\text{min}} \dots \theta_{\text{max}}$** | `-1000 .. +1000` mrad | `0 .. 5000` (axis unit `mm`) |
| **Home Position** | `0` mrad | `0` (fully retracted) |
| **Max Velocity ($v_{\text{max}}$)** | `25` mrad/tick | `20` units/tick |
| **Max Acceleration ($a_{\text{max}}$)** | `10` mrad/tick² | `10` units/tick² |
| **Max Jerk ($j_{\text{max}}$)** | `20` mrad/tick³ | `15` units/tick³ |
| **Forbidden Keep-Out** | `[+250, +650]` (`PERSON`) | `[+4200, +5000]` (`ENDSTOP_BUFFER`) |
| **Actuator Hardware** | PCA9685 PWM (`0x40`, `50 Hz`, `205..410` counts) | PCA9685 PWM (`0x40`, `50 Hz`, `205..410` counts) |
| **Watchdog Budget** | `2` ticks (`2 ms` at `1000 us` period) | `2` ticks (`2 ms` at `1000 us` period) |
| **Attestation Hash** | `1a8e10234f8aabbdfe1ce2d5a8b67459e0c9d0cf386963e9deed8ebd5d27f823` | `a9d877ebf63d5670006593ac8eadc7303b324c52c1d30e29aeacb8b9253e0e5e` |

Both contracts validate with 100% cryptographic integrity using native NIST FIPS 180-2 SHA-256 sidecars.

---

## 7. Target Validation & Build Architecture

Validation across host simulation and QNX target environments:

### 7.1 x86_64 QNX SDP 8.0 Target VM (`qnxqemu`)
- **Kernel**: `procnto-smp-instr` x86_64
- **Safety Invariant 1 (Ability Gatekeeper)**: `./latchctl grant-check` (`open(..., O_RDONLY)` + `DCMD_LATCH_PROBE_ABILITY`) returns exit code 2 (`EPERM`) when invoked without custom `latch/actuator` ability.
- **Safety Invariant 2 (NIST SHA-256 Attestation)**: Sidecar validation confirms exact manifest match. Modifying 1 byte or supplying a stripped manifest triggers immediate fail-closed abort (`EXIT_FAILURE`).
- **Safety Invariant 3 (DT-CBF Boundary Invariance)**: Ingesting 200 verification frames results in 0 keep-out breaches ($[250, 650]$). 12 corrupted frames rejected cleanly.
- **Safety Invariant 4 (Decoupled Session Handshake & EOF)**: Zero premature watchdog trips (`7` keep-out vetoes); writer disconnect completes controlled `WATCHDOG -> HOLD -> HA-HOME` retraction before freezing the tape.
- **Safety Invariant 5 (Decision Timing)**: Every decision tick measures its own latency and reports it; a measured maximum is archived per capture, and it is a measurement on an emulated host, never a worst-case execution-time bound. The archived figures are `docs/evidence/host-sim/` (the Linux host-sim) and `docs/evidence/derived/on-target-numbers.txt` (the demonstrated QEMU AArch64 `virt` session, §7.3).

### 7.2 ARM64 Raspberry Pi 4 Model B (`latch_rpi4.build`)
- **Kernel**: `procnto-smp-instr` aarch64le
- **I2C Actuation**: `/dev/i2c1` via `i2c-bcm2711 -p0xfe804000 -i149 --b400000 --u1` (`GIC_SPI 117 + 32 = IRQ 149`)
- **Hypervisor Support**: `/lib/dll/qvm` packaged into `/proc/boot` with `latch.qvmconf` (`gicd 0xff841000`, `gicc 0xff842000`; QEMU virt uses `latch_qemu_virt.qvmconf` with `0x08000000`, `0x08010000`).
- **Real-Time Actuator Safety**: Fail-closed exit if PCA9685 fails initialization while `actuator.required == true`.

### 7.3 QEMU AArch64 `virt` — the demonstrated target

This is the target the submission demonstrates on, and the only one with a committed evidence trail.

| Property | Value |
|---|---|
| Guest OS | Linux 6.12 (AArch64), freestanding static `/init`, no libc/shell/Python |
| Host | QNX Neutrino RTOS 8.0 (`procnto-smp-instr`) + QNX Hypervisor 8.0 (`qvm`), EL2 VHE |
| Machine | QEMU `virt`, 4x Cortex-A76, GICv2 (`0x08000000`/`0x08010000`), 62.5 MHz architectural timer |
| Accel | **TCG** (the host is x86_64, so there is no KVM for AArch64) |
| Actuation | `latchd -n` — **mock I²C**. There is no PCA9685 on this machine and **the horn does not move**. |
| Guest suite | 84 frames · 12 wire faults · 7 envelope vetoes · 0 ring drops · last accepted seq 80 · latched `0x01AE` |
| Verification | `[1/5]`…`[5c/5]` all PASS, `VERIFY_RC=0` |
| Evidence | `docs/evidence/` — every run's raw console, with an index and a run-output manifest |

The full on-target evidence is archived in `docs/evidence/`, indexed by `docs/evidence/README.md`. The canonical artefact is `docs/evidence/on-target/CURRENT-SESSION.txt`; the defect record is in `docs/evidence/resolution/SUMMARY.md`.

**Note on the latency figures.** The archived timing evidence is from the QEMU AArch64 `virt` session of §7.3 (the Linux host-sim's figures are in `docs/evidence/host-sim/`). The AArch64 `virt` figures are measured under **TCG** — software emulation of AArch64 on an x86_64 host — and are therefore *not* a WCET. The project reports the **last** and the **max** decision latency, in cycles and in nanoseconds, against the manifest's `timing.wcet_budget_us`, and names the machine. On the archived AArch64 `virt` session the **last** decision latency was **64 cycles (1,024 ns)** and the **max** was **40,323 cycles (645,168 ns)**; the authoritative copy is `docs/evidence/derived/on-target-numbers.txt`, which names the session it was derived from.
