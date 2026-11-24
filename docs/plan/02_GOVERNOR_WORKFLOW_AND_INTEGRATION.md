# 02 — GOVERNOR & HOMEOSTAT Workflow, Zero-Regression Integration, LLM Agent Loop & Ashby Ultrastability Engine

**Generated:** 2026-11-23  
**Status:** Validated Technical Architecture & Integration Blueprint  
**Target Platform:** QNX SDP 8.0 (`procnto-smp-instr`) + QNX Hypervisor 8.0 (QEMU AArch64 & Raspberry Pi 4B)  
**Safety Invariant:** Zero Keep-Out Breaches Across All Operating Modes.

---

## 1. Executive Summary

GOVERNOR extends the LATCH runtime assurance supervisor with an industrial-grade, 6-rung supervisory degradation ladder and multi-gate precheck pipeline. It bridges untrusted physical AI planning with real-time physical control without compromising microkernel guarantees. 

**HOMEOSTAT** adds a cybernetic outer loop grounded in W. Ross Ashby’s 1948 mathematical ultrastability formulation, dynamically adapting safety envelopes in response to system stress, jitter, and rejection rates while strictly adhering to the zero-regression principle. **Status: implemented, wired into the supervisor, default-off, and proved by a runtime test — see §3.**

---

## 2. The 6-Rung Degradation Ladder FSM

```
                          ┌────────────────────────┐
                          │   Untrusted AI Guest   │
                          │   (Linux 6.12 / LLM)   │
                          └───────────┬────────────┘
                                      │ Proposes u_cand
                                      ▼
                        ┌───────────────────────────┐
                        │    HOMEOSTAT ADVISOR      │
                        │ (Ultrastable Outer Loop)  │
                        │ Tracks (per epoch):       │
                        │  - Rejection ratio R_rej  │
                        │  - Clamp fraction C_clamp │
                        │  - Latency spread Δt      │
                        │  - Coherence anomalies    │
                        │ Outputs:                  │
                        │  - S ∈ [floor_q8, 256] Q8 │
                        │  - Contracting v_max ceil │
                        │  (default-off; contract- │
                        │   only, never widens)    │
                        └─────────────┬─────────────┘
                                      │ Clamped Envelopes
                                      ▼
                        ┌───────────────────────────┐
                        │      GOVERNOR GATE        │
                        │ (Deterministic Microkernel│
                        │  Simplex DT-CBF Loop)     │
                        │ Checks:                   │
                        │  - Token Bucket           │
                        │  - Lookahead CBF          │
                        │  - Keepout & Bounds       │
                        └─────────────┬─────────────┘
                                      │ Fail-Closed Actuation
                                      ▼
                        ┌───────────────────────────┐
                        │ Physical Actuator/PCA9685 │
                        └───────────────────────────┘
```

| Rung | Name | Actuator Authority | Velocity Bound ($v_{\text{applied}}$) | Demotion Triggers | Recovery Rule (Hysteresis) |
|:---:|:---|:---|:---|:---|:---|
| **0** | **`HP`** | Full autonomous AI control | $v \le v_{\text{max}}$ (25 mrad/tick) | Lease expiry ($> 100\text{ ms}$) or advisory fault | Top rung; nominal operating state |
| **1** | **`ADVISE`** | Proposals admitted with rate tracking | $v \le v_{\text{max}}$ (25 mrad/tick) burst | 3 consecutive advisory faults or lease expiry | 25 consecutive clean commands promote to `HP` |
| **2** | **`CLAMP`** | Clamped to safe step threshold | $v \le \text{clamp\_max\_step}$ (5 mrad/tick) | Lease expiry ($> 100\text{ ms}$) | 25 consecutive clean commands promote to `ADVISE` |
| **3** | **`SLOW`** | Limp-home safety crawl | $v \le \text{clamp\_max\_step} \cdot \text{slow\_scale\_pct} = 1$ mrad/tick | Lease expiry ($> 100\text{ ms}$) | 25 consecutive clean commands promote to `CLAMP` |
| **4** | **`SAFE_STOP`**| AI control revoked; controlled stop | Decelerating slew ($v \to 0$) | Lease expiry ($> 100\text{ ms}$) | 25 consecutive clean commands promote to `SLOW` |
| **5** | **`LATCH`** | Fail-closed `HOLD` interlock | Complete freeze ($v = 0$) | Terminal state on channel silence | Operator release required (`latchctl hold 0`) |

### Key Degradation Invariants
- **Heartbeat Chatter Non-Recovery**: Heartbeat frames (`kind=1`) renew the liveness lease, but **explicitly reset** `clean_command_streak = 0`. An AI agent cannot regain motion authority by spamming health checks.
- **25-Frame Bounded Hysteresis**: Restoring authority up one rung requires strictly 25 (`promote_clean_frames`) consecutive clean, valid, coherent motion proposals (`kind=2`). Any fault resets the streak to 0.
- **Fail-Closed Medical DOSE Clamping**: Over-infusion proposals or rapid bolus attempts violating `min_bolus_interval_ticks` assert `LATCH_FAULT_DOSE` and clamp velocity to zero immediately. Includes time-reversal protection against non-monotonic tick wrapping.

---

## 3. HOMEOSTAT Cybernetic Ultrastability Engine

> **Implementation status (2026-11-24): SHIPPED AND WIRED IN.**
> The engine below is implemented in `qnx/gov_homeostat.c` / `qnx/gov_homeostat.h`
> (109 lines), wired into the supervisor in `qnx/latchd.c`, applied as an
> additional velocity ceiling in `qnx/gov_gate_precheck.c`, configured by an
> **optional, default-off** schema-3 `homeostat` manifest section parsed by
> `qnx/latch_manifest.c`, and proved by `qnx/gov_homeostat_test.c` plus the
> runtime test `tools/homeostat_e2e.py`. The signed contract that exercises it
> is `qnx/contracts/homeostat_servo.manifest` (with its `.sha256` sidecar).
> Every other signed contract carries **no** `homeostat` section, so the loop
> is inert everywhere else and the archived host-sim evidence signature is
> unchanged (`make -C qnx evidence-check` proves this).

### 3.1 Ashby's Ultrastability Formulation
W. Ross Ashby (1948) proved that an ultrastable system maintains essential variables within viable limits by automatically modifying its own internal parameters when external disturbances or unmodeled behaviors push variables beyond physiological bounds.

In physical AI systems, the AI model generates non-deterministic trajectory distributions. Under environmental stress, sensor noise, or prompt degradation, the AI's proposal error rate surges. HOMEOSTAT implements Ashby's ultrastable feedback loop inside the QNX supervisor process.

### 3.2 The Four Essential Variables ($E_v$) — as implemented

The implementation uses **fixed-length epoch aggregates**, not exponential moving
averages. All arithmetic is bounded 64-bit integer; there is no floating point,
no heap and no I/O in the loop.

Each epoch spans `homeostat.epoch_ticks` supervisor ticks and accumulates four
Essential Variables:

1. **Proposal Rejection Ratio ($R_{\text{rej}}$)** — Q8 fixed point:
   $$R_{\text{rej}} = \left\lfloor \frac{\text{rejected} \cdot 256}{\text{proposals}} \right\rfloor$$
   Only *motion* proposals count. A heartbeat or a shrink request carries no
   motion, so counting the supervisor's own liveness traffic as a rejection
   would manufacture stress out of nothing.
2. **Clamp Fraction ($C_{\text{clamp}}$)** — the share of requested motion that
   was **not** applied, in Q8:
   $$C_{\text{clamp}} = \left\lfloor \frac{\text{proposed\_motion} - \text{applied\_motion}}{\text{proposed\_motion}} \cdot 256 \right\rfloor$$
3. **Latency Spread ($\Delta t$)** — the difference between the maximum and the
   minimum decision latency observed inside the epoch, in nanoseconds:
   $$\Delta t = t_{\max} - t_{\min}$$
4. **Coherence Anomalies ($A_{\text{coh}}$)** — the count of frames whose
   24-bit guest coherence counter did not advance within
   `governor.deadman.coherence_max_gap`.

### 3.3 Generic, Non-Hardcoded Adaptive Scaling Function

The scale $S$ is a Q8 fixed-point number in $[S_{\min}, 1.0]$, where $256$
represents unity:

$$S[k+1] = \begin{cases}
\max\left(S_{\min},\ S[k] - C_{\text{step}}\right) & \text{if any threshold is crossed} \\
\min\left(256,\ S[k] + R_{\text{step}}\right) & \text{otherwise}
\end{cases}$$

An epoch is **stressed** when *any* of the following holds (a threshold of `0`
disables that particular trigger):

| Trigger | Manifest key | Comparison |
|:---|:---|:---|
| Rejection ratio | `reject_threshold_q8` | $R_{\text{rej}} \ge$ threshold |
| Latency spread | `latency_spread_threshold_ns` | $\Delta t \ge$ threshold |
| Clamp fraction | `clamp_threshold_q8` | $C_{\text{clamp}} \ge$ threshold |
| Coherence anomalies | `coherence_anomaly_threshold` | $A_{\text{coh}} \ge$ threshold |

Every parameter is a signed manifest value, so the loop is generic and
non-hardcoded: changing a threshold or a step size changes the behaviour of
every plant without a recompile.

### 3.4 Zero-Regression Mathematical Guarantee

HOMEOSTAT acts strictly as an **envelope-contracting advisor**. It is
mathematically barred from ever expanding or widening safety envelopes beyond
the signed manifest limits:

$$v_{\text{max, effective}} = \min\left(v_{\text{max, manifest}},\ \left\lfloor \frac{v_{\text{max, manifest}} \cdot S}{256} \right\rfloor\right)$$

The gate implements this as an additional ceiling (`gov_gate_input_t.homeostat_v_max`),
so the agent's own confidence scale composes **multiplicatively** on top:

$$v_{\text{max, gate}} = \left\lfloor \frac{v_{\text{max, effective}} \cdot q_{\text{confidence}}}{256} \right\rfloor$$

Two properties are enforced by construction and asserted by the test suite:

- **Contracting only.** A ceiling above the manifest limit can never raise it.
  The gate takes `min(manifest, homeostat)` and never the other way round.
- **Never zero.** A scale that would underflow to a zero velocity ceiling is
  floored at the smallest non-zero step the kinematic model can represent
  (1 mrad/tick), because a zero ceiling is indistinguishable from a bug.

If the manifest has **no** `homeostat` section, or the section has
`"enabled": 0`, the loop is inert: $S \equiv 256$ and the supervisor behaves
bit-identically to a build without the module. An out-of-range parameter is a
**manifest-load rejection** (fail closed), never a silent runtime clamp.

The scale is captured at the start of a tick and applied to the **next** one, so
a scale change can never alter a decision that is already in flight.

### 3.5 How to See It Work

```bash
# Unit test of the loop itself (contraction, recovery, Q8 saturation,
# overflow-safe motion accounting, disabled-loop inertness):
make -C qnx governor-homeostat-check

# Runtime proof: drives the real supervisor over the real wire protocol and
# reads the result from the committed evidence-tape format.
make -C qnx homeostat-e2e-check
```

`tools/homeostat_e2e.py` asserts five properties:

| Scenario | Assertion |
|:---|:---|
| A — contraction | A stressed epoch shrinks the per-tick velocity ceiling (24 → 1 mrad/tick in the reference run) |
| B — recovery | A clean epoch recovers the ceiling back to the manifest limit |
| C — contracting only | Over every comparable tick, HOMEOSTAT never moves the plant *faster* than the unadapted run |
| D — default off | A manifest with no `homeostat` section is behaviourally identical to the baseline |
| negative | An out-of-range parameter is rejected at manifest load, not clamped at runtime |

`tools/consistency_check.py` additionally asserts that the module cannot
silently become an orphan again: it checks that `gov_homeostat.c` is linked
into `latchd`, that the three HOMEOSTAT symbols are called from `latchd.c`,
that the gate accepts the ceiling, that the manifest parser reads the section,
and that **only** `homeostat_servo.manifest` carries one.

---

## 4. GOVERNOR: Integrate the Downloaded LLM

### 4.1 Verified Starting Point & Audit of the Existing Setup
- **Downloaded Assets**: The machine has `llama.cpp` built at `/home/skanda/llama.cpp/build/bin/llama-cli` and a 139 MiB `SmolLM2-135M-Instruct-Q8_0.gguf` at `/home/skanda/models/`.
- **Host vs Guest Architecture**: The compiled `llama-cli` binary is an **x86-64 Linux binary**. The QEMU guest VM runs an **AArch64 Linux 6.12** kernel. An x86-64 binary cannot execute directly inside the AArch64 guest VM without an AArch64 cross-compilation or running on the host via the host-sim FIFO bridge.
- **Current Guest Payload**: The existing guest payload is `guest/latch_guest_init.c` (a freestanding static AArch64 C program running as PID 1 using raw `svc #0` syscalls). It executes a deterministic 235-frame scripted sequence. It does not invoke `llama.cpp` or load GGUF weights.
- **The Core Deficiency**: Downloading the model and binary was only Step 0. The system lacked an active, closed-loop **observe $\to$ plan $\to$ propose $\to$ observe** iterative agent architecture.

### 4.2 Missing Functions & Architectural Upgrades Required

```
┌────────────────────────────────────────────────────────────────────────┐
│               ITERATIVE LLM AGENT LOOP ARCHITECTURE                    │
├────────────────────────────────────────────────────────────────────────┤
│  AI GUEST / HOST AGENT                                                 │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ 1. OBSERVE: Receive feedback frame from QNX supervisor            │  │
│  │    (last_seq, verdict, applied_pos, current_rung, fault_bits)    │  │
│  │ 2. PROMPT: Format structured system prompt + observation context │  │
│  │ 3. INFER: Execute bounded inference with SmolLM2-135M            │  │
│  │ 4. VALIDATE: Grammar-constrained JSON output parser              │  │
│  │ 5. PROPOSE: Emit 32-byte Wire v2 frame (kind=2, u_mrad, Q8 conf) │  │
│  │ 6. HEARTBEAT: Dedicated thread maintains lease within deadline   │  │
│  └─────────────────────────────────┬────────────────────────────────┘  │
│                                    │ 32-Byte Proposal Frame            │
│                                    ▼                                   │
│  QNX SAFETY SUPERVISOR (latchd)                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ 1. Gate Prechecks (Units, Token Bucket, DT-CBF Keep-Out, Dose)   │  │
│  │ 2. Evaluate Ladder FSM (Promotions / Demotions)                  │  │
│  │ 3. Dispatch to Actuator (if ALLOW) or Clamp/Hold (if REJECT)     │  │
│  │ 4. EMIT FEEDBACK: Write sequence-correlated decision to return  │  │
│  │    transport for agent observation                               │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

#### 1. Real Observe $\to$ Plan $\to$ Propose $\to$ Observe Loop
Moving from static frame generation to an interactive agent loop:
- **PARTIAL.** `tools/agent_loop.py` exists and implements a bounded, autonomous agent: a heartbeat daemon thread that emits liveness HEARTBEAT frames on a 24-bit coherence counter, and a planning thread that proposes through the GovernorClient SDK. It is a **simulation** — it does not load the GGUF model.
- The live-LLM guest variant `guest/latch_guest_agent.py` does **not** exist.
- Per iteration, the agent queries the current plant state, constructs a structured prompt, calls the local model, validates the structured response, and serializes a 32-byte Wire v2 frame.
- Iteration budget: Bounded token limit (max 64 tokens), timeout enforcement (max 250 ms inference deadline).

#### 2. Explicit Return Feedback Transport
The proposal channel (`virtio-console` write sink) was one-way. A complete feedback loop requires an explicit return path.
- **Implemented** — Wire format: the fixed 24-byte `latch_feedback_t` frame in `qnx/latch_feedback.h`:
  * `uint32_t magic`: `LFBK` (`LATCH_FEEDBACK_MAGIC`).
  * `uint16_t version`, `uint16_t size`: frame version and exact size (`LATCH_FEEDBACK_SIZE == 24`).
  * `uint32_t seq`: Sequence number of the evaluated proposal.
  * `uint8_t verdict`: `0`=REJECT, `1`=ALLOW, `2`=message-only, `3`=shrink-request, `4`=other.
  * `uint8_t rung`: Active degradation rung (`HP`..`LATCH`).
  * `uint16_t fault_bits`, `uint16_t fault_bits2`: Active fault bitmasks.
  * `uint16_t flags`: `LATCH_FEEDBACK_FLAG_TIMEOUT` marks an explicit **absence** of a supervisor verdict.
  * `uint32_t crc32`: IEEE CRC-32 over the first 20 bytes.
  * Compile-time assertions pin the size and the CRC offset.
- The codec (`qnx/latch_feedback.c`) implements encode, strict decode, and `latch_feedback_decode_for_seq()`, which correlates a verdict with the proposal it answers (`-ESTALE` on a sequence mismatch).
- **Status: the codec is built and unit-tested (`make -C qnx latch-feedback-check`), but it is NOT yet on the runtime path.** The supervisor does not currently emit the frame: wire protocol v2 is frozen and the archived on-target GOVERNOR evidence chain is a signed SHA-256 chain over the 62-byte event record, so adding a transport would invalidate evidence that cannot currently be re-captured (the QEMU `GUEST_IMAGE` is unavailable). Emitting it is therefore a separate, explicitly-scoped change, not a silent add-on.

#### 3. Decoupling Planner Liveness from Heartbeat Flooding
A common failure mode in autonomous systems is a heartbeat thread keeping safety leases alive while the planning LLM is completely frozen or caught in an infinite loop:
- **Planner-Progress Deadlines**: The supervisor tracks `last_command_tick`. While heartbeats prevent immediate watchdog timeout, they reset `clean_command_streak = 0`.
- If no valid motion proposal is received within `planner_timeout_ticks` (e.g., 500 ms), the ladder automatically demotes from `HP` to `SLOW` $\to$ `SAFE_STOP`, preventing a stalled model from retaining unmonitored operational authority.

#### 4. Dual-Mode Architecture: Deterministic Replay vs. Live Inference
To ensure 100% reproducibility in CI and judge evaluations:
- **Mode A (Deterministic Replay - CI Baseline)**: Replays exact recorded LLM session transcripts frame-by-frame, verifying that `make check` and `run_attacks.py` pass with byte-identical signatures.
- **Mode B (Live Bounded Inference)**: Launches `llama-cli` / `llama-server` with `SmolLM2-135M-Instruct-Q8_0.gguf` under live prompt injection (Attacks A1..A7) and captures real-time gate rejections.

---

## 5. Implementation Roadmap & File-Level Plan

| Step | Action | Impacted Files | Status & Verification Method |
|:---:|:---|:---|:---|
| **1** | Define the supervisor-verdict feedback frame | `qnx/latch_feedback.h` | **DONE (codec only).** Compile-time `_Static_assert(sizeof(latch_feedback_t) == 24)` and a second assert pinning the CRC offset at 20. Verified by `make -C qnx latch-feedback-check`. Not yet on the runtime path — see §4.2 item 2. |
| **2** | Add Supervisor Feedback Dispatch | `qnx/latchd.c`, `qnx/latch_ingest.c` | **NOT DONE.** Requires a frozen-protocol decision and a fresh on-target evidence capture. The guest-side agent (`guest/latch_guest_agent.py`) does not exist either. |
| **3** | Implement the HOMEOSTAT engine | `qnx/gov_homeostat.c/.h`, `qnx/latch_manifest.c/.h`, `qnx/latchd.c`, `qnx/gov_gate_precheck.c/.h` | **DONE.** Optional schema-3 `homeostat` manifest section (default-off), contracting-only ceiling applied in the gate. Unit test `qnx/gov_homeostat_test.c`; runtime test `tools/homeostat_e2e.py`; both run from `make -C qnx check-governor`. |
| **4** | Build Iterative Agent Loop | `tools/agent_loop.py` | **PARTIAL.** `tools/agent_loop.py` exists (an autonomous planning/heartbeat simulation using the GovernorClient SDK). The live-LLM guest variant `guest/latch_guest_agent.py` does **not** exist. |
| **5** | Integrate SmolLM2-135M Live Demo | `tools/llm_governor_runner.py` | **NOT DONE as named.** The installed assets exist (`/home/skanda/llama.cpp/build/bin/llama-cli`, `/home/skanda/models/SmolLM2-135M-Instruct-Q8_0.gguf`) and `tools/llama_governor_agent_test.py` exercises the agent-side policy, but `tools/llm_governor_runner.py` does not exist. |
| **6** | Zero-Regression Verification Gate | `qnx/Makefile`, `tools/consistency_check.py` | **DONE.** `consistency_check.py` asserts the HOMEOSTAT wiring and the default-off property; `make -C qnx check`, `check-governor`, `fuzz`, `check-asan`, `evidence-check` and `tools/attacks/run_attacks.py` are all green. |
