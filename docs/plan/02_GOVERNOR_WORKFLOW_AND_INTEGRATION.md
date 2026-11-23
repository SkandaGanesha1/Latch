# 02 — GOVERNOR & HOMEOSTAT Workflow, Zero-Regression Integration, LLM Agent Loop & Ashby Ultrastability Engine

**Generated:** 2026-11-23  
**Status:** Validated Technical Architecture & Integration Blueprint  
**Target Platform:** QNX SDP 8.0 (`procnto-smp-instr`) + QNX Hypervisor 8.0 (QEMU AArch64 & Raspberry Pi 4B)  
**Safety Invariant:** Zero Keep-Out Breaches Across All Operating Modes.

---

## 1. Executive Summary

GOVERNOR extends the LATCH runtime assurance supervisor with an industrial-grade, 6-rung supervisory degradation ladder and multi-gate precheck pipeline. It bridges untrusted physical AI planning with real-time physical control without compromising microkernel guarantees. 

**HOMEOSTAT** adds a cybernetic outer loop grounded in W. Ross Ashby’s 1948 mathematical ultrastability formulation, dynamically adapting safety envelopes in response to system stress, jitter, and rejection rates while strictly adhering to the zero-regression principle.

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
                        │ Tracks:                   │
                        │  - Rejection Rate R_rej   │
                        │  - Jitter Variance σ_t    │
                        │  - Thermal / Effort E_k   │
                        │ Outputs:                  │
                        │  - S_adapt ∈ [0.1, 1.0]   │
                        │  - Dynamic Rate Ceiling   │
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

### 3.1 Ashby's Ultrastability Formulation
W. Ross Ashby (1948) proved that an ultrastable system maintains essential variables within viable limits by automatically modifying its own internal parameters when external disturbances or unmodeled behaviors push variables beyond physiological bounds.

In physical AI systems, the AI model generates non-deterministic trajectory distributions. Under environmental stress, sensor noise, or prompt degradation, the AI's proposal error rate surges. HOMEOSTAT implements Ashby's ultrastable feedback loop inside the QNX microkernel.

### 3.2 The Four Essential Variables ($E_v$)
HOMEOSTAT continuously tracks four discrete-time Essential Variables:
1. **Proposal Rejection Stress ($R_{\text{rej}}$)**: An exponential moving average of gate rejections:
   $$R_{\text{rej}}[k] = \alpha_r \cdot R_{\text{rej}}[k-1] + (1 - \alpha_r) \cdot \mathbb{I}(\text{verdict}_k == \text{REJECT})$$
2. **Execution Timing Jitter ($\sigma_t$)**: Jitter measured via `ClockCycles()` against expected period:
   $$\Delta t_k = |t_{\text{tick}}[k] - t_{\text{nominal}}|, \quad \sigma_t[k] = \alpha_t \cdot \sigma_t[k-1] + (1 - \alpha_t) \cdot \Delta t_k$$
3. **Actuator Effort / Thermal Accumulator ($E_k$)**: Cumulative mechanical work proxy:
   $$E_k = \max\left(0, E_{k-1} + |u_k - \theta_k| - \delta_{\text{cool}}\right)$$
4. **Coherence Jump Variance ($C_{\text{var}}$)**: Irregularities in guest counter advancement:
   $$C_{\text{var}}[k] = |\Delta \text{coh}_k - 1|$$

### 3.3 Generic, Non-Hardcoded Adaptive Scaling Function
The adaptive scaling factor $S_{\text{adapt}} \in [S_{\text{min}}, 1.0]$ is computed in bounded 64-bit integer arithmetic:
$$S_{\text{adapt}}[k] = 1.0 - \min\left(0.9, w_r \cdot R_{\text{rej}}[k] + w_t \cdot \frac{\sigma_t[k]}{\sigma_{\text{threshold}}} + w_e \cdot \frac{E_k}{E_{\text{cap}}}\right)$$

### 3.4 Zero-Regression Mathematical Guarantee
HOMEOSTAT acts strictly as an **envelope-contracting advisor**. It is mathematically barred from ever expanding or widening safety envelopes beyond the signed manifest limits:
$$\text{Envelope}_{\text{effective}} = \min\left(\text{Envelope}_{\text{manifest}}, \text{Envelope}_{\text{HOMEOSTAT}}\right)$$
$$v_{\text{max, effective}} = \min\left(v_{\text{max, manifest}}, \lfloor v_{\text{max, manifest}} \cdot S_{\text{adapt}} \rfloor\right)$$

If HOMEOSTAT is disabled (`homeostat.enabled = false` in the contract) or encounters an arithmetic edge-case, $S_{\text{adapt}} \equiv 1.0$, reverting immediately to the baseline GOVERNOR gate.

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
- `tools/agent_loop.py` and `guest/latch_guest_agent.py`: Implement a bounded, iterative agent.
- Per iteration, the agent queries the current plant state, constructs a structured prompt, calls the local model, validates the structured response, and serializes a 32-byte Wire v2 frame.
- Iteration budget: Bounded token limit (max 64 tokens), timeout enforcement (max 250 ms inference deadline).

#### 2. Explicit Return Feedback Transport
The proposal channel (`virtio-console` write sink) was one-way. A complete feedback loop requires an explicit return path:
- Wire format: 16-byte `governor_feedback_t` struct:
  * `uint16_t proposal_seq`: Sequence number of the evaluated proposal.
  * `uint8_t verdict`: `0`=REJECT, `1`=ALLOW, `2`=CLAMPED.
  * `uint8_t current_rung`: Active degradation rung (`HP`..`LATCH`).
  * `int32_t applied_position`: The actual position committed to the actuator.
  * `uint32_t fault_bits`: Active fault bitmask (`0` if clean).
  * `uint32_t reserved`: CRC / padding.
- `latchd` emits this feedback frame over the return console descriptor or feedback pipe immediately upon evaluating the decision tick.
- The agent reads this feedback before calculating the subsequent motion step.

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

| Step | Action | Impacted Files | Verification Method |
|:---:|:---|:---|:---|
| **1** | Define Bidirectional Feedback Protocol | `qnx/latch_protocol.h`, `qnx/governor_wire.h` | Compile-time `_Static_assert(sizeof(governor_feedback_t) == 16)`. |
| **2** | Add Supervisor Feedback Dispatch | `qnx/latchd.c`, `qnx/latch_ingest.c` | Unit test in `qnx/latch_ipc_test.c` asserting feedback generation. |
| **3** | Implement HOMEOSTAT Additive Engine | `qnx/homeostat_policy.c/.h` | Additive precheck in `gov_gate_precheck.c`; unit test suite `homeostat_test.c`. |
| **4** | Build Iterative Agent Loop | `tools/agent_loop.py`, `guest/agent_llm.py` | Host simulation test running 5 iterations of live prompt $\to$ gate $\to$ feedback. |
| **5** | Integrate SmolLM2-135M Live Demo | `tools/llm_governor_runner.py` | Live adversarial prompt injection test; verify 0 keep-out breaches. |
| **6** | Zero-Regression Verification Gate | `Makefile`, `tools/consistency_check.py` | Verify `make check` and `make check-governor` remain 100% PASS. |
