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
Essential Variables. The epoch is closed by the **tick counter**, not by the
number of proposals: a quiet epoch still closes, and every accumulator is reset
when it does.

1. **Proposal Rejection Ratio ($R_{\text{rej}}$)** — Q8 fixed point:
   $$R_{\text{rej}} = \left\lfloor \frac{\text{rejected} \cdot 256}{\text{proposals}} \right\rfloor$$
   Only *motion* proposals count. The supervisor sets `proposal_present` only
   for `kind = CMD` and `kind = CMD_V2`; a heartbeat or a shrink request
   carries no motion, so counting the supervisor's own liveness traffic as a
   rejection would manufacture stress out of nothing.
2. **Clamp Fraction ($C_{\text{clamp}}$)** — the share of requested motion that
   was **not** applied, in Q8:
   $$C_{\text{clamp}} = \left\lfloor \frac{\text{proposed\_motion} - \text{applied\_motion}}{\text{proposed\_motion}} \cdot 256 \right\rfloor$$
   The Q8 fraction is computed by an exact 8-step binary expansion
   (`fraction_q8()` in `qnx/gov_homeostat.c`), so there is no rounding drift
   and no division by zero. Both motion accumulators are saturating 64-bit
   adds, and the applied motion is clamped to the proposed motion before it is
   accumulated, so a frame at the edge of the `int32` range cannot overflow
   the accounting or produce a negative clamp fraction.
3. **Latency Spread ($\Delta t$)** — the difference between the maximum and the
   minimum decision latency observed inside the epoch, in nanoseconds:
   $$\Delta t = t_{\max} - t_{\min}$$
   The latency is sampled on **every tick** of the epoch, because it is a
   property of the decision pipeline rather than of the proposal.
4. **Coherence Anomalies ($A_{\text{coh}}$)** — the count of frames whose
   24-bit guest coherence counter did not advance within
   `governor.deadman.coherence_max_gap`. This is counted **per frame**, not
   per tick.

### 3.3 Generic, Non-Hardcoded Adaptive Scaling Function

The scale $S$ is a Q8 fixed-point number in $[S_{\min}, 1.0]$, where $256$
represents unity:

$$S[k+1] = \begin{cases}
\max\left(S_{\min},\ S[k] - C_{\text{step}}\right) & \text{if any threshold is crossed} \\
\min\left(256,\ S[k] + R_{\text{step}}\right) & \text{otherwise, and the epoch saw at least one proposal}
\end{cases}$$

The three step/floor parameters are **signed manifest values**, not symbols:

| Symbol | Manifest key | Meaning |
|:---|:---|:---|
| $C_{\text{step}}$ | `homeostat.contraction_q8` | How much the scale shrinks in one stressed epoch |
| $R_{\text{step}}$ | `homeostat.recovery_q8` | How much the scale grows in one clean epoch |
| $S_{\min}$ | `homeostat.floor_q8` | The floor the scale may never go below |

**The recovery branch requires the epoch to have seen at least one motion
proposal.** An epoch in which nothing was proposed leaves the scale exactly
where it was. This is a deliberate difference from the bare formula above, and
it is the safer of the two: a supervisor that has seen no traffic has no
evidence that the plant is behaving, so it must not talk itself back up to
unity merely because it went quiet. The shipped condition is
`else if (state->proposals != 0u)` in `gov_homeostat_observe()`.

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

The shipped path, in order, is:

1. `latch_homeostat_vmax()` (`qnx/latchd.c`) computes the ceiling for the
   **current** tick as `min(v_max, floor(v_max · S / 256))` via
   `gov_homeostat_effective_vmax(v_max, scale_q8, 256)`. The third argument is
   `256` (unity) because the agent's own scale is applied by the gate, not
   here. A ceiling that would underflow to zero is floored at `1` mrad/tick.
2. `gov_gate_precheck()` takes `base_v_max = manifest.v_max` and lowers it to
   the HOMEOSTAT ceiling **only if that ceiling is strictly lower and strictly
   positive**. A `homeostat_v_max` of `0` means "not applied" and reproduces
   the pre-HOMEOSTAT behaviour bit-for-bit.
3. The gate then applies the agent's confidence scale to `base_v_max`
   (`v_eff = q8_scale(base_v_max, scale_q8)`), so the two compose
   multiplicatively and the result can only be smaller than either factor.

Two properties are enforced by construction and asserted by the test suite:

- **Contracting only.** A ceiling above the manifest limit can never raise it.
  The gate takes `min(manifest, homeostat)` and never the other way round.
- **Never zero.** A scale that would underflow to a zero velocity ceiling is
  floored at the smallest non-zero step the kinematic model can represent
  (1 mrad/tick), because a zero ceiling is indistinguishable from a bug. The
  floor is applied in both `latch_homeostat_vmax()` and `q8_scale()`. It is a
  **kinematic-model constant, not a safety parameter**, so it is not a
  manifest key: a plant that needs a larger minimum step declares it in its own
  envelope `v_max`, and the floor never raises that value above it.

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
- **Downloaded Assets** (re-verified 2026-11-25): `llama.cpp` is checked out at `/home/skanda/tools/llama.cpp`, revision `44d50873b`, and the host build produces `/home/skanda/tools/llama.cpp/build/bin/llama-cli`. The model is `/home/skanda/models/SmolLM2-135M-Instruct-Q8_0.gguf` — 144,811,360 bytes (138.1 MiB), SHA-256 `5a1395716f7913741cc51d98581b9b1228d80987a9f7d3664106742eb06bba83`. **Neither the model nor the host binary is tracked in this repository**; the model is a 138 MiB artefact and must be delivered to the guest out of band.
- **Host vs Guest Architecture**: the compiled `llama-cli` binary is an **x86-64 Linux binary** (`ELF 64-bit LSB executable, x86-64, dynamically linked`). The QEMU guest VM runs an **AArch64 Linux 6.12** kernel. An x86-64 binary cannot execute directly inside the AArch64 guest VM without an AArch64 cross-compilation or running on the host via the host-sim FIFO bridge. **The requirement for this project is the former**: the inference must run *inside* the guest.
- **Current Guest Payload**: The **scripted** guest payload is `guest/latch_guest_init.c` (a freestanding static AArch64 C program running as PID 1 using raw `svc #0` syscalls). It executes a deterministic 235-frame scripted sequence. **A separate experimental profile** (`qnx/latch_qemu_infer.build`) now also runs the model: the policy stays PID 1 and freestanding, and `clone()`s + `execve()`s a statically linked AArch64 C++ program (`guest/latch_infer.cpp`) that links llama.cpp, loads the GGUF weights, constrains the output with a GBNF grammar, re-validates the JSON independently, and emits a 32-byte wire-v2 frame into a pipe that the policy relays. The model and the inference binary travel on a **read-only virtio-blk asset disk** (`hostdev <…`, read-only enforced by the hypervisor) because qvm's blob loader cannot deliver a large initramfs to an upstream-Linux guest.
- **The Core Deficiency**: Downloading the model and binary was only Step 0. The system lacked an active, closed-loop **observe $\to$ plan $\to$ propose $\to$ observe** iterative agent architecture. **The model now runs inside the guest** and the supervisor judges its proposals against the signed envelope, but the loop's **observe** half is still missing: there is **no bidirectional feedback channel** (see U-2), so the experiment demonstrates one supervised proposal, not a closed loop.

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

#### 2. Explicit Return Feedback Transport (W4 & W5 — Shipped)
The proposal channel (`virtio-console` write sink) was one-way. An explicit return path is now implemented and verified on target:
- **Wire format:** Fixed **28-byte** `latch_feedback_t` frame in `qnx/latch_feedback.h` (`LFBK` magic `0x4C46424B`, version `2`, `size = 28`, `seq`, `session_epoch`, `verdict`, `rung`, `fault_bits`, `fault_bits2`, `flags`, and IEEE CRC-32 over the 24-byte prefix). Compile-time `_Static_assert`s pin the size (`28`) and CRC offset (`24`).
- **Codec & Transport:** `qnx/latch_feedback.c` implements encode, strict decode, and `latch_feedback_decode_for_seq()` (`-ESTALE` on sequence/epoch mismatch). `latchd` publishes verdicts non-blockingly (`qnx/latch_feedback_pub.c`) via `latch_fb_sink` to `/dev/shmem/latch_feedback.img`, exposed read-only (`<`) over `vdev virtio-blk` (`/dev/vda`) and polled by the freestanding guest (`guest/latch_fb_decode.h`, `guest/latch_fb_publish.h` with AArch64 `dmb` barriers).
- **Target status:** W4 (`verify_fb_qemu.py`) and W5 (`verify_fbverdict_qemu.py`) both pass on QEMU AArch64 `virt` (`docs/evidence/governor/feedback-transport.txt`). Remaining gap: `guest/latch_infer.cpp` (experimental W6 LLM profile) does not yet read `/dev/vda` for `>= 2` closed-loop `observe -> plan -> propose -> observe` cycles (**U-3**).

#### 3. Decoupling Planner Liveness from Heartbeat Flooding
A common failure mode in autonomous systems is a heartbeat thread keeping safety leases alive while the planning LLM is completely frozen or caught in an infinite loop:
- **Planner-Progress Deadlines**: The supervisor tracks `last_command_tick`. While heartbeats prevent immediate watchdog timeout, they reset `clean_command_streak = 0`.
- If no valid motion proposal is received within `planner_timeout_ticks` (e.g., 500 ms), the ladder automatically demotes from `HP` to `SLOW` $\to$ `SAFE_STOP`, preventing a stalled model from retaining unmonitored operational authority.

#### 4. Dual-Mode Architecture: Deterministic Replay vs. Live Inference
To ensure 100% reproducibility in CI and judge evaluations:
- **Mode A (Deterministic Replay - CI Baseline)**: Replays exact recorded LLM session transcripts frame-by-frame, verifying that `make check` and `run_attacks.py` pass with byte-identical signatures.
- **Mode B (Live Bounded Inference)**: Launches `llama-cli` / `llama-server` with `SmolLM2-135M-Instruct-Q8_0.gguf` under live prompt injection (Attacks A1..A7) and captures real-time gate rejections.

**As implemented (2026-11-26), Mode B runs the inference binary *inside* the guest** rather than launching `llama-cli` on the host: a statically linked AArch64 C++ program (`guest/latch_infer.cpp`) links llama.cpp, loads the GGUF weights from a read-only virtio-blk asset disk, constrains the output with a GBNF grammar, re-validates the JSON independently, and emits a 32-byte wire-v2 frame into a pipe. The freestanding policy stays PID 1, stays the **sole writer** on the black channel, and relays the frame. The safety envelope is **not** duplicated in the guest — the guest-side check is STRUCTURE only; the keep-out, slew and rate limits live in the signed manifest and are enforced only by the trusted supervisor. The decisive test is a **prompt-injection attack**: the same binary, model, grammar and contract, with only the prompt changed, and the supervisor refuses the forbidden motion and the plant does not move.

---

## 5. Implementation Roadmap & File-Level Plan

| Step | Action | Impacted Files | Status & Verification Method |
|:---:|:---|:---|:---|
| **1** | Define the supervisor-verdict feedback frame | `qnx/latch_feedback.h` | **DONE.** Compile-time `_Static_assert(sizeof(latch_feedback_t) == 28)` and CRC offset assert at 24. Verified by `make -C qnx latch-feedback-check` and `latch-fb-decode-check`. |
| **2** | Add Supervisor Feedback Dispatch (W4/W5) | `qnx/latchd.c`, `qnx/latch_feedback_pub.c`, `qnx/latch_fb_sink.c`, `guest/latch_guest_init.c` | **DONE (for scripted guest policy).** `latchd` publishes verdicts via `latch_fb_sink` over read-only `vdev virtio-blk` (`/dev/vda`); W4 and W5 verified on target (`docs/evidence/governor/feedback-transport.txt`). Experimental `guest/latch_infer.cpp` (U-3) does not yet consume `/dev/vda`. |
| **3** | Implement the HOMEOSTAT engine | `qnx/gov_homeostat.c/.h`, `qnx/latch_manifest.c/.h`, `qnx/latchd.c`, `qnx/gov_gate_precheck.c/.h` | **DONE.** Optional schema-3 `homeostat` manifest section (default-off), contracting-only ceiling applied in the gate. Unit test `qnx/gov_homeostat_test.c`; runtime test `tools/homeostat_e2e.py`; both run from `make -C qnx check-governor`. |
| **4** | Build Iterative Agent Loop | `tools/agent_loop.py` | **PARTIAL.** `tools/agent_loop.py` exists (an autonomous planning/heartbeat simulation using the GovernorClient SDK). The live-LLM guest variant `guest/latch_guest_agent.py` does **not** exist. |
| **5** | Integrate SmolLM2-135M Live Demo | `guest/latch_infer.cpp`, `qnx/latch_qemu_infer.build` | **DONE — EXPERIMENTALLY.** `guest/latch_infer.cpp` is a custom llama.cpp API program running **inside** the guest, and `qnx/latch_qemu_infer.build` is the bootable profile carrying it on a **read-only virtio-blk asset disk**. Proven on target by a decisive **prompt-injection attack** (`docs/evidence/governor/infer-qemu.txt`). The W4/W5 feedback channel (`U-2`) is now shipped for the scripted policy, while wiring `latch_infer.cpp` to read `/dev/vda` for `>= 2` closed-loop cycles (`U-3`) remains open. |
| **6** | Zero-Regression Verification Gate | `qnx/Makefile`, `tools/consistency_check.py` | **DONE.** `consistency_check.py` asserts the HOMEOSTAT wiring and the default-off property; `make -C qnx check`, `check-governor`, `fuzz`, `check-asan`, `evidence-check` and `tools/attacks/run_attacks.py` are all green. |
