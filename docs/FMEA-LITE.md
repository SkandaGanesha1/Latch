# Failure Mode and Effects Analysis (FMEA-Lite) — LATCH & GOVERNOR

**Document Version:** 1.0  
**Scope:** Runtime Assurance Architecture for Physical AI on QNX SDP 8.0 & QNX Hypervisor 8.0  
**Framework Alignment:** IEC 61508 / ISO 26262 Hazard & Risk Analysis  

---

## 1. System Components & Architecture Boundaries

1. **Untrusted Guest Channel:** Linux 6.12 guest VM running LLM / neural planning policy (SOUP).
2. **Black Channel Transport:** virtio-console serial port emitting 32-byte binary wire frames.
3. **Ingestion Bridge (`latch-ingest`):** Unprivileged worker validating CRC32 and translating wire frames to 48-byte `LPR2` IPC messages.
4. **Safety Supervisor (`latchd`):** Privileged QNX microkernel resource manager (`/dev/latch/proposal`, `/dev/latch/actuator`) on `_cpu-0`, `SCHED_FIFO 63`.
5. **Decision & Precheck Gate (`gov_gate_precheck.c`):** Evaluates units, rate burst, confidence shrinkage, keep-out barrier, and medical dose limits.
6. **Blackbox Flight Recorder (`latchlog` / `gov_replay.py`):** 4096-entry `.bss` circular memory ring with offline rolling SHA-256 seal.
7. **Actuator Controller:** PCA9685 hardware PWM controller / mock I²C bus.

---

## 2. Risk Rating Criteria

- **Severity (S):** 1 (Negligible) to 10 (Catastrophic: human harm / lethal dosing).
- **Occurrence (O):** 1 (Extremely Unlikely) to 10 (Inevitable: frequent AI hallucinations / prompt attacks).
- **Detection (D):** 1 (Immediately & Deterministically Intercepted) to 10 (Undetected Silent Failure).
- **RPN (Risk Priority Number):** $S \times O \times D$ (Maximum 1000; Safety Target: RPN $< 100$).

---

## 3. FMEA Tabular Analysis

| Item ID | Component | Potential Failure Mode | Potential Effect of Failure | $S$ | Potential Cause | $O$ | Current Design Controls & Safety Mitigations | $D$ | RPN |
|:---:|:---|:---|:---|:---:|:---|:---:|:---|:---:|:---:|
| **FM-1** | Guest AI Policy | Prompt injection / jailbreak payload commanding forbidden coordinate | Robot moves into human keep-out zone $[250, 650]$ mrad | 9 | Adversarial prompt in visual/text context | 8 | Precheck evaluates DT-CBF keep-out barrier (`LATCH_FAULT_KEEPOUT`, bit 5). Immediate fail-closed transition to `HOLD` mode ($v = 0$). | 1 | **72** |
| **FM-2** | Guest AI Policy | Unit hallucination (e.g., milliradians vs raw integers or microns) | Excessive physical excursion (370,000 raw counts) | 8 | Model tokenizer confusion / prompt drift | 7 | Manifest-declared rational unit matrix. Unknown `unit_id` trips `LATCH_FAULT_UNIT` (bit 12). Clamps candidate to current position; graded ladder demotion. | 1 | **56** |
| **FM-3** | Guest AI Policy | Excessive rate proposal / velocity spike ($\Delta u = 500$ mrad/tick) | High mechanical strain, collision, or motor burn-out | 7 | Planner divergence / loss of gradient stability | 8 | Leaky token-bucket rate limiter clamps step to legal $v_{\text{max}}$ (25 mrad/tick). Asserts `LATCH_FAULT_RATE` (bit 7). | 1 | **56** |
| **FM-4** | Guest AI Policy | Agent crash, infinite loop, or host stall | Stale actuator command execution, loss of control | 8 | Guest kernel OOM, deadlock, or hypervisor vCPU deschedule | 6 | Advancing 24-bit coherence counter and 100 ms deadman lease. Silence trips `LATCH_FAULT_HEARTBEAT` (bit 13); graded ladder drops to fail-closed `LATCH`. | 1 | **48** |
| **FM-5** | Transport Channel | Corrupted bits in wire frame during transmission | Undefined command execution by actuator | 7 | EMI interference, memory bit-flips, bus contention | 4 | CRC32-IEEE validation covering 28 of 32 bytes (`LATCH_FAULT_CRC`, bit 0). Corrupted frame dropped before supervisor queue. | 1 | **28** |
| **FM-6** | Transport Channel | Replay of historical command frames | Stale motion execution out of context | 7 | Adversary intercepting virtio channel or delayed buffer flush | 5 | Monotonic sequence check ($seq > last\_seq$). Non-monotonic frame triggers `LATCH_FAULT_SEQ` (bit 2) and locks plant in `HOLD`. | 1 | **35** |
| **FM-7** | Medical Infusion Plant | Excessive single-bolus or rapid consecutive bolus delivery | Lethal overdose of insulin/narcotics | 10 | Faulty dosage proposal from medical assistant LLM | 6 | Medical schema-3 contracts (`syringe_governor.manifest`) enforce `max_bolus_uL`, `min_bolus_interval_ticks` lockout, and `max_cumulative_dose_uL`. Exceedance asserts `LATCH_FAULT_DOSE` (bit 15) and clamps step to 0. | 1 | **60** |
| **FM-8** | Flight Recorder | Tampering with post-incident crash telemetry | Inability to audit liability / root-cause AI incident | 6 | Compromised guest attempting to cover up malicious commands | 5 | 4096-entry circular event ring is held in QNX `.bss` (inaccessible to guest). Offline `gov_replay.py` seals records into rolling SHA-256 chain; single bit-flip trips `TAMPER_DETECTED`. | 1 | **30** |
| **FM-9** | Supervisor OS | Priority inversion or CPU starvation by guest VM | Safety gate misses 1 kHz deadline, loop jitter | 9 | Heavy AI inference workload on guest cores | 7 | QNX Hypervisor statically pins guest vCPUs to Cores 2-3 at priority 8; `latchd` pinned to Core 0 at `SCHED_FIFO 63`. Max observed WCET is 61.08 µs (budget: 100 µs). | 1 | **63** |

---

## 4. Conclusion & Verification Record

All evaluated failure modes achieve an RPN $< 100$ (target threshold) due to the deterministic detection score ($D = 1$) provided by QNX 8.0 microkernel isolation, hardware memory barriers, and mathematical precheck verification. Every failure mode corresponds directly to one of the seven verified adversarial test scenarios (`A1` through `A7`) and passes 100% of safety invariants.

