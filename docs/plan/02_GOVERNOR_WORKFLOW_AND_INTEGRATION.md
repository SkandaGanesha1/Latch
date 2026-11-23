# 02 — GOVERNOR Workflow, Zero-Regression Integration & Safety Invariants

**Generated:** 2026-11-23  
**Status:** Validated Architecture Specification (GOVERNOR Add-On)  
**Verification Coverage:** 7 Cyber-Physical Attacks (A1..A7), 121 Canonical Ticks, 0% Envelopes Breached

---

## 1. Executive Summary

GOVERNOR extends LATCH with an industrial-grade, 6-rung supervisory degradation ladder and multi-gate precheck pipeline. It bridges untrusted generative AI and real-time physical control without compromising QNX microkernel real-time guarantees.

### The Five Core Advancements
1. **6-Rung Supervisory Ladder**: `HP -> ADVISE -> CLAMP -> SLOW -> SAFE_STOP -> LATCH`.
2. **Host-Tick Liveness Lease**: Host-side lease countdown tied to advancing 24-bit coherence proofs.
3. **Multi-Gate Prechecks**:
   - Rational integer unit normalization (`scale_num / scale_den`).
   - Token-bucket burst rate smoothing.
   - Confidence-driven **shrink-only** dynamic envelope narrowing ($[lo, hi] \subseteq [ko_{lo}, ko_{hi}]$).
4. **Medical Infusion Protection**: Per-tick `DOSE` rate limit, minimum bolus lockout interval (`min_bolus_interval_ticks`), and windowed cumulative dose saturation clamping.
5. **Tamper-Evident Blackbox Recorder**: In-memory 4096-entry ring buffer exposed via devctl `0x44` (`DCMD_LATCH_DUMP_GOV_EVENTS`), with offline rolling SHA-256 cryptographic chain verification.

---

## 2. The 6-Rung Degradation Ladder

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
- **25-Frame Bounded Hysteresis**: Restoring authority up one rung requires exactly 25 (`promote_clean_frames`) consecutive clean, valid, coherent motion proposals (`kind=2`). Any fault resets the streak to 0.
- **Fail-Closed Medical DOSE Clamping**: Over-infusion proposals or rapid bolus attempts violating `min_bolus_interval_ticks` assert `LATCH_FAULT_DOSE` and clamp velocity to zero immediately.

---

## 3. Zero-Regression Legacy Compatibility Principle

GOVERNOR adheres strictly to the zero-regression principle:
1. **Schema-2 Backward Compatibility**: Default schema-2 contracts run with protocol wire v1 (24-byte payload). `latchd` executes the legacy 5-invariant pipeline and reports `ALL 5 MICROKERNEL CRITICALITY INVARIANTS VERIFIED`.
2. **Schema-3 Opt-In**: Contracts declaring `schema_version = 3` and `governor.enabled = true` activate protocol wire v2 (32-byte payload), the 6-rung ladder, and `[6/6]` latch_verify check.
3. **Host-Sim Equivalence**: All unit tests (`make -C qnx check` and `make -C qnx check-governor`) pass identically on Linux host simulation and on target QNX Neutrino microkernel.
