# 04 — Corrections Addendum, Audit Remediation & Harmonized Timeline

**Generated:** 2026-11-23  
**Status:** Authoritative Execution & Submission Schedule  
**Baseline Commit:** `9d46dac` (HEAD on main)

---

## 1. Audit Remediation Matrix (A-Series & B-Series Items)

| Item ID | Component | Original Defect | Remediation & Code Fix | Status |
|:---:|:---|:---|:---|:---:|
| **A-1** | `README.md` | Ladder table listed nonexistent `v_advise` and wrong SLOW scale | Updated to burst rate $v \le v_{\text{max}}$ and $v \le \text{clamp\_max\_step} \cdot \text{slow\_scale\_pct} = 1$ | **VERIFIED** |
| **A-2** | `README.md` | Claimed cumulative dose was future work though implemented | Corrected to state per-tick limiter + windowed cumulative saturation clamping | **VERIFIED** |
| **A-3** | Attack A3 & Metrics | Stale bit index "bit 3, 0x0008" for keep-out violation | Fixed to bit 5 (`0x0020`, `LATCH_FAULT_KEEPOUT`) | **VERIFIED** |
| **A-4** | `run_attacks.py` | Docstring cited 5 attacks while runner imported 7 | Synchronized docstring and runner with all 7 named attacks (A1..A7) | **VERIFIED** |
| **A-5** | `README.md` | devctl range stated as `0x41..0x44` | Updated to `0x40..0x45` matching `latch_protocol.h` | **VERIFIED** |
| **A-6** | `README.md` | Repository tree omitted 10+ newly implemented tools and tests | Full tree re-synced with tools, attacks, evidence, and contracts | **VERIFIED** |
| **A-7** | Readiness doc | "VERIFIED: ASIL D" contradicted strict non-certification rule | Softened to "ARCHITECTURAL ALIGNMENT: Architectural pattern designed in alignment..." | **VERIFIED** |
| **A-8** | Compendium | Stale references claiming "SIL 4" | Corrected to TÜV-certified SIL 3 (IEC 61508 SIL 3) | **VERIFIED** |
| **A-9** | C Headers | Wire v2 split and slay syntax docstrings | Added `LATCH_WIRE_VERSION_V2 2u` define, synced `governor_wire.c`, updated to `slay -9 qvm` | **VERIFIED** |
| **A-10**| Consistency Gate | Tick count drift across docs (105 vs canonical 121) | The gate now **derives** the canonical tick and attack counts from the GENERATED `governor-metrics.txt` and cross-checks the host-sim capture and the merged tape against them — no count is typed into the gate, so adding an attack cannot leave it stale | **VERIFIED** |
| **B-1** | Evidence Tape | `governor-tape.csv` only spanned A1..A3 (20 rows) | The merged tape generator now spans the **full** attack suite, and each attack's rows come from the same scenario builder the attack rig uses (A8's rows are produced by the real two-producer pipeline, not synthesised) | **VERIFIED** |
| **B-2** | Host Sim | Stale tick references in `governor-host-sim.txt` | Regenerated host sim log and verified all 7 scenarios pass cleanly | **VERIFIED** |
| **B-3** | Latency Doc | Missing unified latency reference doc | Authored `docs/evidence/governor/LATENCY.md` — **SUPERSEDED: the doc's 61 µs WCET / 143 ms CFS numbers were later REJECTED and quarantined** (`quarantine/REJECTED-governor-LATENCY.md`); the file now holds a pointer. Honest replacement = update plan U11. | **SUPERSEDED** |
| **B-4** | Benchmarks | Hardcoded `qnx_telemetry` dict in QNX vs Linux benchmark | Refactored `benchmark_qnx_vs_linux.py` to parse live tape and manifest budgets | **VERIFIED** |
| **B-5** | Evidence Automation| Missing governor capture target in Makefile | Added `evidence-governor` Makefile target and `scenario_governor()` | **VERIFIED** |
| **B-6** | Safety Logic | `min_bolus_interval_ticks` was parsed but unread in precheck | Enforced lockout interval and monotonic tick checks in `gov_gate_precheck.c` | **VERIFIED** |
| **B-7** | Geometry | Keep-out bounds `[250, 650]` hardcoded in attack tools | De-hardcoded to query `manifest.envelope.keepout` dynamically | **VERIFIED** |
| **B-10**| Event Ring | Overflow flag non-sticky | Verified atomic sticky latch in `latchd.c` (`atomic_store_explicit(&g_gov_event_overflow, 1u)`) | **VERIFIED** |
| **C-1** | Baseline Pillar | Missing empirical Linux control baseline | Built `benchmark_linux_native.py` and generated `docs/evidence/baseline/` — **SUPERSEDED: the archived baseline was later REJECTED (no reproducible source samples) and quarantined** (`quarantine/REJECTED-linux-baseline/`); the directory now holds a pointer. Honest re-capture = update plan U12. | **SUPERSEDED** |
| **C-4** | Verification Harness| `latch_verify.c` had only 5 steps | Added `[6/6]` step querying `DCMD_LATCH_GET_GOV_STATUS` for schema-3 contracts | **VERIFIED** |
| **C-5** | Security Policy | Missing formal secpol audit log | Authored `docs/evidence/derived/secpol-audit.txt` validating spatial isolation | **VERIFIED** |
| **D-1** | Sanitizers | Missing ASan/UBSan build target | Added `check-asan` target to `qnx/Makefile` using clang `-fsanitize=address,undefined` | **VERIFIED** |
| **D-2** | Fuzz Testing | Missing manifest parser fuzzer | Built `tools/fuzz_manifest.py` and added `make -C qnx fuzz` (300 iterations, 0 crashes) | **VERIFIED** |
| **D-3** | Safety Analysis | Missing FMEA documentation | Authored `docs/FMEA-LITE.md` covering all 16 microkernel fault modes (RPN < 100) | **VERIFIED** |
| **D-4** | SBOM | Missing Software Bill of Materials | Authored `docs/SBOM.md` documenting zero third-party dependencies | **VERIFIED** |
| **E-1** | Submission Plan | Missing video production & submission roadmap | Authored `docs/06_video_and_submission_plan.md` harmonizing submission timeline | **VERIFIED** |

---

## 2. Harmonized Master Timeline

```
 Nov 23 - Dec 11       Dec 12 (Freeze)         Dec 13 (Submit)      Dec 14 (Buffer)      Dec 15 (Cutoff)
───────┬──────────────────────┬───────────────────────┬───────────────────┬───────────────────┬─────────►
       │                      │                       │                   │                   │
   Hardening &            Code Freeze             Submit Devpost     Buffer Window       Hard Deadline
 Verification           Record & Edit          "Never on Deadline   Link & Archive        (2:00 PM EST)
   All Gates Green          Video                      Day"           Check               Platform Freeze
```

| Date | Milestone | Requirements & Gates |
|---|---|---|
| **Friday, Dec 12, 2026** | **Code & Evidence Freeze** | All C sources, Python tools, and evidence files locked. `make check`, `make check-governor`, `check-asan`, and `consistency_check.py` 100% green. |
| **Friday, Dec 12, 2026** | **Video Recording & Polish** | 2 min 35 sec video recorded with `ffmpeg` following the 7-scene storyboard in `06_video_and_submission_plan.md`. Uploaded unlisted to YouTube. |
| **Saturday, Dec 13, 2026**| **Devpost Formal Submission** | Devpost application submitted **48 hours ahead of cutoff** ("Never on deadline day"). |
| **Sunday, Dec 14, 2026** | **Contingency & Audit Buffer** | Verification of public repository visibility, license display in root, and YouTube video playback. |
| **Monday, Dec 15, 2026** | **Official Deadline (14:00 EST)**| Platform freeze. No repository edits. |
| **Jan 15 – 29, 2027**    | **Official Judging Window** | 9-judge panel evaluates Technological Implementation, Design, Impact, and Innovation. |
