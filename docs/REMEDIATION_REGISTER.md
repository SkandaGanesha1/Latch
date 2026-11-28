# Review of the supplied gap register

Baseline: local `latch` tree reconciled from `origin/main` (`5bdd9c9`) + `283fda2` (`NEW-6`) + `latch.v14.zip` (`NEW-1`), plus `L-19`, `M-10`, `Makefile` ASan expansion, `consistency_check.py` ccache resilience, and doc/evidence updates. Findings below describe the local verification state, not an independent certification.

| Finding | Disposition and evidence |
|---|---|
| H-1, H-2 | Open evidence limits: QEMU uses mock I²C and no board run is established. README, submission draft and recording handoff disclose this. Hardware proof needs a board and captured run. |
| H-3 | Open: no physical-target WCET; TCG timings are observations, not worst-case bounds. |
| H-4 | Host attack suite is host simulation. The storyboard carries an explicit host-sim caption. Existing target captures cover different, identified scenarios. |
| H-5 | Volatile event ring and offline sealing disclosed. A power-loss-durable trusted record remains future work. |
| H-6 | Fresh-epoch takeover is not authenticated; disclosed in README. A real identity system is future work requiring a threat model and key provisioning. |
| M-7 | `LATCH_SESSION_EPOCH_RING` is 16. Only retained entries are rejected; eviction, counter wrap and reboot limit replay protection. Source comments and README disclose this. |
| M-8 | CI host checks do not reproduce QNX target captures. Record SDK, image and commands for any fresh target run; exclude build artifacts. |
| M-9 | Schema-3 `syringe_governor.manifest` is the GOVERNOR medical simulation; schema-2 `syringe_pump_bolus.manifest` is the legacy profile. No pump hardware is demonstrated. |
| M-10 | **Resolved & target-verified (2026-11-28):** `qvm_host_t` `settypeid` narrowed to `settypeid:latch_ingest_t` in `qnx/latch.secpol`, gated by `consistency_check.py`/`mutation_check.py`, and verified on enforced QEMU builds (`verify-governor-qemu`, `verify-fbverdict-qemu`, `evidence-governor-vm-kill`). See `docs/secpol-audit-review.md` §9. |
| M-11 | QNX SDP 8.0 documents `mlockall()` as a no-op returning 0 (`all memory is locked`); `latchd.c` retains the warning for unexpected implementations without claiming a timing guarantee. |
| M-12 | `snapshot_gen` is 32-bit and advances twice per normal tick, wrapping in ~24.9 days at 1 kHz (documented in `latchd.c` and `README.md`). ABA exclusion remains open. |
| M-13 | SBOM identifies experimental `llama.cpp` and the model, with local digest. Per-image dependency provenance and model license remain to be verified. |
| L-14 | This register supplements the historical V12 ledger instead of renaming its historical evidence. |
| L-15 | `.gitignore` excludes `__pycache__/` and build outputs. |
| L-16, L-17 | Added quick path and `CONTRIBUTING.md`. |
| L-18 | Added QNX Everywhere setup pointer and mock-I²C disclosure to the codelab. |
| L-19 | **Resolved & target-verified (2026-11-28):** `st->omega_mrad_s = 0` added at `qnx/latchd.c` (`plant_at_rest`, `!st->session_active`, and test reset) with a host-sim regression test. Re-captured `docs/evidence/governor/governor-vm-kill-resume.txt` shows `Velocity / Omega : 0 mrad/tick | 0 mrad/s` after `HA-HOME` + guest kill. |
| L-20 | Verify current titles and judges directly before public use; `docs/plan/03_RESEARCH_LINKS_AND_TECH_STACK.md` clarifies John Wall (President, QNX; listed as "QNX CEO" on Devpost) vs BlackBerry CEO John Giamatteo. |
| NEW-1 | **Code/gate resolved; `LATENCY.md` re-capture pending uncontended host:** Ported saturated quarter index + derived `LATCH_LATENCY_OCTAVES`/`LATCH_LATENCY_DOMAIN_CYCLES` + `_Static_assert` into `qnx/latch_protocol.h`, added `qnx/latch_latency_test.c`, wired `latch-latency-check` into `qnx/Makefile`, and ported `verify_latency_bucket_invariant()` + 5 mutations. A 35-minute target soak ran 2,113,353 ticks (`p50 [768, 1024) >= min 207`), but `verify_latency_qemu.py` rejected archiving it (`687.7/s` vs `855..945 Hz`) due to host RAM/swap contention (`12 GiB` RAM + `22 GiB` swap used). Re-run `make -C qnx evidence-governor-latency` on an uncontended host to replace the stale `2026-11-27` `LATENCY.md`. |

## Verification status

- **Host-sim, ASan/UBSan, Fuzz, Attacks:** `make -C qnx host-sim check demo-syringe check-governor check-asan fuzz` (all **17** ASan/UBSan suites + 300 fuzz runs) and `PYTHONPATH=tools python3 tools/attacks/run_attacks.py` (8/8 attacks, 132 ticks, 0% breaches; Attack A2 prints `0x8080` = `LATCH_FAULT_RATE | LATCH_FAULT_DOSE`) all PASS.
- **Target QEMU captures (2026-11-28):** `evidence-governor-qemu` (`governor-qemu-verify.txt` + `governor-qemu-console.txt`), `evidence-governor-feedback` (W4 + W5 with `guest/latch_fb_publish.h` AArch64 `dmb` barriers), `evidence-governor-vm-kill`, `verify-governor-qemu`, and `verify-fbverdict-qemu` all PASS with `M-10` enforced `secpol`.
- **Consistency & Mutation gates:** `tools/consistency_check.py` uses `_run_compiler()` with `CCACHE_DISABLE=1` and `.github/workflows/ci.yml` sets `CCACHE_DISABLE: "1"`. `verify_latency_bucket_invariant()` passes on the C code/round-trip test and intentionally flags the stale `2026-11-27` `LATENCY.md` until `make -C qnx evidence-governor-latency` completes within the `900 Hz ±5%` rate band.
- **Human submission blockers:** Sign `docs/MANUAL_ACCEPTANCE.md`, record/upload the <3:00 YouTube video, verify Pi 4B BSP ID in QSC (or exclude hardware claim), and submit Devpost (with Codelab URL field per `qnx.devpost.com/rules`).
