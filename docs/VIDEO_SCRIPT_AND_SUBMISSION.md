# LATCH / GOVERNOR — Video Script & Submission Index

> [!NOTE]
> **SUPERSEDED:** This legacy document has been consolidated into the authoritative 3-minute video storyboard:
> **[`docs/DEMO_VIDEO_SCRIPT.md`](DEMO_VIDEO_SCRIPT.md)**
>
> Please refer to `docs/DEMO_VIDEO_SCRIPT.md` for the complete time-coded storyboard, narration script, and visual layout.

---

## 1. Quick Reference

* **Canonical 3-Minute Demo Video Script:** [`docs/DEMO_VIDEO_SCRIPT.md`](DEMO_VIDEO_SCRIPT.md) (Duration: 2:35, ~365 words)
* **Devpost Submission Narrative & Claims:** [`docs/DEVPOST_SUBMISSION.md`](DEVPOST_SUBMISSION.md)
* **Judge Verification & Evidence Ledger:** [`docs/GOVERNOR_JUDGE_READINESS.md`](GOVERNOR_JUDGE_READINESS.md)
* **Evidence Directory Index:** [`docs/evidence/README.md`](evidence/README.md)
* **Adversarial Attack Suite (7/7):** `python3 tools/attacks/run_attacks.py`
* **On-Target QEMU Demonstration:** `python3 tools/verify_governor_qemu.py`
* **Hypervisor Containment Demo:** `python3 tools/qemu_guest_kill.py`
* **Latency-Tape Summarizer (not a benchmark):** `python3 tools/benchmark_qnx_vs_linux.py` — summarises a recorded tape; it does **not** benchmark QNX.

---

## 2. Judge Definition of Done Checklist

1. **One-command QEMU AArch64 build & boot:** `make -C latch/qnx ifs-qemu-governor` + `python3 tools/verify_governor_qemu.py`
2. **Automated end-to-end QEMU verification:** `python3 tools/verify_governor_qemu.py` (`[GOVERNOR_QEMU PASS]`)
3. **VM-Kill Containment Experiment:** `python3 tools/qemu_guest_kill.py` (`100% CONTAINMENT`)
4. **Host-sim & second-plant verification:** `CCACHE_DISABLE=1 make -C latch/qnx check check-governor`
5. **Adversarial Evaluation Suite:** `python3 tools/attacks/run_attacks.py` (7/7 attacks PASS, 0% breach rate)
6. **Cryptographic Blackbox Tamper Verification:** `python3 tools/gov_replay.py --test` (12/12 tests PASS)
7. **Architectural & SHA-256 consistency:** `python3 latch/tools/consistency_check.py` (0 errors)
8. **Latency Summary from the Recorded Tape:** `python3 tools/benchmark_qnx_vs_linux.py` — summarises recorded `cycles_in`/`cycles_out` samples from a tape. It does **not** benchmark QNX, and it yields **no** WCET or deadline-miss claim. The accepted latency statement is the GOVERNOR on-target observation (max 80,911 cyc ≈ 1.29 ms, TCG — **not** a WCET).
9. **Offline UI Dashboards:** `latch/host/console.html` and `latch/host/tape.html` (zero external CDN dependencies)
10. **License & Codelab:** `latch/LICENSE` (MIT) + `latch/codelab/`
