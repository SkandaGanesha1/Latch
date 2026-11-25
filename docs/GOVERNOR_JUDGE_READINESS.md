# GOVERNOR Judge Readiness and Claim Ledger

**Checkpoint:** 2026-11-18  
**Target actually tested:** Installed QNX SDP 8.0.0 AArch64 IFS under QEMU TCG 11.1.3, with the QNX Hypervisor payload in the IFS and a Linux 6.12 guest. This is an experimental host combination, not a QNX-supported Hypervisor platform claim.  
**Purpose:** Keep submission claims traceable to a build, source path, or runtime assertion.

## Verified in the current checkout

| Judge question | Evidence in source or command | Claim we can make |
|---|---|---|
| Does the safety gate run on QNX? | `qnx/latchd.c`, QNX resource manager and devctl paths; `make ifs-qemu-governor`; `python3 tools/verify_governor_qemu.py`; `docs/evidence/governor/governor-qemu-console.txt` | VERIFIED: GOVERNOR path built into a QNX 8.0 image and exercised under QEMU TCG. Full boot transcript and supervisor status telemetry archived in `docs/evidence/governor/governor-qemu-console.txt` (232 KB) and `docs/evidence/governor/governor-status-transition.txt`. |
| Is the guest separated from actuator authority? | `qnx/latch_qemu_governor.qvmconf`, `latch_qemu_governor.build`, ingest-to-resource-manager boundary | VERIFIED: Linux guest supplies a byte stream through the QNX pipe/ingest path. Only `latchd` writes the mock actuator. |
| Does the governor detect loss of liveness? | Manifest lease plus guest A4 scripted 110 ms silence; runtime verifier checks rung demotion; `docs/evidence/governor/governor-qemu-console.txt` | VERIFIED: A delayed guest heartbeat caused lease-based demotion in this run (HP -> ADVISE). Observed in target console at rx=5 (`lease age 8 ticks` of a fresh 100-tick lease — renewed by the recovery command, while the rung stayed ADVISE with recovery credit at 0) and host simulation `docs/evidence/governor/governor-tape.csv:21-99`. |
| Can health chatter recover authority? | 150 heartbeat-only frames; `clean_command_streak` status; ladder implementation; `docs/evidence/governor/governor-status-transition.txt` | VERIFIED: Heartbeats renew liveness lease but do not count as clean recovery commands. Rung remained strictly ADVISE with `recovery=0` across 150 consecutive heartbeat frames (rx=6..155). |
| Can the system recover? | 25 fresh coherent v2 commands; runtime verifier observes HP with command-derived movement; `docs/evidence/governor/governor-tape.csv` | VERIFIED: Clean accepted commands promoted the GOVERNOR rung from ADVISE back to HP after exactly 25 frames (rx=156..180). Actuator motion resumed within bounded limits. |
| What happens after final silence? | Guest sends no frames; verifier checks HEARTBEAT fault and LATCH rung; `docs/evidence/governor/governor-status-transition.txt` | VERIFIED: Final lease expiry reached fail-closed LATCH (HOLD mode) with `LATCH_FAULT_HEARTBEAT` (0x2000) latched. Plant held stationary. |
| Are adversarial attacks detected fail-closed? | `tools/attacks/run_attacks.py`, `docs/evidence/governor/governor-host-sim.txt`, `docs/evidence/governor/governor-metrics.txt` | VERIFIED: Attacks A1 (rogue unit), A2 (rate flood), A3 (prompt injection), A4 (deadman), A5 (coherence spoof), A6 (sequence replay), and A7 (chain tamper) all detected across 121 ticks with 0% keep-out breach rate. |
| Does the architecture satisfy safety standards? | Project evidence and source | No certification or standards conformance has been established; this is a prototype using QNX resource management and a simulated syringe contract. |
| Is event ring forensics tamper-evident? | `qnx/latchd.c:2125, 2460, 2945, 2961`, `qnx/latch_protocol.h:382` (`DCMD_LATCH_DUMP_GOV_EVENTS`), `tools/gov_replay.py`, `make check-governor` | VERIFIED: 4096-entry circular event ring and out-of-band devctl 0x44 dump on target; the manifest-bound rolling SHA-256 chain is computed offline by `gov_replay.py` over that dump and passes 12 standalone and end-to-end cryptographic integrity tests. |
| Can GOVERNOR enforce medical infusion safety? | `qnx/contracts/syringe_governor.manifest`, `qnx/gov_gate_precheck.c:55` (`gov_medical_check()`), `tools/governor_e2e.py` scenario 7 | VERIFIED: Integer-microlitre schema-3 contract enforces `LATCH_FAULT_DOSE` (bit 15), clamping over-infusion attempts and driving ladder degradation. |
| Did the upgrade alter legacy behavior? | `python3 tools/verify_qemu_aarch64.py` on default schema-2/protocol-v1 IFS; native `latch_verify` reported `VERIFY_RC=0`; `make check` retains 200-tick suite | VERIFIED: The separate legacy QEMU profile passed its existing 84-frame suite and native assertions; 200-tick host simulation retains exact signature (`rx=200 | wire=12 | env=7 | eperm=1`). |
| Are metadata and frames generic? | Schema-3 manifest parser, rational unit declarations, v2 wire decoder and malformed-contract tests | VERIFIED: The checked-in contract supplies supported units, limits, and thresholds; unknown/malformed fields are rejected. This does not mean arbitrary unrecognized metadata is accepted. |

## Not implemented or not proven

- No llama.cpp model is currently in the guest path. The demonstrated 235-frame scenario is deterministic scripted input, which makes the attack/recovery sequence repeatable; it is not live LLM inference.
- The QEMU profile runs with mock I2C. No physical actuator movement, board-level timing, certified WCET, warm-reset persistence, safety certification, or production readiness is claimed.
- QNX Hypervisor under QEMU TCG is an empirical demo configuration. QNX documentation allowing QNX OS targets on QEMU does not certify QEMU as a supported QNX Hypervisor host.
- Guest kernel phase markers after init handoff are best-effort in the QEMU serial capture. The verifier uses live supervisor status transitions as authoritative A4/recovery evidence and checks only reliable init-handoff markers.
- The archived GOVERNOR QEMU run reports a max decision latency of **80,911 cycles (1,294,576 ns ≈ 1.29 ms)** — above the 1 ms tick period. Under TCG the host QNX, the guest Linux and `latchd` contend for the same physical cores, so this is an emulation-stall observation, not a safety-logic failure and not a WCET. The watchdog fails closed on a late tick; no hard-real-time bound is claimed on this platform.
- The full supplied newsletter/company/social URL collection and private email messages have not been exhaustively audited. Private mailbox content was not available in the workspace.

## Judge-oriented narrative

The strongest demonstrated story is the *boundary*: untrusted guest commands cross an explicit QNX ingest path; a trusted `latchd` owns the contract, lease, validation, rung and actuator decision; a scripted delayed heartbeat provokes degradation; heartbeat-only traffic cannot regain recovery credit; clean validated commands recover it; silence degrades to LATCH. This demonstrates a meaningful QNX 8.0 implementation rather than a Linux-only mock.

Keep claims proportional to evidence. Describe the guest policy as a scripted Linux guest demo, QNX TCG as the tested environment, the actuator as mock I2C, and the loop measurements as observations rather than WCET. Do not reuse certification language from QNX products as a claim about this project.

## Submission checks from official rules

The current [QNX Global Hackathon rules](https://qnx.devpost.com/rules) require a publicly available open-source repository, reproducible build/run instructions naming QNX version, target and toolchain, an explanation of significant updates for a pre-existing project, and a demo video under three minutes showing the project on its intended platform. The rules list the deadline as December 15, 2026 at 2:00 pm Eastern Time; recheck the live page before submission.

The installed SDK reports `8.0.0` in `/home/skanda/qnx800/target/qnx/etc/qversion`; the website's current release notes identify SDP 8.0.6. The successful builds here are therefore specifically evidence for the installed 8.0.0 toolchain, not yet a compatibility build on 8.0.6. The C compiler used was QNX AArch64 GCC 12.2.0; the guest init was built with AArch64 Linux GCC 16.2.1.

QNX's [SDP 8.0 installation guide](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.qnxsdp.quickstart/topic/install_host.html) lists QEMU as a virtual target for QNX OS development. That statement concerns a QNX OS target on QEMU; the tested nested QNX Hypervisor setup is separately labeled experimental. The installed [QNX `mkifs` reference](https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mkifs.html) describes building an OS image filesystem from a buildfile, which is the image-generation path exercised here.
