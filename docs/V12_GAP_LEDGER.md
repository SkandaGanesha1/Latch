# v12 audit reconciliation

The v12 audit is a snapshot, not a test report for the current working tree.
Use the commands below and fresh target logs when making claims. The QEMU
profile uses mock I2C; it does not demonstrate physical actuation.

| Finding | Current evidence or action |
| --- | --- |
| L-1 anchors | `tools/update_api_index.py --check` is already in CI. Regenerate after source edits with `--write`, then run `--check`. |
| L-2 writer ownership / A8 | QNX QEMU test with the enforced policy and guest disabled: a second process received `EBUSY` while the first held the proposal node; opening succeeded after close. This does not prove concurrent race, abnormal process termination, or live guest takeover behavior. |
| L-3 session flush race | Atomic tail update and a simulated interleaving check exist in `qnx/latchd.c`; target concurrency and counter wrap remain separate checks. |
| L-4 strict keys | Review and execute the manifest negative suite against every contract section; do not infer full coverage from the existence of individual tests. |
| L-5 operator release | Release state and devctl bookkeeping exist in `qnx/latchd.c`; validate behavior across rung changes and the actual CLI. |
| L-6 low-severity findings | Recheck tape index wrap, ability flag symmetry, cycle conversion overflow, shared resource-manager attributes, manifest sidecar TOCTOU, and `latchlog` fallback individually. Their presence in an old audit is not proof of current status. |
| L-7 retained invariants | Re-run `make -C qnx check` and manifest, gate and replay tests; tests cover the exercised inputs, not all possible behavior. |
| D-1 / D-6 timing | Historical questionable latency and baseline evidence is quarantined. A TCG maximum is an observation, not WCET; no million-sample target distribution is established by this ledger. |
| D-2 / D-3 contract documentation | Compare fault names against `qnx/latch_protocol.h` and HOMEOSTAT behavior against `qnx/gov_homeostat.c` whenever those interfaces change. |
| D-4 VM-kill capture | The historical `governor-vm-kill-resume.txt` labels its platform as QNX OS for Safety although its next line names SDP. Treat the product label as unverified until a fresh capture identifies the actual image. |
| D-5 / D-8 repository tree and profile | Check README against actual files; GOVERNOR's experimental profile label describes its validation scope. |
| D-7 Pi image substitution | `qnx/latch_rpi4.build` currently uses `$(GUEST_IMAGE)`; target build and substitution must be verified with its actual mkifs invocation and BSP. |
| M-1 / M-8 / M-9 submission | Video publication, external metadata and a fresh timed codelab execution require their respective evidence; scripts alone do not prove completion. |
| M-2 / M-3 measurements | Preserve measurement configuration, source/build identity, raw samples and failed runs. Linux and QNX results require matched workload and explicit environment before comparison. |
| M-4 security policy | A separate unrestricted generator image produced a delta, errors and unused-rule reports after the 235-frame guest scenario. The delta contains additional requested permissions and type transitions and requires security review; no generated rules have been accepted or deployed. The exercised workload is not comprehensive. |
| M-5 physical Pi | No physical-board result follows from QEMU; record hardware access and actual run separately. |
| M-6 / L-15 guest model and feedback | A host model helper and feedback codec do not establish live guest inference or a working guest feedback loop. Trace and exercise the full target path before claiming either. |

The source documents are `/home/skanda/Downloads/12_CROSS_VERIFICATION_AND_LOOPHOLE_AUDIT_v12.md`, `13_MANUAL_HUMAN_TEST_PLAN_v12.md`, `14_IMPLEMENTATION_PLAN_v12.md`, and `15_RESEARCH_SOURCES_AND_LINKS_v12.md`. This ledger identifies open verification work; it is not a substitute for archived command output.

To repeat the QNX QEMU checks, source the SDP environment, run `make -C qnx ifs-qemu-writer-test ifs-qemu-audit-probe GUEST_IMAGE=/absolute/path/to/linux/Image`, then run `python3 tools/run_target_probe.py writer` and `python3 tools/run_target_probe.py audit`. Raw console logs and generator outputs are written under `qnx/build/`, which is a disposable build directory. The audit image runs unrestricted and must never be deployed.
