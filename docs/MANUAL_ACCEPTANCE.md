# Operator acceptance checklist

Status: **not yet executed or signed by a human**. Run commands from the
repository root; record actual output, date, commit and local modifications.
Host checks exercise a simulator, not physical hardware or QNX timing.

| # | Command | Expected result |
|---|---|---|
| 1 | `git status --short` | Record all local modifications. |
| 2 | `git rev-parse HEAD` | Record the tested commit. |
| 3 | `make -C qnx host-sim` | Exit 0; host binaries built. |
| 4 | `make -C qnx check` | Exit 0; tests and 200-tick host simulation pass. |
| 5 | `make -C qnx check-governor` | Exit 0; GOVERNOR tests pass. |
| 6 | `make -C qnx homeostat-e2e-check` | Exit 0; contraction, recovery and default-off checks pass. |
| 7 | `make -C qnx gov-replay-check` | Exit 0; replay and tamper tests pass. |
| 8 | `make -C qnx latch-manifest-check` | Exit 0; parser tests pass. |
| 9 | `make -C qnx latch-feedback-check` | Exit 0; feedback codec tests pass. |
| 10 | `make -C qnx latch-hold-check` | Exit 0; hold ordering tests pass. |
| 11 | `python3 tools/consistency_check.py` | Exit 0 (`CCACHE_DISABLE=1` is set automatically for compiler probes); otherwise record the failure and stop acceptance. |
| 12 | `make -C qnx evidence-check` | Exit 0; archived host signature matches. |

Operator: __________ Date: __________ Commit: __________

Result / failed command / evidence location: ______________________________

For an on-target run, separately record the exact QNX SDK and image, QEMU or
board, command, serial transcript and observable result. Do not sign off on
hardware motion or WCET based on host-sim or QEMU output.
