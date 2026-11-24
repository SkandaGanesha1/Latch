# QNX scheduling and stack measurement notes

**Scope:** engineering notes for the LATCH prototype; not a safety case or
target qualification report.

## APS status and scheduling choice

QNX OS 8.0 does not support adaptive partitioning: the `aps` configuration
keyword only works on QOS 2.2.x, and "the feature is not supported in SDP
8.x" (QNX QPLMS User's Guide, *QPLMS usage differences between QOS 2.2.x and
SDP 8.x environments*). The QNX Momentics IDE User's Guide 8.0 says the same
thing for the IDE's APS view. LATCH does not claim to use APS.

What LATCH actually uses for determinism is `SCHED_FIFO` thread priorities,
`ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT)` core pinning, and the
hypervisor's static vCPU runmask. The current design configures thread
priorities and CPU affinity where supported, and uses the supervisor's
monotonic timer/tick accounting for lease and planner-freshness deadlines.
These settings are configuration and source facts; they do not by themselves
establish deadline guarantees under a loaded target.

Sporadic scheduling is a distinct QNX scheduling policy, not an APS substitute
that can be inferred from the current `SCHED_FIFO` configuration. It is not
claimed as implemented, and no sporadic scheduling call appears in the source.
Before adopting it, specify the replenishment budget, low priority, and
maximum replenishment count for each relevant thread, then measure interference
and deadline behavior on the supported board.

For execution-time observations, QNX thread runtime clocks can measure runtime
for a selected thread, but no per-thread runtime clock is used by the shipped
supervisor: the measurements in `docs/evidence/` are wall-clock observations
from the decision loop's own timestamps. A runtime-clock sample would be an
observation over the measurement interval, not a worst-case execution-time
proof. Any report must identify the QNX release, board, compiler, workload,
clock source, sample count, and measurement interval. QEMU TCG and
host-simulation timings are emulation/simulation observations and must remain
separate from physical target measurements.

## Stack usage

`make -C qnx stack-usage` compiles the supervisor's translation units with the
selected compiler and `-fstack-usage`, and concatenates the compiler's
per-function `.su` reports into `qnx/build/stack-usage/host-static-stack-usage.txt`.
The result is a compiler-reported static frame estimate for each compiled
function. It is useful for spotting large frames, but it does not sum
transitive call chains, include interrupt/exception context, or predict
QNX/AArch64 compiler output. It is not a runtime high-water mark.

Measured on the default host-sim build (x86_64, host GCC 16.2.1):

| Function | Frame | Where it runs |
|---|---:|---|
| `latch_run_self_tests` | 20,816 B | the host-sim self-test entry point only — **not** on the 1 kHz tick path |
| `latch_export_events_json` | 4,304 B | the offline `latchctl events` dump — not the tick path |
| `main` | 624 B | process startup |
| `latch_simplex_tick` | **352 B** | **the 1 kHz decision tick** |
| `latch_check_envelope` | 112 B | called from within the tick |

The tick path's own frame is small. The two large frames belong to
diagnostic-only code that the 1 ms decision loop never enters. These are
host-sim figures from a different compiler on a different architecture; the
AArch64 numbers must be measured with the QNX toolchain (source
`~/qnx800/qnxsdp-env.sh`, then `make -C qnx stack-usage TARGET=aarch64`).

The project does not currently claim an exact stack high-water measurement.
Do not infer one from a canary value or a filled-stack scan unless the
instrumentation, sampling point, stack ownership, and interrupt treatment are
defined and validated. For a target runtime observation, use QNX-supported
profiling/debugging facilities on a fresh matching-toolchain image and archive
the tool version, target configuration, workload, raw output, and interpretation.

## References

- [QNX SDP 8.0 discontinuation notice](https://qnx.com/developers/docs/relnotes8.0/com.qnx.doc.discontinuation_notice/topic/general.html)
- [QNX sporadic scheduling](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/overview_Sporadic_scheduling.html)
- [QNX execution-time measurements and runtime clocks](https://qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.prog/topic/timing_execution_times.html)
