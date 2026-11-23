# QNX scheduling and stack measurement notes

**Scope:** engineering notes for the LATCH prototype; not a safety case or
target qualification report.

## APS status and scheduling choice

QNX SDP 8.0 discontinues Adaptive Partitioning Scheduler (APS). LATCH does not
claim to use APS. The current design configures thread priorities and CPU
affinity where supported, and uses the supervisor's monotonic timer/tick
accounting for lease and planner-freshness deadlines. These settings are
configuration and source facts; they do not by themselves establish deadline
guarantees under a loaded target.

Sporadic scheduling is a distinct QNX scheduling policy, not an APS substitute
that can be inferred from the current `SCHED_FIFO` configuration. It is not
claimed as implemented. Before adopting it, specify the replenishment budget,
low priority, and maximum replenishment count for each relevant thread, then
measure interference and deadline behavior on the supported board.

For execution-time observations, QNX thread runtime clocks can measure runtime
for a selected thread. A runtime-clock sample is an observation over the
measurement interval, not a worst-case execution-time proof. Any report must
identify the QNX release, board, compiler, workload, clock source, sample
count, and measurement interval. QEMU TCG and host-simulation timings are
emulation/simulation observations and must remain separate from physical
target measurements.

## Stack usage

`make stack-usage` invokes the selected host compiler with `-fstack-usage` and
writes `qnx/build/stack-usage/host-static-stack-usage.txt`. The result is a
compiler-reported static frame estimate for each compiled function. It is
useful for spotting large frames, but it does not sum transitive call chains,
include interrupt/exception context, or predict QNX/AArch64 compiler output.
It is not a runtime high-water mark.

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
