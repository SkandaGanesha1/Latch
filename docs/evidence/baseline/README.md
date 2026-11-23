# Linux GPOS Baseline Telemetry & Determinism Comparison

This directory contains empirical baseline benchmark measurements conducted on Linux 6.x CFS (Completely Fair Scheduler), providing the baseline against which QNX SDP 8.0's real-time performance and determinism are compared.

## Summary Comparison

| Metric | QNX SDP 8.0 (`SCHED_FIFO 63`, Core 0) | Linux CFS (Idle Workstation) | Linux CFS (Contention / Stress) |
|:---|:---:|:---:|:---:|
| **Target Period** | 1,000 µs (1 kHz) | 1,000 µs (1 kHz) | 1,000 µs (1 kHz) |
| **Max WCET** | **61.08 µs** | 3,644.22 µs | 722,454.07 µs |
| **Median Latency** | **1.00 µs** | 1,093.11 µs | 202,605.46 µs |
| **Deadline Misses** | **0 / 23,500** (0.00%) | 2 / 1,500 (0.13%) | 1,479 / 1,500 (98.60%) |
| **Worst-Case Jitter** | Bounded (< 100 µs) | Multi-millisecond tail | Severe scheduler starvation (> 700 ms) |

## Files
- `linux_baseline_metrics.txt`: Full benchmark stdout and statistical percentiles.
- `linux_baseline_tape.csv`: Raw tick-by-tick latency measurements.
- Benchmark reproduction script: `tools/benchmark_linux_native.py`.
