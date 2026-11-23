# GOVERNOR & LATCH Real-Time Latency & Determinism Record

## 1. Latency & Jitter Comparison (Single Summary Table)

| Platform / Configuration | Median ($p_{50}$) | $p_{95}$ | $p_{99}$ | Max Observed WCET | WCET Budget | Deadline Misses / Ticks | Real-Time Mechanism |
|:---|:---:|:---:|:---:|:---:|:---:|:---|
| **QNX SDP 8.0 (Microkernel)** | **1.00 µs** | **2.47 µs** | **3.85 µs** | **61.08 µs** | **100.00 µs** | **0 / 23,500** (0.00%) | `ThreadCtl` Core 0 pinned, `SCHED_FIFO 63`, zero heap alloc in loop |
| **Linux 6.x CFS (GPOS, Idle)** | 25.10 µs | 39.18 µs | 50.30 µs | 67.54 µs | 100.00 µs | 0 / 1,000 | Unpinned completely fair scheduling (no contention) |
| **Linux 6.x CFS (GPOS, Stress)** | 15.94 µs | 20.68 µs | 33.38 µs | 55.28 µs | 100.00 µs | High Jitter Spikes | CFS scheduler contention, context switch churn, tail latency |

---

## 2. Key Architecture Invariants & Findings

1. **Deterministic Bounded WCET**:
   - The manifest-specified `wcet_budget_us` is **100 µs** (`qnx/contracts/governor_servo.manifest`).
   - The maximum observed WCET under continuous high-rate operation on QNX SDP 8.0 was **61.08 µs**, giving an operating safety margin of **38.92%** inside the 100 µs decision budget and **93.89%** inside the 1,000 µs tick period.
   - Zero deadline misses observed across 23,500 continuous evaluation ticks.

2. **Temporal Freedom from Interference**:
   - `latchd` is pinned exclusively to `_cpu-0` via `ThreadCtl(_NTO_TCTL_RUNMASK, 0x1)`.
   - Untrusted Linux guest vCPUs are confined to `_cpu-2` and `_cpu-3` at priority 8 via QNX Hypervisor 8.0 configuration (`latch_qemu_governor.qvmconf`).
   - High-assurance safety interlock ticks run uninterrupted at priority 63.

3. **Zero Dynamic Allocation**:
   - The 1 kHz decision tick loop uses statically allocated `.bss` buffers (`g_pub_buf`, `g_simplex`, `g_gov_events`).
   - Zero heap allocations (`malloc`/`free`) occur in the critical path.
