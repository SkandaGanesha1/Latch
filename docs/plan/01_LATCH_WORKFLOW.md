# 01 — LATCH Current Workflow: Microkernel Runtime Assurance on QNX SDP 8.0

**Generated:** 2026-11-23  
**Status:** Validated Reference Architecture (LATCH v8 + GOVERNOR)  
**Target Platform:** QNX SDP 8.0 (`procnto-smp-instr`) + QNX Hypervisor 8.0 (QEMU AArch64 `virt` & Raspberry Pi 4B)

---

## 1. Executive Summary & Identity

LATCH (Last Authority for Trusted Control Handoff) is an open-source, mixed-criticality runtime assurance and safety supervisor built natively for **QNX SDP 8.0**. It enforces strict spatial and temporal separation between untrusted physical AI planning components and trusted real-time actuation.

An untrusted guest (running inside an isolated Linux 6.12 guest VM or userspace planning agent) proposes 32-byte motion frames over an unprivileged virtio-console black channel. An unprivileged bridge (`latch-ingest`) validates frame framing, CRC32, and message kinds, forwarding proposals via fixed-size native QNX message passing (`/dev/latch/proposal`) to a trusted supervisor (`latchd`). `latchd` is a `SCHED_FIFO` priority 63 ability-locked resource manager pinned to CPU 0, and is **the only process possessing the `latch/actuator` ability required to command the physical or simulated actuator**.

The governing principle: **The AI may propose; only QNX moves.**

---

## 2. Microkernel Architecture and Trust Boundaries

```
┌────────────────────────── QEMU AArch64 virt (TCG) ──────────────────────────┐
│  QNX 8.0 IFS (mkifs) — EL2 host, secpolpush-enforced policy                 │
│                                                                              │
│  SAFETY DOMAIN (Core 0, SCHED_FIFO 63)               AI DOMAIN (Cores 2-3)   │
│  ┌──────────────────────────────────────┐       ┌───────────────────────┐  │
│  │ latchd  (Resource Manager, priority  │       │ qvm  (QNX Hypervisor  │  │
│  │  63, ThreadCtl runmask, 1 kHz tick)  │◄─pipe─┤  8.0 payload in IFS)  │  │
│  │   ├─ /dev/latch/proposal (0666 sink) │       │  ┌─────────────────┐  │  │
│  │   ├─ /dev/latch/actuator (0600 devctl│ vdev  │  │ Linux 6.12 guest │  │  │
│  │   │   requires 'latch/actuator')     │virtio-│  │  /init (PID 1)   │  │  │
│  │   ├─ Ring: 256-slot lockless ring +  │console│  │  v2 235-frame    │  │  │
│  │   │   atomic Seqlock fencing         │       │  │  adversarial     │  │  │
│  │   ├─ GOVERNOR: 6-rung ladder FSM +   │       │  │  attack suite    │  │  │
│  │   │   DT-CBF keep-out enforcement +  │       │  └─────────────────┘  │  │
│  │   │   coherence lease + rate limiter │       └───────────────────────┘  │
│  │   ├─ Blackbox: 4096-entry event ring │                                  │
│  │   │   out-of-band devctl 0x44 dump   │   latch-ingest (unprivileged,    │
│  │   └─ PCA9685 I2C driver (mock-mode)  │    drops abilities, Core 1)      │
│  └──────────────────────────────────────┘                                  │
│  latchctl (admin CLI, ability-gated) · latchlog (continuous tape persistence)│
└──────────────────────────────────────────────────────────────────────────────┘
```

### Key Safety Invariants Enforced by QNX 8.0
1. **Spatial Isolation (`secpolcompile` / `secpolpush`)**:
   - `latchd` runs with ability `latch/actuator`.
   - `latch-ingest` drops all root privileges and abilities immediately after initialization.
   - The untrusted AI guest (`qvm`) is confined to unprivileged EL0 guest execution; direct I/O memory and interrupts are inaccessible.
2. **Temporal Determinism (`ThreadCtl` / `ClockCycles`)**:
   - `latchd` pins its decision thread to Core 0 (`ThreadCtl(_NTO_TCTL_RUNMASK, 0x01)`).
   - Operates strictly at `SCHED_FIFO` priority 63.
   - Non-blocking 1 kHz tick loop backed by QNX monotonic `timer_create(CLOCK_MONOTONIC)`.
3. **Fail-Closed Default**:
   - Any corrupt CRC, out-of-order sequence, Keep-Out envelope intrusion, or expired liveness lease trips microkernel fault bits (`LATCH_FAULT_*`) and drives the ladder to `HOLD` or `LATCH`.
