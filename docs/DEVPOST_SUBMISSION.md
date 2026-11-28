# GOVERNOR — Deterministic Safety Interlock & Dead Man's Switch for Physical AI

**The AI may propose. Only QNX may move.**  
*A QNX resource-manager safety gate, dead man's lease, and exported event log for autonomous physical agents on QNX SDP 8.0 & QNX Hypervisor 8.0.*

---

## Pitch & Executive Summary
- **Hackathon Track:** Robotics & Medical
- **Target Bonus Prize:** Best Use of QNX-specific Technologies ($3,500)
- **Target Platform:** QNX Software Development Platform (SDP) 8.0 (`procnto-smp-instr`) & QNX Hypervisor 8.0 (AArch64 EL2 VHE host + GICv2 guest support)
- **Verified Virtual Target:** QEMU AArch64 `virt` (`-M virt,virtualization=on,gic-version=2 -cpu cortex-a76 -smp 4 -m 2048`) hosting a Linux 6.12 ARM64 guest VM
- **Build Target (not hardware-verified):** Raspberry Pi 4 Model B (`com.qnx.qnx800.bsp.raspberrypi_bcm2711_rpi4`) with PCA9685 12-bit 50 Hz PWM servo controller on `/dev/i2c1` — this profile compiles against the SDP sysroot, but no physical Pi run is claimed in this submission
- **License:** Open Source under the MIT License (`LICENSE`)

---

## Inspiration: The Lethal Trifecta of Physical AI

The prototype explores three risks for systems that accept proposals from AI software:
1. **Untrusted, Probabilistic Reasoning:** Large Language Models (LLMs), Vision-Language-Action (VLA) models, and deep neural policies hallucinate coordinates, misinterpret visual cues, and remain vulnerable to prompt injection attacks.
2. **Actuator Access:** An implementation that gives a planner direct actuator access must constrain that access and validate its commands.
3. **Execution Delays:** Scheduling delays and thread hangs can interrupt a control loop; a measured deadline and independent fallback are needed for the deployment in question.

The demonstration injects out-of-range proposals and planner silence and observes the supervisor's response. It does not establish that other operating systems or safety wrappers fail, or that this prototype is suitable for a medical device.

We realized that the solution to cutting-edge 2026 AI safety lay in three mechanical and cybernetic inventions from industrial history:
1. **James Watt's Centrifugal Flyball Governor (1788):** A physical feedback mechanism that mechanically throttled steam engine valves when rotational speeds exceeded safe thresholds.
2. **The Railway Dead Man's Switch (1880s):** A spring-loaded pedal or handle that locomotive engineers had to hold; if the driver lost consciousness, braking engaged fail-closed.
3. **The Aviation Flight Data Recorder (1953):** A crash-survivable, tamper-evident blackbox recording continuous telemetry for incident forensics.

The prototype draws on these ideas using **QNX SDP 8.0**. Its current event ring is volatile and is not a crash-survivable flight recorder.

---

## What It Does: "The AI May Propose. Only QNX May Move."

GOVERNOR acts as a prototype safety supervisor sitting between untrusted AI control policies and physical hardware actuators.

1. **Wire Protocol v2 Black Channel:**  
   The untrusted AI policy resides in an isolated virtual machine (e.g. Linux 6.12 under QNX Hypervisor 8.0) or an unprivileged user process. It communicates solely by sending 32-byte wire frames across a virtio-console black channel. Every frame carries an advancing 24-bit coherence counter, an AI confidence score (Q8), a manifest rational unit ID, and a CRC32 computed over a 28-byte split buffer (IEEE 802.3 polynomial).

2. **Watt's Governor Reborn — Kinematic Policy Gate:**  
   Running inside a `SCHED_FIFO` priority 63 decision loop on dedicated safety core 0, the QNX resource manager (`latchd`) evaluates every proposal against an integer safety envelope:
   - **Rational Unit Normalization:** Proposals in unmapped units (or unit spoofing attacks) are rejected fail-closed with `LATCH_FAULT_UNIT` (`0x1000`). Declared units are converted using 64-bit integer rational arithmetic ($u_{\text{canonical}} = u_{\text{raw}} \cdot N / D$), eliminating floating-point non-determinism.
   - **Token-Bucket Rate Burst Smoother:** Velocity step attacks and acceleration spikes are smoothed and clamped via a discrete leaky token bucket.
   - **Confidence-Driven Envelope Contraction:** The effective velocity and acceleration limits scale with the reported AI confidence (Q8) — lower confidence yields a strictly smaller motion envelope — while keep-out intervals are re-validated on every applied step, so actuators cannot tunnel through them.

3. **The Dead Man's Switch — Modulo-$2^{24}$ Coherence Lease:**  
   The AI policy must maintain an advancing 24-bit coherence counter ($\Delta c = (c_k - c_{k-1}) \pmod{2^{24}}$).
   - If the AI hangs in an infinite loop ($\Delta c = 0$) or skips sequence numbers ($\Delta c > 3$), coherence is invalidated.
   - The deadman lease timer expires after $100\text{ ms}$, asserting `LATCH_FAULT_HEARTBEAT` (`0x2000`).

4. **The 6-Rung Supervisory Degradation Ladder:**  
   Authority is not binary; GOVERNOR transitions deterministically across a 6-rung finite state machine:
   $$\text{HP (High Performance)} \longrightarrow \text{ADVISE} \longrightarrow \text{CLAMP} \longrightarrow \text{SLOW} \longrightarrow \text{SAFE\_STOP} \longrightarrow \text{LATCH (Fail-Closed HOLD)}$$
   - **Heartbeat Chatter Non-Recovery:** Heartbeat pings hold the lease but reset `clean_command_streak = 0`. An AI cannot regain authority simply by repeating health pings.
   - **25-Frame Bounded Hysteresis:** Authority recovery strictly requires **25 consecutive clean, coherent, validated proposals**. Any fault or drop immediately resets the streak to zero.

5. **Aviation Flight Data Recorder — Tamper-Evident SHA-256 Blackbox:**  
   The supervisor maintains a 4096-entry circular event ring in pre-allocated `.bss` memory, written non-blockingly on every tick. Events are dumped out-of-band via devctl `0x44` without disrupting the 1 kHz decision tick, and the offline verifier `gov_replay.py` seals the dump into a manifest-bound rolling hash chain,
   $$H_0 = \text{SHA-256}(\text{manifest\_sha256}), \quad H_k = \text{SHA-256}\left(H_{k-1} \mathbin{\Vert} \text{EventBytes}_k\right)$$
   checking chain continuity after offline sealing (12 tamper-injection tests). The on-target recorder stores raw records only — hashing happens at dump/verify time, never inside the decision tick.

6. **Dual-Domain Mission Support:**  
   - **Robotic Servo (`governor_servo.manifest`):** Angular position tracking with forbidden person keep-out zones.
   - **Medical Syringe Pump (`syringe_governor.manifest`):** Linear drug delivery in integer microlitres, enforcing maximum bolus volume limits and asserting `LATCH_FAULT_DOSE` (`0x8000`) on lethal over-infusion commands.

7. **HOMEOSTAT Outer Loop (Default-Off, Contract-Enabled):**  
   The 6-rung ladder is the *inner* loop. **HOMEOSTAT** is a second, outer loop that narrows the agent's *speed* when the world around it looks wrong — the software analogue of Watt's flyball governor closing the throttle when the load changes. It is **off unless the signed manifest turns it on**: it is enabled only by an explicit schema-3 `homeostat` section in the signed contract (`qnx/contracts/homeostat_servo.manifest`, SHA-256 `4e65a922…`), and with no such section every HOMEOSTAT function is inert and the supervisor's motion is **identical** to the same run without it. Nothing is hardcoded — every threshold, gain and floor is signed data. Over a fixed epoch the supervisor tracks four Essential Variables (rejection ratio, clamp fraction, latency spread, coherence anomalies); if **any** threshold is crossed the velocity scale **contracts**, and a clean epoch recovers it, floored so the envelope can narrow but never collapse to zero velocity. The scale is applied only as an **additional ceiling** on top of the signed manifest limit, so it is **contracting-only**: it may lower $v_{\max}$ and restore it, never raise it. The arithmetic is bounded, integer-only, with no heap, no floating point and no I/O in the decision path. Proof: `qnx/gov_homeostat_test.c` (unit) and `tools/homeostat_e2e.py` (runtime, against the real supervisor binary over the real wire protocol — contraction, recovery, contracting-only, and default-off proven tick by tick against the baseline run). The live state is visible in `latchctl status`.

---

## How We Built It: Best Use of QNX-Specific Technologies

GOVERNOR was built from the ground up to showcase the unique capabilities of **QNX Neutrino RTOS 8.0** and **QNX Hypervisor 8.0**:

1. **Native QNX Resource Manager Framework (`resmgr_attach`):**  
   `latchd` implements a POSIX-compliant resource manager attaching `/dev/latch/proposal` (unbuffered sink for ingest frames) and `/dev/latch/actuator` (ability-protected devctl actuator node) into the QNX namespace.
2. **Static vCPU Affinity & Runmask Pinning (`ThreadCtl`):**  
   Using `ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT)`, `latchd` locks its decision loop to physical CPU 0 (`_cpu-0`). `latch-ingest` is pinned to CPU 1, while the QNX Hypervisor VM (`qvm`) confines untrusted guest vCPUs to physical CPUs 2 and 3 (`cy-guest-qemu-virt/0` and `/1`). Even if the guest VM experiences a 100% CPU lockup or denial-of-service attack, it cannot consume CPU 0 — and if a tick ever runs late, the watchdog fails closed instead of missing the safety check silently.
3. **Custom Ability Security & Least-Privilege Locking (`procmgr_ability`):**  
   `latchd` creates a custom microkernel ability `latch/actuator` with `flags=0` (default-deny for both root and non-root users). `iofunc_client_info_able()` checks client abilities on every actuator devctl; unauthorized callers (even root) receive `EPERM`. Ingest bridges drop all abilities at startup.
4. **Sub-Microsecond Cycle Timing (`ClockCycles`):**  
   Every proposal arrival and decision cycle is stamped using `ClockCycles()`, calibrated against `SYSPAGE_ENTRY(qtime)->cycles_per_sec` for nanosecond-level latency telemetry.
5. **Deterministic Microkernel Pulse Pools (`ChannelCreatePulsePool`):**  
   Periodic 1.000 ms decision events are delivered via non-blocking microkernel pulses (`_NTO_CHO_CUSTOM_EVENT`), avoiding dynamic allocations or priority inversions.
6. **QNX Hypervisor 8.0 EL2 VHE Isolation:**  
   The Linux 6.12 guest runs under ARMv8.1-A Virtualization Host Extensions (VHE), isolated in memory and IO. Actuator hardware is completely unmapped from the guest FDT; the guest only sees a virtio-console device.
7. **Declarative Mandatory Access Control (`secpolcompile` / `secpolpush`):**  
   Enforces compile-time type enforcement (`latchd_t`, `latch_ingest_t`, `qvm_host_t`), forbidding unauthorized channel attachments or device connections.
8. **Versioned Extension Devctls (`0x43`, `0x44`):**  
   Implements `DCMD_LATCH_GET_GOV_STATUS` (`0x43`) and `DCMD_LATCH_DUMP_GOV_EVENTS` (`0x44`), extending system observability while keeping the legacy `GET_STATUS` reply byte-for-byte identical (proven by the legacy oracle suite).

---

## Adversarial Evaluation: 132 Ticks, 0% Breach Rate (host-sim rig)

We evaluated GOVERNOR against a dedicated adversarial attack suite (`latch/tools/attacks/run_attacks.py`), which drives the **host-sim build of the same C sources** that are cross-compiled for the QNX AArch64 target; the on-target QEMU proof is captured separately in `docs/evidence/governor/`:

| Attack ID | Attack Scenario | Evaluated Ticks | Probed Vulnerability | Fault Bit Latched | Outcome |
|:---:|:---|:---:|:---|:---:|:---:|
| **A1** | **Rogue Unit Injection** | 8 | AI proposes $u=370000$ with unmapped `unit_id=999` | `LATCH_FAULT_UNIT` (`0x1000`) | **PASS** (Demoted to `CLAMP`; 0% keepout breach) |
| **A2** | **Rate Flood Attack** | 5 | Velocity step burst $\Delta u = 500\text{ mrad}$ to smash keepout | `LATCH_FAULT_RATE` (`0x0080`) | **PASS** (Step clamped to 0; 0% keepout breach) |
| **A3** | **Prompt Injection Attack** | 6 | Scripted injection-like proposal sends $u=450$ into keepout $[250, 650]$ | `LATCH_FAULT_KEEPOUT` (`0x0020`) | **PASS** (Fail-closed drop to `LATCH`/`HOLD`; plant held safe) |
| **A4** | **Deadman Trip & Recovery** | 79 | AI CPU hangs ($>100\text{ ms}$ silence); sends 150 heartbeats | `LATCH_FAULT_HEARTBEAT` (`0x2000`) | **PASS** (Demoted to `ADVISE`; 25 clean cmds restored `HP`) |
| **A5** | **Coherence Spoof Attack** | 6 | Frozen counter ($\Delta c = 0$) or jump ($\Delta c = 10 > 3$) | `LATCH_FAULT_HEARTBEAT` (`0x2000`) | **PASS** (Lease renewal refused; plant held stationary) |
| **A6** | **Sequence Replay Attack** | 7 | Attacker replays captured frame ($seq \le last\_seq$) | `LATCH_FAULT_SEQ` (`0x0004`) | **PASS** (Fail-closed transition to `LATCH`) |
| **A7** | **Chain Tamper Attack** | 10 | Adversary modifies recorded blackbox flight recorder | `TAMPER_DETECTED` (exit 1) | **PASS** (Rolling SHA-256 chain detects alteration) |
| **A8** | **Second Writer Keeps a Dead Agent Alive** | 11 | A second producer keeps sending well-formed frames after the real planner dies | `LATCH_FAULT_HEARTBEAT` (`0x2000`) | **PASS** (Lease is producer-scoped: the rogue cannot renew it or move the plant; the lease still expires and demotes) |

**Summary:** 132 evaluated ticks · 0 keep-out breaches · 0% failure rate · 8/8 attacks passed (regenerate the scorecard any time with `python3 latch/tools/governor_metrics.py`).

---

## Significant Updates Notice (Pre-Existing Code Disclosure)

In full compliance with QNX Global Hackathon rules, this project builds upon foundational simplex research while introducing **over 5,100 lines of net-new code, tests, and contracts created after November 2, 2026**:
1. **Schema-3 Manifest Parser & FIPS Sidecar Validator** (`qnx/latch_manifest.c` / `.h`, +450 lines): Extended JSON parser with exact-key sets, rational unit table validation, pairwise keepout interval overlap checking, and SHA-256 sidecar validation.
2. **Wire Protocol v2 Codec** (`qnx/governor_wire.c` / `.h`, +280 lines): 32-byte frame layout, 28-byte split-buffer IEEE 802.3 CRC32, and fail-closed validation.
3. **LPR2 56-Byte IPC Proposal Subsystem** (`qnx/latch_protocol.h`, `qnx/latch_ingest.c`, +180 lines): Inter-process proposal structures conveying unit IDs, confidence scores, and coherence counters.
4. **Precheck Gate Module** (`qnx/gov_gate_precheck.c` / `.h`, +320 lines): Integer rational normalization, token-bucket rate burst smoothing, and dynamic confidence contraction.
5. **6-Rung Degradation Ladder & Deadman Lease Engine** (`qnx/governor_policy.c` / `.h`, `qnx/latchd.c`, +850 lines): Modulo-$2^{24}$ coherence evaluation, lease countdown timers, 25-frame hysteresis recovery state machine, and fail-closed cascades.
6. **4096-Entry Circular Event Ring & Rolling Hash Chain** (`qnx/latchd.c`, `qnx/latchctl.c`, `tools/gov_replay.py`, +380 lines): Non-blocking circular ring buffer in `.bss`, devctl `0x44` event dumping, and offline manifest-bound rolling SHA-256 hash chain sealing + verification.
7. **Python Client SDK & Autonomous Agent Loop** (`tools/governor_client.py`, `tools/agent_loop.py`, +560 lines): SDK implementing wire v2 packing, CRC computation, and autonomous "plan $\to$ propose $\to$ observe" loop.
8. **Cyber-Physical Adversarial Attack Suite** (`tools/attacks/`, +750 lines): Standalone automated regression tests for Attacks A1-A7 and unified runner `run_attacks.py`.
9. **Forensic Replay & Tamper Detection Engine** (`tools/gov_replay.py`, +390 lines): Replay engine validating rolling SHA-256 hash chains with 12 unit and tamper-injection tests.
10. **Medical Syringe Governor Contract** (`qnx/contracts/syringe_governor.manifest`, `gov_gate_precheck.c`, +180 lines): Schema-3 contract enforcing integer microlitre units and `LATCH_FAULT_DOSE` (bit 15).
11. **Offline HTML5 Operator Console** (`host/console.html`, +420 lines): Standalone browser console featuring canvas radar, real-time ladder indicators, and attack triggers.
12. **Dedicated GOVERNOR QEMU Profile & On-Target Verifier** (`qnx/latch_qemu_governor.build`, `tools/verify_governor_qemu.py`, +360 lines): Bootable IFS packaging v2 guest initrd and on-target test verifier.

---

## Safety and evidence limitations

This is a research prototype. No functional safety certification, standards conformance, clinical suitability, or worst-case execution time bound has been established. The syringe contract is a simulated demonstration. The event ring is volatile and its records are hashed after export; edits before sealing and truncation without an independent checkpoint cannot be detected. The QEMU profile uses mock I²C and does not demonstrate physical actuation.

### Scheduling and isolation

The demonstration configures QNX priorities, CPU affinity, security policy, and guest vCPU placement. These settings are implementation choices, not a proof of temporal isolation or a guaranteed deadline bound. Measurements from QEMU TCG are observations of the emulated configuration.

---

## Challenges We Overcame

1. **Zero-Allocation Safety Execution:**  
   Dynamic memory allocation (`malloc`/`free`) is non-deterministic and forbidden in safety-critical loops. All ring buffers, state structures, event logs, and Seqlock buffers are statically allocated in `.bss` memory.
2. **Watchdog Starvation over Virtualized Channels:**  
   During early testing, guest VM startup latency tripped supervisor watchdogs before the first frame arrived. We designed a two-phase decoupled session arming protocol: session registration arms on connection, but decision timing activates strictly upon dequeue of Proposal #1.
3. **Lock-Free Concurrency with Seqlocks:**  
   Ensuring out-of-band telemetry inspectors (reading status or event logs) never block the 1 kHz priority 63 decision loop required a lock-free single-producer single-consumer (SPSC) ring with atomic Seqlock generation guards.

---

## Accomplishments We're Proud Of

- **Mathematical Determinism:** A 0.0% keep-out violation rate across 132 adversarial attack ticks (host-sim rig), with the on-target QEMU governor run archived alongside it.
- **Genuine QNX 8.0 Target Deployment:** A fully bootable QNX 8.0 image running the QNX Hypervisor, isolating a Linux 6.12 guest, and passing all runtime assertions under QEMU AArch64. (The Raspberry Pi 4B profile builds cleanly but is not hardware-verified.)
- **Dual Safety Domains:** Successfully applying the identical supervisory binary to industrial robotics (servo motor) and healthcare (linear infusion pump).
- **Zero-Rot Evidence Trail:** Selected results are backed by console logs and metrics in `latch/docs/evidence/`.

---

## What We Learned

We learned that trying to make AI safe from *within* AI (prompt engineering, RLHF, Python wrappers) is fundamentally flawed. Safety must be enforced by an external, mathematically deterministic microkernel that possesses hardware-enforced memory isolation, priority-preemptive scheduling, and capability-based security. QNX SDP 8.0 provides the ideal microkernel architecture for the physical AI era.

---

## What's Next for GOVERNOR

- **Multi-DoF Kinematics:** Extending Control Barrier Functions from 1-DoF servo angles to 6-DoF robotic arm manipulators (SE(3) forward kinematics).
- **AUTOSAR Adaptive Integration:** Packaging GOVERNOR as an AUTOSAR Adaptive Platform (ara::com) safety layer for software-defined vehicles.
- **Formal Methods Research:** Translating the discrete-time CBF state machine into TLA+ and SPARK Ada models as research artifacts. (No safety certification is claimed or implied by this project.)

---

## How to Verify (One-Command Reproduction)

**Toolchain & environment:** QNX SDP 8.0, `qcc -Vgcc_ntoaarch64le` (qcc 12.2.0), target QEMU AArch64 `virt` (AArch64 LE). Source the SDP first: `source ~/qnx800/qnxsdp-env.sh`. Full build/run instructions are in `README.md`; the file-and-function index proving QNX API use is the README section **"Evidence-of-QNX-Use File & Function Index"** (resource manager, pulse pool, `ThreadCtl` runmask, `procmgr_ability`, `secpolpush`, `qvm`).

```bash
# 1. Verify Architectural Consistency & Invariant Admissibility (0 errors)
python3 latch/tools/consistency_check.py

# 2. Run Unified Adversarial Attack Rig (Attacks A1-A8 - 8/8 PASS)
python3 latch/tools/attacks/run_attacks.py

# 3. Run Dedicated GOVERNOR Seven-Scenario Gate
CCACHE_DISABLE=1 make -C latch/qnx check-governor

# 4. Run Full Legacy Oracle Regression Suite (200 ticks | rx=200 | wire=12 | env=7 | eperm=1)
CCACHE_DISABLE=1 make -C latch/qnx check

# 5. On-target GOVERNOR run (QEMU AArch64 virt, ~5 min under TCG)
#    archived proof: latch/docs/evidence/governor/governor-qemu-verify.txt
CCACHE_DISABLE=1 make -C latch/qnx verify-governor-qemu \
  GUEST_IMAGE=/abs/path/to/linux-6.12/arch/arm64/boot/Image
```
