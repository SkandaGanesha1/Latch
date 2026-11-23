# 06 — GOVERNOR Video Production & Devpost Submission Master Plan

**Project:** GOVERNOR — Deterministic Safety Interlock & Dead Man's Switch for Physical AI on QNX SDP 8.0  
**Repository:** `https://github.com/SkandaGanesha1/Latch.git`  
**License:** MIT License (Stated in repository root `LICENSE`, `README.md`, and Devpost About section)  
**Hackathon:** QNX Everywhere Global Hackathon 2026 (Devpost: `qnx.devpost.com`)  
**Official Deadline:** December 15, 2026 at 2:00 pm EST  
**Judging Period:** January 15 – 29, 2027  
**Prizes:** $50,000 Total Prize Pool (Grand Prize $20,000; Category Prizes; Multi-Prize Eligible)  

---

## 1. Master Timeline & Submission Schedule (Conflict-Resolved)

All conflicting dates across prior planning drafts are harmonized below into the **authoritative execution schedule**:

| Milestone | Target Date | Status | Description |
|---|---|---|---|
| **Pillar 1: Code & Evidence Freeze** | **Dec 12, 2026 (23:59 UTC)** | Active Target | All C sources, Python harnesses, tests, and evidence files locked. 100% green on all 5 gates. |
| **Pillar 2: Video Recording & Editing** | **Dec 12, 2026** | Ready | Multi-pane screen capture using local `ffmpeg`, narration track recording, 7-scene assembly. |
| **Pillar 3: Devpost Formal Submission** | **Dec 13, 2026 (18:00 UTC)** | Scheduled | Devpost form submitted **48 hours before official deadline** ("Never on deadline day"). |
| **Pillar 4: Final Verification Buffer** | **Dec 14, 2026** | Contingency | Link verification, portfolio check, repository branch protection verification. |
| **Pillar 5: Submission Hard Deadline** | **Dec 15, 2026 (14:00 EST)** | Locked | Official platform freeze. Post-deadline repo edits prohibited per competition rules. |
| **Pillar 6: Judging Window** | **Jan 15 – 29, 2027** | Evaluation | 9-member expert panel evaluates microkernel evidence, safety alignment, and demonstration. |

---

## 2. 3-Minute Demo Video Production Specification

### 2.1 Technical Constraints & Rules
- **Duration:** 2 minutes 35 seconds (Hard Devpost limit: under 3 minutes 00 seconds).
- **Word Count:** ~365 words spoken at 135 words per minute.
- **Recording Tool:** Local host `ffmpeg` (`/home/skanda/.local/bin/ffmpeg` or system binary) capturing X11/Wayland display at 1080p60:
  ```bash
  # Screen capture example
  ffmpeg -f x11grab -video_size 1920x1080 -framerate 60 -i :0.0 -c:v libx264 -preset fast -crf 18 output_raw.mp4
  ```
- **Resolution & Codec:** 1920x1080 (16:9), H.264 / AAC 48 kHz stereo.
- **Mandatory On-Screen Honesty Captions:**
  1. *"QEMU AArch64 virt take — mock I²C, no physical actuator motion."*
  2. *"QEMU TCG software emulation; guest policy is scripted deterministic C (PID 1), not a live LLM."*
  3. *"Aligned with EU AI Act Article 12 (obligations phase in 2027–2028); no formal CE mark claimed."*

### 2.2 Seven-Scene Video Narrative & Execution Script

```
+-----------------------------------------------------------------------------------------+
| Scene 1 (0:00 - 0:13)  | Hook: The Centrifugal Governor meets Humanoid Robotics (13s)   |
| Scene 2 (0:13 - 0:29)  | The Problem: The Lethal Trifecta of Physical AI (16s)          |
| Scene 3 (0:29 - 0:48)  | Architecture: QNX Hypervisor 8.0 & SCHED_FIFO 63 Core (19s)    |
| Scene 4 (0:48 - 1:15)  | Live Attack Demo: A1 Unit Injection -> Fail-Closed CLAMP (27s) |
| Scene 5 (1:15 - 1:48)  | Dead Man's Switch: A4 Lease Trip & 25-Clean Hysteresis (33s)    |
| Scene 6 (1:48 - 2:15)  | Medical Syringe Pump: Zero-Hardcoded Dual-Domain Safety (27s)   |
| Scene 7 (2:15 - 2:35)  | Blackbox Flight Recorder & Closing Verdict (20s)                |
+-----------------------------------------------------------------------------------------+
Total Time: 2 minutes 35 seconds (155 seconds)
```

#### Detailed Scene Storyboard

1. **Scene 1: Historical Parallel (0:00 – 0:13)**
   - *Visual:* Side-by-side split screen: 1788 James Watt flyball governor technical patent drawing next to modern high-speed robotic actuator.
   - *Voiceover:* *"In 1788, James Watt tamed runaway steam engines with a physical flyball governor that throttled valves the instant speed exceeded safe limits. Today, Physical AI needs that exact same instinct, in software."*

2. **Scene 2: The Lethal Trifecta (0:13 – 0:29)**
   - *Visual:* Architecture animation showing: (1) Probabilistic LLM Reasoning + (2) Direct Actuator Handles + (3) Non-Deterministic OS = Failure. Flashing warning card: Prompt Injection / Out-of-Distribution / Thread Hang.
   - *Voiceover:* *"Robots and medical infusion pumps are increasingly driven by probabilistic models. When a model hallucinates, or an agent thread hangs, what stops the machine? Userspace wrappers on general-purpose Linux crash or overrun under pressure. We built the answer on QNX 8.0."*

3. **Scene 3: QNX Hypervisor 8.0 Isolation (0:29 – 0:48)**
   - *Visual:* Split terminal: Left shows QNX 8.0 host microkernel (`pidin -p qvm threads`), right shows Linux guest VM.
   - *Terminal Commands:*
     ```bash
     pidin -p qvm threads
     pidin -p latchd threads
     ```
   - *Voiceover:* *"Here is QNX SDP 8.0 running under QEMU software emulation. On CPUs 2 and 3, an untrusted Linux guest runs a scripted policy — a deterministic stand-in for an AI agent. It possesses zero direct hardware access; every proposal crosses a single virtio-console pipe into QNX CPU 0, where latchd executes at SCHED_FIFO 63 with a 1 kHz microkernel pulse."*

4. **Scene 4: Live Cyber-Physical Attack A1 (0:48 – 1:15)**
   - *Visual:* HTML5 Console radar display (`console.html`) on left, terminal running Attack A1 on right.
   - *Terminal Commands:*
     ```bash
     python3 tools/attacks/attack_a1_unit_injection.py
     ```
   - *Voiceover:* *"Watch an adversarial attack. The AI guest injects a coordinate out of range — three hundred seventy thousand in an unmapped unit. The QNX supervisor catches the invalid unit, asserts LATCH_FAULT_UNIT, and immediately drops the 6-rung ladder down to CLAMP. The actuator never touches the forbidden keepout zone."*

5. **Scene 5: Railway Dead Man's Switch — Attack A4 (1:15 – 1:48)**
   - *Visual:* Lease countdown bar in `console.html` dropping to zero; ladder dropping from `HP` to `ADVISE`.
   - *Terminal Commands:*
     ```bash
     python3 tools/attacks/attack_a4_deadman.py
     ```
   - *Voiceover:* *"Now the dead man's handle. The guest AI hangs for 110 milliseconds; the 100 ms coherence lease expires and drops authority to ADVISE. The guest wakes up and spams 150 heartbeats to regain power. QNX refuses: heartbeats maintain the lease, but cannot promote authority. Only 25 consecutive clean commands restore full High Performance."*

6. **Scene 6: Dual-Domain Medical Syringe Pump (1:48 – 2:15)**
   - *Visual:* Manifest diff showing `governor_servo.manifest` vs `syringe_governor.manifest` with integer microlitre units.
   - *Terminal Commands:*
     ```bash
     python3 tools/governor_e2e.py
     ```
   - *Voiceover:* *"GOVERNOR is completely zero-hardcoded. Swap the signed SHA-256 manifest contract, and the identical microkernel binary guards an intravenous syringe pump in integer microlitres. An excessive bolus rate triggers LATCH_FAULT_DOSE and clamps the plunger before harmful medication can enter the patient."*

7. **Scene 7: Blackbox Forensics, EU AI Act & Final Verdict (2:15 – 2:35)**
   - *Visual:* Terminal executing `gov_replay.py --test` showing rolling SHA-256 genesis hashes and ladder state verification. Closing hero card: QNX SDP 8.0 + GOVERNOR.
   - *Terminal Commands:*
     ```bash
     python3 tools/gov_replay.py --test
     ```
   - *Voiceover:* *"Every tick and fault is sealed into a rolling SHA-256 hash chain in .bss — audit-ready forensics aligned with EU AI Act Article 12, whose high-risk obligations phase in during 2027 and 2028. On general-purpose operating systems, AI safety is a promise. On QNX, it is a hard real-time invariant. The AI may propose. Only QNX may move."*

---

## 3. Devpost Submission Text & Field Checklist

### 3.1 Basic Information
- **Project Title:** GOVERNOR — Deterministic Safety Interlock & Dead Man's Switch for Physical AI
- **Tagline:** The AI may propose. Only QNX may move.
- **Repository URL:** `https://github.com/SkandaGanesha1/Latch.git`
- **Video Demo URL:** YouTube / Vimeo unlisted link (under 3 min)
- **Built With:** QNX SDP 8.0, QNX Hypervisor 8.0, C11, Python 3, QEMU AArch64, HTML5/Canvas
- **License in About Section:** MIT License

### 3.2 Written Answers for Submission Form

#### 1. What inspired you to build GOVERNOR?
Autonomous robots, surgical assistants, and automated drug delivery systems are adopting generative neural policies and Foundation Models. However, LLMs and neural policies suffer from non-deterministic latency, hallucinated values, and susceptibility to prompt injection. When deployed directly to physical actuators on Linux or ROS, thread starvation or software stalls lead to physical destruction or patient injury. Inspired by James Watt's 1788 centrifugal flyball governor, we built GOVERNOR to act as an un-bypassable microkernel dead man's switch.

#### 2. What does it do?
GOVERNOR enforces a 1 kHz deterministic safety boundary between untrusted AI agents in a QNX Hypervisor VM and physical actuators:
1. **6-Rung Degradation Ladder:** Dynamically shifts operational authority (`HP → ADVISE → CLAMP → SLOW → SAFE_STOP → LATCH`) based on command validity and lease freshness.
2. **Dead Man's Lease & Coherence:** Requires a periodic $\le 100$ ms countdown lease with modulo-$2^{24}$ sequence tracking. Heartbeats hold leases but never promote degraded rungs.
3. **Multi-Domain Manifest Admissibility:** Signed JSON schema contracts enforce physical limits without recompilation (e.g. robotic angular joint vs. medical infusion pump in microlitres).
4. **EU AI Act Article 12 Blackbox Recorder:** 4,096-event circular flight recorder sealed with manifest-bound rolling SHA-256 hash chains, providing tamper-evident post-incident replay.

#### 3. How we built it (Evidence of QNX Use)
- **QNX Neutrino SDP 8.0 Microkernel Architecture:** Built as native C11 resource managers (`resmgr_attach`) on `/dev/latch/proposal`, `/dev/latch/actuator`, and `/dev/governor`.
- **Real-Time Determinism:** Bounded WCET under 62 microseconds (`ClockCycles()` instrumentation), memory locked via `mlockall(MCL_CURRENT | MCL_FUTURE)`, pinned to physical CPU 0 via `ThreadCtl(_NTO_TCTL_RUNMASK)`.
- **Mandatory Access Control:** Compiled via `secpolcompile` and pushed via `secpolpush` at boot, enforcing custom uninheritable ability `latch/actuator`.
- **Virtualization Isolation:** Runs untrusted AI workloads in QNX Hypervisor 8.0 (`qvm`), isolating guest failures completely from safety-critical control channels.

#### 4. Challenges we ran into & how we solved them
- **Tick & Hysteresis Tuning:** Ensuring recovery from degraded states cannot be gamed required a strict 25-clean-command threshold where heartbeats earn zero recovery credit.
- **Microsecond WCET Budget:** Eliminating all dynamic heap allocations (`malloc`/`free`) from the real-time execution loop and using pre-allocated `.bss` rings.
- **Subsystem Parity:** Emulating high-resolution QNX timebase cycles on host-sim environments for exhaustive CI test runs across 7 cyber-physical attack vectors.

#### 5. What we learned & what's next
Real-time microkernel operating systems like QNX 8.0 are the missing foundation for safe Physical AI. While the AI community focuses on prompt sanitization, true physical safety must be enforced at the operating system and actuator boundary. Next steps include hardware deployment on physical SIL-certified microcontrollers and formal TLA+ state machine verification.

---

## 4. Pre-Flight Devpost Verification Checklist

Before clicking Submit on December 13, 2026:
- [ ] Video runtime is strictly $\le 2\text{ min }59\text{ sec}$.
- [ ] YouTube/Vimeo video visibility set to **Public** or **Unlisted** (NOT Private).
- [ ] License is explicitly stated as MIT in the project description text.
- [ ] GitHub repository is public with complete `README.md` and build instructions.
- [ ] Evidence files linked in submission (`docs/evidence/governor/*`, `LATENCY.md`).
- [ ] All 9 judge names reviewed against project documentation tone.
- [ ] Submission submitted on Dec 13, leaving a 48-hour buffer before the Dec 15 2:00 pm EST cutoff.

