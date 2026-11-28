# GOVERNOR — 3-Minute Demo Video Script & Storyboard

**Title:** GOVERNOR — Deterministic Safety Interlock & Dead Man's Switch for Physical AI  
**Target Duration:** 2 minutes 35 seconds (hard rule: under 3 minutes; ~359 narration words at 130–140 wpm)  
**Format:** Split-screen video featuring on-target QNX terminal sessions, architecture diagrams, HTML5 Canvas radar visualization, and live cyber-physical attack demonstrations.  
**Tagline:** *"The AI may propose. Only QNX may move."*

**Honesty captions (on-screen text, mandatory):**
- During QEMU segments: *"QEMU AArch64 virt take — mock I²C, no physical actuator motion."*
- During architecture segment: *"QEMU TCG software emulation; guest policy is scripted deterministic C (PID 1), not a live LLM."*
- During the closing segment: *"Aligned with EU AI Act Article 12 (obligations phase in 2027–2028); no formal CE mark claimed."*

> **THIS IS THE CANONICAL VIDEO PLAN.** There was one storyboard before
> this file; there were three. `docs/VIDEO_SCRIPT_AND_SUBMISSION.md` and
> `docs/06_video_and_submission_plan.md` are **SUPERSEDED** stubs that
> point here. The **written** Devpost answers live in exactly one place —
> [`docs/DEVPOST_SUBMISSION.md`](DEVPOST_SUBMISSION.md) — and are not
> duplicated below.

---

## Detailed Storyboard & Time-Coded Breakdown

| Timestamp | Visual / Screen Layout | Actions & Terminal Commands | Narration & Audio Script |
|:---:|:---|:---|:---|
| **0:00 – 0:13**<br>*(13 sec)* | **Title Card & Historical Visual**<br>Side-by-side juxtaposition: 1788 technical engraving of James Watt's Centrifugal Flyball Governor next to a high-speed humanoid robotic arm. | Fade in bold text:<br>`GOVERNOR`<br>*The AI May Propose. Only QNX May Move.* | *"In 1788, James Watt tamed runaway steam engines with a physical flyball governor that throttled the valve the moment speed exceeded safe limits. Physical AI needs the same instinct, in software."* |
| **0:13 – 0:29**<br>*(16 sec)* | **The Modern Problem: Lethal Trifecta**<br>Animated graphic highlighting: Probabilistic Neural Reasoning + Direct Actuator Handles + Non-Deterministic OS. | Red warning box flashes: *"Prompt Injection / Hallucinated Coordinates / Thread Hang"*. | *"Today's robots and medical pumps are driven by probabilistic models. When a model hallucinates or a thread hangs, what stops the machine? Wrappers on general-purpose operating systems fail under pressure. We built the answer on QNX 8.0."* |
| **0:29 – 0:48**<br>*(19 sec)* | **Architecture: QNX Hypervisor 8.0 Isolation**<br>Split screen: Left side shows QNX host; Right side shows Linux guest VM.<br>Lower-third on-screen card (3 s, on-screen text — NOT narration): "HOMEOSTAT outer loop — default-off, contract-enabled. Rejection ratio / clamp fraction / latency spread / coherence anomalies → the velocity ceiling CONTRACTS, floored at 26/256, and never above the signed limit." | Terminal 1 (QNX host):<br>`pidin -p qvm threads`<br>Shows vCPU threads `cy-guest-qemu-virt/0` and `/1` pinned to physical CPUs 2 & 3. | *"Here is QNX SDP 8.0 running under QEMU's TCG software emulation. On CPUs two and three, an untrusted Linux guest runs a scripted policy — a deterministic stand-in for an AI agent. It has no direct access to actuators; every frame crosses a single virtio-console channel."* |
| **0:48 – 1:00**<br>*(12 sec)* | **Microkernel Safety Core on CPU 0**<br>Diagram zooming into `latchd` on CPU 0 at `SCHED_FIFO 63`. | Terminal 2 (QNX host):<br>`pidin -p latchd threads`<br>Shows priority 63 decision thread on CPU 0 with pulse pool channel. | *"On CPU zero, latchd runs at SCHED_FIFO priority 63. Every millisecond, a microkernel pulse triggers it to evaluate Control Barrier Functions before permitting a single micro-step of motion."* |
| **1:00 – 1:15**<br>*(15 sec)* | **Attack A1: Rogue Unit Injection**<br>Left: HTML5 console (`console.html`) radar view.<br>Right: Terminal running `attack_a1_unit_injection.py`. | Inject $u = 370000$ with unmapped `unit_id=999`.<br>Microkernel asserts `LATCH_FAULT_UNIT` (`0x1000`) on all 4 rogue proposals.<br>Ladder demotes: `HP` → `ADVISE` → `CLAMP`.<br>Terminal ends with `[ATTACK A1 VERDICT] PASS`. | *"Watch an attack. The guest sends an out-of-scale command — three hundred seventy thousand in an unmapped unit. QNX asserts LATCH_FAULT_UNIT and demotes authority from High Performance down to CLAMP. The plant never enters the forbidden zone."* |
| **1:15 – 1:29**<br>*(14 sec)* | **Attack A2: Rate Flood Attack**<br>Left: Velocity step chart.<br>Right: Terminal running `attack_a2_rate_flood.py`. | Inject sudden step $\Delta u = 500\text{ mrad}$ in 1 ms.<br>Asserts `LATCH_FAULT_RATE` (`0x0080`) **together with** the shared dose-limit bit `LATCH_FAULT_DOSE` (`0x8000`) — the terminal shows `faults=0x8080`, because a step beyond `v_max` trips both.<br>Output step clamped to $0\text{ mrad} \le v_{\text{max}}$.<br>Terminal ends with `[ATTACK A2 VERDICT] PASS`. | *"A prompt injection then orders a violent five-hundred-milliradian burst in one millisecond. The token-bucket rate limiter catches the spike, clamps the step to zero, and the keep-out breach rate stays at zero percent."* |
| **1:29 – 1:48**<br>*(19 sec)* | **Attack A4: Deadman Lease Trip & Recovery**<br>Left: Lease countdown progress bar.<br>Right: Terminal running `attack_a4_deadman.py`. | The lease expires and trips `LATCH_FAULT_HEARTBEAT` (`0x2000`) → `ADVISE`. *(The attack scenario shortens the lease to **4 ticks** for deterministic host-sim timing; the shipped `governor_servo.manifest` lease is **100 ticks = 100 ms** at 1 kHz — say "the guest goes silent", not a millisecond figure.)*<br>**15** heartbeats sent: clean streak remains 0.<br>Exactly **25** clean commands sent: streak reaches 25 → promotes to `HP`.<br>Terminal ends with `[ATTACK A4 VERDICT] PASS`. | *"Now the railway dead man's switch. The guest goes silent; the twenty-four-bit coherence lease expires and authority drops to ADVISE. The guest wakes and spams heartbeats — authority refuses to budge. Only twenty-five consecutive clean commands promote it back."* |
| **1:48 – 2:02**<br>*(14 sec)* | **Attacks A5 & A6: Coherence Spoof & Replay**<br>Left: Fault bit matrix LEDs.<br>Right: Terminal running `run_attacks.py`. | Frozen counter ($\Delta c = 0$) trips the heartbeat lease (`LATCH_FAULT_HEARTBEAT`, `0x2000`) and demotes `HP` → `ADVISE`.<br>Replayed sequence number trips `FAULT_SEQ` (`0x0004`) → fail-closed `LATCH`.<br>Terminal ends with `[ATTACK A5 VERDICT] PASS` and `[ATTACK A6 VERDICT] PASS`; the suite ends with `[SUITE VERDICT] ALL 8 ADVERSARIAL ATTACKS PASSED (0% FAILURE RATE)`. | *"Attacks five and six probe counter spoofing and sequence replay. A frozen counter or a duplicate frame trips a fault and drops straight into fail-closed LATCH. Zero keep-out breaches across the whole suite."* |
| **2:02 – 2:15**<br>*(13 sec)* | **Dual-Domain: Medical Infusion Pump**<br>Visual: Linear syringe pump contract (`syringe_governor.manifest`). Graphic showing microlitre drug delivery. | Terminal command:<br>`CCACHE_DISABLE=1 make -C latch/qnx check`<br>The medical scenario prints: `[GOVERNOR_SCENARIO_7] PASS: medical DOSE fault holds the plant` | *"GOVERNOR is zero-hardcoded. Swap the signed SHA-256 manifest, and the same microkernel binary guards a medical syringe pump in integer microlitres. An excessive bolus trips LATCH_FAULT_DOSE and clamps the plunger."* |
| **2:15 – 2:35**<br>*(20 sec)* | **Event Replay & Closing**<br>Visual: Rolling SHA-256 event chain validation in `gov_replay.py`.<br>Closing logo banner: QNX SDP 8.0 + GOVERNOR. | Terminal command:<br>`python3 latch/tools/gov_replay.py --test`<br>12 sub-tests pass and it prints `[GOV_REPLAY_TEST] ALL TESTS PASSED` | *"Every event is sealed into a rolling SHA-256 hash chain — offline hash-chain checks for exported records, with limitations before sealing. The guest proposes; the supervisor checks each command. The AI may propose. Only QNX may move."* |

---

## Technical Production Notes for Voiceover & Capture

1. **Audio Pace:** Crisp, authoritative, and energetic pacing (approx. 130–140 words per minute). The narration above is ~359 words, which reads in ~2:35 — comfortably under the 3-minute hard limit.
2. **Terminal Displays:** 
   - High-contrast dark theme (Solarized Dark or Monokai) with 18pt font.
   - Terminal 1: QNX AArch64 QEMU serial console showing real-time `latchctl status` and `pidin`.
   - Terminal 2: Host simulation test suite executing `run_attacks.py` and `gov_replay.py`.
3. **Browser Visualizer:** Screen capture of `latch/host/console.html` displaying the animated radar dial, ladder badges, and fault LEDs during Attack A1 and Attack A4.
4. **Real Captures Only (replaces any stock hardware footage):** Every visual in this script is a recording of something that actually exists in the repo — the QEMU serial console, `console.html`, the attack terminals, and `make check` output. Do **not** stage hardware footage: the Raspberry Pi 4B profile is build-verified only, and the QEMU take runs mock I²C, so no physical servo motion exists to film.
5. **EU AI Act phrasing:** Say *"aligned with … obligations phase in during 2027 and 2028"* — never *"compliant"* (Annex III high-risk obligations apply from Dec 2, 2027; Annex I machinery/medical from Aug 2, 2028).
6. **Recording Tool, Resolution & Codec:** capture the workstation display locally with `ffmpeg` (`-f x11grab -video_size 1920x1080 -framerate 60 -i :0.0 -c:v libx264 -preset fast -crf 18`), encode at **1920x1080 (16:9)**, **H.264 / AAC 48 kHz stereo**, and record the narration track separately so the pace can be corrected without re-shooting the screen.
7. **Duration & Word Count (the two numbers the submission is checked against):** the storyboard's ten segments total **155 s** and the narration is **359 words** at 130–140 wpm. The Devpost rule is "under three (3) minutes"; 2:35 is the plan, and the rule is not a target to creep towards.

---

## Submission Timeline (authoritative execution schedule)

All conflicting dates across the earlier planning drafts are harmonised here. This table is the **only** schedule; the superseded plan carried a copy of it.

| Milestone | Target Date | Status | Description |
|---|---|---|---|
| **Pillar 1: Code & Evidence Freeze** | **Dec 12, 2026 (23:59 UTC)** | Active Target | All C sources, Python harnesses, tests and evidence files locked. Every gate green. |
| **Pillar 2: Video Recording & Editing** | **Dec 12, 2026** | Ready | Multi-pane screen capture using local `ffmpeg`, narration track recorded, assembly cut to this storyboard. |
| **Pillar 3: Devpost Formal Submission** | **Dec 13, 2026 (18:00 UTC)** | Scheduled | Devpost form submitted **48 hours before the official deadline** — never on deadline day. |
| **Pillar 4: Final Verification Buffer** | **Dec 14, 2026** | Contingency | Link verification, portfolio check, repository branch-protection verification. |
| **Pillar 5: Submission Hard Deadline** | **Dec 15, 2026 (14:00 EST)** | Locked | Official platform freeze. |
| **Pillar 6: Judging Window** | **Jan 15 – 29, 2027** | Evaluation | The panel evaluates the microkernel evidence, the safety alignment and the demonstration. |

**Hackathon:** QNX Everywhere Global Hackathon 2026 (`qnx.devpost.com`) — **official deadline December 15, 2026 at 2:00 pm EST**, **judging January 15 – 29, 2027**. **Repository:** `https://github.com/SkandaGanesha1/Latch.git`. **License:** MIT (`LICENSE`, `README.md`, and the Devpost *About* section).

---

## Pre-Flight Devpost Verification Checklist

Before clicking Submit on December 13, 2026:

- [ ] Video runtime is strictly $\le 2\text{ min }59\text{ sec}$ (the plan is 2:35).
- [ ] Every terminal line in the video was **actually produced by the command shown** — no staged output, no stock footage.
- [ ] The three mandatory honesty captions are burnt into the video, including the mock-I²C / no-physical-actuation caption.
- [ ] YouTube/Vimeo video visibility is set to **Public** or **Unlisted** (NOT Private).
- [ ] The license is explicitly stated as **MIT** in the project description text.
- [ ] The GitHub repository is public, with a complete `README.md` and build instructions.
- [ ] The evidence files are linked from the submission (`docs/evidence/governor/*`, `LATENCY.md`, and the index at `docs/evidence/README.md`).
- [ ] The **written** answers in [`docs/DEVPOST_SUBMISSION.md`](DEVPOST_SUBMISSION.md) are the ones pasted into the form — this file carries the **video** plan only.
- [ ] No claim in the video or the text asserts a WCET, a certification, or physical actuation on the QEMU take. The accepted latency statement is the on-target TCG observation, labelled *not* a WCET.
- [ ] The submission is submitted on Dec 13, leaving a 48-hour buffer before the Dec 15 2:00 pm EST cutoff.

