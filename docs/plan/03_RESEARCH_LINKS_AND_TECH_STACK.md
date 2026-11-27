# 03 — Research Compendium: Metadata Tech Stack, Deep Research Links, Newsletter Signals & QNX Platform Facts

**Generated:** 2026-11-23  
**Last re-verified:** 2026-11-25  
**Status:** Live-Verified Link & Citation Register  
**Context:** QNX Everywhere Global Hackathon 2026 (Devpost: `qnx.devpost.com`)  
**Target Tracks:** Grand Prize ($10,000 + Podcast + CEO John Wall Coffee Chat), Robotics & Medical ($4,000), Best Use of QNX-Specific Tech ($3,500), Best Codelab ($3,500).

**How these rows were verified (2026-11-25):** every version in §1 was read
from the **installed** SDP on the build workstation — the SDP release from
`qnx800/target/qnx/etc/qversion`, the Hypervisor package version from
`qnx800/.packages/metadata/com.qnx.qnx800.target.hypervisor.core/`, and the
model file size from the file itself — not recalled. The external platform
facts in §3 and the rules in §2 were read from the live official pages on
2026-11-25, with the quoted wording copied from those pages. The physical
target in §1 is the one board the repository can actually build:
`tools/consistency_check.py` fails the build if this table ever names a board
with no `qnx/*.build` file behind it.

---

## 1. Metadata-Based Project Tech Stack

| Layer | Component | Exact Version / Identifier | Source / Documentation Reference |
|:---|:---|:---|:---|
| **Host OS** | Linux Development Host | **Build host used here: Fedora Linux 45** (x86_64, kernel 7.3.4-300.fc45). QNX's *documented* supported hosts for SDP 8.0 are Windows 11/10, Ubuntu Desktop 22.04/20.04 LTS and **Red Hat Enterprise Linux 9** — **Fedora is not on that list**, so this host is a working but *non-QNX-supported* configuration. | SDP 8.0 GA Release Notes, "Development host OSs" (`developers.qnx.com/developers/docs/relnotes8.0/com.qnx.doc.release_notes/topic/sdp8_rn.html`) |
| **Target RTOS** | **QNX SDP 8.0** (`procnto-smp-instr`) | **Installed and built against: SDP `8.0.0`** (`8.0.0.00141T202311271501L`, branch `qnx/8.0.0/main`) — read from `qnx800/target/qnx/etc/qversion` on the build workstation.<br>Current upstream release: **8.0.6** (release notes, "Date of this edition: November 12, 2026"). Every successful build here is evidence for **8.0.0**, *not* for 8.0.6. | `qnx.com/developers/docs/BSP8.0`; the installed-vs-current split is stated in `docs/GOVERNOR_JUDGE_READINESS.md` |
| **Hypervisor** | **QNX Hypervisor 8.0** | Package version `3.6.0.00802T202608071638L` (Aug 2026 build) — read from the installed package metadata `qnx800/.packages/metadata/com.qnx.qnx800.target.hypervisor.core/3.6.0.00802T202608071638L/`. | Included in the free QNX Everywhere tier. EL2 VHE host, GICv2 guest vdevs. |
| **Guest OS** | Untrusted AI VM | Linux 6.12 AArch64 (512 MB VM) + freestanding `/init` | Minimal Linux kernel `Image` + reproducible cpio initramfs (`latch_guest_init.c`). |
| **Virtual Target** | QEMU AArch64 `virt` | QEMU **11.1.3** as used here (`-M virt,virtualization=on,gic-version=2 -cpu cortex-a76 -smp 4 -m 2048`); the project targets 8.0+ | Documented official QNX virtual development target. |
| **Physical Target** | Hardware Target (Stretch) | **Raspberry Pi 4 Model B (BCM2711) — the only physical board this project claims.** It is implemented by `qnx/latch_rpi4.build`; there is no buildfile for any other board, so no other board is claimed. | BSP `com.qnx.qnx800.bsp.raspberrypi_bcm2711_rpi4` (build 837, released with SDP 8.0.6). PCA9685 12-bit PWM over `/dev/i2c1`. |
| **Compiler** | QCC Cross-Compiler | QNX GCC 12.2.0 (`gcc_ntoaarch64le`) | Flag set: `-std=c11 -Wall -Wextra -Werror -Wpedantic -O2 -D_QNX_SOURCE`. |
| **Image Tooling** | QNX Utilities | `mkifs`, `secpolcompile`, `secpolpush` | System utilities in `$QNX_HOST/usr/bin/`. |
| **Guest AI Engine** | Local Inference (installed, **now on a demonstrated runtime path — EXPERIMENTALLY**) | `llama.cpp` + `SmolLM2-135M-Instruct-Q8_0.gguf` (`144,811,360` bytes = 138.1 MiB, verified on disk) | CPU-only bounded inference, Apache-2.0 license. The **scripted** guest profiles are unchanged and are still what the 235-frame verification exercises. A **separate experimental profile** (`qnx/latch_qemu_infer.build`) now runs a statically linked AArch64 C++ program that links llama.cpp **inside** the Linux guest and proposes the motion; the freestanding policy stays PID 1, stays the sole writer on the wire, and relays the frame. The model and the inference binary travel on a **read-only virtio-blk asset disk** and are **not** tracked in this repository. Evidence: `docs/evidence/governor/infer-qemu.txt` (`docs/plan/02` §5, `docs/GOVERNOR_JUDGE_READINESS.md`). |
| **Tooling & CI** | Automation & Testing | Python **3.15.2** as used here (project targets 3.10+), GitHub Actions | **Zero external pip dependencies** — verified: there is no `requirements.txt`, `pyproject.toml` or `Pipfile`, and every tracked tool imports only the Python standard library plus its own sibling modules; uses standard `hashlib`, `struct`, `json`, `csv`. |

---

## 2. Verified Hackathon Guidelines & Devpost Rules

| Rule / Field | Confirmed Requirement | Source |
|:---|:---|:---|
| **Registration & Submission Period** | **November 2, 2026 (11:00 am ET) – December 15, 2026 (2:00 pm ET)** | `qnx.devpost.com/rules`; schedule at `qnx.devpost.com/details/dates` |
| **Submission Deadline** | **December 15, 2026 at 2:00 PM EST** | `qnx.devpost.com/details/dates` |
| **Judging Period** | **January 15 – 29, 2027**, judging and public voting both **10:00 am – 5:00 pm EST**; **Winners announced February 4, 2027 at 2:00 pm EST** | `qnx.devpost.com/details/dates` |
| **Total Prize Pool** | **$50,000 in cash**, plus other prizes. Grand Prize **$10,000** (1 winner; + *Code the Future* podcast episode and a coffee chat with John Wall, QNX CEO) · 5× **Best of \<Category\>** **$4,000** (Robotics & Medical, Automotive & Mobility, Low-level Software, Developer Tooling & Host Tools, Open-Source Contribution & Ports) · 5× **Runner-Up** **$2,000** (one per category) · 3× **Honorable Mention** **$1,000** · **Best Codelab / Tutorial** **$3,500** · **Best use of QNX-specific Technologies** **$3,500**. ($10,000 + 5×$4,000 + 5×$2,000 + 3×$1,000 + $3,500 + $3,500 = $50,000.) **Community Choice** carries no cash amount — a blog and social feature plus QNX swag. | Devpost Overview "Prizes" + Devpost Rules |
| **Multi-Prize Rule** | "A project can win one (1) Overall prize, one (1) Bonus prize, and one (1) Community Choice prize. If there are no eligible submissions for a bonus prize, that prize will not be awarded." | Devpost Rules, "Important notes on multiple prize eligibility" |
| **Judging Criteria** | **Technological Implementation** · **Design** · **Potential Impact** · **Innovation & AI Creativity** — judged by the 9-judge panel | Devpost Overview, "Judging Criteria" |
| **Participation** | **2,511 participants** (observed 2026-11-25; this count moves daily, so quote it only with its date) | `qnx.devpost.com` |
| **Video Requirement** | The video **should be less than three (3) minutes** and **should include footage that shows the Project functioning on the device for which it was built**; it **must be uploaded to and made publicly visible on YouTube**, and a link must be provided on the submission form. It must not include third-party trademarks or copyrighted music without permission. | Devpost Rules §4 + the challenge Overview |
| **Open Source Rule** | Public GitHub/GitLab repository with OSI-approved license visible in root (`LICENSE`) | Devpost Rules §4 |
| **Evidence of QNX Use** | Description must identify specific files, functions, lines, and logs proving native QNX execution | Devpost Rules §4 |
| **Judge Roster** | 9 BlackBerry QNX Leaders: Sheridan Ethier (VP, Engineering Middleware), Patrick Murtha (Senior Director, Product Management), Cris Sinnott (Senior Director Engineering, Open Source), Andy Gryc (Director, Developer Ecosystem), Dongkai Guo (Director, Software Development), John Dallas (Principal Academic Partnerships Manager), Morgan McKeen (Developer Engagement Marketing Manager), Mike Shane (Senior Systems Software Developer), John Hanam (Manager, Developer Relations) | `qnx.devpost.com` |

---

## 3. QNX Platform Facts & APS Status in SDP 8.0

1. **Adaptive partitioning (APS) is not supported in SDP 8.x**:
   - The `aps` configuration keyword **only works on QOS 2.2.x**; the QNX Process Launch and Monitor Service (QPLMS) User's Guide states that "the feature is not supported in SDP 8.x" — *QPLMS usage differences between QOS 2.2.x and SDP 8.x environments*, `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.plms/topic/usage_differences.html`.
   - The *QNX Momentics IDE User's Guide 8.0*, "APS View" page (`https://www.qnx.com/developers/docs/8.0/com.qnx.doc.ide.userguide/topic/APS_view.html`), states verbatim: *"QNX OS 8.0 does not support adaptive partitioning; if your target is based on 8.0, then the IDE won't receive any APS data and this pane isn't meaningful. For targets based on an earlier OS version, this pane is meaningful only when the target uses adaptive partitioning."*
   - The legacy `aps` adaptive partitioning scheduler present in QNX SDP 6.x and 7.x therefore does not exist in QNX SDP 8.0.
   - Temporal determinism in SDP 8.0 is achieved via strict priority-preemptive `SCHED_FIFO` 63, core pinning via `ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT)`, and hypervisor vCPU clustering.
   - LATCH claims **no** APS. It also does **not** claim QNX *sporadic* scheduling: that is a distinct policy, it is not implemented here, and it must not be inferred from the `SCHED_FIFO` configuration — see `docs/architecture/QNX_SCHEDULING_AND_STACK_USAGE.md`.
2. **Functional Safety Certification Reality**:
   - QNX OS for Safety 8.0 is certified by TÜV Rheinland to **ISO 26262 ASIL D, IEC 61508 SIL 3 (not SIL 4), IEC 62304 Class C, and ISO/SAE 21434** (QNX product page and QNX Download Center).
   - QNX Hypervisor 8.0 (the free / QNX Everywhere tier) is **non-certified**: its release notes state "QNX Hypervisor (QH) is *not* a certified product. It must *not* be used in a safety-related production system." Safety deployments require the commercial **QNX Hypervisor for Safety (QHS)** product, used only as specified in its Safety Manual.
   - QNX's own pages are **not consistent** on QHS's IEC 61508 SIL level: the Download Center says SIL 3 while QNX's March 2026 announcement says SIL 4. No SIL level for QHS is asserted here.
   - All documentation uses precise "architectural alignment" rather than false certification claims. **LATCH itself is not certified and makes no conformity claim.**
3. **Black Channelvirtio-console Communication**:
   - The guest VM has zero shared memory, zero pointers, and zero direct hardware access to the host.
   - All communication crosses a strictly serialized 32-byte point-to-point stream validated fail-closed by `latch-ingest`.

---

## 4. Synthesis of Industry Signals & Tech Newsletters

### 4.1 Core Engineering & System Design Newsletters
- **ByteByteGo (Alex Xu)**: Visual breakdown of Simplex runtime assurance architecture. Separating high-throughput, non-deterministic planning agents from simple, verified, low-latency safety controllers.
- **The Pragmatic Engineer (Gergely Orosz)**: Analysis of the 2026 embedded shift: AI models moving to edge robotics, encountering strict regulatory boundaries under the EU AI Act.
- **Scale Engineer**: Zero-dynamic-allocation memory patterns, lockless SPSC ring buffers, and cache-coherent atomic synchronization in safety-critical C11 systems.

### 4.2 AI Automation, Prompting & Regulatory Newsletters
- **TLDR AI & AI Breakfast**: Fast tracking of physical AI agent failures and prompt injection vulnerabilities in robotics. Highlighting the necessity of hardware/OS interlocks.
- **Superhuman AI**: Real-world case studies demonstrating that LLMs cannot be trusted with autonomous physical actuators without deterministic supervisory boundaries.
- **Simon Willison's "Lethal Trifecta" (2025-2026)**: Untrusted inputs + privileged tool access + real-world physical consequences. LATCH/GOVERNOR breaks the lethal trifecta by placing the QNX microkernel between the tool and the consequence.

### 4.3 QNX Market Intelligence & Industry Studies
- **QNX "Inside the Robot" Survey (May 2026, 1,000 Developers)**:
  * 95% of robotics developers state real-time determinism is critical.
  * 91% currently run safety workloads on general-purpose OSs (Linux), risking unpredictable jitter and crashes.
  * 27% cite software architecture and mixed-criticality integration as their single largest bottleneck.
- The prior InfectBot citation and associated numerical claims could not be verified and have been withdrawn.
- External Simplex research does not establish a latency bound for this implementation; use the project's own captured measurements for its demonstrated behavior.

---

## 5. Curated Links & Authoritative Reference Index

### QNX Official Documentation & SDKs
- QNX Everywhere Portal: `https://qnx.software/en/developers/get-started/qnx-everywhere`
- QNX SDP 8.0 Lib Reference: `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/`
- QNX Hypervisor User Guide: `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/`
- QNX Security & secpol Guide: `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/`
- QNX Raspberry Pi 4 BSP Release Notes: `https://www.qnx.com/developers/docs/BSP8.0/com.qnx.doc.bsp.releasenotes/topic/rel_sdp80.bsp.broadcom.rpi4.bcm2711.html`
- QNX Momentics IDE User's Guide 8.0 — "APS View" (the APS-not-supported note quoted in §3): `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.ide.userguide/topic/APS_view.html`
- QNX QPLMS User's Guide — "QPLMS usage differences between QOS 2.2.x and SDP 8.x environments" (the `aps` keyword note quoted in §3): `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.plms/topic/usage_differences.html`
- QNX GitLab Hypervisor Samples: `https://gitlab.com/qnx/hypervisor/getting-started`

### Regulatory & Standards Documentation
- EU AI Act Regulation (EU) 2024/1689: `https://artificialintelligenceact.eu/article/12/` (Article 12: Logging, Article 14: Human Oversight).
- ISO 26262-4:2018: Road Vehicles - Functional Safety (Part 4: Product Development at the System Level).
- IEC 61508-3:2010: Functional Safety of Electrical/Electronic/Programmable Electronic Safety-Related Systems.
- IEC 62304:2015: Medical Device Software - Software Life Cycle Processes.

### Academic Research Papers
- Ames, A. D., et al. (2019): *Control Barrier Functions: Theory and Applications*, European Control Conference.
- Sha, L. (2001): *Using Simplex to Build Dependable Systems Using Uncertified Components*, IEEE Software.
- Han, et al. (2026): *Before We Trust Them: Decision-Making Failures in Navigation of Foundation Models*, arXiv:2601.05529.
- Ashby, W. R. (1948): *Design for a Brain: The Origin of Adaptive Behaviour*, Chapman & Hall (Ultrastability formulation).
