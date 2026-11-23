# 03 — Research Compendium: Metadata Tech Stack, Deep Research Links, Newsletter Signals & QNX Platform Facts

**Generated:** 2026-11-23  
**Status:** Live-Verified Link & Citation Register  
**Context:** QNX Everywhere Global Hackathon 2026 (Devpost: `qnx.devpost.com`)  
**Target Tracks:** Grand Prize ($10,000 + Podcast + CEO John Wall Coffee Chat), Robotics & Medical ($4,000), Best Use of QNX-Specific Tech ($3,500), Best Codelab ($3,500).

---

## 1. Metadata-Based Project Tech Stack

| Layer | Component | Exact Version / Identifier | Source / Documentation Reference |
|:---|:---|:---|:---|
| **Host OS** | Linux Development Host | Ubuntu 22.04 LTS or Fedora 40/41 | QNX-supported host per SDP 8.0 installation guide. |
| **Target RTOS** | **QNX SDP 8.0** (`procnto-smp-instr`) | Baseline: `8.0.0.00141T202311271501L` (`qnx/8.0.0/main`)<br>Production: **8.0.6** (BSP release notes Nov 12, 2026) | `qnx.com/developers/docs/BSP8.0` |
| **Hypervisor** | **QNX Hypervisor 8.0** | Version `3.6.0.00802T202608071638L` (Aug 2026 build, Hypervisor 8.0.5 release) | Included in free QNX Everywhere tier. EL2 VHE host, GICv2 guest vdevs. |
| **Guest OS** | Untrusted AI VM | Linux 6.12 AArch64 (512 MB VM) + freestanding `/init` | Minimal Linux kernel `Image` + reproducible cpio initramfs (`latch_guest_init.c`). |
| **Virtual Target** | QEMU AArch64 `virt` | QEMU 8.0+ (`-M virt,virtualization=on,gic-version=2 -cpu cortex-a76 -smp 4 -m 2048`) | Documented official QNX virtual development target. |
| **Physical Target** | Hardware Target (Stretch) | Raspberry Pi 4 Model B (BCM2711) / Pi 5 | BSP `com.qnx.qnx800.bsp.raspberrypi_bcm2711_rpi4` (build 837). PCA9685 12-bit PWM over `/dev/i2c1`. |
| **Compiler** | QCC Cross-Compiler | QNX GCC 12.2.0 (`gcc_ntoaarch64le`) | Flag set: `-std=c11 -Wall -Wextra -Werror -Wpedantic -O2 -D_QNX_SOURCE`. |
| **Image Tooling** | QNX Utilities | `mkifs`, `secpolcompile`, `secpolpush` | System utilities in `$QNX_HOST/usr/bin/`. |
| **Guest AI Engine** | Local Inference | `llama.cpp` + `SmolLM2-135M-Instruct-Q8_0.gguf` (139 MB) | CPU-only bounded inference, Apache-2.0 license. |
| **Tooling & CI** | Automation & Testing | Python 3.10+ Standard Library, GitHub Actions | Zero external pip dependencies; uses standard `hashlib`, `struct`, `json`, `csv`. |

---

## 2. Verified Hackathon Guidelines & Devpost Rules

| Rule / Field | Confirmed Requirement | Source |
|:---|:---|:---|
| **Submission Deadline** | **December 15, 2026 at 2:00 PM EST** | `qnx.devpost.com/rules` |
| **Judging Period** | **January 15 – 29, 2027** (Winners announced ~Feb 4, 2027) | Devpost Rules §6 |
| **Total Prize Pool** | **$50,000 Total** ($10k Grand Prize, 5×$4k Category, 5×$2k Category Runners-up, 2×$3.5k Bonus) | Devpost Rules §7-8 |
| **Multi-Prize Rule** | One entry can win: 1 Overall Prize (Grand Prize OR Category Prize) + 1 Bonus Prize + Community Choice | Devpost Rules §8 |
| **Video Requirement** | Public YouTube video, **under 3 minutes 00 seconds**, demonstrating real software running | Devpost Rules §4 |
| **Open Source Rule** | Public GitHub/GitLab repository with OSI-approved license visible in root (`LICENSE`) | Devpost Rules §4 |
| **Evidence of QNX Use** | Description must identify specific files, functions, lines, and logs proving native QNX execution | Devpost Rules §4 |
| **Judge Roster** | 9 BlackBerry QNX Leaders: Sheridan Ethier, Patrick Murtha, Cris Sinnott, Andy Gryc, Dongkai Guo, John Dallas, Morgan McKeen, Mike Shane, John Hanam | `qnx.devpost.com` |

---

## 3. QNX Platform Facts & Discontinuation of APS

1. **Adaptive Partitioning Scheduler (APS) Discontinued in SDP 8.0**:
   - The legacy `aps` adaptive partitioning scheduler present in QNX SDP 6.x and 7.x **does not exist in QNX SDP 8.0**.
   - Official QNX Momentics IDE User's Guide: *"QNX OS 8.0 does not support adaptive partitioning; if your target is based on 8.0, then the IDE won't receive any APS data."*
   - Temporal determinism in SDP 8.0 is achieved via strict priority-preemptive `SCHED_FIFO` 63, core pinning via `ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT)`, and hypervisor vCPU clustering.
2. **Functional Safety Certification Reality**:
   - QNX OS for Safety 8.0 is certified by TÜV Rheinland to **ISO 26262 ASIL D, IEC 61508 SIL 3 (not SIL 4), IEC 62304 Class C, and ISO/SAE 21434**.
   - QNX Hypervisor 8.0 (free in QNX Everywhere) is **non-certified**; safety deployments require commercial "QNX Hypervisor for Safety".
   - All documentation uses precise "architectural alignment" rather than false certification claims.
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
- **InfectBot / Autonomous Agent Hijacking (IJCAI 2026)**:
  * 100% obedience rate in compromised foundation models under prompt injection. Demonstrates that guest AI must be treated as completely adversarial.
- **Multi-Candidate Simplex over Type-1 Hypervisors (arXiv 2509.21014 & 2610.35040)**:
  * Demonstrates that running Simplex supervisors natively in RTOS microkernels achieves average decision latencies of 0.028 ms, bounding worst-case execution under physical AI faults.

---

## 5. Curated Links & Authoritative Reference Index

### QNX Official Documentation & SDKs
- QNX Everywhere Portal: `https://qnx.software/en/developers/get-started/qnx-everywhere`
- QNX SDP 8.0 Lib Reference: `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/`
- QNX Hypervisor User Guide: `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.hypervisor.user/`
- QNX Security & secpol Guide: `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/`
- QNX Raspberry Pi 4 BSP Release Notes: `https://www.qnx.com/developers/docs/BSP8.0/com.qnx.doc.bsp.releasenotes/topic/rel_sdp80.bsp.broadcom.rpi4.bcm2711.html`
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
