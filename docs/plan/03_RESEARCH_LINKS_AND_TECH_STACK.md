# 03 — Research Links, Hackathon Rules & Verified Platform Specifications

**Generated:** 2026-11-23  
**Status:** Live-Verified Link & Citation Register  
**Context:** QNX Everywhere Global Hackathon 2026 (Devpost: `qnx.devpost.com`)

---

## 1. Verified Hackathon Guidelines & Rules

| Parameter | Confirmed Value | Verification Method / Source |
|---|---|---|
| **Submission Deadline** | **December 15, 2026 at 2:00 PM EST** | Live verified on `qnx.devpost.com/rules` |
| **Judging Period** | **January 15 – 29, 2027** (Winners announced ~Feb 4, 2027) | Devpost Rules §6 |
| **Prize Pool** | **$50,000 Total** ($10k Grand Prize + CEO meeting; Category & Bonus prizes) | Devpost Rules §7-8 |
| **Multi-Prize Rule** | Eligible for Category Prize + Bonus Prizes (Best Codelab $3.5k, Best Use of QNX Tech $3.5k) | Devpost Rules §8 |
| **Demo Video Requirement** | Public YouTube video, **under 3 minutes 00 seconds**, demonstrating software on intended platform | Devpost Rules §4 |
| **Open Source Requirement** | Public GitHub repository with OSI-approved license visible in root (`LICENSE`) | Devpost Rules §4 |
| **Post-Deadline Policy** | Submissions cannot be edited after Dec 15 2:00 PM EST (portfolio changes remain allowed) | Devpost Rules §11 |
| **Judge Roster** | Exactly 9 judges confirmed on competition landing page | `qnx.devpost.com` |

---

## 2. QNX SDP 8.0 & Hypervisor Platform Facts

- **SDP 8.0.6 Current Baseline**: Active production release is QNX SDP 8.0.6 (Release notes Nov 12, 2026).
- **Target OS Nuance**: Installed SDK image builds report `8.0.0` in `/target/qnx/etc/qversion` with branch metadata `qnx/8.0.0/8.0.5`. All claims explicitly disclose building on installed 8.0.0 toolchain rather than assuming 8.0.6.
- **Adaptive Partitioning Scheduler (APS)**: APS is **not present** in QNX SDP 8.0. Real-time deterministic scheduling relies on priority-preemptive `SCHED_FIFO`, core runmask pinning (`ThreadCtl`), and hardware interrupt routing.
- **Functional Safety Certifications**: QNX OS for Safety 8.0 is certified by TÜV Rheinland to **ISO 26262 ASIL D, IEC 61508 SIL 3 (not SIL 4), IEC 62304 Class C, and ISO/SAE 21434**.
- **Virtual Target Support**: QEMU AArch64 (`-M virt,virtualization=on,gic-version=2 -cpu cortex-a76`) is an officially documented development target.

---

## 3. Curated Link & Academic Citation Register

### Competition & QNX Documentation
- Devpost Hackathon: `https://qnx.devpost.com/`
- Official Competition Rules: `https://qnx.devpost.com/rules`
- QNX Everywhere Developer Portal: `https://qnx.software/en/developers/get-started/qnx-everywhere`
- Writing QNX Resource Managers: `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/write_resource_manager.html`
- QNX Security & secpol Guide: `https://www.qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/developer_checklist.html`

### Academic Safety & Physical AI References
- **Ames et al. (2019)**: *Control Barrier Functions: Theory and Applications*, IEEE European Control Conference.
- **EU AI Act (Regulation 2024/1689)**: Article 12 (Automatic Recording of Events / Logging Obligations), phased enforcement 2027–2028.
- **Willison (2023–2024)**: *Prompt Injection and the Dual-LLM Boundary Pattern*.
- **InfectBot / LLM Security (IJCAI 2024)**: Demonstrating untrusted black-channel exploitation in autonomous agents.
