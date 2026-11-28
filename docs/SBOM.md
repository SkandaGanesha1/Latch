# Software Bill of Materials (SBOM) — LATCH & GOVERNOR

**Format:** Human-readable inventory; not a complete SPDX or CycloneDX document.
**Scope:** Prototype supervisor, Linux guest and optional experimental inference profile.
**Completeness:** Model provenance, exact model hash and transitive inference dependencies must be recorded for each built image.

---

## 1. System Inventory & Component Registry

### A. Safety Supervisor & Core Microkernel Subsystems (`qnx/`)

| Package / Component | Version / Commit | Supplier / Origin | License | Criticality | Dependencies | Integrity Digest (SHA-256) |
|:---|:---:|:---|:---|:---:|:---:|:---|
| **`latchd`** | 1.0.0 | LATCH Project | MIT | **Architectural alignment with ISO 26262 / IEC 62304 concepts; not certified** | POSIX C11, `librt`, `libpthread` | Compiled from source (`latchd.c`) |
| **`latch_ingest`** | 1.0.0 | LATCH Project | MIT | Mixed-Criticality | POSIX C11 | Compiled from source (`latch_ingest.c`) |
| **`latchctl`** | 1.0.0 | LATCH Project | MIT | Diagnostic | POSIX C11 | Compiled from source (`latchctl.c`) |
| **`latchlog`** | 1.0.0 | LATCH Project | MIT | Diagnostic | POSIX C11 | Compiled from source (`latchlog.c`) |
| **`latch_verify`** | 1.0.0 | LATCH Project | MIT | Verification | POSIX C11 | Compiled from source (`latch_verify.c`) |
| **`latch.manifest`** | Schema 2 | LATCH Project | MIT | Safety Contract | None (JSON) | `1a8e10234f8aabbdfe1ce2d5a8b67459e0c9d0cf386963e9deed8ebd5d27f823` |
| **`syringe_pump_bolus.manifest`** | Schema 2 | LATCH Project | MIT | Safety Contract | None (JSON) | `a9d877ebf63d5670006593ac8eadc7303b324c52c1d30e29aeacb8b9253e0e5e` |
| **`governor_servo.manifest`** | Schema 3 | LATCH Project | MIT | Safety Contract | None (JSON) | `a29b81341077ac0e4276d91b5ff703c700243db69b674f7cbb466c0689ddc53b` |
| **`syringe_governor.manifest`** | Schema 3 | LATCH Project | MIT | Safety Contract | None (JSON) | `7378df8166a4a83c6a91cd4fc74f7c434819ee417165710a65bd9e5328e046fd` |
| **`homeostat_servo.manifest`** | Schema 3 | LATCH Project | MIT | Safety Contract | None (JSON) | `4e65a92283e30e84898e332db1be9e510e8200f95094d28e6bb999e93dc9ba30` |
| **`latch.secpol`** | 1.0.0 | LATCH Project | MIT | Mandatory Access Control | `secpolcompile` | Policy source (`latch.secpol`) |

### B. Untrusted Linux Guest Environment (`guest/`)

| Component | Version | Supplier / Origin | License | Criticality | Dependencies |
|:---|:---:|:---|:---|:---:|:---|
| **Linux Kernel** | 6.12 (ARM64) | The Linux Foundation | GPL-2.0-only | Untrusted SOUP | Unmapped hardware |
| **Guest Init (`/init`)** | 1.0.0 | LATCH Project | MIT | Freestanding | Direct Linux syscalls (`-nostdlib -static`) |
| **llama.cpp** | `guest/Makefile` specifies revision `44d50873b` as a build default; verify the actual checkout | ggml-org contributors | MIT (verify against the selected checkout) | Experimental guest inference only | Static C++/GGML dependencies; not part of the supervisor |
| **GGUF model** | Local `SmolLM2-135M-Instruct-Q8_0.gguf`, SHA-256 prefix `5a1395716f791374`; matching it to an archived run is not established | Model publisher | Verify for the selected model | Experimental guest inference only | Loaded from the guest asset disk |

### C. Host & Tooling Dependencies (`tools/`, `host/`)

| Tool / Interface | Runtime | Required 3rd-Party Packages | License | Isolation Guarantee |
|:---|:---:|:---|:---|:---|
| **`consistency_check.py`** | Python 3.10+ | **None** (Standard Library only: `json`, `hashlib`, `re`, `sys`) | MIT | Non-blocking static analysis |
| **`gov_replay.py`** | Python 3.10+ | **None** (Standard Library only: `hashlib`, `json`, `struct`) | MIT | Cryptographic forensic replay |
| **`run_attacks.py`** | Python 3.10+ | **None** (Standard Library only) | MIT | Standalone adversarial test harness |
| **`benchmark_qnx_vs_linux.py`**| Python 3.10+ | **None** (Standard Library only) | MIT | Latency-tape summarizer — summarises recorded `cycles_in`/`cycles_out` samples; it does **not** benchmark QNX |
| **`console.html`** | HTML5 / JS | **None** (Pure Vanilla JS Canvas, zero external CDNs / JS frameworks) | MIT | Completely functional airgapped offline |

---

## 2. Platform SDK & Compiler Toolchain

| Toolchain / Runtime Component | Exact Package / Identifier | Provenance |
|:---|:---|:---|
| **QNX SDP** | QNX Software Development Platform 8.0.0 (`com.qnx.qnx800 8.0.0.00141T202311271501L`) | BlackBerry QNX — QNX SDP 8.0 release notes; the installed-vs-current split (installed 8.0.0, current upstream 8.0.6) is stated in `docs/plan/03_RESEARCH_LINKS_AND_TECH_STACK.md` |
| **QNX Host Tools (metapackage)** | `com.qnx.qnx800.host.linux.x86_64 0.0.1.02005T202411230033L` — the metapackage. Its `ResourceDescriptor.afd` **requires** the per-tool packages below; it does **not** require `mkifs`. | BlackBerry QNX — read from the QSC install manifest `~/qnx800/.packages/metadata/` |
| **QNX Host Tools (per-tool)** | `com.qnx.qnx800.host.linux.x86_64.qcc 8.0.0.00121T202510081309L` (`qcc`) · `com.qnx.qnx800.host.linux.x86_64.secpol 0.5.0.00132T202605281115L` (`secpolcompile`) · `com.qnx.qnx800.host.linux.x86_64.qlicense 8.0.0.00114T202411221950L` (`qlicense`) · `com.qnx.qnx800.host.linux.x86_64.mkifs 1.2.2.00014T202605190942L` (`mkifs`) | BlackBerry QNX — read from the QSC install manifest |
| **QNX Hypervisor** | `com.qnx.qnx800.target.hypervisor.group 3.6.0.00802T202608071638L` (Aug 2026 build) — this package version is the one published for **QNX Hypervisor 8.0.5**, so the installed hypervisor **is** 8.0.5 | BlackBerry QNX — QNX Hypervisor 8.0.5 Product Release Notes, "Date of this edition: August 21, 2026": `https://www.qnx.com/developers/docs/relnotes8.0/com.qnx.doc.release_notes/topic/qh8.0_prod_release_notes/hypervisor8.0.5_rn.html` |
| **QNX Cross-Compiler** | QNX GCC 12.2.0 (`gcc_ntoaarch64le`, `gcc_ntox86_64`) via `qcc` — package `com.qnx.qnx800.host.linux.x86_64.gcc 12.2.0.00500T202604231841L` | BlackBerry QNX |
| **Host Tooling** | GCC 16.2.1 / Clang 23.1.5 / QEMU 11.1.3 (AArch64 `virt`) | Fedora Linux |

---

## 3. Cryptographic Sidecar Verification

The loader compares each selected contract to a plain SHA-256 sidecar. These
sidecars are not digital signatures and cannot authenticate a manifest when
an attacker can replace both files. The following are the expected digests:
- `qnx/latch.manifest.sha256`: `1a8e10234f8aabbdfe1ce2d5a8b67459e0c9d0cf386963e9deed8ebd5d27f823`
- `qnx/contracts/syringe_pump_bolus.manifest.sha256`: `a9d877ebf63d5670006593ac8eadc7303b324c52c1d30e29aeacb8b9253e0e5e`
- `qnx/contracts/governor_servo.manifest.sha256`: `a29b81341077ac0e4276d91b5ff703c700243db69b674f7cbb466c0689ddc53b`
- `qnx/contracts/syringe_governor.manifest.sha256`: `7378df8166a4a83c6a91cd4fc74f7c434819ee417165710a65bd9e5328e046fd`
- `qnx/contracts/homeostat_servo.manifest.sha256`: `4e65a92283e30e84898e332db1be9e510e8200f95094d28e6bb999e93dc9ba30`

