# Software Bill of Materials (SBOM) — LATCH & GOVERNOR

**Standard Alignment:** SPDX 2.3 / CycloneDX 1.5 Minimal Specification  
**System Integrity Level:** High-Assurance Runtime Interlock  
**External 3rd-Party Runtime Dependencies:** **0 (Zero)**  

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
| **`governor_servo.manifest`** | Schema 3 | LATCH Project | MIT | Safety Contract | None (JSON) | `a29b81341077ac0e4276d91b5ff703c700243db69b674f7cbb466c0689ddc53b` |
| **`syringe_governor.manifest`**| Schema 3 | LATCH Project | MIT | Safety Contract | None (JSON) | `6b62927a81c2566d1f2d7d0e8ff5047d9f22086f1693044ea9a77de7c142b392` |
| **`latch.secpol`** | 1.0.0 | LATCH Project | MIT | Mandatory Access Control | `secpolcompile` | Policy source (`latch.secpol`) |

### B. Untrusted Linux Guest Environment (`guest/`)

| Component | Version | Supplier / Origin | License | Criticality | Dependencies |
|:---|:---:|:---|:---|:---:|:---|
| **Linux Kernel** | 6.12 (ARM64) | The Linux Foundation | GPL-2.0-only | Untrusted SOUP | Unmapped hardware |
| **Guest Init (`/init`)** | 1.0.0 | LATCH Project | MIT | Freestanding | Direct Linux syscalls (`-nostdlib -static`) |

### C. Host & Tooling Dependencies (`tools/`, `host/`)

| Tool / Interface | Runtime | Required 3rd-Party Packages | License | Isolation Guarantee |
|:---|:---:|:---|:---|:---|
| **`consistency_check.py`** | Python 3.10+ | **None** (Standard Library only: `json`, `hashlib`, `re`, `sys`) | MIT | Non-blocking static analysis |
| **`gov_replay.py`** | Python 3.10+ | **None** (Standard Library only: `hashlib`, `json`, `struct`) | MIT | Cryptographic forensic replay |
| **`run_attacks.py`** | Python 3.10+ | **None** (Standard Library only) | MIT | Standalone adversarial test harness |
| **`benchmark_qnx_vs_linux.py`**| Python 3.10+ | **None** (Standard Library only) | MIT | Empirical determinism benchmark |
| **`console.html`** | HTML5 / JS | **None** (Pure Vanilla JS Canvas, zero external CDNs / JS frameworks) | MIT | Completely functional airgapped offline |

---

## 2. Platform SDK & Compiler Toolchain

| Toolchain / Runtime Component | Exact Package / Identifier | Provenance |
|:---|:---|:---|
| **QNX SDP** | QNX Software Development Platform 8.0.0 (`com.qnx.qnx800 8.0.0.00141T202311271501L`) | BlackBerry QNX |
| **QNX Target Utils** | Built from branch `qnx/8.0.0/8.0.5` | BlackBerry QNX |
| **QNX Hypervisor** | `target.hypervisor.core 3.6.0.00802T202608071638L` (Aug 2026 build) | BlackBerry QNX |
| **QNX Cross-Compiler** | QNX GCC 12.2.0 (`gcc_ntoaarch64le`, `gcc_ntox86_64`) via `qcc` | BlackBerry QNX |
| **Host Tooling** | GCC 16.2.1 / Clang 23.1.5 / QEMU 11.1.3 (AArch64 `virt`) | Fedora Linux |

---

## 3. Cryptographic Sidecar Verification

All contracts in the repository are verified prior to execution against signed SHA-256 sidecars conforming to NIST FIPS 180-2:
- `qnx/contracts/governor_servo.manifest.sha256`: `a29b81341077ac0e4276d91b5ff703c700243db69b674f7cbb466c0689ddc53b`
- `qnx/contracts/syringe_governor.manifest.sha256`: `6b62927a81c2566d1f2d7d0e8ff5047d9f22086f1693044ea9a77de7c142b392`
- `qnx/latch.manifest.sha256`: `1a8e10234f8aabbdfe1ce2d5a8b67459e0c9d0cf386963e9deed8ebd5d27f823`
- `qnx/contracts/syringe_pump_bolus.manifest.sha256`: `a9d877ebf63d5670006593ac8eadc7303b324c52c1d30e29aeacb8b9253e0e5e`

