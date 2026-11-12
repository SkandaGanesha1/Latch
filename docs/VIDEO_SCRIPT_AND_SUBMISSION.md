# LATCH — Video Script (≤ 3:00) & Devpost Submission Checklist

**Target:** QNX Global Hackathon 2026 (`QEMU AArch64 virt`, QNX SDP 8.0 + QNX Hypervisor 8.0.5)

---

## 1. 3-Minute Demo Video Shot List

| Time | Scene / Terminal Command | Key Narrative |
| :--- | :--- | :--- |
| **0:00–0:20** | Boot QEMU (`cd latch/qnx && ./run_qemu.sh`), show `syspage::hypinfo::flags=0x00000001` and `latchd` banner | *"The AI may propose. Only QNX may move. Here is QNX SDP 8.0 booting in EL2 VHE on QEMU AArch64 virt."* |
| **0:20–0:55** | Show `/dev/shmem/guest_console.log` (`Run /init as init process`) + `/proc/boot/latchctl status` (`Proposals Received: 200`, `Wire Faults Caught: 12`, `Envelope Vetoes: 7`, `Ring Drops: 0`) | *"A Linux 6.12 guest streams 200 proposals over virtio-console to an unprivileged `latch-ingest` bridge. Keep-out proposals into `[250, 650]` mrad are vetoed within 1 tick."* |
| **0:55–1:30** | Run `/proc/boot/latch_verify -m /proc/boot/latch.manifest` and `echo VERIFY_RC=$?` | *"All 5 microkernel invariants pass (`VERIFY_RC=0`): nominal HP tracking, keep-out veto, CRC bit-flip containment, watchdog `HA-HOME` retraction to `0` mrad, and `EPERM` ability enforcement."* |
| **1:30–2:05** | Highlight `EPERM` from `[5a/5]–[5c/5]` (`PROBE_ABILITY`, `FORCE_HOLD`, `open(O_WRONLY)`) and `pidin -P latchd` | *"Root is not the credential — `latch/actuator` (`flags = 0`) is. `latchd` runs `SCHED_FIFO 63` on CPU 0 while the guest runs at priority 8."* |
| **2:05–2:35** | Open `latch/host/tape.html` offline in browser, show `suite_tape.csv` + `ClockCycles()` latency | *"Every tick is stamped with `ClockCycles()` in a 4096-entry `.bss` ring: ~1.1–1.8 µs steady-state on QEMU TCG, 1,012 ns max in host-sim."* |
| **2:35–3:00** | Run `sha256sum latch/qnx/latch.manifest` (`135aadeb...`) + `make -C latch/qnx demo-syringe` | *"Zero-hardcoding manifest verified via FIPS 180-2 SHA-256 — same `latchd` binary enforces both a 1-DoF servo and a medical syringe pump."* |

---

## 2. Judge Definition of Done Checklist

1. **One-command QEMU AArch64 build & boot:** `make -C latch/qnx ifs-qemu-aarch64 GUEST_IMAGE=/path/to/Image` + `./run_qemu.sh`
2. **Automated end-to-end QEMU verification:** `make -C latch/qnx verify-qemu` (`VERIFY_RC=0`)
3. **Host-sim & second-plant verification:** `make -C latch/qnx check demo-syringe`
4. **Architectural & SHA-256 consistency:** `python3 latch/tools/consistency_check.py` (0 errors)
5. **Offline evidence tape viewer:** `latch/host/tape.html` (zero CDN dependencies)
6. **Codelab & License:** `latch/codelab/dead-mans-handle.md` + `latch/LICENSE` (MIT)

