# LATCH — Video Script (≤ 3:00) & Devpost Submission Checklist

**Target:** QNX Global Hackathon 2026 (`QEMU AArch64 virt`, QNX SDP 8.0 + QNX Hypervisor 8.0.5)

---

## 1. 3-Minute Demo Video Shot List

| Time | Scene / Terminal Command | Key Narrative |
| :--- | :--- | :--- |
| **0:00–0:20** | Boot QEMU (`cd latch/qnx && ./run_qemu.sh --arch aarch64`), show `syspage::hypinfo::flags=0x00000001` (EL2 VHE host) and the `latchd` banner | *"The AI may propose. Only QNX may move. Here is QNX SDP 8.0 booting in EL2 VHE on QEMU AArch64 virt."* |
| **0:20–0:55** | `latchctl console` (shows the Linux 6.12 guest kernel console and the guest policy's nine fault phases) + `/proc/boot/latchctl status` (`Proposals Received`, `Wire Faults Caught`, `Envelope Vetoes`, `Ring Drops: 0`) | *"A Linux 6.12 guest streams proposals over virtio-console to an unprivileged `latch-ingest` bridge. Keep-out proposals into `[250, 650]` mrad are vetoed within 1 tick."* |
| **0:55–1:30** | Run `/proc/boot/latch_verify -m /proc/boot/latch.manifest` and `echo VERIFY_RC=$?` | *"All 5 microkernel invariants pass (`VERIFY_RC=0`): nominal HP tracking, keep-out veto, CRC bit-flip containment, watchdog `HA-HOME` retraction to `0` mrad, and `EPERM` ability enforcement."* |
| *(cut)* | *Guest phase 9 is the real one: the guest stops writing bytes entirely. PID 1 in the guest IS the policy, so say "the guest stopped talking", never "we killed the policy process".* | |
| **1:30–2:05** | Highlight `EPERM` from `[5a/5]–[5c/5]` (`PROBE_ABILITY`, `FORCE_HOLD`, `open(O_WRONLY)`) and `pidin -p qvm threads` (vCPU threads `cy-guest-qemu-virt/0` and `/1`) | *"Root is not the credential — `latch/actuator` (`flags = 0`) is. `latchd` runs `SCHED_FIFO 63` on CPU 0 while the guest vCPUs are statically pinned to CPUs 2 and 3."* |
| **2:05–2:35** | Open `latch/host/tape.html` offline in browser, show the tape + the `ClockCycles()` latency line from `latchctl status` | *"Every tick is stamped with `ClockCycles()` in a 4096-entry `.bss` ring. The last-sample and max latency are both printed, in cycles and in nanoseconds, against the 100 µs budget."* |
| **2:35–3:00** | Run `sha256sum latch/qnx/latch.manifest` (`1a8e1023...27f823`) + `make -C latch/qnx demo-syringe` | *"Zero-hardcoding manifest verified via FIPS 180-2 SHA-256 — same `latchd` binary enforces both a 1-DoF servo and a medical syringe pump."* |

---

## 1a. The committed on-target transcript

`docs/evidence/README.md` is the index: it maps every claim to the archive file
that proves it, lists the commands that regenerate each file, and states what is
**not** proven.

The canonical artefact is `docs/evidence/on-target/CURRENT-SESSION.txt` — the
raw QNX host console of **one continuous boot** of the QEMU AArch64 `virt` image:
the EL2-VHE hypervisor banner, `pidin -p latchd threads`, `pidin -p qvm threads`
(the guest vCPU threads named `cy-guest-qemu-virt/0` and `/1`, i.e. the static
pins), `latchctl status`, the five verification steps, and `VERIFY_RC=0`.

Two more files earn their place on camera:

- `docs/evidence/derived/on-target-run-index.txt` — the whole bring-up in one
  table. Each run differs from the one before it by exactly one fix, and the
  envelope-veto count falls `51 → 48 → 27 → 7` as a result. This is the honest
  version of the story: not "it works", but "here is how we found out".
- `docs/evidence/resolution/SUMMARY.md` — the four defects, each with its
  mechanism and its proof.

Use these files as the source for every number quoted in the video and on the
Devpost page. If a number is not in this archive, it is not a measurement.

---

## 2. Judge Definition of Done Checklist

1. **One-command QEMU AArch64 build & boot:** `make -C latch/qnx ifs-qemu-aarch64 GUEST_IMAGE=/path/to/Image` + `./run_qemu.sh`
2. **Automated end-to-end QEMU verification:** `make -C latch/qnx verify-qemu` (`VERIFY_RC=0`)
3. **Host-sim & second-plant verification:** `make -C latch/qnx check demo-syringe`
4. **Architectural & SHA-256 consistency:** `python3 latch/tools/consistency_check.py` (0 errors)
5. **Offline evidence tape viewer:** `latch/host/tape.html` (zero CDN dependencies)
6. **Codelab & License:** `latch/codelab/dead-mans-handle.md` + `latch/LICENSE` (MIT)

