# Codelab: A Dead-Man's Handle in an Afternoon on QNX 8.0

**Time required:** 45 minutes  
**Target OS:** QNX Software Development Platform (SDP) 8.0 + QNX Hypervisor 8.0.5  
**Target Platform:** QEMU AArch64 `virt` (`4x Cortex-A76`, EL2 VHE, GICv2) or Linux Host Simulation (`host-sim`)

---

## 1. Goal (00:00 – 05:00)

In physical AI, the policy that plans motion should not hold the credential that moves the motor. In this 45-minute codelab, you will build and fault-test **LATCH** (**Last Authority for Trusted Control Handoff**):

1. **`latch-ingest`** on `_cpu-1`: Reads 32-byte `LATH` frames from the guest `virtio-console`, checks IEEE CRC32 and header invariants, discards corrupted payloads, and forwards checked proposals to `/dev/latch/proposal`. It has **no** `latch/actuator` ability and **no** I2C file descriptor.
2. **`latchd`** on `_cpu-0`: Runs a `CLOCK_MONOTONIC` timer pulse loop on a `_NTO_CHF_FIXED_PRIORITY` channel, evaluates the 10-tick forward lookahead envelope, enforces `iofunc_client_info_able()` for `latch/actuator` on `/dev/latch/actuator`, drives a PCA9685 at `0x40`, and records `ClockCycles()` into a 4096-entry `.bss` ring buffer.

---

## 2. Build for QNX SDP 8.0 and Host Simulation (05:00 – 15:00)

### 2.1 Build and Run Locally (`host-sim`)

```bash
cd qnx
make host-sim
make check
```

`make check` runs both the built-in C self-test suite and a 200-tick UNIX pipe simulation feeding `guest/liar.py` into `latch-ingest` and `latchd`, outputting `host/suite_tape.csv`.

### 2.2 Build & Boot for QEMU AArch64 `virt` (`aarch64le` + Linux 6.12 Guest)

```bash
source ~/qnx800/qnxsdp-env.sh
cd qnx
make ifs-qemu-aarch64 GUEST_IMAGE=/path/to/linux-6.12/arch/arm64/boot/Image
./run_qemu.sh
```

Inside the booted QNX shell, verify the live Linux 6.12 guest stream and run the native 5-invariant verifier:

```ksh
/proc/boot/latchctl status
/proc/boot/latch_verify -m /proc/boot/latch.manifest
```

---

## 3. How the Custom Ability (`latch/actuator`) Works (15:00 – 25:00)

At startup, before attaching `/dev/latch/proposal` or `/dev/latch/actuator`, `latchd` registers the custom ability with `flags = 0` so neither `PROCMGR_ADN_ROOT` nor `PROCMGR_ADN_NONROOT` holds it by default:

```c
g_ability_actuator_id = procmgr_ability_create("latch/actuator", 0);
```

When any process calls `devctl()` on `/dev/latch/actuator`, `latchd` checks the caller's ability with `iofunc_client_info_able()` (which wraps `ConnectClientInfoAble()`):

```c
struct _client_info *info = NULL;
struct _client_able  able;
memset(&able, 0, sizeof(able));
able.ability = (uint32_t)g_ability_actuator_id;

/* QNX SDP 8.0 signature: (ctp, ioflag, &info, flags, &able, nable) */
int status = iofunc_client_info_able(ctp, msg->connect.ioflag, &info, 0, &able, 1);
bool authorized = (status == EOK) && (info != NULL) &&
                  ((info->flags & _NTO_CI_UNABLE) == 0u);
if (info != NULL) iofunc_client_info_ext_free(&info);
if (!authorized) return EPERM;
```

Because `flags == 0` leaves root out of the default set, even a `root` shell on QNX receives `EPERM` when attempting to `devctl` `/dev/latch/actuator`.

---

## 4. Run the Five Faults (25:00 – 38:00)

From the guest VM (writing to `/dev/hvc0`) or on your workstation via pipe, run each of the five faults in `guest/liar.py`:

| # | Command | What Happens |
| --- | --- | --- |
| 1 | `python3 guest/liar.py keepout --device /dev/hvc0` | Proposes `+450` mrad inside the `[250, 650]` box. `latchd` vetoes within 1 tick (`LATCH_FAULT_KEEPOUT`) and holds position. |
| 2 | `python3 guest/liar.py corrupt --device /dev/hvc0` | Flips 1 bit after CRC calculation. `latch-ingest` drops `u_mrad` and sets `LATCH_FAULT_CRC`; `latchd` enters `HOLD`. |
| 3 | `python3 guest/liar.py replay --device /dev/hvc0` | Repeats `seq` (`LATCH_FAULT_SEQ`), then stops sending (`LATCH_FAULT_WATCHDOG` after 2 ticks). |
| 4 | `kill -9 $(pgrep -f liar.py)` | Guest policy dies. Host tick counter on `_cpu-0` never blinks; after 50 ticks in `HOLD`, `HA-HOME` retracts the horn to `0` mrad. |
| 5 | Root shell `devctl` on `/dev/latch/actuator` | `iofunc_client_info_able()` returns `EPERM` (`LATCH_FAULT_EPERM`). |

---

## 5. Inspect the Evidence Tape (38:00 – 45:00)

Open `host/tape.html` in any browser and load `host/suite_tape.csv` (or inspect the pre-loaded 200-tick run). Verify:
- The applied angle `theta_applied` never enters the shaded `[250, 650]` mrad keep-out zone.
- `HP` mode is only restored after 25 consecutive clean frames (`ticks 33..57`).
- After the guest is killed at tick 85, `latchd` transitions from `HOLD` to `HOME` after 50 ticks and steps monotonically back to `0` mrad (which `latch_verify` explicitly asserts via `DCMD_LATCH_DUMP_TAPE`).
