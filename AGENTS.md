# LATCH — Agent Notes

This repository is **LATCH** (Last Authority for Trusted Control Handoff): a
mixed-criticality runtime-assurance component for physical AI, built on
**QNX SDP 8.0** + **QNX Hypervisor 8.0**. If you are an AI agent working in
this tree, read this file, then read `docs/LATCH-implementation.md` (the
architecture) and `docs/envelope.md` (the safety envelope).

The project is **one** product with **one** story: *the guest may propose a
32-byte motion frame; only a pinned, ability-locked QNX process may write the
actuator, and it fails closed if the guest hangs, lies, or dies.* Do not add a
second architecture, a second guest policy, a second plant skin, or a second
framework. Scope discipline is the deliverable here, not just a nice-to-have.

---

## 1. Layout

```text
latch/
  qnx/        QNX SDP 8.0 sources, mkifs buildfiles, qvm guest configs, secpol
  guest/      the in-guest policy (freestanding C) + the workstation generator
  host/       the offline evidence-tape viewer and the committed tape
  tools/      cross-file invariant checker + the QEMU on-target harness
  docs/       architecture, envelope spec, research log, video script
  codelab/    the 45-minute hands-on tutorial
```

**The single guest policy** is `guest/latch_guest_init.c` — a freestanding
static AArch64 binary (`-nostdlib -ffreestanding -static`) packed as
`guest/linux-guest.initrd`. There is **no libc, no shell and no Python inside
the guest**. `guest/liar.py` is the *workstation* generator used by
`make check` through a POSIX pipe; it emits the same suite but never enters the
hypervisor guest. Keep exactly one of these paths alive at a time.

---

## 2. Universal rules

These hold for every task, in this repository.

1. **Prove claims with command output before acting.** Do not assert platform
   behaviour, dependency state, or build results as fact without having run
   the command that shows it. This includes the facts written in this file:
   a doc is a strong prior, not evidence. When a statement here is
   load-bearing for what you are about to do, spend the one command to confirm
   it, and correct this file when it turns out to be wrong. "100%", "verified"
   and "certain" are specific claims, not tones — say them only after running
   the exact check that proves that claim against the authoritative artifact
   (the freshly built IFS, the current file on disk), never against a proxy
   such as an earlier build.

2. **Treat statements as claims, not evidence — including official ones, and
   including your own.** A ticket comment, a handoff note, an upstream doc, a
   previous session's notes are all strong priors and all equally capable of
   being stale. Either verify a claim or attribute it — "per the release note,
   X" is honest, bare "X" is not. Where two sources disagree, resolve the
   disagreement rather than picking the reading that lets you continue. Name
   the limits of the test in the same breath as the result.

3. **Never commit to a repository a human reviews, and never push.** Git is a
   tool you need: run it freely for inspection (`git status`, `log`, `diff`,
   `show`). What you never do: `git push`; commit; or run history-altering or
   destructive commands (`reset --hard`, `checkout --`, `rebase`, `clean`)
   that could discard work. Prepare the change and hand off — the human
   commits, branches, and pushes.

4. **Every safety parameter is signed data, not code.** The manifest
   (`qnx/latch.manifest` plus its `.sha256` sidecar) is the single source of
   truth for the plant geometry, the envelope, the timing, the paths and the
   actuator calibration. If you change a manifest, you must regenerate the
   sidecar and update the same digest in `README.md` and
   `docs/LATCH-implementation.md`. `tools/consistency_check.py` is the gate
   that proves you did.

5. **Fail closed.** The loader rejects unknown keys, missing required keys,
   a missing or mismatched sidecar, and out-of-range values. A new code path
   that silently falls back to a compiled-in default is a defect, not a
   convenience.

6. **Record confirmed facts back into this file** the moment they are proven,
   so the next session starts ahead of this one. A QNX platform fact that
   cost you an hour belongs in §4 below.

---

## 3. Build and verification

```bash
source ~/qnx800/qnxsdp-env.sh      # QNX SDP 8.0 environment

cd latch/qnx
make check                         # host-sim: self-tests + 200-tick fault suite
make demo-syringe                  # the second plant, zero recompiles
make guest-initrd                  # build the freestanding AArch64 /init
make ifs-qemu-aarch64 GUEST_IMAGE=/abs/path/to/linux-6.12/arch/arm64/boot/Image
./run_qemu.sh --arch aarch64 --kernel build/nto-aarch64-le/latch_qemu.ifs
```

`python3 tools/consistency_check.py` asserts the cross-file invariants
(manifest ↔ sidecar ↔ README ↔ docs, buildfile payloads against the
**installed** SDP sysroot, the static vCPU pin form, the guest burst fitting
the ring, and the secpol grammar). It is the cheapest way to catch drift.

`tools/verify_qemu_aarch64.py` boots the built IFS under QEMU and asserts the
on-target signature. It is the only thing that proves the on-target numbers.

**The evidence archive** lives in `docs/evidence/` and is generated by
`tools/capture_evidence.py`:

```bash
make -C qnx evidence            # everything except the QEMU boot (~20 s)
make -C qnx evidence-on-target  # a fresh QEMU AArch64 `virt` capture (~5 min)
make -C qnx evidence-check      # the anti-rot gate
```

Rules for the archive:

- **Never hand-edit a file under `docs/evidence/`.** The tool writes every
  one of them. If a number is wrong, fix the code and regenerate.
- **The archive is the target proof.** A judge without a QNX SDP licence
  cannot rebuild the IFS, so the raw console logs are what the claims rest
  on. `docs/evidence/README.md` is the index, and it also lists what is
  **not** proven — keep that section honest.
- **`make -C qnx evidence-check` must pass.** It re-runs the host-sim
  capture and compares the signature against the archived one. A mismatch
  means the code has drifted from the committed evidence, and CI must fail.

---

## 4. QNX 8.0 platform facts (proven on this tree)

These cost real time to establish. They are the ones that are easy to get
wrong.

- **QNX Hypervisor 8.0 `cpu` takes an indented options block**, whose only
  two options are `cluster` and `sched`. The Hypervisor 7.1 one-line form
  `cpu _cpu-2 sched 8r` is **rejected** by the 8.0 qvm with
  `Unknown option '_cpu-2'`, and a bare `cpu` / `sched 8r` block leaves the
  vCPU **floating** on every core — including the one `latchd` runs on.
  `cluster` takes exactly **one** name; a comma-separated list is parsed as
  a single token and rejected.
- **The `qvm` process must be started with an unconstrained runmask.**
  `on -C <n>` and `on -R <mask>` both resolve to a *predefined single-CPU
  cluster*, and no predefined cluster covers CPUs 2+3 together, so `-R 0xc`
  and `-C 2 -C 3` both fail with
  `Invalid cluster runmask specified`. The isolation comes from the qvmconf
  pins, not from the process affinity.
- **PSCI must be asserted explicitly on QEMU.** `qvm` auto-detects host PSCI
  support by reading the *host device tree*, and QNX's startup cannot read
  QEMU's DTB on this platform. Without `set psci-supported on` the guest FDT
  gets no PSCI node and Linux hangs forever in secondary-CPU bring-up.
  `set pointer-authentication off` and `set linux-fdt-free on` are the
  companions.
- **`vdev virtio-console` guest→host forwarding is pulse-driven**, and the
  pulse priority defaults low. Under QEMU TCG — where the host QNX, the guest
  Linux and `latchd` (SCHED_FIFO 63) all contend for the same x86 cores —
  the starved forward showed up as 16- and 28-tick gaps in the frame
  delivery, during which the supervisor's 2-tick watchdog fired, failed
  closed into HA-HOLD → HA-HOME, retracted `theta`, and turned every later
  frame into a spurious RATE veto. `sched 60` on the vdev fixes it.
- **A starved transport does not look like a starved transport.** It looks
  like a *safety-logic* bug: 51 envelope vetoes where 7 are correct, with
  `theta` spuriously retracted. The chain is — a starved forward → a tick
  with no proposal → the watchdog fires → fail closed into HA-HOLD → retract
  `theta` by HA-HOME → `theta` no longer matches the value the next proposal
  carries → that proposal is vetoed as a RATE fault. **When a safety counter
  is wrong, suspect the data path before you suspect the safety logic.**
  The measurement that settles it is the *starvation stall*: a run of
  supervisor ticks during which the frame's sequence number does not
  advance. `tools/capture_evidence.py` reports them.
- **The PL011 console is slow, and it stalls the guest.** QNX's own
  hypervisor documentation says the PL011 "is slow and has slow output". A
  blocking write to the guest's `/dev/console` stalled the guest ~24 ms per
  line. Guest diagnostics belong in `/dev/kmsg` (the kernel log ring
  buffer), which returns immediately.
- **Do not add a second `vdev virtio-console`.** It was tried, to give the
  guest's markers a fast dedicated channel, and it **corrupted the frame
  channel**: the guest delivered 26 of 84 frames and the wire-fault count
  tripled. The single-virtio-console design is a decision with a measured
  cost, not an accident. See `docs/evidence/resolution/05-rejected-2nd-virtio-console.txt`.
- **There is no `vdev-gic.so` and no `libqvm.so.1` in QNX SDP 8.0.** The
  GIC vdev is linked into the `qvm` binary and `qvm` links `libqh.so.1`.
  `tools/consistency_check.py` verifies the buildfile payloads against the
  installed sysroot rather than a hardcoded list.
- **`mlockall()` is a no-op on SDP 8.0** ("all memory is locked for the
  entire duration of the process"). Never present it as a determinism
  technique.
- **The minimal IFS has no `sleep`.** Driving the QNX shell from a script
  means the script must run on the **host** and its *stdout* must be piped
  into QEMU's stdin. Sending the script text into the guest instead makes
  the shell answer `sleep: cannot execute - No such file or directory` for
  every pause — and then every command runs at once, before the guest has
  booted. `tools/capture_evidence.py` shows the working form.
- **Capture to a FILE, not through a pipe.** `subprocess.run(..., stdout=PIPE)`
  followed by a timeout raises `TimeoutExpired` and **discards** the captured
  output — which throws away a ten-minute TCG boot. Redirect the child's
  stdout to a file: whatever was printed is on disk the instant it dies.
- **Adaptive partitioning (APS) was removed in SDP 8.0.** Use the static
  vCPU runmask and `ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT)`. Do
  not name APS anywhere in the README, the codelab or the video.

---

## 5. What this project must never claim

- No ASIL / SIL / ISO 26262 / IEC 61508 / IEC 62304 certification claim.
  Claim a **measured fail-closed runtime filter** and show the faults on
  camera.
- No "WCET" for a number that is a TCG observation. Report the **last** and
  the **max** decision latency, in cycles and in nanoseconds, against the
  manifest's `timing.wcet_budget_us`, and name the machine.
- On the **QEMU AArch64 virt** take, `latchd` runs with `-n` (mock I²C):
  **no PCA9685 is present and the horn does not move.** Say so. The Raspberry
  Pi 4B build is the same binary with the real `i2c-bcm2711` bus.
- The guest policy is **PID 1**. There is no separate guest process to
  `kill -9`. Say *"the guest stopped sending; the 1 kHz loop did not stop."*
- No SSH on the virt IFS: it has no `sshd` and no NIC driver. The operator
  shell is on the serial console.
- No "production-grade", no "certified", no "formally verified".

---

## 6. Commits and hygiene

- The public repo must contain one coherent story. Do not publish unrelated
  tooling, and do not commit build artifacts (`qnx/build/` is gitignored).
- `TARGET.md` is gitignored and must contain **no passwords or private
  keys**. If you need target connection details, ask the user; never guess,
  and never proceed to touch a target before the connection is verified.
- `latch/qnx/build/` and `latch/guest/linux-guest.initrd` are build
  outputs. The initrd is the one tracked binary (CI cannot cross-compile the
  AArch64 guest); keep it regenerated and in sync with
  `guest/latch_guest_init.c`.
