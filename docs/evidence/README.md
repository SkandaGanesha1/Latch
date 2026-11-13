# LATCH — Evidence Archive

Every number this project quotes comes from a file in this
directory. This index says which file proves which claim, how to
regenerate each one, and — just as important — what is **not**
proven here.

A judge without a QNX SDP licence cannot rebuild the IFS, so this
archive is the target proof. It is raw console output, not a
summary written for you.

---

## 1. The headline numbers, and where each one comes from

| Claim | Value | Source file |
|---|---|---|
| Guest suite frames delivered | `84` | `on-target/20261113-001157-console.txt` |
| Wire faults caught | `12` | `on-target/20261113-001157-console.txt` |
| Envelope vetoes | `7` | `on-target/20261113-001157-console.txt` |
| Ring drops | `0` | `on-target/20261113-001157-console.txt` |
| Last accepted proposal | `-180 mrad (seq=80)` | `on-target/20261113-001157-console.txt` |
| Latched fault bits | `0x01AE (CRC\|SEQ\|NAN\|KEEPOUT\|RATE\|WATCHDOG)` | `on-target/20261113-001157-console.txt` |
| Decision latency | `last = 212 cyc (3392 ns) \| max = 40374 cyc (645984 ns)` | `on-target/20261113-001157-console.txt` |
| Proposal backlog | `peak 14 frames \| 0 over limit` | `on-target/20261113-001157-console.txt` |
| Manifest digest (attestation) | `1a8e10234f8aabbdfe1ce2d5a8b67459e0c9d0cf386963e9deed8ebd5d27f823` | `on-target/20261113-001157-console.txt` |
| Verification | `[1/5]`…`[5c/5]` all PASS, `VERIFY_RC=0` | `on-target/20261113-001157-console.txt` |
| Static vCPU pin | `cy-guest-qemu-virt/0` and `/1` | `on-target/20261113-001157-console.txt` (the `pidin -p qvm threads` section) |
| Host-sim signature | `wire=12 · envelope=7 · last_seq=80` | `derived/host-sim-signature.txt` |
| Keep-out breaches | `0` | `tape/latch_tape6-metrics.txt` |
| HA-HOME retraction | `17` rows, monotonic | `tape/latch_tape6-metrics.txt` |
---

## 2. What is in here

```
docs/evidence/
  build/
      20261113-001333-ifs.txt
      20261113-001333-initrd.txt
  derived/
      RUN-OUTPUT-MANIFEST.md
      host-sim-signature.txt
      on-target-metrics.txt
      on-target-numbers.txt
      on-target-run-index.txt
      tape-signatures.csv
  host-sim/
      20261113-181136-consistency.txt
      20261113-181136-host-sim.txt
  on-target/
      01-guest-boot-console.txt
      02-run1-51-envelope-vetoes.txt
      03-run2-48-envelope-vetoes.txt
      04-run3-no-guest-pacing.txt
      05-run4-27-envelope-vetoes.txt
      06-run6-suite-correct-verify-race.txt
      07-run7-verify-all-pass.txt
      08-rejected-2nd-virtio-console.txt
      09-canonical-session.txt
      20261113-001157-console.txt
      20261113-001157-guest-console.txt
      20261113-001157-status.txt
      20261113-001157-tape-dump.txt
      20261113-001157-threads.txt
      20261113-001157-verify.txt
      CURRENT-SESSION.txt
  resolution/
      01-guest-stall-psci.txt
      02-vcpu-pin-syntax.txt
      03-qvm-runmask.txt
      04-transport-starvation.txt
      05-rejected-2nd-virtio-console.txt
      06-session-reset-defect.txt
      SUMMARY.md
  tape/
      latch_tape-metrics.txt
      latch_tape.txt
      latch_tape2-metrics.txt
      latch_tape2.txt
      latch_tape4-metrics.txt
      latch_tape4.txt
      latch_tape5-metrics.txt
      latch_tape5.txt
      latch_tape6-metrics.txt
      latch_tape6.txt
  README.md
```
---

## 3. How to regenerate each one

Everything in this archive is produced by one tool:
`tools/capture_evidence.py`. Nothing here is hand-edited.

```bash
source ~/qnx800/qnxsdp-env.sh

cd latch

# Everything except the QEMU run (~20 s, no QNX licence needed beyond the SDP)
python3 tools/capture_evidence.py --all

# A fresh on-target capture: boots QEMU AArch64 `virt` and drives it (~5 min)
python3 tools/capture_evidence.py on-target

# Or, through the Makefile
make -C qnx evidence          # --all
make -C qnx evidence-on-target # the QEMU run
```

The `history`, `tape` and `resolution` scenarios read the raw console
logs of the bring-up from `/tmp` (override with `--raw-dir`). If those
are gone, the `on-target` scenario produces a fresh canonical session
and the rest of the archive follows from it.

---

## 4. The bring-up, in one table

Each run differs from the one before it by exactly one fix. This is
the part a judge should read: it is not a claim that the thing
works, it is the record of finding out how to make it work.

```
LATCH on-target run index -- the bring-up in one table

Each run differs from the one before it by exactly one fix, so the
counters form a monotone story. Every number below is parsed out of
the archived console next to it.

  CURRENT canonical session (the run the quotable numbers come from):
    20261113-001157-console.txt                     84     12      7      0     80  0

  file                                        frames   wire    env  drops    seq  VERIFY_RC
  --------------------------------------------------------------------------------------------
  01-guest-boot-console.txt                        -      -      -      -      -  -
  02-run1-51-envelope-vetoes.txt                  84      8     51      0     25  0
  03-run2-48-envelope-vetoes.txt                  84      8     48      0     35  0
  04-run3-no-guest-pacing.txt                     84      8     48      0     35  0
  05-run4-27-envelope-vetoes.txt                  84      8     27      0     57  0
  06-run6-suite-correct-verify-race.txt           84     12      7      0     80  1
  07-run7-verify-all-pass.txt                     84     12      7      0     80  0
  08-rejected-2nd-virtio-console.txt              26     26      0      0      0  0
  09-canonical-session.txt                        84     12      7      0     80  0

  What each run changed:
    01-guest-boot-console.txt                  The Linux 6.12 guest booting to /init. The guest console on the serial port, before the LATCH path was driven.
    02-run1-51-envelope-vetoes.txt             Run 1. The guest's 40 ms phase pauses starve the supervisor: its 2-tick watchdog fires, it fails closed, retracts theta, and every later frame becomes a spurious RATE veto.
    03-run2-48-envelope-vetoes.txt             Run 2. The guest's pauses reduced to 1 ms: 48 vetoes -- barely better.
    04-run3-no-guest-pacing.txt                Run 3. The guest pauses removed entirely. IDENTICAL to run 2 (48 vetoes) -- which is what proved the guest was NOT the variable and the transport was.
    05-run4-27-envelope-vetoes.txt             Run 4. The virtio-console vdev's forwarding pulse given a real priority (sched 40) and the bridge's artificial sleep removed: 51 -> 27 vetoes.
    06-run6-suite-correct-verify-race.txt      Run 6. The guest suite is exactly right (84 frames, 12 wire faults, 7 envelope vetoes, last seq 80). latch_verify's step 1 still failed: it sent its ramp unpaced, so the supervisor's watchdog tripped while the tool was still polling.
    07-run7-verify-all-pass.txt                Run 7. latch_verify paces its proposals at one per supervisor tick. All five invariants PASS and VERIFY_RC=0.
    08-rejected-2nd-virtio-console.txt         REJECTED EXPERIMENT. A second virtio-console for the guest's phase markers. It corrupted the frame channel: 26 of 84 frames delivered, wire faults tripled. Reverted; recorded here so the failure is not repeated.
    09-canonical-session.txt                   THE CANONICAL SESSION. One continuous boot of the QEMU AArch64 `virt` image with every fix in place: the EL2-VHE banner, the static vCPU pin proof, the supervisor counters, the five verification steps and VERIFY_RC=0.
```

---

## 5. The host-sim signature

The host simulation runs the same safety logic on the workstation.
It is the gate CI enforces on every push.

```
LATCH host-sim exact signature

This is the ONLY place the numbers in the README, the video script and
the Devpost page may be taken from. The on-target signature lives in
docs/evidence/on-target/ and must agree with this table.

  wire faults (CRC|SEQ|NAN)   : 12
  envelope vetoes (KEEP|BND|RATE): 7
  last accepted seq           : 80
  HA-HOME retraction rows     : 17
  keep-out breaches          : 0

  EXPECTED: wire=12  envelope=7  last_seq=80  home>=10  breaches=0

  RESULT: PASS -- signature matches
```

---

## 6. What is NOT proven here

Stated plainly, because a claim the evidence does not cover is worse
than no claim at all.

- **The horn does not move on this target.** The QEMU AArch64 `virt`
  image runs `latchd -n` (mock I²C). There is **no PCA9685** on the
  QEMU machine and no horn. The Raspberry Pi 4B build is the same
  `latchd` binary with the real `i2c-bcm2711` bus and the PCA9685
  attached — that is the take that moves the horn. **Do not mix the
  two sentences.**
- **The Raspberry Pi 4B path is unexecuted.** No Pi 4B hardware was
  available. The buildfile and the qvmconf are correct and are
  checked by `tools/consistency_check.py`, but nothing here proves
  the Pi boots.
- **The latency numbers are not a WCET.** They are measured
  decision-cycle latencies under **QEMU TCG** (pure software
  emulation of AArch64 on an x86_64 host). TCG timing is not the
  target's timing. Report the last and the max latency, in cycles
  and in nanoseconds, against the manifest's `timing.wcet_budget_us`,
  and name the machine.
- **No certification claim.** No ASIL, no SIL, no ISO 26262, no IEC
  61508, no IEC 62304. This is a **measured fail-closed runtime
  filter**, and the faults are visible on camera.
- **The guest's console markers are cosmetic.** The PL011 console is
  slow and the kernel's console driver drops entries under load, so
  the guest's phase markers may be missing from the guest console
  log. The **host's** evidence tape is complete, and it is what the
  claims rest on.
- **The security policy IS enforced on every boot — but it has not been
  audited against the running system.** `qnx/latch_qemu.build` pushes the
  compiled policy with `secpolpush` at boot, and pushing the policy is
  what *triggers* enforcement (QNX SDP 8.0: *"Pushing the security policy
  (using secpolpush) triggers policy enforcement"*). So the
  `latch/actuator` ability's fail-closed behaviour is demonstrated
  **under an enforced policy** — that is `latch_verify` steps 5a/5b/5c.
  What has NOT been done is an `secpolgenerate` audit of the rule
  graph against the running image, which is the only way to know that
  the rules stated in `qnx/latch.secpol` are the rules the system
  actually needs. (`secpollaunch` is a different utility entirely — a
  setuid-root launcher — and is not the enforcement mechanism.)
- **One platform, one architecture.** Everything here is AArch64
  on QEMU `virt`. Nothing here is a claim about x86_64 QSTI, about
  the Pi's real I²C bus, or about any other guest OS.

---

## 7. The archive cannot rot

`make -C qnx evidence-check` re-runs the host-sim capture and
compares the signature against the archived one. CI runs it on
every push: if the code drifts away from the archived evidence, the
build fails rather than the submission quietly becoming false.

> **The current canonical session is `docs/evidence/on-target/CURRENT-SESSION.txt`** -- a stable pointer to the timestamped capture family, so this file never has to be rewritten when a capture is re-run.
