# LATCH — Run Output Manifest

**This is the list you asked for: what files each kind of run
produces, and where they land.**

Everything is produced by `tools/capture_evidence.py`. Nothing is
hand-edited; re-running the tool regenerates the files.

---

## A. `make -C qnx evidence-on-target` — QEMU AArch64 `virt`

Boots the IFS, drives the QNX operator shell over the serial
console, and captures. **~5 minutes** (TCG boot is ~3 min, then the
guest needs ~150 s to warm up).

| # | Output file | What it contains |
|---|---|---|
| 1 | `on-target/<ts>-console.txt` | The **raw** QNX host console of one continuous boot: the EL2-VHE hypervisor banner, `FOUND GICv2 / 288 interrupts`, the LATCH banner, `latchd`'s manifest digest, `latchlog`'s banner |
| 2 | `on-target/<ts>-threads.txt` | `pidin -p latchd threads` (the decision loop on CPU 0 at SCHED_FIFO 63) and `pidin -p qvm threads` — the vCPU threads named `cy-guest-qemu-virt/0` and `/1`, **the static-pin proof** |
| 3 | `on-target/<ts>-status.txt` | `latchctl status`: tick counter, mode, angle, **last & max decision latency in cycles and ns**, proposals received, wire faults, envelope vetoes, ring drops, WCET overruns, proposal-backlog peak, EPERM rejections, active/latched fault bits, manifest SHA-256 |
| 4 | `on-target/<ts>-verify.txt` | `latch_verify`: the five steps `[1/5]`…`[5c/5]` each with its PASS/FAIL line, the telemetry block, and `VERIFY_RC=0` |
| 5 | `on-target/<ts>-guest-console.txt` | The guest kernel console from `/dev/shmem/guest_console.log`: the Linux 6.12 boot, `psci: PSCIv1.1 detected in firmware`, `Run /init as init process`, the guest's policy phases |
| 6 | `on-target/<ts>-tape-dump.txt` | The evidence tape as the supervisor's own `latchctl dump` printed it |
| 7 | `derived/on-target-metrics.txt` | **Distilled**: the fault-bit histogram inside and outside the traffic window, the mode-transition timeline, the HA-HOME retraction path and its monotonicity, the keep-out-breach count, the starvation-stall list, the latency maximum |
| 8 | `derived/on-target-numbers.txt` | The quotable-numbers table: every number the submission may cite, with the file it was read from |

---

## B. `make -C qnx evidence-host-sim` — the workstation pipeline

**~5 seconds.** No QNX licence, no QEMU. This is what CI runs.

| # | Output file | What it contains |
|---|---|---|
| 1 | `host-sim/<ts>-host-sim.txt` | Four labelled sections: the 9 safety/EOF/parser/Seqlock self-tests; `manifest-verify` for the servo plant **and** the syringe plant (sidecar digests + admissibility); the 200-tick pipe-sim summary (`rx=200 \| wire_faults=12 \| env_faults=7 \| eperm_rejects=1`); the viewer's embedded-tape re-sync |
| 2 | `host-sim/<ts>-consistency.txt` | Every cross-file invariant check, each with its PASS line, and the exit status |
| 3 | `derived/host-sim-signature.txt` | The exact signature table: `wire=12 · envelope=7 · last_seq=80 · HOME rows ≥ 10 · keep-out breaches = 0`, and a PASS/FAIL verdict |

---

## C. `make -C qnx evidence-build` — what is inside the image

**~10 seconds** plus the IFS build itself.

| # | Output file | What it contains |
|---|---|---|
| 1 | `build/<ts>-ifs.txt` | The full `mkifs -v` listing: every file packed into the bootable image with its offset and size — **the proof of what is in the image** (the Linux `Image`, the initrd, the LATCH binaries, the vdev DLLs, `secpol.bin`, both manifests + sidecars) |
| 2 | `build/<ts>-initrd.txt` | The initramfs forensics: the newc-cpio entry list with each entry's mode and size, and the extracted `/init` identified as a freestanding static AArch64 ELF (no libc, no shell, no Python inside the guest) |

---

## D. `make -C qnx evidence-history` — the bring-up record

Archives the raw console of every QEMU boot in the bring-up, each
with its counters parsed out of it and a note on what that run
proves.

| # | Output file | What it contains |
|---|---|---|
| 1 | `on-target/01-guest-boot-console.txt` | The Linux 6.12 guest booting to `/init` |
| 2 | `on-target/02-run1-51-envelope-vetoes.txt` | Run 1 — the guest's 40 ms phase pauses starve the supervisor |
| 3 | `on-target/03-run2-48-envelope-vetoes.txt` | Run 2 — the guest's pauses reduced to 1 ms |
| 4 | `on-target/04-run3-no-guest-pacing.txt` | Run 3 — the guest pauses removed entirely; **identical** to run 2, which is what proved the transport was the variable |
| 5 | `on-target/05-run4-27-envelope-vetoes.txt` | Run 4 — the vdev's forwarding priority + the unpaced bridge |
| 6 | `on-target/06-run6-suite-correct-verify-race.txt` | Run 6 — the suite is exactly right; `latch_verify`'s step 1 lost a race with the watchdog |
| 7 | `on-target/07-run7-verify-all-pass.txt` | Run 7 — `latch_verify` paced; all five invariants PASS, `VERIFY_RC=0` |
| 8 | `on-target/08-rejected-2nd-virtio-console.txt` | The **rejected** experiment: a 2nd virtio-console corrupted the frame channel |
| 9 | `on-target/` + final_src | **THE CANONICAL SESSION** — one continuous boot with every fix in place |
| 10 | `derived/on-target-run-index.txt` | The whole bring-up in one table, with each run's parsed counters, and the CURRENT canonical session at the top |
| 11 | `on-target/CURRENT-SESSION.txt` | A **stable pointer** to the current canonical capture family, so the README, the video script and the Devpost page can cite it without being rewritten on every capture |

---

## E. `make -C qnx evidence-tape` — the evidence tape

The raw tapes are ~10 MB each and 99.9 % idle post-suite ticks, so
the tool windows them: the console preamble plus the first 200 tape
rows, which covers the whole guest suite.

| # | Output file | What it contains |
|---|---|---|
| 1 | `tape/latch_tape*.txt` | The windowed tape: the console preamble plus the first 200 CSV rows |
| 2 | `tape/latch_tape*-metrics.txt` | The analysis: the fault-bit histogram inside and outside the traffic window, the mode timeline, the HA-HOME retraction and its monotonicity, the keep-out-breach count, the starvation stalls and their lengths |
| 3 | `derived/tape-signatures.csv` | One row per tape: rows, envelope vetoes, wire faults, last accepted seq, HOME rows, keep-out breaches, starvation stalls, longest stall |

---

## F. `make -C qnx evidence-resolution` — the defect record

| # | Output file | What it contains |
|---|---|---|
| 1 | `resolution/SUMMARY.md` | The four-defect table, the measured progression, the starvation-signature table, and the rejected experiment |
| 2 | `resolution/01-guest-stall-psci.txt` | Defect 1: PSCI never reached the guest FDT — symptom, mechanism, fix, proof |
| 3 | `resolution/02-vcpu-pin-syntax.txt` | Defect 2: the QNX 8.0 `cpu` syntax — the rejected forms and the working one |
| 4 | `resolution/03-qvm-runmask.txt` | Defect 3: `on -C`/`-R` cannot express "CPUs 2+3" |
| 5 | `resolution/04-transport-starvation.txt` | Defect 4: the four compounding transport causes, and how they produced 51 vetoes |
| 6 | `resolution/05-rejected-2nd-virtio-console.txt` | The rejected experiment, measured, and why it was reverted |
| 7 | `resolution/06-session-reset-defect.txt` | The defect that made the archive contradict itself: opening the proposal node reset the supervisor's sequence baseline and teleported its plant state |

---

## G. `make -C qnx evidence` — everything except the QEMU run

Runs B, C, D, E and F in sequence (~20 s).

---

## H. `make -C qnx evidence-check` — the anti-rot gate

Re-runs the host-sim capture and compares the signature against
`derived/host-sim-signature.txt`. A mismatch fails CI, so the archive
cannot silently drift away from the code.
