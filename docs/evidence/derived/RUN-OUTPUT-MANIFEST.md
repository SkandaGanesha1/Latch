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
| 7 | `derived/on-target-metrics.txt` | **Distilled**: the fault-bit histogram inside and outside the traffic window, the mode-transition timeline, the HA-HOME retraction path and its monotonicity, the keep-out-breach count, the starvation-stall list, the latency maximum. **A DERIVED file, not a capture**: it carries a `Provenance` block naming the raw dump it was computed from and that dump's SHA-256, and a `Scope` block separating its tape-window numbers from the whole-session counters. `tools/consistency_check.py` re-derives it from the archived raw dump and DIFFs the result, so a hand-edit fails the gate. |
| 8 | `derived/on-target-numbers.txt` | The quotable-numbers table: every number the submission may cite, with the file it was read from |

**Re-deriving row 7 without a QEMU boot.** `derived/on-target-metrics.txt`
is a deterministic ANALYSIS of row 6, not a capture of its own, so it can
be re-derived from the archived raw dump without QEMU, without a licence
and without a guest image:

```bash
make -C qnx evidence-rederive-on-target
```

This changes no evidence: it re-reads the already-archived raw QEMU console
slice and recomputes the summary from it. `tools/consistency_check.py` runs
the same derivation into a temporary directory and DIFFs the result against
the committed file on every invocation, so the archived derived file cannot
drift from its raw source without failing the gate. The derived file itself
carries the SHA-256 of the raw dump it was computed from.

---

## B. `make -C qnx evidence-host-sim` — the workstation pipeline

**~5 seconds.** No QNX licence, no QEMU. This is what CI runs.

| # | Output file | What it contains |
|---|---|---|
| 1 | `host-sim/<ts>-host-sim.txt` | Four labelled sections: the safety/EOF/parser/Seqlock self-tests; `manifest-verify` for the servo plant **and** the syringe plant (sidecar digests + admissibility); the 200-tick pipe-sim summary (`rx=200 \| wire_faults=12 \| env_faults=7 \| eperm_rejects=1`); the viewer's embedded-tape re-sync |
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

## G. `make -C qnx evidence-governor-vm-kill` — the kill / restart / resume transcript

Boots QEMU AArch64 `virt` against the GOVERNOR IFS (~6 min) and drives
the whole containment-and-recovery story on the real target: the guest
VM is killed, the supervisor is shown to fail closed, the operator
restarts the guest through the narrowly-typed lifecycle daemon, and
the writer-session handoff is **observed** rather than timed.

The harness writes the transcript DIRECTLY into the archive and exits
non-zero WITHOUT touching the archive on failure, so a failed run can
never replace good evidence with a partial transcript.

| # | Output file | What it contains |
|---|---|---|
| 1 | `governor/governor-vm-kill-resume.txt` | The full transcript: the security-type map, the kill, the fail-closed status, the observed handoff, the new writer session, and the privilege re-check |

---

## H. `make -C qnx evidence-governor-infer` — the EXPERIMENTAL in-guest language model

Boots QEMU AArch64 `virt` against the **experimental in-guest inference**
IFS twice (~10 min): once with the nominal prompt and once with the
**attack** prompt. The model, the inference binary and the prompt live
on a **read-only virtio-blk asset disk**; the initramfs carries only the
freestanding policy, because qvm's blob loader cannot deliver a large
initramfs to an upstream-Linux guest.

The harness writes BOTH captures DIRECTLY into the archive and exits
non-zero WITHOUT touching the archive unless **both** runs pass, so a
failed run can never replace good evidence with a partial transcript.

| # | Output file | What it contains |
|---|---|---|
| 1 | `governor/infer-qemu.txt` | Both runs' structured reports: the model's own decision lines (read out of the guest console), the policy's kernel-stamped markers, the command event from the supervisor's event ring, the ring's fault statistics, the status snapshot before and after the 25 s lease hold, the contract sidecar verification, and the verdict |
| 2 | `governor/infer-qemu-console.txt` | The raw guest console of both runs: the Linux boot, the asset-disk mount, the llama.cpp load, the model's decision line, and the policy's markers with the guest kernel's own timestamps |

---

## I. `make -C qnx evidence-governor-qemu` — the scripted GOVERNOR profile, on target

Boots QEMU AArch64 `virt` against the **scripted GOVERNOR** IFS (~8 min)
and captures the deadman proof: the guest goes silent for a scripted
110 ms, the signed 100-tick lease expires **once**, the ladder demotes
exactly one rung (HP → ADVISE), heartbeat-only traffic does **not** earn
the clean-command recovery credit, 25 clean commands recover HP, and the
final silence ratchets the ladder to LATCH with the HEARTBEAT fault.

These two files used to be **orphans** in the archive — they had no
generator anywhere in the tree, which is exactly how they went stale.
This target is that generator. The archive is written ONLY when the run
passes: a failed run exits non-zero WITHOUT touching `docs/evidence/`.

| # | Output file | What it contains |
|---|---|---|
| 1 | `governor/governor-qemu-verify.txt` | The banner, the structured runtime report (the A4 sample table, the recovery ladder, the final state, the on-target contract verification and the guest's own console), and the verifier's own output ending in `[GOVERNOR_QEMU PASS]` |
| 2 | `governor/governor-qemu-console.txt` | The raw serial transcript of the session, verbatim |

---

## J. `make -C qnx evidence-secpol-audit` — the security-policy generation audit

Boots QEMU AArch64 `virt` against the **DISPOSABLE, unrestricted**
`secpolgenerate` audit image (~8 min) -- never the enforced deployment
image -- lets the 235-frame scripted guest scenario run to completion,
and captures what the generator observed:

| # | Output file | What it contains |
|---|---|---|
| 1 | `governor/secpol-audit.txt` | The banner, the process-type map under audit, the workload's completion, the five observation files (`policy` = the DELTA, `errors` = the failed ability checks, `unused` = the rules the workload did not exercise, plus the `request` and `control` channels), and the supervisor's final state under the generated policy |

The archive is written ONLY when the run passes: a failed run exits
non-zero WITHOUT touching `docs/evidence/`.

**The capture is an OBSERVATION, not a rule set.** The disposition of
every delta entry is the written review
(`docs/secpol-audit-review.md`), which accepted **none** of them, and
`qnx/latch.secpol` is untouched by the audit.

---

## K. `make -C qnx evidence-governor-feedback` — the LFBK feedback transport and the verdict control loop

Boots QEMU AArch64 `virt` **twice** (~10 min) against the two
feedback images:

- **W4** (`qnx/latch_qemu_fbprobe.build`) asks whether a verdict
  reaches the freestanding guest **at all**. The transport is a
  **polled verdict file** on `vdev virtio-blk` — the vdev's own usage
  is `hostdev [<]<pathname>`, and the `<` makes the backing file
  **read-only to the guest**, enforced by the *hypervisor*, not by the
  guest behaving. The pass bar is a **change**: the guest's own polling
  must see the sequence number move, with every frame re-synchronised
  on the magic and CRC-validated.
- **W5** (`qnx/latch_qemu_fbverdict.build`) asks the question that
  matters: when the **trusted supervisor** refuses the guest's
  proposal, does the guest find out — and does it **stop asking**? The
  W5 image contains **no synthetic publisher**: `latchd -f
  /dev/latch/feedback_pub` is the only writer of the verdict file, and
  the guest decodes the verdict, correlates it with the proposal it
  answers (by sequence number **and** session epoch), and stops on a
  `REJECT`. It reuses the W4 qvmconf **verbatim**, so the only
  difference between the two measurements is who publishes and what the
  guest does with it.

The archive is written ONLY when **both** runs pass: a failed run exits
non-zero WITHOUT touching `docs/evidence/`, so a broken build can never
replace good evidence with a partial transcript. The failing run's own
transcript and report are still written, into a temporary directory, so
the failure can be diagnosed.

| # | Output file | What it contains |
|---|---|---|
| 1 | `governor/feedback-transport.txt` | The banner, the **guest's own reports** for both runs (read back out of the raw transcripts, one line per **distinct** marker — the PL011 console echoes every record several times), both verifiers' own output ending in `[FB_QEMU PASS]` and `[FBVERDICT_QEMU PASS]`, and an explicit **WHAT THIS DOES NOT PROVE** section |
| 2 | `governor/feedback-transport-console.txt` | The **raw** serial transcript of the W4 transport probe, verbatim |
| 3 | `governor/feedback-verdict-console.txt` | The **raw** serial transcript of the W5 verdict watcher, verbatim |

---

## L. `make -C qnx evidence-governor-latency` — the U-4 decision-latency measurement

Boots QEMU AArch64 `virt` **once** against the **measurement** image
(`qnx/latch_qemu_latency.build` -- the GOVERNOR profile with NO evidence
logger, so nothing perturbs the state being measured) and runs the
**full 35-minute soak**: the guest streams in-envelope `CMD_V2` frames at
900 Hz, the supervisor samples its own per-tick decision latency **once
per tick**, and the histogram is aggregated **on the target** and read
back through the output-only devctl `latchctl latency`.

**Every figure in `LATENCY.md` is parsed out of the TARGET's own report**
-- none of them is typed in by hand -- and the archive is written ONLY
when the run passes: a failed run exits non-zero WITHOUT touching
`docs/evidence/`, so a broken build can never replace a measurement with
a partial transcript.

| # | Output file | What it contains |
|---|---|---|
| 1 | `governor/LATENCY.md` | The banner (the target machine, the emulation, the profile, the signed contract and the workload), **THE MEASUREMENT** (the sample counts, the p50/p99 **bucket ranges**, the **exact** min/max, the means, the over-budget and over-period counts, the mode ticks and the achieved rates), the **HOW TO READ THE PERCENTILES** section, the **RAW TARGET REPORT** verbatim, and a **WHAT THIS DOES NOT PROVE** section |
| 2 | `governor/latency-console.txt` | The **raw** serial transcript of the measurement session, verbatim |

**The figures are a TCG OBSERVATION, not a WCET.** Under TCG the
supervisor shares host cores with the guest and with QEMU itself, so the
distribution's maxima are the **host's** scheduling noise; its
percentiles are **bucket ranges**, not exact values; and its workload is
**one** workload -- a HOLD at 100 mrad. The file says all of this itself,
and the consistency gate requires it to.

---

## M. `make -C qnx evidence` — everything except the QEMU run

Runs B, C, D, E and F in sequence (~20 s).

---

## N. `make -C qnx evidence-check` — the anti-rot gate

Re-runs the host-sim capture and compares the signature against
`derived/host-sim-signature.txt`. A mismatch fails CI, so the archive
cannot silently drift away from the code.
