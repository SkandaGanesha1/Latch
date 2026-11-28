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
`guest/linux-guest.initrd`. The **policy itself** has no libc, no shell and
no Python inside the guest. `guest/liar.py` is the *workstation* generator
used by `make check` through a POSIX pipe; it emits the same suite but never
enters the hypervisor guest. Keep exactly one of these paths alive at a
time.

**One exception, and it is deliberate.** The experimental in-guest
inference profile (`guest/latch_infer.cpp`) adds a second binary to the
guest: a statically linked AArch64 C++ program that links a libc and
llama.cpp, and runs the language model that proposes the motion. It is
**not** the policy and it does not become one:

- the policy stays PID 1, stays freestanding, and stays the **only**
  writer on the black channel (`/dev/hvc0`);
- the inference program writes to a **pipe**, and the policy relays;
- the inference program holds no actuator ability and cannot reach the
  QNX side at all — it is inside the untrusted guest;
- the safety envelope is **not** duplicated in the guest. The guest-side
  check is STRUCTURE only; the keep-out, the slew limit and the rate
  limit live in the signed manifest and are enforced only by the trusted
  QNX supervisor.

So "no libc inside the guest" is true of the POLICY and false of the
guest as a whole, for one experimental profile. Do not restate the old
claim, and do not let the inference program's presence turn the policy
into a library-using process.

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

**And there is a gate on THAT gate.** A gate that cannot fail is a gate
that proves nothing, so `tools/mutation_check.py` mutates every property
the consistency checker checks — 79 mutations, each written against a
**real measured defect** — and requires the checker to fail on every one:

```bash
make -C qnx mutation-check        # no QNX licence, no QEMU
python3 tools/mutation_check.py --list   # list the mutations, run none
```

It runs against a scratch **copy** of the repository, so the tree it checks
is never written to, and it proves that at the end by comparing digests. A
mutation whose anchor no longer exists is a **SKIP**, and a skip is a
**failure** of the battery, not a warning: that is exactly how the previous
battery decayed after the transport changed from a PTY pair to the polled
verdict file, until nine of its twelve mutations were stale and it still
printed "PASSED" for the three that were left. Run this whenever a
consistency gate is added or changed.

**Run the whole CI job locally before you push:**

```bash
python3 tools/run_ci_locally.py     # every `run:` step of .github/workflows/ci.yml
```

This executes each workflow step locally with the same shell and working
directory GitHub Actions uses. It exists because this job had **three
independent faults** that each hid the next, and the job had been red for its
entire history (18/18 runs): a gcc-13-only `-Werror=stringop-overflow`, a
case-sensitive path prefix in the anchor checker, and a double-escaped regex
in the harness step. A failing step is found locally in seconds instead of
after a push and a CI cycle. Use `--only <substring>` to run one step and
`--keep-going` to see every failure at once.

**And a failing CI step must keep its OWN TRANSCRIPT.** The evidence
captures already follow that rule (§4d); it applies to the job as well, and
it matters more here, because **the job's raw log is NOT public**: GitHub's
API demands admin rights for a job's logs — `GET
/repos/<owner>/<repo>/actions/jobs/<id>/logs` returns **403** for a
non-admin **even on a public repository**. What *is* public on a public
repository is the **annotations** on the job page, the **step summary**, and
the **artifacts** (`GET /repos/<owner>/<repo>/actions/artifacts` answers
**200** unauthenticated). So every `run:` step is wrapped in
`tools/ci_step.sh`, which

- runs the step with `bash --noprofile --norc -e -x`, so the transcript
  shows **every command** and the failing one is the last line before the
  error;
- tees the transcript into `$RUNNER_TEMP/latch-ci-logs/`, which the job
  uploads as the public `latch-ci-logs` artifact (`if: always()`, so it is
  published for a red job too);
- on failure, copies the transcript into `$GITHUB_STEP_SUMMARY` and raises
  its last lines as `::error::` annotations.

So a red CI job carries its own diagnosis whether or not you can read the
raw job log — and `tools/run_ci_locally.py` exercises the same wrapper, so
the wrapper cannot rot unnoticed.

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
  **`docs/evidence/README.md` and `derived/RUN-OUTPUT-MANIFEST.md` are
  GENERATED too** — by `tools/capture_evidence.py index` — so a hand-edit
  to them is silently replaced by the next `make -C qnx evidence-index`,
  and the commit that carried it is wrong in a way nobody can see. Put the
  change in the **generator**, and regenerate. The consistency checker
  now proves this: it regenerates the index into a scratch copy of the
  archive and **DIFFs** it against the committed files, and a byte
  difference fails the gate.
- **Every file in the archive has to be named in the index's file tree.**
  `governor/governor-qemu-verify.txt` and `governor-qemu-console.txt`
  used to be **orphans** — they had no generator anywhere in the tree,
  and the November capture was still quoted in 2026-11-26, long after the
  code had moved. An orphan in the evidence archive is a silent lie,
  because nothing notices it rotting. The checker now walks the archive
  and fails if any file is missing from the index's tree.
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

- On this workstation on 2026-11-25, `qcc -V` timed out after 15 seconds
  in the restricted execution sandbox but succeeded outside it after sourcing
  `~/qnx800/qnxsdp-env.sh`. The normal and development-only GOVERNOR QEMU
  images then built with `qcc`; `tools/verify_governor_qemu.py` passed against
  the fresh normal image. This observation does not identify which sandbox
  restriction causes the hang and does not prove writer-session behavior.

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
- **A session reset must be a SESSION event, not an OPEN event.** Arming the
  supervisor's reset on every open of the proposal node let *any* second
  process flush the ring, re-base the sequence baseline (defeating replay
  detection) and teleport the plant angle. Reset only on the 0 → 1 writer
  transition; a second writer joins the live session.
- **A writer-session handoff must be OBSERVED, never timed.** The legacy
  QEMU verifier used to kill the guest's ingest and then wait a fixed 2 s
  before starting `latch_verify`; when the resource manager had not yet
  processed the ingest's disconnect, `latch_verify`'s own open of the
  proposal node was refused with `EBUSY` and the run failed for a reason
  unrelated to the invariants under test. The fix is an output-only devctl
  (`DCMD_LATCH_GET_SESSION_STATUS`, `0x47`) that reports whether the
  exclusive writer OCB is still held; the harness polls it and starts the
  verifier only after the supervisor says the writer is gone. Measured on
  2026-11-25: `slay -9 qvm` makes the ingest see EOF and exit by itself
  (`slay -9 latch-ingest` then reports "Unable to find process"), and the
  writer is released shortly afterwards — but "shortly afterwards" is
  exactly what a fixed sleep cannot guarantee.
- **`slay` matches by name OR PID, and does not prompt for a single
  match.** The installed SDP 8.0 `slay` manual says it "prompts for
  confirmation when more than one process bears the specified name or ID".
  With one `qvm` and one `latch-ingest` there is no prompt, so a handoff
  that "ate the next command" is not a `slay` behaviour — look for the
  real cause. `slay` also exits non-zero when it finds no match, which is
  normal after the target has already exited.
- **qvm reads its configuration as an ARGUMENT FILE.** The QNX `@file`
  sigil means "read the command-line arguments from this file", so the
  working form is `on -T qvm_host_t /proc/boot/qvm @/proc/boot/…qvmconf`.
  Passing the bare path is **not** equivalent: measured on the QEMU
  AArch64 target on 2026-11-25, qvm rejects it with
  `Unknown option '/proc/boot/latch_qemu_governor.qvmconf'` and exits
  immediately with status 65 (0x41). The symptom looks like "the guest
  never boots" and the cause is one character.
- **The operator shell can STOP the guest but cannot START it.**
  `slay -9 qvm` from the operator shell works, but
  `on -T qvm_host_t … qvm @qvmconf` is refused with
  `on: Operation not permitted`, because `operator_shell_t` holds no
  `settypeid` and no `spawn`. The fix is a **dedicated typed lifecycle
  process**, not a grant to the shell: granting the operator shell
  `settypeid:qvm_host_t` would collapse the "the operator shell is
  deliberately unprivileged" property that the `latchctl grant-check`
  EPERM demonstration depends on.
- **`secpol_posix_spawnattr_settypeid(NULL, &attr, "qvm_host_t",
  SECPOL_TYPE_NAME)` gives the child EXACTLY that type.** Verified on the
  target with `pidin -F "%a %b %_ %28n"`: the qvm child shows
  `qvm_host_t` and the lifecycle daemon shows `latch_guestd_t`. The
  `SECPOL_TYPE_NAME` flag is what selects the literal type name instead
  of deriving a child type from the caller's type — without it the call
  means "derive a type named `qvm_host_t` from my own type", which is a
  different request.
- **`pidin -F "%_"` prints the process's security type.** The `_` format
  character is the one to reach for; `pidin -F "%a %b %_ %28n"` is the
  single-picture privilege-boundary dump (it shows every process's type,
  so a misplaced type is visible at a glance). This is the cheapest way
  to check that a type transition actually took effect.
- **A type's ability set is what the policy grants it — a missing
  `settypeid` is a refusal, not a no-op.** Measured: `operator_shell_t`'s
  policy block grants `nonroot pathspace public_channel` only, and
  `on -T qvm_host_t …` from that shell fails with `Operation not
  permitted`. So a rule that omits an ability really withholds it.
- **A writer-session handoff is not the same thing as the frame counter
  moving.** The killed guest's ingest drains the frames it had already
  read from the pipe before it sees EOF and exits, so the supervisor's
  "Proposals Received" keeps ticking for a while after the guest is dead.
  A harness that treats "the counter moved" as "the guest came back"
  passes on the OLD session's tail. The observable fact that a NEW
  session exists is `writer_held == 1` **and** `session_generation`
  advanced (`DCMD_LATCH_GET_SESSION_STATUS`, `0x47`).
- **`secpolpush` IS the enforcement mechanism.** `secpollaunch` is an
  unrelated setuid-root launcher. Pushing the compiled policy at boot is
  what *triggers* enforcement, so a buildfile with `secpolpush` has an
  enforced policy on every boot — and the ability checks are then
  demonstrated under enforcement, not in theory.
- **A producer must outrun the consumer, and a burst is not a burst.**
  The supervisor consumes exactly one proposal per tick, so a *burst* is
  applied at precisely the same rate as a paced stream — but the ring
  holds the frames, so the watchdog cannot fire. A stream paced at exactly
  one frame per tick is a coin flip: one millisecond of jitter and the
  watchdog fires. This applies to the guest policy, to the bridge, and to
  the verification harness alike.
- **The supervisor returns to HP only after
  `recovery.hysteresis_clean_frames` CONSECUTIVE clean frames.** In HOLD
  the plant is frozen, so a ramp sent while the supervisor is in HOLD is
  *consumed but not applied*. Any test that ramps the plant must first
  drive the supervisor back to HP with clean frames.
- **Read the answer from the evidence tape, not from an instantaneous
  status read.** The tape records (tick, seq, u, theta, mode, faults) for
  every tick, so it is the authoritative record. An instantaneous read has
  to catch a window as short as two ticks.
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
  Two official sources say so, and the exact wording is worth quoting:
  the **QNX QPLMS User's Guide** ("QPLMS usage differences between QOS 2.2.x
  and SDP 8.x environments") — the `aps` config keyword "only works on QOS
  2.2.x. The feature is not supported in SDP 8.x" — and the **QNX Momentics
  IDE User's Guide 8.0**, "APS View" — "QNX OS 8.0 does not support adaptive
  partitioning; if your target is based on 8.0, then the IDE won't receive any
  APS data and this pane isn't meaningful."
- **QNX SDP 8.0's supported development hosts are Windows 11/10, Ubuntu
  Desktop 22.04/20.04 LTS and Red Hat Enterprise Linux 9 — not Fedora.**
  The build workstation here is Fedora 45, so the host configuration works but
  is **not** a QNX-supported one; never describe it as supported. The list
  moves between point releases (8.0.2 swapped Ubuntu 20.04 for 24.04 and
  dropped Windows 10), so read the release notes for the version in hand.
- **QNX publishes a Raspberry Pi 5 BSP** (`com.qnx.qnx800.bsp.hw.raspberrypi_bcm2712_rpi5`,
  build 738) alongside the Pi 4 one (`com.qnx.qnx800.bsp.raspberrypi_bcm2711_rpi4`,
  build 837). **That does not make Pi 5 a LATCH target**: the repository has
  exactly one Pi buildfile, `qnx/latch_rpi4.build`, so Pi 4B is the only board
  this project claims. `tools/consistency_check.py` fails the build if a doc
  ever names a target the repository cannot build.
- **The QSC package manifest is the authority for "what is installed".**
  Every installed package has a directory
  `~/qnx800/.packages/metadata/<package-id>/<package-version>/`, so the
  exact build strings are readable without opening the GUI:
  `ls ~/qnx800/.packages/metadata/*/*/AssetDescriptor.json`.
  On this workstation that yields `com.qnx.qnx800
  8.0.0.00141T202311271501L` (SDP) and `com.qnx.qnx800.target.hypervisor.*
  3.6.0.00802T202608071638L` (Hypervisor).
- **The host-tools package is a METAPACKAGE, and it does not require
  `mkifs`.** `com.qnx.qnx800.host.linux.x86_64`'s `ResourceDescriptor.afd`
  requires `.qcc`, `.gcc`, `.secpol`, `.qlicense`, `.mkxfs`, `.mkqfs` and
  others — but **not** `mkifs`. The tool-providing packages are separate:
  `...host.linux.x86_64.qcc`, `...host.linux.x86_64.secpol`,
  `...host.linux.x86_64.qlicense`, `...host.linux.x86_64.mkifs`
  (`1.2.2.00014T202605190942L`). So "the host-tools package provides
  `qcc`, `mkifs`, `secpolcompile`, `qlicense`" is **false**; name the
  per-tool packages instead.
- **The host-sim's decision latency is HOST-LOAD dependent, so the
  hand-written docs must not quote it.** The archived captures show
  `max_latency=1413 ns` and `max_latency=2154 ns` on the same code — the
  number moves with the machine's load, and `make evidence` re-measures it
  on every capture. The docs therefore **point at**
  `docs/evidence/host-sim/` instead of copying its number; a quoted
  figure would be stale the moment the archive is refreshed, and the
  refresh is what archives the gate's own output. `tools/consistency_check.py`
  enforces this (§6j): a fragment that mentions the host-sim may not carry
  a measured latency figure.
- **In an on-target console there are SEVERAL status polls.** The first
  `Decision Latency` line in `*-console.txt` reads `last = 0 cyc (0 ns)` —
  it was polled before the guest booted. The quotable latency is the one
  in the family's **`*-status.txt`** (the pre-verification snapshot), and
  that is the file `tools/consistency_check.py` treats as the authority.
  The post-verification `*-verify.txt` shows a different `last` because
  the harness's own frames have run by then.
- **A Hypervisor package internal version identifies the product release.**
  `3.6.0.00802T202608071638L` is published by the **QNX Hypervisor 8.0.5
  Product Release Notes** ("Date of this edition: August 21, 2026"), so the
  installed hypervisor **is** 8.0.5 — the `00802` is the product build
  number, and the `3.x.y` prefix is the package's own version. The mapping is
  checkable against the official page:
  `https://www.qnx.com/developers/docs/relnotes8.0/com.qnx.doc.release_notes/topic/qh8.0_prod_release_notes/hypervisor8.0.5_rn.html`.
  The child pages live under `topic/qh8.0_prod_release_notes/`; the plain
  `qh8.0_updates.html` page only carries the older build 549.
- **No Raspberry Pi BSP is installed on this workstation.** The only BSP
  packages present are the hypervisor *guest* BSPs (`...bsp.hypervisor_guest_arm`
  / `_x86`). So `qnx/latch_rpi4.build` exists and is documented, but the Pi 4B
  image **cannot be built here**; the verified target is QEMU AArch64 `virt`.
  Say so rather than implying the physical board was exercised.
- **`_FORTIFY_SOURCE` is a DISTRO default, not a compiler default.** Ubuntu
  24.04's gcc (13.3, the CI compiler) enables `_FORTIFY_SOURCE=3` by itself;
  Fedora 45's gcc (16.2, this workstation) enables **nothing**. That single
  difference is what let a bounds defect compile cleanly here and fail in CI
  under `-Werror=stringop-overflow`. The host-sim target now requests
  `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3` **explicitly**, so the bounds
  analysis is the same on every toolchain. `-U` comes first so a distro that
  already defines the macro at another level cannot trip `-Werror` with a
  redefinition warning.
- **A `read()` length computed as `len - offset` is not provably bounded for
  the compiler.** gcc 13's value-range analysis cannot see through
  `total += (size_t)n` (where `n` is an `ssize_t` it cannot bound) and
  concludes the count may be astronomically large, so
  `-Werror=stringop-overflow` fires even though the code is correct. The
  portable shape is a **monotonically decreasing `remaining` counter** plus
  `want = min(remaining, room-left-in-buffer)`: `remaining` never wraps, and
  the count can never exceed the destination's room. Verified: the old code
  fails on gcc 13.3 (exit 2) and the new code passes (exit 0), at every
  optimisation level from `-O0` to `-Os`.
- **The CI runner checks the repo out into a directory named after the
  GitHub repository (`Latch`), but the documentation uses the lowercase
  `latch/` prefix.** Any tool that resolves a documented path against the
  repo root must match that prefix **case-insensitively**, or it resolves
  locally (where the checkout directory happens to be `latch`) and fails in
  CI. This silently broke `tools/update_api_index.py --check` for 17
  references.

### 4b. Facts about the `secpolgenerate` audit

These were measured on the QEMU AArch64 target on 2026-11-26. They cost
three boot cycles each; read them before changing the audit.

- **The observation files are STREAMS, not regular files.** The QNX System
  Security Guide says it plainly: *"Because secpolgenerate generates policy
  content as the file is being read, it does not provide a meaningful file
  size."* So there is no `stat`-able size and no seek; the only way out is
  to read until EOF.

- **NEVER detect the end of a QNX shell command with `buf.endswith(b"# ")`
  when the command's own output might contain a line ending in `# `.**
  Every line of `/dev/secpolgenerate/policy` does. The detector fires on
  the *file's own content*, after its second character, and the harness
  walks away and kills QEMU (and the reader) mid-write. **The reader never
  hung** — the harness mistook the file content for the shell prompt. The
  captured output's last bytes were exactly `# `, confirmed with `od -c`:
  `… r u l e s \r \r \n # <space> \n`. Use a **sentinel matched with its
  exit-code digit** instead: `cmd; echo TAG_$?` → match `TAG_(\d)`. The
  v12 harness was right for exactly this reason — it required the prompt
  **AND** a sentinel. The same `endswith(b"# ")` pattern exists in
  `tools/verify_infer_qemu.py`, `tools/verify_governor_qemu.py`,
  `tools/qemu_guest_kill.py`, `tools/verify_qemu_aarch64.py` and
  `tools/run_target_probe.py`; a grep of every archived transcript found
  **0** lines currently ending in `# `, so they are latent rather than
  active, and they should be hardened when touched.

- **The reader is NOT the problem, and neither is `-f`.** Measured on the
  same boot, on the same file, with the same image: a plain blocking read
  (`latch_target_probe dump`) completed in **0.1 s / 2004 bytes**, and the
  cancellable-worker reader completed in **0.2 s / 2004 bytes** — with and
  without `secpolgenerate -f 1`. The `-f 1` option ("flush the trace
  events every second") was measured to be a **red herring**: it does not
  stop the policy snapshot from reaching EOF. Do not "improve" the
  generator invocation without re-measuring the capture.

- **`secpolgenerate -s state_file` saves all observed ability data on
  SIGTERM to a REGULAR file.** From the QNX System Security Guide: whenever
  `secpolgenerate` receives a `SIGTERM`, before it exits it saves in the
  specified file all the data related to abilities that processes
  associated with a type used or failed to use. That is the **fallback**
  extraction route if the stream route ever stops working.

- **The audit image's `unused` file is NOT a removal list.** It lists
  `latch/actuator` as unused for `latchd_t` and `channel_connect:latchd_t`
  as unused for `latch_ingest_t` — and **both are contradicted by the run
  itself** (235 proposals were applied; the ingest demonstrably connected).
  The cause is that the audit image runs the generator **unrestricted**
  (`-u`), in which ability checks are bypassed and therefore cannot be
  observed as "uses". So the file is the audit's **partial coverage**, not
  a list of removable rules.

- **The audit's ONE observed error must NOT be "fixed".**
  `procnto-smp-instr (pid:1 type:default) failed to use ability
  latch/propose as root` → the generator suggests
  `allow default self:ability { latch/propose };`, which would grant the
  propose ability to **every untyped process on the system**. That is the
  least-privilege boundary working, visible as
  `Unable to access "/dev/latch/proposal" (1)`. Reject it.

- **The audit's ONE actionable finding is recorded, NOT applied.**
  `qnx/latch.secpol` grants `qvm_host_t` the **unrestricted** `settypeid`
  ability (line 128); the generator observed exactly one transition,
  `settypeid:latch_ingest_t`, matching all four profiles' identical
  `hostdev >"|on -T latch_ingest_t …"` form. Narrowing it is a **policy
  change** and must be validated on the **enforced** image in its own
  reviewed change — adopting a rule from a superset, on the strength of one
  run, is the mistake the audit exists to prevent. The written disposition
  is `docs/secpol-audit-review.md`.

- **The minimal IFS has no `cat`, no `ls` and no `dd`.** Any on-target file
  read needs a purpose-built reader binary. `latchctl` has no generic
  file-dump command either, and the QNX host's `/dev/shmem` is invisible to
  the Linux harness, so **all** target data must exit over the serial
  console.

### 4a. Facts about the EXPERIMENTAL in-guest inference path

These were all measured on the QEMU AArch64 target on 2026-11-26. They
cost a boot cycle each; read them before changing the path.

- **qvm cannot put a large blob in the guest's initramfs.** `load_blob()`
  (qvm aarch64le, `0x29bb0`) copies a small guest blob straight into guest
  memory, but transfers a blob above a size threshold in **64 KiB
  message-block chunks** (`qvm_msgblock_start` / `pread` /
  `qvm_msgblock_stop`, `0x29c74`) that **the guest has to service** — and
  that service code lives in the **QNX guest BSP**, not in upstream Linux.
  Measured symptom: an 8.9 MiB initramfs reached the guest kernel as a
  buffer that was **not** the gzip archive —
  `Initramfs unpacking failed: invalid magic at start of compressed archive`
  after 30 ms — while the scripted profile's 3.3 KiB initramfs works. The
  model and the inference binary therefore travel on the **virtio-blk
  asset disk**, which is served over the virtio protocol and never goes
  through the blob loader. Keep the inference initramfs under a few tens
  of KiB; `tools/consistency_check.py` fails the build above 256 KiB.

- **`vdev virtio-blk` supports `hostdev [<]<pathname>`, and the `<` makes
  the backing file READ-ONLY to the guest.** That is the vdev's own usage
  text, read out of the installed
  `target/qnx/aarch64le/lib/dll/vdev-virtio-blk.so`. It is the mechanism
  that makes the model an input the untrusted guest cannot rewrite, and it
  is enforced by the **hypervisor**, not by the guest behaving. The known
  good addresses are `loc 0x1c0d0000` / `intr gic:41` — they are the ones
  the SDP's own `qvmconf-aarch64le` example uses.

- **arm64 Linux has no `poll` and no `pipe` syscall.** The guest policy
  uses `ppoll` (syscall 73) and `pipe2` (59); there is no `poll` and no
  `pipe` to fall back on. `pipe2` with `O_CLOEXEC` is what keeps the
  pipe's descriptors out of the exec'd child.

- **`clone(SIGCHLD, stack = 0)` gives EXACT fork semantics on arm64.**
  `arch/arm64/kernel/process.c`'s `copy_thread()` sets the child's SP
  **only** `if (stack_start)`, so passing 0 leaves the child with the
  parent's SP — the only safe choice in a freestanding C binary, where
  the child cannot re-enter the parent's stack frame.

- **llama.cpp's default logger prints DEBUG, and on the PL011 that stalls
  the guest.** The graph dump is thousands of lines, and a blocking write
  to the guest console costs tens of milliseconds of guest time per line.
  Measured: the guest console reached **1.8 GB** and the model had still
  not produced a decision 90 s after the relay started. The inference
  program installs a log callback that keeps WARN/ERROR and drops
  DEBUG/CONT. After that, load + first decision takes ~35 s under
  `qemu-aarch64-static` on this host. **If the model seems slow, look at
  the console volume before you blame the model.**

- **A cross-compiled static AArch64 C++ binary needs `libgcc_eh.a`
  MERGED INTO `libgcc.a`.** On AArch64 the unwinder lives in a separate
  archive, and GCC's link line
  (`-lstdc++ -lm --start-group -lgcc -latomic_asneeded -lc --end-group`)
  has no `-lgcc_eh`; adding it on the command line does not work because
  it lands before `-lc`. The working recipe is in
  `tools/build_aarch64_sysroot.sh`.

- **A `-DCMAKE_C_FLAGS=...` cache entry SHADOWS `CMAKE_C_FLAGS_INIT`.** The
  flags have to live in the toolchain file
  (`guest/aarch64-toolchain.cmake`), where nothing can shadow them.

- **`grep -q` under `set -o pipefail` is a SIGPIPE trap.** `nm … | grep -q`
  reports failure even on a match, because `grep -q` closes the pipe
  early. Use `grep -c` or capture into a variable.

- **The event ring exposes at most 64 entries per devctl
  (`LATCH_GOV_EVENT_DUMP_MAX`), and the policy's 10 ms heartbeat fills it
  at ~83 entries/s.** A fixed 64-entry window therefore covers only
  ~0.8 s of history: polling it and hoping **will miss** the one command
  that matters. Page it with `latchctl events -n 64 -s <index>` and a
  monotonically advancing cursor. This is why
  `tools/verify_infer_qemu.py` pages instead of polling.

- **`clamp_max_step` is the CLAMP/SLOW rung's limit, NOT the HP rung's.**
  In `HP` and `ADVISE` the per-tick slew limit is `envelope.v_max`
  (25 mrad/tick in the signed contract), and a step beyond it raises
  `LATCH_FAULT_DOSE | LATCH_FAULT_RATE`. An earlier note in this project
  expected the supervisor to clamp a −20 mrad request to 5 mrad; the
  measurement says otherwise — in HP it applied −20 mrad, because
  −20 ≤ `v_max`. The keep-out check uses the **normalised target**, not
  the slew-clamped candidate, so a request for +400 mrad raises
  `KEEPOUT` (it crosses the signed PERSON box) **and** `RATE`/`DOSE`
  (it is beyond `v_max`) **and** the plant does not move.

- **The applied angle is the plant's NEW ANGLE, not the step.** The
  event ring prints `u=raw->normalised->theta`, and the gate computes
  `step = clamp(candidate - theta, lo_step, hi_step)` and then
  `candidate = theta + step`. So the third number is an absolute angle.
  A harness must not compare it with the model's raw request: from
  rest, the signed `a_max` (10 mrad/tick²) scaled by the command's own
  confidence (210/256 → 8 mrad) bounds the FIRST step, so a request for
  −20 mrad is applied as −8 mrad on the first tick and the plant
  converges on the target over the following ticks.

- **A phase marker costs ~30 ms of GUEST TIME on this PL011.** A
  `/dev/kmsg` write becomes a printk, and printk has to take the console
  lock — so a marker blocks until the console is free. Measured
  between two consecutive markers on the QEMU AArch64 target
  (2026-11-26): 59 ms for two markers. Markers are therefore placed
  where they cost nothing: before the session is open, or once.

- **THE PRODUCER MUST SIGNAL READY BEFORE IT OPENS ITS SESSION.** The
  supervisor's deadman starts counting when the first frame arrives, so
  the moment the session opens is the moment the producer has to be
  ready to produce. The in-guest inference profile broke this and the
  measurement is the reason it is written down here:
  - mounting the 209 MiB ext4 asset disk takes **337 ms inside ONE
    syscall** (guest-t 8.049 → 8.386) — the policy cannot heartbeat
    during it;
  - a write to `/dev/hvc0` **BLOCKED for 73 ms** (guest-t 8.579 →
    8.653) while the host was serving the child's 168 MB of block I/O
    — the host's virtio-console forwarding stalls under that load;
  - together: a **594-tick hole** in the frame stream, five deadman
    expiries, and the supervisor demoting itself
    HP → ADVISE → CLAMP → SLOW → SAFE_STOP → LATCH before the model had
    said a word.

  The fix is the handshake: the inference child writes one byte
  (`0xA5`) once it has a **proposal** ready, and only then does the
  policy send the warm-up heartbeats and open the session. **The
  deadman must measure a producer's LIVENESS, not its STARTUP.**

- **A CONSOLE LINE COSTS 1.3–1.8 ms PER CHARACTER ON THIS GUEST.**
  This is the second half of the lease story, and it is the reason the
  profile's console discipline exists. A `/dev/kmsg` write becomes a
  printk, and the guest's PL011 console is slow. Measured on the
  QEMU AArch64 target (2026-11-26), from the guest's own kernel
  timestamps between consecutive markers:

  | marker | chars | gap to the next marker |
  |---|---:|---:|
  | `[INFER] the model is ready: opening the session` | 47 | 86 ms |
  | `[INFER] warm-up heartbeats...` | 27 | 57 ms |
  | `[INFER] relaying: the policy is the sole writer on the wire` | 57 | 88 ms |
  | `[INFER] relay: first heartbeat write starting` | 41 | 70 ms |

  So a line costs **57–88 ms of guest time**, and the signed lease is
  100 ticks ≈ 100 ms. **A single marker is most of the lease.** The
  model's own decision line is 119 characters, so announcing it inside
  the supervised window cost about **153 ticks** — the deadman fired,
  and the supervisor demoted itself out of HP, not because the model
  had gone silent but because the model's own announcement had eaten
  the lease.

  The rules that follow, and they are rules, not preferences:
  - **the relay path writes NOTHING to the console** — not a marker, not
    a status line, not a "still alive";
  - markers go where they cost nothing: **before the session is open**,
    or on a fault path bracketed by heartbeats;
  - the inference child announces its **first** proposal *before* the
    session opens and relays every later proposal **silently**;
  - a line's cost is roughly **linear in its length**, so a short line
    is proportionally cheaper.

- **THE SCRIPTED GOVERNOR PROFILE HAD THE SAME DEFECT, AND THE
  `/dev/kmsg` RATE-LIMIT FIX IS WHAT EXPOSED IT.** This is the most
  instructive defect in the file, because the thing that *fixed* a
  silent-drop bug *created* a lease bug.

  The `/dev/kmsg` userspace writes are rate limited by default
  (`printk_devkmsg` = "ratelimit", `DEFAULT_RATELIMIT_BURST` = 10 per
  `DEFAULT_RATELIMIT_INTERVAL` = 5·HZ). The scripted GOVERNOR profile
  used to write each marker as **three** separate `/dev/kmsg` writes
  (`"<6>"`, the text, `"\n"`), so it burned the burst budget quickly —
  and the kernel **silently dropped** the later records. The archived
  November console transcript proves it: only the two lifecycle markers
  (`=== LATCH Linux 6.12 Guest Userspace (/init) Alive ===` and
  `[guest] /dev/hvc0 opened! ...`) ever reached the console; the
  `[GOVERNOR]` and `[A4]` scenario annotations are **absent**.

  That was a bug (a marker that vanishes without anyone noticing is a
  lie), and the fix was right: one `/dev/kmsg` record per marker, and
  `printk_devkmsg` set to "on" so no marker can be dropped. **But the
  fix made every annotation VISIBLE — and a visible annotation costs
  ~70 ms of guest time.** Two of them sat inside the A4 silent window:

  ```
  guest-t 7.857  [GOVERNOR] v2 demo: four liveness heartbeats
  guest-t 7.940  [A4] guest CPU spinner, then 110 ms delay   (+83 ms)
  guest-t 8.128  [A4] one command renews lease              (+188 ms)
  ```

  so the "scripted 110 ms silence" became ~250 ms. The signed lease is
  100 ticks, so the deadman expired **twice** instead of once, and the
  ladder ratcheted HP → ADVISE → CLAMP → SLOW → LATCH instead of
  demoting exactly one rung. The on-target verifier failed with
  `Latched Fault Bits: 0x8000 (DOSE)`.

  The fix is **not** to drop the annotations again. It is to print
  them where they cost nothing: **before the session opens**, while
  the supervisor's deadman is not yet running. The scripted profile now
  prints its whole scenario *plan* before the warm-up heartbeats and
  writes **nothing** to the console afterwards, so the A4 window
  contains the scripted sleep and nothing else.
  `tools/consistency_check.py` fails the build if a marker appears
  after the warm-up flush in `run_governor_demo()` — the same gate
  shape as the inference profile's relay-path gate.

  **The general lesson: on this platform a diagnostic that can change
  the measured quantity is a defect, and a fix that makes a silent
  drop visible can change the timing it did not touch.**

- **PRINTING BEFORE THE SESSION OPENS IS NECESSARY BUT NOT SUFFICIENT
  — THE CONSOLE MUST BE *QUIET* BEFORE THE SUPERVISED WINDOW OPENS.**
  This is the second half of the defect above, and it was found by
  instrumenting the guest with its own clock (`clock_gettime`,
  `CLOCK_MONOTONIC`) and comparing it against the supervisor's tick
  index. The guest's clock said the scenario was fast and accurate:

  | measurement (the guest's own `CLOCK_MONOTONIC`) | value |
  |---|---:|
  | `nanosleep(110)` — the scripted A4 delay | **111.66 ms** |
  | the write syscall that sent the A4 command | **0.97 ms** |
  | 4 frames + 4 × `sleep(1 ms)` | 10.81 ms |
  | A4 start → the command was written | **112.63 ms** |

  …while the supervisor's tick index advanced **268 ticks** for that
  same event — a **2.4× skew**. The guest's clock and the supervisor's
  tick index agreed 1:1 during the busy phases on *either* side of the
  window, so the skew was confined to the window in which the console
  burst was still draining. The cause is that a `/dev/kmsg` write
  returns as soon as the record is in the kernel's ring buffer, but the
  kernel's console thread then pushes it out through the PL011 at the
  measured **1.3–1.8 ms per character** — so the guest has finished
  "printing" the plan while the **host** is still busy serving it. The
  deadman counted that host-side drain as guest silence and demoted the
  ladder **twice** for a silence that was meant to expire the lease
  once; the A4 command arrived at the CLAMP rung and was REJECTED with
  DOSE (0x8000).

  The fix is `LATCH_GOVERNOR_CONSOLE_DRAIN_MS` (1500 ms) between the
  last annotation and the warm-up heartbeats: the console goes quiet
  **while the deadman is not yet running**. Measured after the fix: the
  A4 silence is **112 ticks**, **exactly one expiry** (HP → ADVISE), the
  A4 command is **ACCEPTED with no faults**, all 151 hold frames sit at
  rung ADVISE, and 25 clean commands recover HP.

  The wait is tied to the plan's own console cost by
  `tools/consistency_check.py`: the gate counts every character the plan
  prints (including markers written as *concatenated* string literals),
  adds the kernel's ~15-character timestamp prefix per line, multiplies
  by the measured **1.8 ms/char upper bound**, and fails the build if
  `LATCH_GOVERNOR_CONSOLE_DRAIN_MS` is shorter than that. **Grow the
  plan and the wait has to grow with it.** The gate also requires the
  wait to sit after the last annotation and before the warm-up flush.

  **The rule, in one line: the console must be quiet BEFORE the
  supervised window opens — not merely quiet of new writes.**

- **The supervised window must contain NOTHING that can stall it.**
  The relay path's console writes, the model's load-time I/O, and the
  host's forwarding stalls are all the same class of problem: each one
  is a hole in the frame stream, and the deadman sees every hole. The
  measured steady-state heartbeat jitter under TCG — with no console
  traffic at all — is a median of **13 ticks**, p90 **23**, p99 **41**
  and a maximum of **66** against the 100-tick lease. That jitter is an
  emulation artefact; the scripted profile shows the same class of
  stall. **Keep the guest's console and the host's I/O load out of the
  supervised window.**

- **A host stall longer than the lease breaks it, and no guest-side
  trick can hide that.** The supervisor consumes exactly one proposal
  per tick, so the supervisor's view of the frame stream is capped at
  1000 frames/s — and a burst cannot absorb a stall longer than the
  lease, because the backlog drains at one frame per tick. Any host
  stall over `lease_ticks` (100 ms) is visible to the deadman, full
  stop. The only remedies are to keep the host's load off the
  forwarding path (which is what the READY handshake does) or to make
  the stall shorter; **never** to lengthen the lease, which the
  manifest loader caps at 100 on purpose.

### 4c. Facts about the FEEDBACK (LFBK) TRANSPORT

These were measured on the QEMU AArch64 target on 2026-11-26. Each one
cost a boot cycle; read them before changing the transport.

- **A QNX `devc-pty` pair delivers in the OPPOSITE direction to the
  documentation.** The QNX System Architecture chapter `char_PTY.html`
  says: *"anything written on the master device is given to the worker
  device as input; anything written on the worker device is presented as
  input to the master device"*, and `devc-pty` names the master the
  CONTROLLER (`/dev/ptyp0`) and the worker the WORKER (`/dev/ttyp0`).
  Measured on the target, with a distinct marker written on each end:

  | what was written | what was read | bytes |
  |---|---|---:|
  | `/dev/ptyp0` `"CTRLMARK01"` | `/dev/ttyp0` | **0** |
  | `/dev/ttyp0` `"PEERMARK02"` | `/dev/ptyp0` | 20 (`"CTRLMARK01"` then `"PEERMARK02"`) |

  So the direction that DELIVERS is **write the WORKER, read the
  CONTROLLER** — and what is written to the controller comes back on the
  controller's OWN read side. The publisher writes `/dev/ttyp0`; the
  hypervisor reads `/dev/ptyp0`. The publisher runs this same
  measurement at every boot (`latch_fb_pump --peer`), so the platform's
  behaviour is checked rather than assumed.

- **`delayed forever` NEVER OPENS THE HOST ENDPOINT.** The
  `vdev-pl011.so` usage says `delayed <num>|forever` means *"Delay
  opening host device until first guest reference"*. Measured on the
  target, the guest DID open the feedback device (the probe's census
  showed the port opened) and the host endpoint was still never opened:
  every publisher write was refused with `EAGAIN` from the very first
  frame (`sent=0 dropped=64 seq=64`) and the guest read **0** bytes.
  The "first guest reference" that `delayed` waits for is therefore NOT
  the guest driver's `open()` of the device node. The endpoint is opened
  unconditionally at qvm start instead, and the ordering that `delayed`
  was there to guarantee — the pty pair exists before the hypervisor
  opens it — is guaranteed by the **buildfile** (`devc-pty` →
  `waitfor /dev/ptyp0` → publisher → `latch_guestd`).

- **THE LINUX GUEST DOES NOT CONTROL THE PL011 DEVICE NAMES.** The
  driver takes each port's index from the guest device tree's `serial`
  alias when there is one and from the driver's PROBE ORDER when there
  is not (`drivers/tty/serial/amba-pl011.c`, `pl011_probe_dt_alias()`),
  and neither is in the guest's hands. Measured on the target, with the
  console PL011 declared FIRST in the qvmconf:

  ```
  1c0b0000.uart: ttyAMA0 at MMIO 0x1c0b0000   (the FEEDBACK port)
  1c090000.uart: ttyAMA1 at MMIO 0x1c090000   (the CONSOLE port)
  ```

  — the **REVERSE** of the declaration order. A guest that trusts
  `/dev/ttyAMA<n>` therefore opens the WRONG port and reports a false
  negative. The guest-side probe opens EVERY candidate and lets the
  DATA decide which one carries the channel. The guest console log
  still works, because the kernel's `earlycon=pl011,0x1c090000` plus
  `keep_bootcon` sends every message to the console PL011 as well as to
  the real console.

- **`devc-pty` NEEDS THE `rsrcdbmgr` ABILITY, AND ITS USAGE TEXT
  DISAGREES WITH THE OLDER NOTES.** `devc-pty` is built on QNX's
  io-char library, and io-char calls `rsrcdbmgr_devno_attach()` to
  reserve a device number; the QNX C Library Reference says that
  function requires `PROCMGR_AID_RSRCDBMGR`. Without the ability it
  fails with `devc-pty: Unable to create device (No space left on
  device)` — ENOSPC, which points at the device table and is really a
  security-policy refusal. And the installed `devc-pty` usage text
  says `-E` ("raw") is the **DEFAULT** and `-e` selects edited mode,
  which is the opposite of what the older notes in this file said.

- **`on` RESOLVES A TYPE NAME BY READING `/proc/boot/secpol.bin`.** Its
  `-S path` option overrides it, but the default is the conventional
  path — so a profile that installs the policy anywhere else makes
  every `on -T <type>` fail with `Unable to open policy file
  /proc/boot/secpol.bin: No such file or directory`. The fbprobe image
  installs the generated experiment policy at that path.

- **THE CHOSEN HOST→GUEST TRANSPORT IS A POLLED VERDICT FILE ON
  `vdev virtio-blk`, AND THREE CANDIDATES WERE REJECTED BY MEASUREMENT.**
  The `vdev virtio-blk` usage text is `hostdev [<]<pathname>`, and the
  `<` makes the backing file **READ-ONLY to the guest** — enforced by
  the hypervisor, not by the guest behaving. The known-good addresses
  are `loc 0x1c0d0000` / `intr gic:41` (the SDP's own
  `qvmconf-aarch64le` example). The file is `/dev/shmem/latch_feedback.img`,
  exactly 1 MiB, mode 0600 root; the hypervisor opens it `O_RDONLY`, so the
  guest cannot write it, and only `latch_fb_sink`'s one-sided WRITE node
  accepts frames. The guest polls it with `pread64` (AArch64 syscall 67)
  and correlates by sequence number + session epoch.

  | candidate | why it was rejected |
  |---|---|
  | QNX `devc-pty` pair | the OPEN order decides usability and **any** process could write the channel — the verdict would not be the supervisor's |
  | PL011 vdev host→guest injection | the bytes DO reach the vdev (`delivered=11`), but the guest's UART never receives one, because the vdev waits for a receiver-enable state the guest never reaches |
  | `virtio-console` input | the `vdconsole_pulse` path is unreachable from this guest |

  `CONFIG_STRICT_DEVMEM` blocks `/dev/mem`, so there is no fifth option.

- **THE `waitfor` SELF-TEST PROVES THE FILE EXISTS, NOT THE NODE.** The
  buildfile's `waitfor /dev/latch/feedback 4` is a self-test with a
  measured contract: it opens the node with the hypervisor's
  `_IO_XTYPE_READCOND`, DATA ONLY at offset 0, `_IO_SET_READ_NBYTES`, and
  there is **no `ENOSYS` fallback** — so the probe that passes is the
  probe that exercises the real read path. The rule it encodes is
  **"node exists ⇒ file exists at its final size"**, which is exactly the
  property the VM start depends on: `latch_fb_sink` CREATES the file
  BEFORE it registers its nodes, and the nodes are registered BEFORE the
  lifecycle daemon starts the hypervisor.

- **THE CONSOLE CAN BE THE FEEDBACK PORT, AND THE GUEST CANNOT TELL.**
  The guest's PL011 names follow the **driver's probe order**, not the
  qvmconf's declaration order (see the `ttyAMA0`/`ttyAMA1` reversal
  above). A feedback channel delivered on a console therefore arrives
  mixed with the guest's own diagnostics, and the host cannot separate
  them. That is one more reason the transport is a file.

- **THE GUEST'S PAGE CACHE HID EVERY UPDATE, AND `O_DIRECT` IS REFUSED
  WITH `ENOTDIR`.** With a plain `O_RDONLY`, the guest's own page cache
  answered every poll from the FIRST read: 600 buffered `pread64`s over
  12 s returned the identical CRC-valid frame (seq 74 → 74) while the
  host wrote dozens of verdicts into the very same sector. The device
  was right, the address was right and the frame was valid — only the
  **FRESHNESS** was missing, and a channel that cannot show a change is
  not a channel. Two fixes, both required:
  - an `O_DIRECT` open is attempted first — and the guest's `O_DIRECT`
    open of `/dev/vda` is **REFUSED WITH `ENOTDIR` (20)**, so the
    buffered path is what actually runs;
  - `sys_fadvise64(fd, 0, 0, POSIX_FADV_DONTNEED)` (AArch64 syscall 223)
    before **every** buffered read. Measured: `ferr=0` and the updates
    become visible.

  The report carries `dir=`, `derr=`, `ferr=` and `rerr=` so a freshness
  failure is attributable rather than mysterious. **Note that the
  freshness rule is a MACRO and not a `static inline` function:** a
  `static inline` helper changed the W4 guest's compiled binary, and the
  W4 initrd's SHA-256 is the zero-regression witness for the transport
  work.

- **THE MAILBOX RING MUST BE A WHOLE NUMBER OF FRAMES.** `FB_RING_BYTES`
  was 4096 with a 28-byte frame, and 4096 = 146 × 28 **+ 8** — so the
  147th enqueue's `memcpy(&ring[4088], frame, 28)` ran **20 bytes past
  the end of `ring[]`**. Proven byte-for-byte on the target:
  `published=0xC61A88B2` was the frame's own CRC32, `queued=9599862` was
  frame bytes 16..19, the ring's `tail` had been overwritten with the
  epoch `0xa5a5a5a5`, and `file_writes` froze at exactly **147**. The
  fix is `FB_RING_BYTES (146u * FB_FRAME_SIZE)` plus
  `_Static_assert((FB_RING_BYTES % FB_FRAME_SIZE) == 0u)`. **The rule is
  general: a byte-sized ring whose length is not a multiple of the
  record size overruns on the first full cycle, and the symptom is a
  corrupt counter that looks like a protocol bug.**

- **THE VERDICT FILE IS WRITTEN *BEFORE* THE FRAME IS MIRRORED INTO THE
  MAILBOX.** The sink published to the file only *after* `fb_enqueue()`
  succeeded, so a full mailbox starved the transport — the one channel
  the supervisor needs to answer the guest. The order is now
  `fb_publish_to_block(frame)` → `g_fb.published++` → `fb_enqueue(frame)`,
  and the mirror's `EAGAIN` is counted as a drop but **never** returned
  as a failed publish. The status line reports `dropped=`, not
  `refused=`.

- **THE QNX CONSOLE ENDS ITS LINES WITH THREE `\r` AND A `\n`.** A
  line-anchored regex over console output — `[FBPROBE][^\r\n]*\r?$` —
  **never matches**, and the harness then reports "the guest never sent
  the marker" for a guest that sent it perfectly. The marker parser must
  tolerate the extra carriage returns, and completeness must be judged by
  the CENSUS (a contiguous `p0..pN` / `e0..eN` run that finishes on the
  highest index), not by the end of the line.

- **THE CONSOLE DRAIN BEFORE THE SESSION OPENS IS 1700 ms, AND IT IS
  TIED TO THE PLAN'S OWN COST BY A GATE.** The rule from §4a — "the
  console must be quiet BEFORE the supervised window opens" — applies
  here too, and `tools/consistency_check.py` fails the build when
  `LATCH_GOVERNOR_CONSOLE_DRAIN_MS` is shorter than the measured cost of
  the plan it is protecting. Grow the plan and the wait has to grow with
  it.

- **A `CLONE_THREAD` CHILD'S STACK POINTER MUST LEAVE A MARGIN *ABOVE*
  ITSELF.** The kernel sets the child's stack pointer to `newsp`
  **EXACTLY** (`kernel/fork.c`: `childregs->sp = stack_start`), and the
  compiler gives that entry point a FRAME it **SHARES with the parent** —
  so the callee-saved spill slots sit at **POSITIVE offsets from SP**,
  not below it. Measured on the QEMU AArch64 target with the Linux 6.12
  guest (2026-11-27): with the child's stack pointer at the TOP of its
  static array, and the array's top at the end of the ELF's RW segment
  (`__bss_end__` = 0x432000), the child's **FIRST store** —
  `stp x19, x20, [sp, #16]`, i.e. 0x432010 — was in the first unmapped
  page above the image. The child died with SIGSEGV and, because it is a
  thread of PID 1, the whole init group went down with it: *"Kernel
  panic - not syncing: Attempted to kill init! exitcode=0x0000000b"*.
  The symptom is a kernel panic with **no fault address and no oops**,
  because a user-space fault in a thread of PID 1 is delivered as a
  signal and the group's death takes the panic path. **Put the child's
  stack pointer BELOW the top of the mapping, with a margin of at least
  four times the frame size, and keep the margin INSIDE the mapped
  array.** (`LATCH_FB_STACK_SLACK`, 4 KiB.)

  While measuring this: **arm64 DOES select `CONFIG_CLONE_BACKWARDS`**
  (`arch/arm64/Kconfig:126`), so the kernel's signature is
  `clone(clone_flags, newsp, parent_tidptr, tls, child_tidptr)`. An
  earlier note in the guest source claimed the opposite and was wrong.

- **THE SUPERVISOR PUBLISHES ITS OWN VERDICTS, AND THE VERDICT
  VOCABULARY IS CLOSED.** The W5 profile has **no `latch_fb_pump`** — the
  only thing that writes the verdict file is the TRUSTED SUPERVISOR, via
  `latchd -f /dev/latch/feedback_pub`. The publisher is **OFF by
  default**, its failure is **NOT fatal** (the supervisor's own dead-man
  is the fail-closed path; the feedback channel is advisory), and its
  writer thread runs at **SCHED_FIFO 40** — below the safety core (63),
  above the actuator worker (20) — on a node opened
  `O_WRONLY|O_NOCTTY|O_NONBLOCK`, with a bounded 50 × 20 ms EAGAIN
  retry. The tick's publish is a **memcpy and a signal**, nothing else.

  A verdict is published **only** for a `GOVERNOR_WIRE_CMD_V2` motion
  proposal **from the session owner with a valid bound epoch**. A
  heartbeat, a shrink request, a foreign session or a spent epoch gets
  **silence** — a verdict that answers nothing is a lie. The verdict is
  **ACCEPT** iff `gov_frame_accepted && st->mode == LATCH_MODE_HP`: a
  supervisor that has failed closed into HOLD or HOME is not following
  anybody, and saying "accepted" to a proposal that was silently not
  applied would be a lie the guest would act on.

  The vocabulary is `ACCEPT 0x01`, `REJECT 0x02`, `TIMEOUT 0xFF`, and an
  **unknown verdict is `-EBADMSG`** on the host and `LATCH_FB_EVERDICT`
  in the guest — "I did not understand" is **never** read as "yes". The
  host and the guest are two implementations of one protocol and the
  numbers are gated to be identical.

- **A ZERO-REGRESSION WITNESS IS THE `init` BINARY, NOT THE INITRD.** The
  W4 and W5 witnesses are the SHA-256 of the **`init` binary inside** the
  initramfs (`f0c51a86…` and `80a96b2e…`), because that is the artefact
  whose behaviour the transport work could change; the **container** is a
  gzip of a cpio of that binary plus four empty directories, and its
  digest is a different number. Comparing the container's digest against
  the binary's witness says "the tree changed" when the tree did not —
  and the panic that follows ("the transport regressed!") sends you
  hunting a defect that is not there.

  The way to tell them apart is to look at what the digest covers:

  ```bash
  # the CONTAINER (this is what git tracks for the legacy guest):
  sha256sum guest/linux-guest.initrd
  # the BINARY inside a profile's initramfs:
  mkdir -p /tmp/x && (cd /tmp/x && zcat qnx/build/governor-linux-guest-feedback.initrd \
      | cpio -idm --quiet) && sha256sum /tmp/x/init
  ```

  The legacy container is `c6584dae…` and the plain GOVERNOR container is
  `224eaf01…`; the W4 and W5 **binaries** are `f0c51a86…` and
  `80a96b2e…`. All four are unchanged by the U-4 work.

- **A COMPILER BARRIER IS NOT A MEMORY BARRIER, AND THE GUEST HAS TWO
  CORES.** The GOVERNOR qvmconf gives the guest **two** vCPUs —
  `_cpu-2` and `_cpu-3`, each bound to its own single-CPU cluster
  (`qnx/latch_qemu_governor.qvmconf`) — so the verdict watcher and the
  main thread really can be running on DIFFERENT cores at the same
  time. AArch64 is **weakly ordered**: a store can become visible to
  another core before an EARLIER store of the same program has become
  visible, and two loads can be reordered with respect to each other.

  The W5 code used to order the watcher's words against the main
  thread's with

  ```c
  static inline void fb_barrier(void) {
      __asm__ volatile("" ::: "memory");
  }
  ```

  That stops the COMPILER from reordering the accesses and does
  **nothing for the CPU**. Two consequences, both real: the watcher's
  summary stores (PLAIN memory, not even `volatile`) could become
  visible *after* the `volatile` flag store that announces them, so the
  main thread could read a **half-updated** summary; and the two
  sequence-number stores could become visible in the OPPOSITE order, so
  the watcher could read `cmd_seq = N` together with `seq_sent = N-1`.
  The guest's own comment claimed the opposite — *"a fold that saw
  `cmd_seq = N` is guaranteed to see `seq_sent >= N`"* — and a compiler
  barrier did not deliver that guarantee on weakly ordered hardware. A
  verdict discarded as stale by that read is a verdict the guest never
  acts on.

  **A `volatile` ACCESS IS NOT AN ATOMIC OPERATION.** In the C11 model
  `volatile` constrains the *compiler*; it does not create a
  synchronises-with edge, so a fence-based handshake built on
  `volatile` alone orders nothing. The protocol's accesses go through
  `__atomic_store_n` / `__atomic_load_n` (with `__ATOMIC_RELAXED`, so
  each is still ONE `str`/`ldr` on AArch64) and the fences carry the
  ORDERING.

  **MEASURED, on this tree, with the SHIPPED header compiled for
  AArch64** (`-ffreestanding -O2 -S`):

  | compiler | a RELEASE accessor | an ACQUIRE accessor |
  |---|---|---|
  | `aarch64-linux-gnu-gcc` | `dmb ishld` + `dmb ishst` | `dmb ishld` |
  | `clang --target=aarch64-linux-gnu` | `dmb ish` | `dmb ishld` |

  Both are CORRECT, and the difference is worth knowing: gcc emits the
  **narrowest** domain that does the job (`ishst` orders stores, `ishld`
  orders loads), while clang emits the full `ish` for a release. The
  gate accepts either shape — `ishst` or `ish` for a publishing
  accessor, `ishld` or `ish` for a consuming one — and REJECTS the
  wrong direction, because `ishld` does not order a store and `ishst`
  does not order a load.

  **AN INSTRUCTION-LEVEL PROOF NEEDS AN INSTRUCTION-LEVEL TOOL, AND
  ONE OF THE TWO ROUTES NEEDS NO SYSROOT.** `clang
  --target=aarch64-linux-gnu -ffreestanding -S` works with **nothing
  installed**: clang carries its own freestanding headers, so no
  sysroot and no cross-toolchain package are required. That is why the
  gate can run on the CI runner image (which carries clang 16/17/18)
  without an `apt-get install` step. The other route,
  `aarch64-linux-gnu-gcc`, is the cross compiler this repository
  already needs for `make guest-initrd`. **If neither is present the
  gate FAILS** — "the instruction-level proof was skipped" is a hole in
  the proof, and this repository's rule is that a skipped check is a
  failure, not a warning.

  The general shape, and it is the same rule the evidence index
  follows: **a source-level "there is a fence" is a CLAIM; the
  generated assembly is the EVIDENCE.** A compiler barrier produces no
  instruction at all, so the source can read "fence" while the CPU is
  told nothing — and on a two-core guest, that is the whole defect.

### 4d. Facts about the DECISION-LATENCY MEASUREMENT (U-4)

These were measured on the QEMU AArch64 target on 2026-11-27. Each one
cost a boot cycle or a failed calibration run; read them before changing
the measurement.

- **AN EMPTY PROPOSAL QUEUE IS A JERK, NOT A PAUSE.** The supervisor's
  kinematic model carries three quantities: the position, the velocity (the
  last applied step) and the acceleration (the change of the velocity). Its
  **jerk** limit (`envelope.j_max` = 20 mrad/tick³) is checked against the
  **difference of two consecutive accelerations**. Now consider a tick that
  finds the proposal queue **EMPTY** while the plant is moving: the
  supervisor applies no motion that tick, so the applied velocity is 0 and
  the acceleration becomes `-v`. The **next** command then has to satisfy

  ```
  jerk = a_step - a_cur = a_step + v  <=  j_max
  ```

  and with `v` at the envelope's `v_max` (25 mrad/tick) and `a_step` up to
  10, that is ~35 — **above `j_max`**. Measured on the target: the
  supervisor **refused** the command, latched `LATCH_FAULT_RATE` (0x0080),
  dropped to HOLD, and the ladder ratcheted all the way to LATCH. **The
  supervisor's behaviour here is fail-closed and CORRECT.** The fix belongs
  in the **WORKLOAD**, not in the safety logic — this is the same lesson as
  §4a's "when a safety counter is wrong, suspect the data path first", one
  level up.

- **THE SETTLING STAIRCASE, AND WHY IT HAS NO GAP.** The soak's measured
  phase is a HOLD at 100 mrad, and to get there the plant has to MOVE. So
  it is walked up on a **staircase**: each command advances the target by
  `LATCH_GOVERNOR_SOAK_SETTLE_STEP_MRAD` (5 mrad), and the commands are
  sent **back-to-back at the same rate as the measured window**. The
  targets are **absolute**, so the plant is never more than one step behind
  and its velocity never exceeds the step; the acceleration is the change
  of that velocity, so it stays inside the step; and the worst-case jerk
  **after an empty tick** is `2 × step = 10 ≤ j_max = 20`. Then 200 HOLD
  commands let the plant come to rest.

  The obvious alternative — a settling **gap** of heartbeats between the
  steps — was **rejected by reasoning and measurement**: the gap is a
  **SILENCE**, the signed lease is **100 ticks (~100 ms)**, and a guest's
  sleep is only as accurate as the host's scheduler, which under TCG is not
  a promise. Sending the steps back-to-back removes the question: there is
  no gap for the dead-man to count.

- **A HARNESS MUST DECIDE "IS THE GUEST ALIVE?" FROM THE LEASE AGE, NOT
  FROM A COUNTER.** The naive observable — "the proposal counter advanced
  since the last poll" — is **wrong**, and it is wrong in the direction
  that turns the supervisor's **CORRECT** fail-closed behaviour into a
  false failure: the counter advances for the frames that arrive *between*
  two polls, so a poll that lands after the guest has already stopped
  still shows a counter that moved. The supervisor had, by then, done
  exactly what it is supposed to do (the lease expired, the ladder demoted
  one rung, and after five expiries it latched) — and the harness called
  that a workload defect. The honest observable is the **lease age**: the
  number of supervisor ticks since the session owner last sent a frame.
  It is 0–4 while the guest is streaming and it grows without bound once
  the guest stops, so it says whether the producer was alive **at the
  instant of the poll**. The predicate is

  ```python
  live = lease_age is not None and lease_age <= LIVE_LEASE_AGE_TICKS  # 50 = half the lease
  ```

- **THE SOAK MUST ALSO ASSERT ITS OWN WORKLOAD.** The harness checks that
  the plant stood at **100 mrad with velocity 0** on every live sample,
  and that the rung was **HP** throughout the streaming window. Without
  that, the phrase "decision latency under load" would mean something the
  report does not say.

  The harness's first sample lands **~12 s after the guest's plan marker**
  (measured: tick 21,780 at the first poll), and the guest's settling
  staircase plus its rest window is **~250 ms** after a **1,700 ms** drain
  — so the first poll is **~10× past** the settling window. A poll that
  landed inside the staircase would fail the assertion loudly and name the
  angles it saw, which is a diagnosable failure rather than a silent one;
  but the margin is the reason the workload check can be a strict
  equality and not a tolerance.

- **THE GUEST ABORTS BEFORE THE SESSION OPENS IF IT CANNOT BE PACED.** The
  pacer is deadline-based on the guest's own `clock_gettime(CLOCK_MONOTONIC)`
  (AArch64 syscall 113). If that clock reads 0, the soak prints
  `[LATENCY] ABORT: the guest monotonic clock is unavailable, so the soak
  cannot be paced` and stops **before** the session opens — the abort is
  visible on the console and costs the dead-man nothing. The harness
  recognises the marker and fails fast instead of burning the whole budget.
  A soak that cannot be paced is not a measurement; it is a random-length
  run.

- **THE HISTOGRAM SAMPLES EVERY TICK, INCLUDING THE PRE-SESSION IDLE
  PATH.** The legacy `Decision Latency` telemetry is deliberately **not**
  updated from the idle path — changing it would break the `last`/`max`
  pair the README and the archived status files are bound to. The
  histogram is **additive**: two of them, `hist_decision` (ticks that
  dequeued a proposal) and `hist_idle` (ticks whose queue was empty), plus
  `samples_motion`. A supervisor that only ever measured its idle path
  would have produced a much smaller number, which is exactly why the idle
  path is counted separately rather than folded in.

- **A PERCENTILE FROM A HISTOGRAM IS A BUCKET RANGE.** The histogram has
  112 buckets: the **exact** cycles 0..63, and above that three sub-buckets
  per octave — a **25 % resolution**. The `min`/`max` figures are **exact**,
  because they are tracked separately from the histogram. Say which one you
  are quoting.

- **A MEASUREMENT IMAGE MUST NOT CARRY A LOGGER.** The measurement image
  (`qnx/latch_qemu_latency.build`) is the GOVERNOR profile **minus**
  `latchlog`: `latchlog` polls the supervisor every 100 ms, dumps the
  event ring and the tape, and writes every tick to a CSV — over a
  35-minute soak at 1 kHz that is ~2 million CSV rows and a continuous
  background reader of the very state the measurement is about. The
  measurement image also starts `latchd` with **no `-f`**: the advisory
  feedback publisher would be another concurrent writer of the supervisor's
  own state. Everything else — the signed contract and its sidecar, the
  compiled security policy, the qvmconf with its static vCPU pins — is the
  GOVERNOR profile's, **verbatim**.

- **`mkifs` DOES NOT SUBSTITUTE ENVIRONMENT VARIABLES INSIDE `[+script]`
  BLOCKS.** Variables work only in **file entries** like `${GUEST_IMAGE}`
  and `${GOVERNOR_GUEST_INITRD}`. A `${...}` inside a `+script` block is
  copied literally into the image.

- **THE PLAN MARKER IS STRINGIFIED FROM THE MACROS, SO IT STATES THE
  ACTUAL BUILD VALUES.** `LATCH_STR(LATCH_GOVERNOR_SOAK_TARGET_HZ)` is
  what the harness reads back, and the harness checks it against
  `LATENCY_QEMU_EXPECT_HZ` / `_EXPECT_DURATION_MS`. The macros therefore
  carry **no `u` suffix** (the suffix would show up in the printed text as
  "900u Hz"), and the Makefile's `SOAK_TARGET_HZ` / `SOAK_DURATION_MS`
  defaults are gated to agree with the source's — otherwise the marker
  would state a rate the build does not use.

- **A GENERATED EVIDENCE FILE NEEDS A GATE THAT PROVES IT IS STILL WHAT
  ITS GENERATOR PRODUCES — AND A MEASUREMENT FILE CANNOT BE RE-RUN TO
  PROVE IT.** `docs/evidence/governor/LATENCY.md` cannot be reproduced by
  re-running its capture: that is a **40-minute** measurement, so a CI job
  will never regenerate it, and a gate that re-runs it is a gate nobody
  runs. The file therefore carries the **target's own report VERBATIM**,
  and the generator's body is a **pure function of that report**, so the
  archived file can be re-derived from it in a second and **DIFFed**.

  The defect this catches was **real, and it happened here**: the
  generator's percentile regex stopped before the figure's closing
  parenthesis, so the archive's summary lines read
  `[160, 192) cyc ([2560, 3072) ns` — an **unbalanced** figure — while the
  raw report underneath them read
  `[160, 192) cyc ([2560, 3072) ns)`. The truncated figure also flowed
  into the evidence **index**, which derives its U-4 row out of the
  summary, so one regex error reached two files and neither looked wrong.
  **The summary of a measurement is a claim about the measurement, and it
  has to be machine-checked against it.**

  The rule generalises: **a generated artefact that cannot be re-run must
  carry its own input**, so that the generator's output can be re-derived
  and diffed. That is the same trick the evidence index uses (it is
  regenerated into a scratch copy and diffed), applied to a file that is
  too expensive to regenerate from scratch.

  The gate normalises the two lines that are not in the report — the
  **date** and the **host** — because the archive is generated on one
  machine and checked on another. Everything else must match **byte for
  byte**.

- **A TCG MEASUREMENT MUST NOT SHARE THE HOST WITH A CPU-HEAVY JOB.**
  The first full soak **passed** (2,129,049 ticks, **0** ring drops). The
  re-run, with the *same* code and the *same* image, **failed** with
  **972 dropped frames** — because the 67-mutation battery was running
  **at the same time**. The battery runs the whole consistency checker
  **67 times** and copies the entire tree each round, and under TCG the
  guest Linux, the QNX host and `latchd` all share the host's cores.

  The failure mode is the interesting part: it is **not** a latency
  figure that got worse, it is the **producer outrunning the consumer**.
  The guest's 900 Hz stream fills the 256-frame proposal ring faster than
  the supervisor's 1 kHz tick drains it, and a full ring **drops** frames.
  So host load does not merely add noise to a TCG latency measurement —
  it can break the **workload** the measurement is about.

  **The rule: run a measurement on an otherwise idle host, and do not
  start a build, a test battery or a capture while it is in flight.**
  The calibration runs and the first full soak were both done with
  nothing else running, and both were clean.

- **A RATE LIMITER MUST KEEP THE RATE *AND* BOUND THE CATCH-UP.**
  Measured on the QEMU AArch64 `virt` target (2026-11-27): a soak with
  the **same** code and the **same** image failed with **186 dropped
  frames**, and the drop was **one abrupt event** — 0 drops, then 186 in
  a single poll, then frozen for the rest of the run. The cause was not
  host load (there was none): it was the soak's own **pacer**.

  The pacer advanced its deadline by one period and then, if the guest
  had been starved past that deadline, sent the next frame
  **immediately** and left the deadline **behind** `now`. That is a rate
  limiter that **accumulates credit**: every missed period became a frame
  owed, and the producer paid the whole debt back in **one burst**. A
  ~0.5 s host stall left the producer ~450 frames behind, and the
  catch-up burst put **255 frames into the supervisor's 256-frame
  proposal ring** and dropped **186** of them.

  The stall was the **host's** — the supervisor's own WCET-overrun
  counter jumped by **99** in the same window, against a background of
  about **6** — but the **burst** was the **producer's own**, and it
  broke the very workload the measurement is about. A host stall is the
  host's problem; the producer must not convert it into a burst.

  **The first fix was wrong in the other direction, and the measurement
  caught it.** Dropping the credit on *any* lateness removes the burst
  (2 frames) but **costs the rate**: the guest's own scheduling jitter
  puts it late about half the time, every late frame then costs a full
  period, and the measured rate fell from **901/s to 610/s** — a flat
  32% loss, visible in the archive as a stream at 610 proposals/s under
  a "900 Hz" workload line. The measurement still *passed* its own
  criteria (0 drops, a peak backlog of 4), which is exactly why the
  rate has to be read out of the report and not assumed from the
  build's constants.

  **WHY THE GUEST IS LATE ALL THE TIME.** The guest's per-frame cost is
  ~550 µs, but its `nanosleep` **wake overshoots by more than a whole
  period** under TCG (~1.7 ms), so the guest is ~1.02 periods behind its
  own schedule *by construction*. It can only hold the target rate by
  sending **two or three frames back-to-back** and then sleeping to the
  grid — which is the OLD pacer's regular pattern, and the reason its
  peak backlog was 72. A pacer that forbids back-to-back frames
  therefore caps the rate at ~1/(550 µs + 1.1 ms) ≈ **600/s**, whatever
  the target says.

  **The rule, in one sentence: the producer may fall at most the LAG
  ALLOWANCE behind its own schedule, and it keeps its grid.** Inside the
  allowance (ordinary jitter) → **keep the grid**, and the frame that is
  due goes out immediately. Outside it (a host stall) → **drop the
  missed deadlines** and resume from *now*. The checkable form is
  `now - latch_soak_next_deadline(...) <= LATCH_SOAK_MAX_LAG_PERIODS *
  period` for every input.

  The allowance is **4 periods**, and that is not a guess: the guest's
  measured normal lateness is ~1.02 periods, so 4 is ~3× the ordinary
  jitter, and the catch-up it permits is a handful of frames against a
  **256-frame** ring. An allowance of **1** period is the first fix's
  value and collapses the rate to 646/s.

  All four pacers, measured on the same target with the same guest:

  | pacer | rate during the stream | peak backlog | catch-up after a 0.5 s stall |
  |---|---:|---:|---:|
  | keep the grid, catch up without limit | 901/s | 72 | **~450 frames → 186 DROPPED** |
  | drop the credit on any lateness | 610/s | 4 | 1 frame |
  | allowance of 1 period | 646/s | 4 | 1 frame |
  | **allowance of 4 periods** | **899/s** | **7** | **~8 frames** |

  The pacing decision therefore lives in a shared, host-testable header
  (`guest/latch_soak_pace.h`), the behavioural proof is
  `qnx/latch_soak_pace_test.c` (15 checks, in `make check-governor` and
  in CI), and it is proved **non-vacuous in EVERY direction**: the same
  test fails 5 checks against the original pacer, 4 against the
  rate-killing one, and 2 against a one-period allowance.

  Three measurement rules fall out of this. A burst check has to count
  the frames in a **sub-window** after the stall — the **total** frame
  count does not discriminate, because a pacer that accumulates credit
  catches up and delivers the same total, just in a burst. **The
  achieved rate is a result, not an input**: the archive must carry it,
  because a rate limiter that is "correct" on paper and 32% slow on the
  target has changed the workload the measurement is about. And **the
  rate has to be read over the STREAMING WINDOW**: a short calibration
  averages the guest's rate over the whole harness window, including the
  tail after the guest stops, and reports a number (749/s) that the
  per-poll rates (898–899/s) contradict.

- **A MEASUREMENT MUST CHECK THE RATE IT CLAIMED, OR IT MEASURED
  SOMETHING ELSE.**
  The third rule above was a *measurement* rule, and the lesson from it
  is general enough to be its own: **the achieved rate is a RESULT, and a
  result has to be CHECKED against the claim it is compared to.**

  The soak's workload is "a 900 Hz producer". The harness checked that
  the producer kept the supervisor fed (0 ring drops), that the backlog
  stayed small, that the rung was HP throughout, that the plant stood
  at 100 mrad with velocity 0, and that the sample floor was met. It
  did **not** check the rate — and so a run that produced at **610/s**
  under a "900 Hz" workload line passed **every** one of those criteria.
  The archive would have carried a measurement of a 610 Hz workload
  under a heading that said 900 Hz, and nothing in it would have looked
  wrong.

  The fix is the same shape as the rest of this repository's rules: the
  decision is a **pure function** (`rate_verdict()` in
  `tools/verify_latency_qemu.py`), the consistency checker **imports and
  exercises it** against the rates that were measured on the target — the
  two that must be accepted (897.6/s, 901/s) and the two regressions
  that must be rejected (646/s, 610/s) — and the harness calls it on the
  measured rate before it declares the run good. The band is **±5%**:
  the measured rate is within 1% of the target, and the two
  regressions are 28% and 32% out, so the band separates them
  decisively while leaving the TCG host's jitter room. A gate that
  cannot fail is a gate that proves nothing, so the band is capped at
  **10%** by the consistency checker — a wider band would let a run at
  two thirds of the declared rate pass, which is exactly what happened.

  The rate is read over the **STREAMING WINDOW** — the samples whose
  lease age says the producer was alive — and the report carries **two**
  rates, because they are not the same number and confusing them is
  how the bug hides:

  | | a 60-second calibration | the 35-minute soak |
  |---|---:|---:|
  | `guest proposals/s` (the whole harness window) | 749/s | 887/s |
  | `producer rate` (the streaming window) | 897/s | 895/s |

  The whole-window rate is diluted by the tail after the guest stops, so
  it is a figure about the HARNESS, not about the workload. The
  streaming-window rate is the figure about the workload, and it is the
  one the band is checked against.

  The general shape: **when a measurement's own criterion is a NUMBER,
  the number has to be measured and checked — not inferred from the
  build's constants.** "The guest was built for 900 Hz" is a fact about
  a macro; "the guest produced 898 proposals/s" is a fact about the
  target. The first is what the plan says; the second is what happened.

- **A FAILING CAPTURE MUST KEEP ITS OWN TRANSCRIPT.** The failed re-run
  printed *"the failing run's own transcript is at …"* — and the cleanup
  had **already deleted it**, because the scratch directory was removed
  in a `finally` that ran on the failure path too. The message was a
  dead link, and the price of the next diagnosis would have been another
  forty-minute measurement. The five capture scenarios now remove the
  scratch directory **only on success** (`scratch_cleanup(tmp, ok)`), and
  a failing run says where its evidence was kept.

### 4e. Facts about the CI JOB ITSELF

These were measured on 2026-11-27, while diagnosing the red CI run
`45980130747` (sha `9f0d7b9`). They cost a push-and-a-cycle each; read them
before diagnosing a red job.

- **THE JOB'S DURATION IS A DIAGNOSTIC, AND "EXIT CODE 2" IS NOT A
  COMMAND.** Measured on this workstation: the consistency check takes
  **0.74 s** and the mutation battery **12.2 s**. The failed job took
  **26 s in total** — which, against those two numbers, leaves about
  **two seconds** for the step that failed. The failing step ("Run
  200-Tick End-to-End Pipeline & Second Plant Tests") indeed took **1.0 s**,
  and **GNU make exits with status 2 whenever ANY recipe fails** — so
  "exit code 2" says only "a recipe failed"; it does NOT mean the second
  command failed, nor that the failing recipe's own exit code was 2. The
  per-step timestamps are readable from the public API
  (`…/actions/jobs/<id>` → `steps[].started_at` / `completed_at`), and they
  are the cheapest way to tell an early failure from a late one.

- **THE COMMITTED TREE PASSES THE JOB IN A CI-FAITHFUL CONTAINER.** Built
  and measured: `ubuntu:24.04` + **gcc 13.3.0** + **GNU make 4.3** +
  **Python 3.11.18** (the CI's exact toolchain), the workflow's `run:`
  blocks extracted from the YAML with the same parser the local runner
  uses and executed **in order** with `bash -e` from the workspace root,
  with `CI=true` and `GITHUB_ACTIONS=true` set. Result: **18/18 green**.
  So a red job on the runner is **not** proof that the tree is broken — and
  the local runner's green result is **not** proof that the runner is happy
  either. Both are evidence; neither is a verdict.

- **A gcc-13 CONTAINER REPRODUCTION IS ONLY A REPRODUCTION IF IT REBUILDS
  FROM SCRATCH.** The first attempt copied a tree whose `qnx/build/`
  already held objects compiled by Fedora's gcc 16.2, so **gcc 13 never
  recompiled the new code at all** and the "PASS" proved nothing about the
  compiler the CI uses. The reproduction has to start from a pristine
  `git clone` (which carries no `build/` directory, because it is
  gitignored) and copy THAT into the image. **A reproduction that reuses
  somebody else's artefacts reproduces nothing.**

- **"THE CI WAS GREEN" IS A STATEMENT ABOUT A SHA, NOT ABOUT THE BRANCH.**
  The last **green** CI run was sha `4627040`. The commit after it
  (`2eba17b1`, the W4/W5/W6 work) failed at **step 3**, so **the tree that
  followed it never reached step 9 in CI at all** — and every later claim
  about "CI is broken" was really about a step that had not run yet. Check
  which sha the last green run belongs to before blaming a commit for a
  red job.

- **THE PUBLIC API IS BLIND TO THE JOB'S LOG BUT NOT TO ITS VERDICT.** The
  run's and job's `conclusion` and every **step's** conclusion are public,
  and so are the job page's **annotations** (the web page carries "Process
  completed with exit code 2" for a non-admin, even though the log itself
  403s). The **artifacts** API answers 200 unauthenticated, and the
  **step summary** is rendered on the job's public page. Those three
  channels are why the workflow now wraps every step in
  `tools/ci_step.sh` (§3): a red job has to be diagnosable by somebody who
  is not the repository's administrator.

- **GITHUB KEEPS ONLY THE FIRST TEN ANNOTATIONS OF A STEP — AND THE
  INTERESTING ONES ARE AT THE *END*.** Measured on run `45988680440`
  (2026-11-27): the wrapper raised one `::error::` annotation per
  transcript line (41 of them) and the job page showed **"10 errors and 1
  warning"** — the FIRST ten of the tail, so the `make: ***` error at the
  BOTTOM of the transcript was **silently dropped**. The page's annotations
  are rendered newest-first, which is what makes this so easy to misread:
  the reader sees a plausible-looking block of command lines and concludes
  that the step died at the command in the middle of it. It did not.
  **The tail has to go out as ONE multi-line annotation** (newlines
  escaped as `%0A`, `%` as `%25`), and it has to go out FIRST, because the
  budget is the first ten. One annotation for the whole tail, plus one
  short fallback, is the shape that cannot be truncated.

- **THE JOB'S ARTIFACT IS PUBLIC — BUT NOT THROUGH GITHUB'S OWN URL.**
  `GET …/actions/runs/<id>/artifacts` answers **200** unauthenticated and
  lists the artifact with its size and digest, while the
  `archive_download_url` it hands out answers **401** for a non-admin, and
  the web UI's download paths 404. The third-party proxy **`nightly.link`**
  serves the same ZIP unauthenticated
  (`https://nightly.link/<owner>/<repo>/actions/runs/<run>/<artifact>.zip`).
  Use it to READ a red job's transcript from outside the repository; do
  not make the project depend on it.

- **A FLAKY TEST CAN FAIL ONLY ON A FASTER MACHINE, AND A FIXED-SIZE
  READ WINDOW IS THE CLASSIC WAY TO GET ONE.** The red CI run
  `45988680440` failed in `latch_feedback_pub_test` with *"the node does
  not hold the LATEST verdict"*, and the **publisher was right**: the node
  did hold the latest verdict. The TEST read the node into a fixed
  **4096-byte** buffer and compared the last frame *inside that window*
  with the last frame published — and a frame is 28 bytes, so the window
  holds at most **146** frames, while the number of frames the writer
  thread lands during the burst is a **race**. Measured on this
  workstation the writer lands 18-34 of the 500 burst frames with the node
  on the repository's disk, and 104-132 with the node on tmpfs (the window
  holds the whole file, the test passes); on the runner it landed more
  than 146 (the window held the first 146, the test compared frame 145
  with the last published frame, and failed). The same file had a second
  instance of the same class of defect: `written` is a **cumulative**
  counter, and it was compared against the burst's own size — so on a
  machine where the writer keeps up with every publish, `written` reaches
  501 and the test fails with *"the publisher wrote more frames than it
  was given"*. **A test that addresses data by a fixed-size window, or
  compares a cumulative counter against a partial count, is a test whose
  verdict depends on the machine.** Address the data by **index** (read
  the node's size, then `pread` the frame you mean) and compare
  cumulative counters against cumulative counters.

- **A FLAKY TEST CAN BE REPRODUCED WITHOUT TOUCHING IT, AND THE WAY IS A
  `LD_PRELOAD` SHIM.** The defect above was reproduced with the **shipped
  binary** by making the publisher's hot loop slower: an
  `LD_PRELOAD` library that wraps `pthread_cond_signal` (called only by
  the publisher) to mark the thread and `pthread_mutex_unlock` to sleep
  **after** the real unlock. The delay has to be **outside** the critical
  section: a delay inside it starves the writer thread and makes the
  writer land FEWER frames — the opposite of the runner. With a 0-2 us
  delay the shipped test fails with the runner's exact message; with
  3 us and up it fails with the second message. The fixed test passes at
  every setting, with the node holding 125, 478, 499, 500 and 501 frames.
  **A defect that only appears on a faster machine can be brought back
  to a slow one on purpose.**

- **A REPRODUCTION'S CONTEXT MUST BE A REAL CHECKOUT.** Building the
  faithful container's context with `tar --exclude=…/build` dropped
  **`docs/evidence/build/`**, which is **TRACKED** (two files), and the
  consistency checker correctly failed with *"docs/evidence/README.md is
  NOT what the generator produces"*. The context is now a real
  `git clone` plus the changed files, which is also what the runner
  gets. **Do not filter a checkout by directory name: `build` is
  gitignored in one place and tracked in another.**

### 4f. Facts about the iofunc NOTIFICATION LIST

These were measured by disassembling the installed SDP 8.0 library
(`target/qnx/aarch64le/lib/libc.so.6`) on 2026-11-28. Read them before
touching any `iofunc_notify*` call.

- **THE NOTIFICATION LIST IS SHARED MUTABLE STATE, AND THE LIBRARY
  TAKES NO MUTEX OF ITS OWN.** `iofunc_notify_t` is
  `{ int cnt; struct _iofunc_notify_event *list; }` — a 16-byte element,
  and a resource manager owns an ARRAY of three of them (INPUT, OUTPUT,
  OUT-OF-BAND). The `list` is a singly-linked list of armed events, and
  three library entry points change it:

  - `iofunc_notify()` ALLOCATES an event and LINKS it into
    `nop[index].list`, and writes `nop[index].cnt`;
  - `iofunc_notify_trigger()` / `iofunc_notify_trigger_strict()` walk the
    list, deliver a pulse with `MsgDeliverEvent()`, and UNLINK the
    events they fire;
  - `iofunc_notify_remove()` / `iofunc_notify_remove_strict()` walk the
    SAME list and `free()` the events.

  **MEASURED: none of the five notify entry points calls
  `pthread_mutex_lock`, `pthread_mutex_unlock` or `SyncMutexLock_r`.**
  The library provides NO lock here, so the resource manager has to.

- **THE RACE IS A USE-AFTER-FREE, NOT A LOST COUNT.**
  `iofunc_notify_trigger_strict()` loads the list head with
  `ldr x19, [x23, #8]` (the `list` member at offset 8), follows it with
  `ldr x19, [x19]` (the event's `next` at offset 0), calls
  `MsgDeliverEvent()` and unlinks the event; `iofunc_notify_remove_strict()`
  follows the same chain and calls `free()`. So a trigger that runs
  while a remove is running walks into an event the remove just freed,
  and the two unlinks both write the predecessor's `next` — a node can
  be lost, duplicated, or made to point at itself.

- **NO NOTIFY ENTRY POINT REACHES `iofunc_attr_lock`,** so there is no
  lock-ordering cycle between the attribute lock and the notification
  lock inside the library. **That is not a licence to nest them in the
  resource manager**, though: two locks taken in two different orders
  are a deadlock, and the order is per-resource-manager. LATCH keeps
  them apart by construction (the notify header never mentions the
  attribute lock, and the attribute header never mentions the notify
  lock), and `tools/consistency_check.py` proves it structurally.

- **THE RACE IS LIVE IN `latch_fb_sink.c` AND ONLY THERE.** The sink
  creates its dispatch channel with `DISPATCH_FLAG_NOLOCK` and runs TWO
  dispatch threads on it, so two messages really can be in flight at the
  same time. The WRITE handler's trigger and the READ/close handlers'
  arm and remove run on DIFFERENT threads, and they all touch the same
  node's list. `latchd.c` and `latch_guestd.c` do not use notifications
  at all today.

- **THE ARMED-COUNT CHECK AND THE TRIGGER HAVE TO BE ONE CRITICAL
  SECTION.** `IOFUNC_NOTIFY_INPUT_CHECK(nop, cnt, tran)` reads
  `nop[IOFUNC_NOTIFY_INPUT].cnt` and `iofunc_notify_trigger()` walks
  `nop[IOFUNC_NOTIFY_INPUT].list`. If they were two critical sections,
  a notification could be armed between them and the count the trigger
  used would not be the count the check compared against.

- **`IOFUNC_NOTIFY_INIT(nop)` SETS ALL THREE COUNTS TO `INT_MAX` AND
  ALL THREE LISTS TO NULL,** and that initial armed count is part of the
  node's observable state — `latch_rm_notify_init()` preserves it
  exactly, because changing it changes when the first notification
  fires.

### 4g. Facts about the DOCUMENTATION-CLAIMS gate

These were measured by hand on 2026-11-28, while remediating the v14
P0 documentation drift. Read them before editing a judge-facing
document.

- **A DOCUMENT IS A CLAIM ABOUT THE CODE, AND THE CHEAPEST WAY TO KEEP
  THE CLAIM TRUE IS TO DERIVE IT.** The `verify_documentation_claims()`
  gate in `tools/consistency_check.py` derives every property it
  checks: the LFBK frame size comes out of `qnx/latch_feedback.h`'s
  `LATCH_FEEDBACK_SIZE`; HOMEOSTAT's default-off property comes out of
  `qnx/latchd.c`'s `latch_homeostat_vmax()`; the canonical video plan
  comes out of the documents themselves; the `latchctl` verbs come out
  of `qnx/latchctl.c`'s `strcmp(cmd, ...)` dispatch table. **A gate
  that hard-codes the file list has to be edited every time a file is
  added, and the day it is not edited is the day it stops covering
  anything.** The frame size is the clearest case: the README used to
  call the LFBK frame 24 bytes, which is the CRC's COVERAGE (bytes
  [0..23]), not the frame (28 bytes) — and a reader told the frame is
  24 bytes rejects a valid 28-byte frame.

- **A QUARANTINED ARTEFACT MUST SAY SO IN ITS OWN FIRST LINES.** The
  withdrawal notice used to live in a README *beside* the artefact, so
  the artefact itself — opened on its own, copied into a slide, pasted
  into a review — read like a live measurement. The marker is the
  literal string `WITHDRAWN -- NOT EVIDENCE`, and
  `tools/quarantine_secpol_audit.py` writes it into the archived copy
  **idempotently**: re-running the tool on an archive that already
  carries the banner changes nothing, and re-running it on one that
  lost the banner restores it.

- **A GATE ON A DOCUMENT HAS TO HAVE A MUTATION, AND A DOCUMENT-WIDE
  MUTATION HAS TO SURVIVE A REWORDING.** The D-3 mutation that removes
  HOMEOSTAT from the Devpost submission has to replace EVERY
  occurrence — the heading, the running text and every file name — or
  the document still mentions the module and the gate stays green. But
  pinning the occurrence COUNT turns every harmless rewording into a
  stale mutation, and a stale mutation is a hole in the proof. So the
  mutation tool accepts the count `"all"`: the anchor still has to
  EXIST (otherwise the mutation is stale and the battery fails), but
  its count is not frozen. **A count is a proxy for "this anchor is
  still the one I meant"; where the anchor is a word the document may
  use any number of times, "the anchor is still there" is the real
  property.**

- **THE NARRATION WORD COUNT IS A MEASURED NUMBER, NOT A ROUNDED
  ONE.** The storyboard's ten segments total 155 s and carry **359**
  narration words (the gate counts the `*"..."*` spans in the `| **`
  rows). The script used to say "~365", which the gate's ±15 tolerance
  accepted — and a tolerance is a tolerance, not a derivation. The
  document now states the measured number, and the gate checks the
  first `~N narration words` against the count it measures.

### 4h. Facts about the PUBLISHER'S PRIMITIVE LIFETIME

These were measured on this tree on 2026-11-28, while remediating the
v14 P0 finding C-3. Read them before touching
`qnx/latch_feedback_pub.c`.

- **ON GLIBC, `pthread_mutex_destroy()` OF A NORMAL MUTEX IS VERY NEARLY
  A NO-OP — SO A USE-AFTER-DESTROY IS INVISIBLE WHEN THE CODE IS RUN.**
  The publisher's `stop()` destroyed its mutex and its condvar, and
  every public entry point used them again afterwards: a `publish()`
  after a stop (to refuse the frame), a `get_status()` after a stop (to
  hand the operator a final snapshot), and a `start()` after a stop (to
  run a new writer thread on the SAME primitives). POSIX leaves the
  behaviour **undefined** after a destroy, but the host test passes
  either way, because glibc's destroy of a normal (non-robust,
  non-error-checking) mutex leaves the object usable by accident.
  **"It happens to work on the library we test with" is not a safety
  argument.** So the rule is enforced **STATICALLY** — in the SOURCE,
  by `verify_feedback_pub_lifetime()` in `tools/consistency_check.py` —
  and the host test is the *behavioural* proof of what the rule
  delivers (a refused publish, a status snapshot and a RESTART all work
  after a stop). A defect that cannot be seen by running the code has to
  be caught by a gate that reads the code.

- **THE SAME IS TRUE OF RE-INITIALISATION.** `start()` used to call
  `pthread_mutex_init()` on **every** start, which is undefined
  behaviour on an already-initialised mutex, and it meant that a
  `publish()` arriving before the first `start()` locked a mutex that
  had **never been initialised at all**. The primitives are now
  **process-lifetime objects**: initialised EXACTLY ONCE by
  `pthread_once` (`g_pub_prim_once = PTHREAD_ONCE_INIT`) and **never
  destroyed**. `start()`, `publish()`, `stop()` and `get_status()` all
  call the `fb_pub_primitives_ready()` guard.

- **`pthread_once` IS IN THE INSTALLED QNX SDP 8.0.** Confirmed in
  `/home/skanda/qnx800/target/qnx/usr/include/pthread.h` (the sysroot
  has no per-architecture `usr/include`; the include lives one level up,
  under `target/qnx/usr/include`): `PTHREAD_ONCE_INIT` is defined as
  `{ .__once=0, .__mutex=PTHREAD_MUTEX_INITIALIZER }`, and
  `pthread_once` is a MACRO that does an `__atomic_load_n(...,
  __ATOMIC_ACQUIRE)` and only calls `__pthread_once()` when the flag is
  still zero. So the fast path on QNX is one atomic load, and the
  initialiser runs exactly once.

- **A HOST TEST THAT RESTARTS A PUBLISHER NEEDS A SECOND NODE FILE.**
  The publisher's stand-in node on a POSIX host is an ordinary FILE, and
  a file that is opened again starts writing at **offset 0** — so a
  restarted publisher pointed at the SAME file **overwrites** its first
  frame instead of appending, and the frame count does not move. The
  real publisher node is a resource manager's one-sided WRITE node, which
  is a **stream**: every write appends. The test therefore gives the
  restarted publisher a node of its own
  (`g_node_path_2`), so the assertion is about the publisher (it wrote
  a frame) and not about the stand-in's file semantics.

- **THE GATE THAT COMPILES A SHIPPED MODULE AGAINST ITS OWN HOST TEST
  NEEDS `-DLATCH_HOST_SIM` AND A SCRATCH WORKING DIRECTORY.**
  `qnx/latch_protocol.h` refuses to compile without either the QNX
  compiler flags or `-DLATCH_HOST_SIM`, and the host test writes its
  stand-in node under `build/host-sim/` **relative to its working
  directory** — so the gate runs the binary with `cwd` set to a scratch
  directory (with `build/host-sim/` created inside it), never in the
  repository. A gate that compiles a module it does not own has to
  reproduce the module's own build flags exactly, or it is testing
  something the module does not ship.

---

## 5. What this project must never claim

- No ASIL / SIL / ISO 26262 / IEC 61508 / IEC 62304 certification claim.
  Claim a **measured fail-closed runtime filter** and show the faults on
  camera.
- No "WCET" for a number that is a TCG observation. Report the **last** and
  the **max** decision latency, in cycles and in nanoseconds, against the
  manifest's `timing.wcet_budget_us`, and name the machine.
- No "WCET" for the **U-4 distribution** either, and no "worst case". It is
  the observed distribution of one emulated target under TCG, where the
  supervisor shares host cores with the guest and with QEMU — so its
  maxima are the **host's** scheduling noise. Its percentiles are **bucket
  ranges**, not exact values, and its workload is **one** workload (a HOLD
  at 100 mrad). Point at `docs/evidence/governor/LATENCY.md`; do not copy
  a figure out of it into a hand-written document, where it would rot
  silently the moment the archive is refreshed.
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
