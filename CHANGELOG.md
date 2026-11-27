# Changelog — LATCH + GOVERNOR Project

All notable changes to the LATCH (Last Authority for Trusted Control Handoff) and GOVERNOR runtime-assurance architecture are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Fixed
- **The secpolgenerate audit harness was killing the reader mid-write**: the harness detected the end of a QNX shell command with `buf.endswith(b"# ")` — the shell prompt — but **every line of `/dev/secpolgenerate/policy` begins with `# `**. The detector therefore fired on the *file's own content*, after its second character, and the harness walked away and took QEMU (and the reader) with it. The reader never hung. Measured on the target: the captured output's last bytes were exactly `# `, and a plain blocking read of the same file completed in **0.1 s / 2004 bytes**. The harness now uses **sentinels matched with their exit-code digit** (`cmd; echo TAG_$?` → match `TAG_(\d)`) for every command, so the shell's echo of the typed command can never be mistaken for the command's output. The same `endswith(b"# ")` pattern exists in `tools/verify_infer_qemu.py`, `tools/verify_governor_qemu.py`, `tools/qemu_guest_kill.py`, `tools/verify_qemu_aarch64.py` and `tools/run_target_probe.py`; a grep of every archived transcript found **0** lines currently ending in `# `, so they are latent rather than active, and they should be hardened when touched.
- **The scripted GOVERNOR profile's deadman window was measuring the console, not the lease**: The profile now prints its whole scenario *plan* before the session opens and writes **nothing** to the console afterwards, but printing the plan is only half the fix. A `/dev/kmsg` write returns as soon as the record is in the kernel's ring buffer, while the kernel's console thread then pushes it out through the PL011 at the measured **1.3–1.8 ms per character** — so the guest finished "printing" the plan while the **host** was still serving it. Measured on the QEMU AArch64 `virt` target (2026-11-26) with the guest instrumented by its own `CLOCK_MONOTONIC`: the guest's `nanosleep(110)` took **111.66 ms** and the A4 command's write took **0.97 ms**, but the supervisor's tick index advanced **268 ticks** for that same event — a **2.4× skew** confined to the window in which the console burst was still draining. The deadman counted that host-side drain as guest silence and demoted the ladder **twice** (HP → ADVISE → CLAMP) for a silence that was meant to expire the lease once, so the A4 command arrived at the CLAMP rung and was **REJECTED** with `DOSE` (0x8000). The profile now waits `LATCH_GOVERNOR_CONSOLE_DRAIN_MS` (1500 ms) for the console to go quiet **before** the session opens, while the deadman is not yet running. Measured after the fix: the A4 silence is **112 ticks**, **exactly one expiry** (HP → ADVISE), the A4 command is **ACCEPTED with no faults**, all 151 hold frames sit at rung ADVISE, and 25 clean commands recover HP. `tools/consistency_check.py` ties the wait to the plan's own console cost — it counts every character the plan prints (including markers written as concatenated string literals), adds the kernel's timestamp prefix, multiplies by the measured 1.8 ms/char upper bound, and fails the build if the wait is shorter; it also requires the wait to sit after the last annotation and before the warm-up flush.
- **Cross-Session Replay (RT-02, HIGH)**: The supervisor re-bases its sequence baseline whenever a session opens, and the **first** frame of a session was accepted with any non-zero sequence number. A frame captured in an earlier session — say one carrying `seq = 999999` — was therefore accepted as the first frame of the new session, became the new baseline, and could move the plant. The session now carries an explicit **epoch**: `latch_ipc_proposal_v2_t` grows 48 → 56 bytes with `session_epoch` at offset 48 and a must-be-zero `reserved1` at 52, `latch-ingest --session-epoch N` stamps it (the default is a fresh value derived from the monotonic clock, the wall clock and the pid), and the supervisor binds the epoch of the session it is running and rejects every frame that names a different one. The epoch binds **only after** the sequence check, so a stale frame that arrives first cannot become the session's identity. A ring of the 16 most recently spent epochs outlives the session, so a producer that restarts and reuses its previous epoch is rejected. The **first frame of a session opened by a new producer must carry `seq == 1`** — a session's sequence space starts at 1, so this is the only frame that can legitimately open one. The 32-byte **wire** frame and the 84-frame and 235-frame scripted baselines are unchanged; the change is host-side only. Telemetry: `session_epoch`, `session_epoch_valid` (`DCMD_LATCH_GET_GOV_STATUS`, `extension_version` 5 → 6).
- **Legacy Verifier Handoff (L-2, HIGH)**: The 84-frame QEMU verifier killed the guest's ingest and then waited a **fixed two seconds** before starting `latch_verify`, on the assumption that the resource manager would have processed the ingest's disconnect by then. When it had not, `latch_verify`'s own open of the proposal node was refused with `EBUSY` and the run failed for a reason unrelated to the invariants under test. The supervisor now reports whether the exclusive writer OCB is still held through the new output-only `DCMD_LATCH_GET_SESSION_STATUS` (`0x47`), and `tools/verify_qemu_aarch64.py` starts the verifier only after the supervisor itself says the writer is gone. Writer exclusivity is unchanged, and the operator shell still gets no ability.
- **Producer-Scoped Dead-Man Lease (L-2, HIGH)**: The dead-man lease was renewed by **any** frame that arrived on `/dev/latch/proposal`, so a second unprivileged writer could keep a session alive whose real planner had died — precisely the failure a dead-man's switch exists to prevent. The lease is now owned by a **producer**: `latch_ipc_proposal_v2_t.reserved0` is repurposed as a `producer_tag`, `latch-ingest --producer-tag N` stamps it, and the supervisor resolves lease authority before the sequence check. A foreign producer's frame is **lease-inert** — it cannot renew the lease, cannot advance the coherence baseline, cannot earn warm-up credit, cannot move the plant, cannot advance the owner's sequence epoch and cannot reset the recovery streak. A takeover is possible only after the owner's lease has **expired**, and it starts a new epoch (fresh sequence baseline, re-earned warm-up). Tag `0` is reserved and an unscoped v2 frame is rejected at the IPC boundary. Telemetry: `lease_owner_tag`, `lease_owner_valid`, `session_dead`, `foreign_frames`, `producer_takeovers` (`DCMD_LATCH_GET_GOV_STATUS`, `extension_version` 4 → 5).
- **Ring-Flush Read-Tail Regression (L-3)**: A session flush could move the consumer's `read_tail` **backwards**, letting a pre-reset frame be re-applied. The flush now bumps a `flush_epoch` and advances `read_tail` with an atomic compare-exchange; the consumer reads under an epoch guard.
- **Manifest Key-Set Validation (L-4)**: The loader now rejects unknown keys in **every** section and at the top level, not just in a subset.
- **Operator Release Honesty (L-5)**: The operator release token is **retained** while the ladder rung is unchanged and **invalidated** on any rung change; the new output-only `DCMD_LATCH_GET_HOLD_STATUS` (`0x46`) reports `LATCH_RELEASE_NONE` / `DEFERRED` / `ARMED`, and `latchctl hold 0` prints the same state instead of implying an armed release.
- **The verdict watcher's thread died with SIGSEGV and took the whole init group with it**: the clone child's stack pointer was at the **top** of its static array, and the array's top was the end of the ELF's RW segment (`__bss_end__` = 0x432000). The kernel sets the child's stack pointer to `newsp` **exactly**, and the compiler gives that entry point a frame it **shares with the parent** — so the callee-saved spill slots sit at **positive offsets from SP**, and the child's **first store** (`stp x19, x20, [sp, #16]`, i.e. 0x432010) was in the first unmapped page above the image. Because the child is a thread of PID 1, the group died with it: *"Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b"*, with **no fault address and no oops**, because a user-space fault in PID 1's thread group is delivered as a signal. The child's stack pointer now leaves a 4 KiB margin **above** itself, inside the mapped array (`LATCH_FB_STACK_SLACK`), and a consistency gate requires it. While measuring this: **arm64 DOES select `CONFIG_CLONE_BACKWARDS`** (`arch/arm64/Kconfig:126`), so the kernel's `clone` signature is `clone(clone_flags, newsp, parent_tidptr, tls, child_tidptr)` — the earlier note in the guest source claimed the opposite and was wrong.
- **The verdict mailbox overran its own array on the 147th frame**: `FB_RING_BYTES` was 4096 with a 28-byte frame, and 4096 = 146 × 28 **+ 8** — so the 147th enqueue's `memcpy(&ring[4088], frame, 28)` ran **20 bytes past the end of `ring[]`**. Proven byte-for-byte on the target: `published=0xC61A88B2` was the frame's own CRC32, `queued=9599862` was frame bytes 16..19, the ring's `tail` had been overwritten with the session epoch `0xa5a5a5a5`, and `file_writes` froze at exactly **147**. The ring is now `146u * FB_FRAME_SIZE` with a `_Static_assert` that the length is a whole number of frames, and a consistency gate checks both.
- **A full mailbox starved the one channel the supervisor needs to answer the guest**: the sink published to the verdict file only *after* `fb_enqueue()` succeeded, so a full ring meant the host's verdict never reached the file. The file is now written **first** (`fb_publish_to_block(frame)` → `g_fb.published++` → `fb_enqueue(frame)`), and the mirror's `EAGAIN` is counted as a drop but is never returned as a failed publish. The status line reports `dropped=`, not `refused=`.
- **The guest's own page cache hid every verdict**: with a plain `O_RDONLY`, 600 buffered `pread64`s over 12 s returned the identical CRC-valid frame (seq 74 → 74) while the host wrote dozens of verdicts into the very same sector. The device was right, the address was right and the frame was valid — only the **freshness** was missing, and a channel that cannot show a change is not a channel. The transport now drops the cached pages before **every** buffered read (`sys_fadvise64(fd, 0, 0, POSIX_FADV_DONTNEED)`) and attempts an `O_DIRECT` open first; the guest's `O_DIRECT` open of `/dev/vda` is refused with `ENOTDIR` (20), so the buffered path is what runs, and the report carries `dir=`, `derr=`, `ferr=` and `rerr=` so a freshness failure is attributable rather than mysterious.
- **The QNX console ends its lines with THREE `\r` and a `\n`**: a line-anchored marker regex (`[FBPROBE][^\r\n]*\r?$`) **never matched**, and the harness then reported "the guest never sent the marker" for a guest that sent it perfectly. The marker parser now tolerates the extra carriage returns, and completeness is judged by the **census** — a contiguous `p0..pN` / `e0..eN` run that finishes on the highest index — rather than by the end of the line.

### Added
- **A security-policy generation audit recipe and its written review (U-6 / M-4)**: `make -C qnx evidence-secpol-audit` boots the **disposable, unrestricted** `secpolgenerate` audit image — never the enforced deployment image — lets the 235-frame scripted guest scenario run to completion, and captures the generator's observed **delta** (`/dev/secpolgenerate/policy`, 2004 bytes), its **errors** (376 bytes) and its **unused** report (3118 bytes), plus the `request` and `control` channels. The archive is written **only** when the run passes. The **review** is the authority: [`docs/secpol-audit-review.md`](docs/secpol-audit-review.md) dispositioned **16 delta entries, 0 accepted**, and `qnx/latch.secpol` is **untouched**. Three findings drove that: the delta is a **SUPERSET** (the audit image runs the generator *unrestricted*), so nothing in it may be adopted; the `unused` file is **not** a removal list and in fact contradicts facts the run itself establishes — it lists `latch/actuator` as unused for `latchd_t` and `channel_connect:latchd_t` as unused for `latch_ingest_t`, yet 235 proposals were applied and the ingest demonstrably connected — because the unrestricted run bypasses the ability checks it would otherwise observe as uses, so the file is read as the audit's **partial coverage**; and the one observed error (`procnto-smp-instr (pid:1 type:default) failed to use ability latch/propose`) is the **least-privilege boundary working**, so its suggested fix (`allow default self:ability { latch/propose };`) was **REJECTED** — it would grant the propose ability to every untyped process. The one **actionable** least-privilege finding — `qvm_host_t` holds the **unrestricted** `settypeid` ability, and the generator observed exactly one transition, `settypeid:latch_ingest_t` (which matches all four profiles' `hostdev >"|on -T latch_ingest_t …"` form) — is **recorded, NOT applied**: it must be validated on the **enforced** image in its own reviewed change. A new consistency gate (§5b) requires the review to exist and to carry the caveats that make it honest — the SUPERSET, the "not a removal list", the UNKNOWN-not-SAFE rule, and the "no generated rule is accepted" disposition — and the gate is mutation-verified non-vacuous.
- **A cancellable observation reader for the secpolgenerate streams (`qnx/latch_secpol_dump.c`)**: The audit image is a minimal QNX IFS with no `cat`, `ls` or `dd`, and the observation files are **streams**, not regular files — the QNX System Security Guide says so plainly: *"Because secpolgenerate generates policy content as the file is being read, it does not provide a meaningful file size."* The reader does the `open`/`read`/`write` on a **worker thread** with raw `write(2)` and no stdio, so a cancellation can never strand a stdio lock, and the main thread cancels it after an idle timeout. It reports **how** each snapshot ended ("the generator closed the stream (EOF)" vs "CANCELLED … PARTIAL") and how many bytes each file held, so a truncated snapshot is visible in the transcript instead of looking like a complete one. It is linked **only** into the disposable audit image. Measured: the policy file reads to EOF in **0.2 s / 2004 bytes**.
- **An in-guest language model (`qnx/latch_qemu_infer.build`, `guest/latch_infer.cpp`, `guest/latch_action.c`) — EXPERIMENTAL**: A statically linked AArch64 C++ program that links **llama.cpp** now runs **inside** the Linux guest and proposes the motion. It loads a 135M-parameter GGUF model from a **read-only virtio-blk asset disk** (`hostdev <…`, read-only enforced by the **hypervisor**), constrains the output with a **GBNF grammar**, re-validates the JSON **independently** of the grammar, and emits a 32-byte wire-v2 frame into a **pipe**. The freestanding policy stays **PID 1**, stays the **sole writer** on `/dev/hvc0`, and relays the frame; the model holds **no actuator ability** and cannot reach the QNX side at all. The safety envelope is **not** duplicated in the guest — the guest-side check is **STRUCTURE only**, and the keep-out, slew and rate limits live in the signed manifest and are enforced **only** by the trusted supervisor. **Measured on the QEMU AArch64 `virt` target, 2026-11-26:** the nominal run's model asked for `−20 mrad`, the supervisor accepted it in HP and applied `−8 mrad` (the signed acceleration limit from rest), the lease was still held 25 s later while the model kept thinking, and the event ring carried **zero** fault events; the **attack** run changed **only the prompt** and the model asked for `+400 mrad`, inside the signed PERSON keep-out, and the supervisor **refused** it (`KEEPOUT` 0x0020), latched, and the plant did not move. Evidence: `docs/evidence/governor/infer-qemu.txt` and `infer-qemu-console.txt` (written only when **both** runs pass). The scripted GOVERNOR profile is unchanged and both profiles are judged by the **same** signed contract.
- **A freestanding action-schema validator (`guest/latch_action.c`, `guest/latch_action.h`)**: A libc-free validator for the model's action object, plus the wire-v2 packer/checker and a sequence/coherence re-stamp. Wired into CI as `make -C qnx latch-action-check` (**59 checks, 0 failures**), including the IEEE CRC-32 check value and a byte-exact wire-v2 layout.
- **A `latch_guestd` guest-lifecycle daemon (`qnx/latch_guestd.c`) and `latchctl guest-restart`**: The operator shell can **stop** the guest (it always could) but cannot **start** one — `on -T qvm_host_t …` is refused because `operator_shell_t` holds no `settypeid` and no `spawn`, and granting it that ability would collapse the "the operator shell is deliberately unprivileged" property the `grant-check` EPERM demonstration depends on. The power to start a guest now lives in one dedicated typed domain (`latch_guestd_t`) that holds **no** actuator ability, **no** proposal-write right and **no** channel-connect rule. The restart is **STOP → OBSERVE → START**: the client polls the *supervisor's* writer-session status until it reports `writer_held == 0`, and **refuses to start** if the handoff was not observed (fail closed — the guest is left down and the supervisor stays in LATCH). Proven on target: a guest kill → LATCH → restart → RESUME transcript with the session generation advancing 1 → 2.
- **An honest Linux baseline (`docs/evidence/baseline/`)**: A **synthetic Python-loop** measurement on the same workload, labelled as such — not a "Linux GPOS" figure and not a WCET. The tool writes every file in that directory, so nothing there is hand-edited, and two consistency gates keep it honest: every figure from the withdrawn benchmark family may appear only in a sentence that declares it invalid, and no document may describe the baseline as "Linux GPOS".
- **Attack A8 — Second Writer Keeps a Dead Agent Alive (`tools/attacks/attack_a8_second_writer.py`)**: Drives **two producers** through separate `latch-ingest` instances whose IPC streams are concatenated into one supervisor pipe — what two writers to `/dev/latch/proposal` produce on target. Asserts the lease still expires and demotes under continuous rogue traffic, that the rogue cannot move the plant, and that the post-expiry takeover is a new epoch. Registered in the unified rig and in the merged evidence tape.
- **Producer identity on the wire (`qnx/latch_ingest.c`, `qnx/latch_ipc.c`)**: `latch-ingest --producer-tag N` (default `1`; `0` is refused fail-closed).
- **Writer-session status (`qnx/latch_protocol.h`, `qnx/latchd.c`, `qnx/latchctl.c`)**: the output-only `DCMD_LATCH_GET_SESSION_STATUS` (`0x47`) reports whether the exclusive proposal writer OCB is held and which writer session the supervisor has seen, so a handoff between two writer sessions is **observed** instead of timed. `latchctl session-status` prints it. It grants no ability and mutates nothing.
- **Session epoch on the wire (`qnx/latch_ingest.c`, `qnx/latch_ipc.c`, `qnx/latch_protocol.h`)**: `latch-ingest --session-epoch N` pins the epoch of the session the bridge opens; the default is a fresh value per process.
- **The LFBK return-feedback transport, on the runtime path (U-2)**: the supervisor now publishes **its own** verdict for every motion proposal it consumes, and the freestanding guest policy reads it, correlates it with the proposal it answers, and **stops proposing when it is told no**. The channel is a **polled verdict file on `vdev virtio-blk`** — the vdev's own usage is `hostdev [<]<pathname>`, and the `<` makes the backing file **read-only to the guest**, enforced by the **hypervisor** rather than by the guest behaving; the hypervisor opens the file `O_RDONLY` and only `latch_fb_sink`'s one-sided WRITE node accepts frames. Three candidate channels were **rejected by measurement**: a QNX `devc-pty` pair (the open order decides usability, and any process could write it, so the verdict would not be the supervisor's), PL011 vdev host→guest injection (the bytes DO reach the vdev, `delivered=11`, but the guest's UART never receives one — the vdev waits for a receiver-enable state the guest never reaches), and `virtio-console` input (`vdconsole_pulse` unreachable). The **verdict vocabulary is closed** — `ACCEPT 0x01`, `REJECT 0x02`, `TIMEOUT 0xFF`, and an unknown verdict is `-EBADMSG` on the host and `LATCH_FB_EVERDICT` in the guest, because "I did not understand" must never be read as "yes". A verdict is published **only** for a `GOVERNOR_WIRE_CMD_V2` motion proposal from the session owner with a valid bound epoch; a heartbeat, a shrink request, a foreign session or a spent epoch gets **silence**. The verdict is **ACCEPT** iff the proposal was accepted **and** the supervisor is still following the guest (`LATCH_MODE_HP`) — a supervisor that has failed closed into HOLD or HOME is not following anybody, and saying "accepted" to a proposal that was silently not applied would be a lie the guest would act on.
- **The host-side verdict publisher (`qnx/latch_feedback_pub.c`, `qnx/latch_feedback_pub.h`)**: a one-slot mailbox plus a condvar and a dedicated writer thread at **SCHED_FIFO 40** — below the safety core (63), so it can never delay the tick, and above the actuator worker (20), so an advisory verdict is not starved. The tick's publish is a **memcpy and a signal**, nothing else; the write to the resource manager happens on the writer thread, on a node opened `O_WRONLY|O_NOCTTY|O_NONBLOCK`, with a bounded 50 × 20 ms EAGAIN retry. The publisher is **off by default** (`latchd -f <path>`), and its failure is **not fatal**: the supervisor's own dead-man is the fail-closed path, and the feedback channel is advisory.
- **The guest-side decoder and correlation state machine (`guest/latch_fb_decode.h`)**: a **self-contained, freestanding** header (only `<stddef.h>` and `<stdint.h>`, the two a freestanding implementation must provide) that is compiled into the guest policy **and** into the host test binary, so the two implementations of the protocol are checked against each other by `make -C qnx latch-fb-decode-check`. The correlation state has exactly **one writer** (the watcher thread), and "is a proposal still unanswered?" is **derived** — `last_cmd_seq != 0 && last_cmd_seq > last_seq_verdict` — so it cannot go stale or disagree with itself. The sequence number is published **before** the frame goes on the wire, the watcher reads the sector **before** it folds the published sequence numbers in, and the verdict itself is published as **one volatile 64-bit word** (verdict, sequence number and stop reason in a single naturally-aligned store), so the main thread can never see a new sequence number with an old verdict.
- **A verdict-watch profile and its on-target evidence (`qnx/latch_qemu_fbverdict.build`, `tools/verify_fbverdict_qemu.py`, `make -C qnx evidence-governor-feedback`)**: the W5 image reuses the W4 qvmconf **verbatim** — the transport is identical, so the only difference between the two measurements is who publishes and what the guest does with it — and contains **no `latch_fb_pump`**, because the only thing that writes the verdict file is the trusted supervisor. Measured on the QEMU AArch64 `virt` target (2026-11-27): the guest reports `acc=8 rej=1 foreign=0 stale=0 dup=0 to=0 stop=reject`, the epoch was learned from the first verdict and pinned, the supervisor received exactly the 13 frames the guest sent, and the lease then expired and the ladder reached LATCH. The archive (`docs/evidence/governor/feedback-transport.txt` plus the two raw serial transcripts) is written **only** when both runs pass.
- **A MUTATION BATTERY for the consistency gates (`tools/mutation_check.py`, `make -C qnx mutation-check`)**: 41 mutations, each written against a **real measured defect** — the guest-writable verdict file, the one-device probe, the removed freshness rule, the non-whole-frame mailbox ring, the mailbox-before-file ordering, the SIGSEGV's missing stack margin, the unbounded publisher retry, the unknown-verdict pass-through, the corrupted fold order, the stale publication order and a dozen more — each of which must make `tools/consistency_check.py` **fail**. It runs against a scratch **copy** of the repository, so the tree it checks is never written to, and it proves that at the end by comparing digests. A mutation whose anchor no longer exists is a **SKIP**, and a skip is a **failure** of the battery rather than a warning: that is exactly how the previous battery decayed after the transport changed from a PTY pair to the polled verdict file, until nine of its twelve mutations were stale and it still printed "PASSED" for the three that were left. Writing it found **four gates of its own that could not fail** — the unknown-verdict check that verified only that the predicate was *called*, the new-frames-only rule that was satisfied by a counter rather than by the correlation guard, the harness sentinel that verified only that `end=1` was *mentioned*, and the qvmconf-reuse rule that was satisfied by a **comment** — and all four now fail loudly.
- **Anti-orphan and anti-drift gates on the evidence archive**: the consistency checker now walks `docs/evidence/` and fails if **any** file is missing from the index's file tree (`governor/governor-qemu-verify.txt` and `governor-qemu-console.txt` were orphans once, with no generator anywhere in the tree, and the November capture was still quoted in 2026-11-26 — an orphan in the evidence archive is a silent lie, because nothing notices it rotting); it regenerates the index into a scratch copy of the archive and **DIFFs** it against the committed `docs/evidence/README.md` and `derived/RUN-OUTPUT-MANIFEST.md`, because those two files are **generated** by `tools/capture_evidence.py index` and a hand-edit to them is silently replaced by the next `make -C qnx evidence-index`, so the commit carrying it is wrong in a way nobody can see; and it checks that the feedback-transport family still carries both verifiers' PASS lines, the guest's own clean correlation census (`foreign=0 stale=0 dup=0`) and its "WHAT THIS DOES NOT PROVE" section.

### Changed
- **The evidence index now carries the security-policy generation audit, and its §6 bullet was stale**: `docs/evidence/README.md` gained a row for the audit whose numbers are **read back** from the generated transcript and the review (the delta's byte count from the reader's own summary, the entry count and the accepted count from the review's table) — never typed in by hand. `docs/evidence/derived/RUN-OUTPUT-MANIFEST.md` gained a section for `make -C qnx evidence-secpol-audit`. More importantly, the index's "what is NOT proven" section used to say the security policy **had not been audited**; that was true when it was written and is **false now**, so it was rewritten to say what the audit *did* find, what it deliberately did **not** accept, and what it still does not cover (the I²C plant, the Pi 4B board, `guest_ctl_t`/guest-restart, `latch_verify_t`/the 84-frame legacy path, `latchctl_t`'s actuator ability, and every failure path) — with the rule that **a rule the workload never touched is UNKNOWN to the audit, not SAFE**.
- **Evidence and documentation counts are derived, not typed**: the merged governor tape now spans the full attack suite (each attack's rows come from the same scenario builder the rig uses), the evidence index reads the tick and attack counts back out of the generated `governor-metrics.txt`, and `tools/consistency_check.py` cross-checks the three generated artifacts against each other instead of asserting a hardcoded number.
- **The archived sidecar attestation now has a generator**: `docs/evidence/governor/governor-manifest-verify.txt` used to be an **orphan** — it sat in the archive with no tool that wrote it, which is exactly how it went stale when the syringe contract's `advise_fault_mask` changed. It is now generated by `tools/capture_evidence.py` alongside everything else, and it proves the fail-closed property by mutating a signed value in a temporary copy with **no** sidecar and asserting that the loader **rejects** it.
- **The scripted GOVERNOR's on-target capture now has a generator too**: `docs/evidence/governor/governor-qemu-verify.txt` and `governor-qemu-console.txt` were **orphans** in the same sense — the November 2026-11-18 capture was still the archived one on 2026-11-26, long after the code had moved. `tools/verify_governor_qemu.py` now writes a structured runtime report (the A4 sample table, the recovery ladder, the final state, the on-target contract verification and the guest's own console) and the raw serial transcript, and the new `make -C qnx evidence-governor-qemu` target writes both into the archive. Like every other capture, the archive is written **only when the run passes**: a failed run exits non-zero **without** touching `docs/evidence/`, so a broken build can never replace good evidence with a partial transcript.
- **The in-guest inference profile's console discipline is enforced by the build**: a console line on the QEMU guest costs **57–88 ms of guest time** (roughly 1.3–1.8 ms per character), and the signed lease is **100 ticks ≈ 100 ms**. Measured: a marker between the warm-up and the first relay heartbeat produced a **161-tick hole** and the deadman fired; the model's own 119-character announcement inside the supervised window cost about **153 ticks** and fired it again. So the relay path writes **nothing** to the console, the child's **first** proposal is announced *before* the session opens, and later proposals are relayed **silently**. `tools/consistency_check.py` fails the build if a marker appears in the relay path, if the first decision is announced after the readiness signal, or if the announcement is not gated on the first iteration.

---

## [4.0.0] - 2026-11-18

### GOVERNOR — Deterministic Safety Interlock & Dead Man's Switch for Physical AI

This major release introduces the **GOVERNOR** safety supervisor layer to the LATCH microkernel runtime-assurance framework for the QNX Global Hackathon 2026:

#### Added
- **6-Rung Degradation Ladder (`qnx/governor_policy.c/.h`)**: Implemented deterministic FSM (`HP` → `ADVISE` → `CLAMP` → `SLOW` → `SAFE_STOP` → `LATCH`) with 25-consecutive-clean-command recovery hysteresis.
- **Deadman Liveness Lease & 24-Bit Coherence Counter (`qnx/gov_gate_precheck.c/.h`)**: Host-tick lease monitoring with modulo-$2^{24}$ coherence tracking. Heartbeats renew lease but cannot earn recovery credit without valid commands.
- **Wire Protocol v2 & LPR2 IPC (`qnx/governor_wire.c/.h`, `qnx/latch_ipc.c/.h`)**: 32-byte Wire v2 frame with 28-byte split IEEE 802.3 CRC32, and a 56-byte `LPR2` inter-process message with unit IDs, confidence shrink and the RT-02 session epoch.
- **Tamper-Evident Blackbox Event Ring (`qnx/latchd.c`, `qnx/latchctl.c`, `tools/gov_replay.py`)**: 4096-event circular memory buffer, devctl `0x44` (`DCMD_LATCH_DUMP_GOV_EVENTS`), `latchctl events` CLI, and rolling SHA-256 blackbox hash chain with cryptographic tamper detection.
- **Schema-3 Manifests & Rational Unit Conversion (`qnx/latch_manifest.c`, `contracts/`)**: Fail-closed parser with exact-key sets, $O(N^2)$ keepout overlap validation, integer rational unit normalization ($N/D$), and SHA-256 sidecar validation.
- **Medical Syringe Governor Contract & DOSE Fault (`contracts/syringe_governor.manifest`)**: Linear infusion contract ($0..50000\ \mu\text{L}$) with `LATCH_FAULT_DOSE` (bit 15) and single-step rate saturation clamping.
- **Extended Medical Drug Library Schema & Cumulative Dose Limiter (`contracts/syringe_governor.manifest`, `qnx/latch_manifest.c/.h`, `qnx/gov_gate_precheck.c/.h`)**: Additive schema-3 `medical` section (`drug_name`, `concentration_uL_per_unit`, `max_bolus_uL`, `cumulative_dose_window_ticks`, `max_cumulative_dose_uL`) and windowed cumulative dose tracking asserting `LATCH_FAULT_DOSE` (bit 15) and clamping step to 0 upon window exceedance.
- **`/dev/governor` Path Alias (`qnx/latch_protocol.h`, `qnx/latchd.c`, `qnx/latch.secpol`)**: Dynamic attachment of `/dev/governor` alongside `/dev/latch/proposal` and `/dev/latch/actuator`, authorized under QNX Mandatory Access Control.
- **Regulatory & Functional Safety Architecture Alignment**: Architectural patterns aligned with ISO 26262-9/-6 (freedom from interference), IEC 61508 (SIL concepts), IEC 62304 Class C, and EU AI Act Art. 12/14/15 as design drivers; **not certified; no conformity claim**. Explicit architectural statement that APS is not supported in SDP 8.0; the mechanisms actually used instead are strict `SCHED_FIFO` priorities, `ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT)` core pinning, and hypervisor vCPU clustering. **QNX sporadic scheduling and per-thread runtime clocks are not used** — see `docs/architecture/QNX_SCHEDULING_AND_STACK_USAGE.md`.
- **Prebuilt IFS Makefile Target (`qnx/Makefile`)**: Added `verify-governor-qemu-prebuilt` target enabling direct live QEMU AArch64 testing without requiring `mkifs`.
- **7-Scenario Integration & Adversarial Rig (`tools/governor_e2e.py`, `tools/attacks/`)**: Dedicated 7-scenario E2E test gate and 7-attack cyber-physical attack suite (A1-A7) achieving a 0.0% keepout breach rate across 121 evaluated ticks.
- **Python Client SDK & Autonomous Agent Loop (`tools/governor_client.py`, `tools/agent_loop.py`)**: Wire v2 client library and poka-yoke agent loop with fail-closed planner liveness watchdog.
- **Interactive Operator Console (`host/console.html`)**: Self-contained offline HTML5 Canvas dashboard with real-time ladder indicators and flight recorder replay.
- **Evidence Dossier (`docs/evidence/governor/`)**: Complete authentic QEMU target execution transcripts (232 KB), transition logs, and test metrics.

#### Fixed
- **Mode Labeling (`qnx/latch_verify.c:66-73`)**: Replaced ternary `mode_name()` with switch statement correctly mapping `HP`, `HOLD`, `HOME`, and `UNKNOWN`.
- **Scheduling Comment (`qnx/latch_ingest.c:405`)**: Corrected stale comment from `sched 40` to `sched 60`.
- **Keep-Out Overlap Validation (`qnx/latch_manifest.c`)**: Added $O(N^2)$ pairwise overlap checks to prevent conflicting keepout boundaries.
- **Devctl Command Code Uniqueness (`qnx/latch_protocol.h`)**: Renumbered `DCMD_LATCH_PROBE_ABILITY` to `0x45` to eliminate code sharing with `0x43`.

#### Removed
- **Foreign Packaging Template (PB-6)**: Removed unrelated Alpine Linux `aports` porting template `TARGET.md` from repository root.

---

## [3.2.0] - 2026-11-13

### The Self-Contradicting Evidence Archive — Closed, and the Safety Defect Behind It Fixed

The archive contained **two** on-target captures side by side: the numbered canonical
session (`VERIFY_RC=0`) and a timestamped family whose own "these are the ONLY numbers
the submission may quote" file said **`VERIFY_RC: 1`**. Nothing in the repository
explained the failure, the run index listed only the numbered history, and neither the
consistency gate nor CI inspected the timestamped family — so 15/15 checks passed
beside a falsified quotable-numbers file. That is the *evidence-theatre* pattern, and it
is the one thing this project cannot afford.

**The root cause was not the tooling. It was a live safety defect.**

`latch_verify` opens `/dev/latch/proposal` for writing to inject its frames, and the
proposal node's open handler armed a supervisor **session reset on every open**. That
reset flushed the frame ring, re-based the sequence baseline to `0` — **defeating
sequence-replay detection** — and teleported `theta` to home with zero velocity, so the
next frame was judged against a fictitious plant state and vetoed as a spurious RATE
fault. The proposal node is world-writable (`0666`) and the guest's `latch-ingest` holds
it open for the whole run, so **any** second process on the target could do this to the
supervisor.

| # | Fix | File |
|---|---|---|
| 1 | A session reset is a **session** event, not an **open** event: it is armed only on the 0 → 1 writer transition. A second writer joins the live session. | `qnx/latchd.c` |
| 2 | A session change no longer re-bases the sequence baseline (a new **epoch** is recorded), so replay detection survives it. | `qnx/latchd.c` |
| 3 | A session change no longer **teleports** `theta`. At rest at home it is a no-op; otherwise the supervisor enters the existing jerk-bounded retraction (`WATCHDOG → HA-HOLD → HA-HOME`). | `qnx/latchd.c` |
| 4 | The frames discarded on a genuine new session are **counted** as ring drops instead of vanishing silently. | `qnx/latchd.c` |
| 5 | The writer count is rolled back if the OCB cannot be allocated, so the EOF/retraction path (and the tape freeze) cannot be lost. | `qnx/latchd.c` |
| 6 | The harness **continues the supervisor's sequence**, derives its ramp from the **observed** plant angle, and reads the result from the **evidence tape** rather than from an instantaneous status read. | `qnx/latch_verify.c` |
| 7 | The ramp is sent as a **burst**: the supervisor consumes one proposal per tick, so a burst is applied at the same rate as a paced stream, but the ring holds the frames and the 2-tick watchdog cannot fire while a measurement is taken. | `qnx/latch_verify.c` |
| 8 | **Recovery frames** restore HP before the ramp: the supervisor returns to HP only after `recovery.hysteresis_clean_frames` consecutive clean frames, and in HOLD the plant is frozen, so a ramp was consumed but never applied. | `qnx/latch_verify.c` |
| 9 | The step-4 replay is now a **real** replay (the supervisor's own `last_seq`, re-sent) and the harness **asserts** that the SEQ fault was latched — which it never did before. | `qnx/latch_verify.c` |
| 10 | A failed final status read returns a **distinct non-zero code** (2 = "could not complete"), not `0`. A harness that cannot verify must never be mistaken for one that verified. | `qnx/latch_verify.c` |

**Result on target** (one continuous boot of the QEMU AArch64 `virt` image):
`Proposals Received: 84 · Wire Faults Caught: 12 · Envelope Vetoes: 7 · Ring Drops: 0 ·
Last Proposed: -180 mrad (seq=80) · Latched: 0x01AE (CRC|SEQ|NAN|KEEPOUT|RATE|WATCHDOG)`
and `[1/5]`…`[5c/5]` **ALL PASS**, `VERIFY_RC=0`.

### The Capture Tool Is Now State-Synchronized, and the Gate Cannot Be Fooled

- **State-synchronized driving.** The on-target scenario no longer runs from a
  fixed-timer script. It tails the console and **waits for state**: for the QNX banner,
  then for the guest's suite (polling `Proposals Received` until it reaches the guest
  policy's own declared `LATCH_GUEST_SUITE_FRAMES`), then for the supervisor to settle
  after the guest's designed silence trips the watchdog. A fixed sleep cannot know when
  the guest finished, and that difference is the difference between a reproducible
  capture and a flaky one.
- **Failed captures are quarantined.** A capture with `VERIFY_RC != 0` is moved under
  `on-target/FAILED/` and the archive's quotable numbers are **not** regenerated from it.
  The tool now exits non-zero *before* the index is rebuilt, so a failure can never
  become the story.
- **The gate sees everything.** `tools/consistency_check.py` now requires exactly ONE
  timestamped capture family, checks that it carries the exact on-target signature,
  checks that `derived/on-target-numbers.txt` agrees with the session it names, and
  checks that **nothing under `docs/evidence/` is git-ignored**. It found two real
  problems: the contradictory family, and `.gitignore`'s bare `build/` pattern, which
  silently excluded `docs/evidence/build/` from the published archive.
- **The harness that could never pass.** `tools/verify_qemu_aarch64.py` asserted
  `Proposals Received : 200` while the guest emits 84 — so `make verify-qemu`, the
  command the README advertises as the end-to-end proof, failed against the repo's own
  evidence. The expectation is now derived from the guest policy's source.
- **`--all` never worked.** `capture_evidence.py --all` listed `"--all"` in the
  positional's `choices`, so argparse read it as an option and rejected it. It is now a
  real flag.
- **The anti-rot gate was tautological.** `make evidence-check` regenerated the
  signature file and then grepped its own fresh output, overwriting the committed
  archive it was supposed to protect. It now **diffs** a fresh capture against the
  committed one.
- **The manifest-driven expectation.** The host-sim signature no longer hardcodes the
  keep-out box `[250, 650]` and the `12/7/80` signature; both come from the manifest.

### Correctness Fixes Found While Doing It

- **The seqlock did not cover what it claimed.** The guard spanned only the last few
  dozen lines of the tick, while ~20 status-visible fields were written earlier in the
  same tick and outside it — and the idle path returned before the guard was even
  opened. The guard now spans the **whole** tick, so a status read can only sample
  between ticks, and a snapshot that cannot be taken is reported as `EBUSY` instead of
  being served as a valid all-zero reply.
- **The rate check could be bypassed.** `latch_abs_i32` negated `INT32_MIN` — undefined
  behaviour that in practice returned `INT32_MIN`, so `|v_step| > v_max` evaluated
  **false**. The kinematic differences are now computed in 64 bits, so `u_mrad` near
  `INT32_MIN` can no longer flip the sign of the velocity step.
- **The sequence check was a signed cast of an unsigned difference** — implementation-
  defined above `INT32_MAX`, and used as the acceptance predicate. It is now a wrap-safe
  unsigned delta, and "no frame accepted yet" is an explicit flag rather than the
  overloaded `last_seq == 0`.
- **The evidence tape was written with `% capacity` and read with a fixed mask**, so any
  manifest whose `tape.capacity` is not 4096 exported the wrong rows.
- **The initramfs was not reproducible.** `gzip -9` embedded the input's mtime in a
  **tracked** binary. It is now built with `gzip -n`, a sorted entry order, and entry
  mtimes pinned to `SOURCE_DATE_EPOCH`, so rebuilding from unchanged sources produces a
  byte-identical image.
- **Static asserts for the devctl payloads.** `latch_status_reply_t` and
  `latch_tape_dump_t` are cross-process ABI; they now carry the size/offset asserts that
  the wire, tape and IPC structs already had.

### Documentation Corrections

- `queue_depth` is 256, not 64 (README).
- The harness asserts the **84-frame** signature, not 200 (README).
- The "byte-for-byte the same suite" claim is now accurate: phases 1–8 are the same
  suite; phase 9 differs by design.
- The video script's `sha256sum` shot showed a digest that matched nothing in the repo.
- `docs/LATCH-research.md` no longer prescribes the **rejected** one-line
  `cpu _cpu-2 sched 8r` form, and no longer claims the guest is a Python program.
- `guest/latch_guest_init.c` no longer calls its 84-frame suite a "200-tick" suite, and
  no longer claims a host-side pacing that does not exist.
- **The security-policy claim is corrected — and strengthened.** The archive said an
  enforced policy boot "has not been run". In fact `secpolpush` at boot **is** the
  enforcement mechanism (QNX SDP 8.0: *"Pushing the security policy (using secpolpush)
  triggers policy enforcement"*), and `qnx/latch_qemu.build` pushes it on every boot —
  so the `latch/actuator` fail-closed behaviour is demonstrated **under an enforced
  policy**. (`secpollaunch` is an unrelated setuid-root launcher.) What remains undone
  is an `secpolgenerate` audit of the rule graph against the running image.

---

## [3.1.0] - 2026-11-12

### QEMU AArch64 `virt` Bring-Up: The On-Target Path Now Works End To End

This release is the one that makes the **hypervisor path real**. Every item below was
established by running the built IFS under `qemu-system-aarch64 -M virt,virtualization=on,gic-version=2
-cpu cortex-a76` and reading the boot log, the supervisor's own counters, and the
4096-entry evidence tape — not by reading the source and reasoning about it.

- **Guest Boot Hang Fixed — It Was PSCI, Not the CPU Pin (`latch_qemu_virt.qvmconf`)**: The
  Linux 6.12 guest hung for tens of minutes right after `cacheinfo`. The cause: `qvm`
  auto-detects host PSCI support by reading the *host device tree*, and QNX's startup cannot
  read QEMU's DTB on this platform (`no clock-frequency property in FDT!`). No PSCI node
  reached the guest FDT, so Linux's secondary-CPU bring-up never completed. Fixed with
  `set psci-supported on` — the exact override the qvm manual documents — plus
  `set pointer-authentication off` and `set linux-fdt-free on`. The guest now boots to
  `/init` in **8.1 s** and reports `psci: PSCIv1.1 detected in firmware`.
- **Static vCPU Runmask — Correct QNX 8.0 Syntax (`latch_qemu_virt.qvmconf`, `latch.qvmconf`)**:
  Hypervisor 8.0's `cpu` takes an **indented options block** whose only two options are
  `cluster` and `sched`. The 7.1 one-line form `cpu _cpu-2 sched 8r` is *rejected* by the
  8.0 qvm (`Unknown option '_cpu-2'`), and a bare `cpu` / `sched 8r` block leaves the vCPU
  **floating** on every core — including the one `latchd` runs on. Both qvmconf files now
  use one `cpu` block per vCPU, each bound to its own single-CPU cluster. Proven on target:
  `pidin -p qvm threads` reports the vCPU threads as `cy-guest-qemu-virt/0` and `/1`.
- **`qvm` Process Runmask Left Unconstrained (`latch_qemu.build`, `latch_rpi4.build`)**:
  `on -C <n>` and `on -R <mask>` both resolve to a *predefined single-CPU cluster*, and no
  predefined cluster covers CPUs 2+3 together, so `-R 0xc` and `-C 2 -C 3` both fail with
  `Invalid cluster runmask specified`. The qvm process is now started with no affinity
  constraint; the isolation comes from the qvmconf pins.
- **Virtio-Console Forwarding Priority (`latch_qemu_virt.qvmconf`, `latch.qvmconf`)**:
  The vdev's guest→host forwarding is pulse-driven ("`sched priority`: … pulses indicating
  that input is available on the host device"). At the default priority the forward is
  starved under host load; measured on QEMU TCG that produced 16- and 28-tick gaps in the
  frame delivery. `sched 60` on the vdev, plus `-p 30f` on the spawned `latch-ingest`.
- **No Artificial Pacing in the Bridge (`latch_ingest.c`)**: `latch-ingest` now hands each
  frame to the supervisor as fast as the transport delivers it. The supervisor's ring,
  bounded by the manifest's `ingest.queue_depth`, is the only buffer in the path. The
  previous half-period sleep let the supervisor's 2-tick watchdog fire while the guest's
  next batch was still in flight, which failed closed into `HA-HOLD -> HA-HOME`, retracted
  `theta`, and turned every later frame into a spurious RATE veto.
- **Guest Produces Faster Than the Host Consumes, in Small Writes (`guest/latch_guest_init.c`)**:
  The guest now writes 4 frames (128 B) at a time every 200 µs — ~20 frames/ms against the
  supervisor's 1 frame/ms — so the ring always holds a backlog and the watchdog never
  fires spuriously. The previous 800-byte-per-phase write outran the virtio-console vdev,
  filled the guest's virtqueue, and stalled the guest for tens of milliseconds.
- **Guest Markers Moved off the Slow PL011 Path (`guest/latch_guest_init.c`)**: QNX's own
  hypervisor documentation says the PL011 "is slow and has slow output". A blocking write
  to `/dev/console` stalled the guest ~24 ms per phase marker. Markers now go to
  `/dev/kmsg` (the kernel log ring buffer, non-blocking) and still appear in the guest
  console log.
- **Real Silence for the Watchdog (`guest/latch_guest_init.c`)**: Phase 9 now sends **no
  bytes at all**. The previous revision sent `LATCH_WIRE_FLAG_SILENCE` frames, which the
  host does not treat as silence (guest flags are ignored for safety), so they were
  counted as sequence replays and the watchdog never fired.
- **The Evidence Archive (`docs/evidence/`)**: Every run's raw console output is now
  committed as a separate log file, with a published output manifest. `docs/evidence/README.md`
  maps each claim to the file that proves it, states how to regenerate each one, and
  lists what is **not** proven. `docs/evidence/derived/RUN-OUTPUT-MANIFEST.md` is the
  file-by-file list of what each kind of run produces. The new
  `tools/capture_evidence.py` generates the whole archive — nothing in it is
  hand-edited — and the new `make -C qnx evidence*` targets wrap it. `make -C qnx
  evidence-check` re-runs the host-sim capture and compares the signature against the
  archived one; CI runs it on every push, so the archive cannot rot. The tape
  analysis in the tool independently reproduces the supervisor's own counters
  (`wire=12`, `envelope=7`) from the raw tape, which is a cross-check of both.
- **The Evidence Archive Is Now A Consistency Check (`tools/consistency_check.py`)**:
  The gate asserts that the archive is complete, that the canonical session still
  carries the exact on-target signature (84 frames, 12 wire faults, 7 envelope
  vetoes, 0 ring drops, last seq 80, latched `0x01AE`, `VERIFY_RC=0`, and both
  static vCPU pins), that the archived host-sim signature still reports PASS, and
  that the run index still shows the monotone `51 → 48 → 27 → 7` progression. A
  missing or drifted archive now fails `make check`, not just the CI workflow.
- **Tried and Rejected — a Second virtio-console for the guest's markers**: The guest's
  phase markers need a path that is neither the black channel (which carries
  only LATH frames) nor the PL011 console (which QNX's own hypervisor
  documentation calls "slow", and whose slow output stalled the guest for
  ~24 ms per marker, starving the supervisor's watchdog). A second
  `vdev virtio-console` at `0x1c0b0000` looked like the right answer. It is
  **not**: with two virtio-consoles the guest delivered only **26 of 84**
  frames and the wire-fault count tripled. The second vdev was removed and
  the single-virtio-console design restored. The markers now go to `/dev/kmsg`
  (non-blocking), and the *host's* evidence tape -- not the guest's console --
  is the artefact that carries the story.
- **One Guest Policy, One Path (`guest/`)**: Deleted `guest/guest_init.sh` and
  `guest/initramfs/`, which `exec python3` — there is no Python in the shipped C-only
  initramfs. `guest/latch_guest_init.c` is now the only in-guest policy;
  `guest/liar.py` is the workstation generator used by `make check`.
- **`latchctl console` (`latchctl.c`)**: New command that mirrors the guest kernel console
  (`/dev/shmem/guest_console.log`) to the operator terminal. The minimal IFS ships no
  `cat`, `tail` or `grep`, so this is the supported way to read what the guest printed.
- **Manifest Is Now the Only Source of Paths (`latch_manifest.c/.h`, `latchlog.c`, `latch_verify.c`)**:
  Added the required key `tape.log_path`; `latchlog` now reads both the device node and
  the output path from the signed manifest, and `latch_verify` uses the manifest's
  actuator path instead of a hardcoded device name. `ingest.queue_depth` raised from 64
  to 256 (the ring capacity) so a whole guest burst fits. Sidecars regenerated and the
  attestation digests updated in `README.md`, `docs/LATCH-implementation.md` and CI.
- **Cross-File Invariants That Would Have Caught The Above (`tools/consistency_check.py`)**:
  The buildfile payload check now resolves against the **installed** SDP sysroot instead
  of a hardcoded "this library does not exist" list; the static-vCPU-pin check asserts
  the 8.0 block form; a new check proves the guest's declared suite size fits
  `ingest.queue_depth`; and the offline viewer's embedded tape is proved to be in sync
  with the committed CSV. New `tools/embed_default_tape.py` regenerates that embedded copy.
- **Linux 6.12 Claim Consistent (`README.md`, `docs/`, `codelab/`)**: the guest is 6.12
  everywhere. `docs/envelope.md` no longer cites envelope macros that were deleted.
- **`AGENTS.md` Rewritten, `guest_init.sh` Path Removed**: `AGENTS.md` now describes
  LATCH (one product, one story, one guest policy) instead of an Alpine aports packaging
  companion, and carries the QNX 8.0 platform facts that cost real time to establish.

### Verified on target (QEMU AArch64 `virt`, QNX SDP 8.0)

- Linux 6.12 guest boots to `/init` in 8.1 s; `psci: PSCIv1.1 detected in firmware`.
- `pidin -p qvm threads` → vCPU threads `cy-guest-qemu-virt/0` and `/1` (static pins).
- `latch_verify` → `[1/5] … [5c/5] ALL PASS`, `VERIFY_RC=0`.
- Host timer: 62,500,000 Hz (AArch64 architectural timer).
- `make check` → `rx=200 | wire_faults=12 | env_faults=7 | eperm_rejects=1`.

---

## [3.0.0] - 2026-11-12

### Safety, Concurrency & QNX 8.0 Reconciliation Fixes
- **Single-Writer Tick Ownership & Graceful EOF Retraction (`latchd.c`)**: Removed immediate `g_simplex.session_active = false` mutation from `latch_io_close_ocb()`. Writer disconnect now sets atomic `writer_closed_eof`, allowing `_cpu-0` to finish `WATCHDOG -> HA-HOLD -> HA-HOME` jerk-bounded retraction before freezing the evidence tape.
- **Lock-Free Cross-Thread EPERM Propagation (`latchd.c`)**: Routed `latch_record_eperm_fault()` through atomic `eperm_pending` so resource-manager threads never perform concurrent RMW writes on `latched_faults` or `g_latch_tape[]`. Added pre-Frame-1 idle wait handling so empty ticks between `open()` and Frame #1 do not trip `WATCHDOG`.
- **Protocol Telemetry & Multi-Keepout Hardening (`latch_protocol.h`, `latchd.c`, `latchctl.c`)**: Added `total_ring_drops` and `wcet_overruns` (`wcet_budget_us * 1000` ns comparison) to `latch_status_reply_t` and `latchctl status`; updated keep-out snapping across all `num_keepouts` intervals.
- **String-Aware Strict Manifest Validation (`latch_manifest.h`, `latch_manifest.c`, `latch_ingest.c`)**: Implemented string-literal-aware / object-depth-aware JSON scanning (`json_find_key_depth`, `json_find_object_end`), `ERANGE` overflow guards, complete anti-silent-defaults key validation across all schema sections, explicit sidecar policy (`latch_manifest_load_opts`), concrete `procmgr_ability()` IDs in `latch_ingest.c`, and fail-closed startup loading.
- **Valid QNX 8.0 Security Policy & Hardware Alignments (`latch.secpol`, `Makefile`, `*.build`, `*.qvmconf`)**: Rewrote `latch.secpol` in valid `secpolcompile` grammar (`type`, `ability`, `self:ability`, `allow_attach`, `:channel connect`), switched to `secpolcompile` and `secpolpush`, restored RPi4 `i2c-bcm2711 -i149` (`GIC_SPI 117 + 32`), split RPi4 (`0xff841000`) and QEMU virt (`0x08000000`) `.qvmconf` files, and removed the 4 KB zero dummy guest image stub.
- **Verification, Viewer, Logger & CI Hardening (`latch_verify.c`, `latchlog.c`, `tape.html`, `consistency_check.py`, `ci.yml`)**: Made `latch_verify.c` derive test geometry from manifest and fail Step 4 unless monotonic `HA-HOME` rows exist; added `# GAP` wraparound detection in `latchlog.c`; made `host/tape.html` gridlines/NaN/badges manifest-driven; synced CI and cross-file invariant checks.

---

## [2.1.0] - 2026-11-11

### Major Architecture Upgrades
- **Dedicated Read-Only Ability Probe (`P0-1, P0-7`)**: Added non-mutating devctl `DCMD_LATCH_PROBE_ABILITY` (`__DION(_DCMD_MISC, 0x43)`). Replaced hold mutation probe in `latchctl grant-check` with pure read-only ability verification, eliminating risk of mutating operator hold state.
- **Fail-Closed Manifest Loading & Sidecar SHA-256 Verification (`P0-2, P0-3, P0-4`)**: Enforced strict fail-closed manifest loading across both native QNX Neutrino and host-sim modes. Automatically validates cryptographic integrity against `<path>.sha256` sidecar file and added `latchctl manifest-verify <path> [sha256]`.
- **Manifest Schema v2 Completion**: Implemented full parsing and admissibility validation for all declared schema keys (`actuator.addr`, `freq_hz`, `prescale`, `retries`, `init_delay_us`, `required`, `tape.capacity`, `protocol.*`, `plant.axes[]`, `pulse_priority`, `wcet_budget_us`, `max_backlog_ticks`).
- **Dynamic Full-Scale PWM Math**: Converted PWM calculation from fixed `1000` divisor to dynamic span calculated from active manifest plant axis stops.
- **QEMU & Guest Bring-Up Hardening (`P0-5, P1-8`)**: Updated `startup-qemu-virt -v -Q enable` for EL2 hypervisor host mode, corrected vdev DLL paths to `/lib/dll/qvm/`, added `libqvm.so.1`, parameterized guest kernel Image, and added `--loop` continuous streaming mode to `liar.py`.
- **Architectural Consistency Automation (`P2-1, P2-2`)**: Added `tools/consistency_check.py` and semantic CI assertions validating 0 keep-out breaches, monotonic sequence advancement, and verified latching of microkernel abilities.

---

## [2.0.0] - 2026-11-10

### Major Architecture Upgrades
- **Zero-Hardcoding Manifest Architecture (`G8`)**: Migrated ~40 hardcoded constants (kinematic limits, keep-out intervals, lookahead horizon, watchdog timers, bus paths, PCA9685 calibration, CPU affinity) into `latch.manifest`. Created `latch_manifest.h` and `latch_manifest.c` featuring a fail-closed, memory-safe JSON parser and self-contained FIPS 180-2 SHA-256 attestation engine.
- **Lock-Free Atomic Seqlock Buffer (`E-2, G6`)**: Replaced the two-slot pointer flip with an atomic generation-counter Seqlock (`latch_seqlock_slot_t`), eliminating the race condition on rapid publisher updates and guaranteeing untorn 24-byte IPC proposal reads.
- **QNX SDP 8.0 Native Ability Semantics (`E-1, G3`)**: Corrected ability verification in `iofunc_client_info_able()` to check `(info->flags & _NTO_CI_UNABLE) == 0u` as the primary authorization signal, preventing false-positive `EPERM` rejections on target hardware while retaining `LATCH_ABLE_STRICT_FLAGS` for experimental ABI toggling.
- **Truthful Cycle-to-Nanoseconds Calibration (`E-4, G4`)**: Calibrated `ClockCycles()` deltas against `SYSPAGE_ENTRY(qtime)->cycles_per_sec` on QNX (and monotonic timespecs on host simulation), storing nanosecond figures in status replies and evidence tape headers.
- **Decoupled Wire Framing vs Semantic Discard (`E-5`)**: Updated `latch_ingest.c` to discard sequence and payload only on framing/CRC/reserved corruptions. Preserves sequence numbers on semantic faults (such as `INT32_MIN` NaN sentinels), ensuring clean `0x0008` (`LATCH_FAULT_NAN`) reporting without spurious `0x0004` sequence drops.
- **Monotonic Sequence Progression (`E-3, G5`)**: Relaxed the HP sequence progression rule from strict $seq = last + 1$ to strictly increasing $seq > last$, enabling latest-wins queue coalescing under high CPU load while preserving strict vetoes on stale or replayed frames.
- **Torn-Read Protection in Telemetry (`E-7`)**: Protected `latch_fill_status()` and `latch_fill_tape_dump()` using snapshot generation sequencing to guarantee consistent reads of supervisor state across concurrent devctl calls.
- **Devctl Input Size Validation (`E-6`)**: Added explicit message size bounds checks to `DCMD_LATCH_GET_STATUS` in `latch_io_devctl()`.
- **System Call Hardening & PWM Arithmetic (`E-8`)**: Added return value checks for `pthread_setschedparam()`, `latch_pca9685_init()`, and CPU affinity calls. Corrected PCA9685 PWM span arithmetic to ensure exact mathematical symmetry across both upper and lower halves of travel.

### Added
- **`latchctl` CLI Utility (`G3`)**: Added native management and verification tool (`latchctl.c`) supporting `status`, `grant-check` (ability validation), `hold` (emergency stop), and `dump` (tape extraction).
- **`latchlog` Evidence Persistence Daemon (`G10`)**: Added background logger daemon (`latchlog.c`) querying `DCMD_LATCH_DUMP_TAPE` to stream evidence tape records to `/dev/shmem/latch_tape.csv` (or a specified path).
- **QNX Security Policy (`G2`)**: Added `qnx/latch.secpol` declaring custom ability `latch/actuator`, confining `/dev/i2c1` and actuator nodes to `latchd`, and isolating the hypervisor guest domain.
- **Guest VM Bring-Up Automation (`G1`)**: Added `guest/guest_init.sh` for booting and configuring `/dev/hvc0` inside the Linux guest VM.
- **Automated CI Workflow (`G7`)**: Added `.github/workflows/ci.yml` running protocol static asserts, Seqlock unit tests, and 200-tick pipeline regression on Ubuntu 24.04.
- **Offline Self-Containment (`G13`)**: Added fallback styles to `host/tape.html` for air-gapped viewing without internet or CDN access.

---

## [1.0.0] - 2026-11-05
- Initial working prototype for QNX SDP 8.0 and host simulation.
- 32-byte packed wire protocol with IEEE 802.3 CRC32.
- 1 kHz Simplex decision loop on CPU 0 and ingest bridge on CPU 1.
- Initial 5-fault verification menu and basic HTML canvas viewer.

