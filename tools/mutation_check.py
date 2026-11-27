#!/usr/bin/env python3
"""MUTATION BATTERY for the LATCH consistency gates.

WHAT THIS IS FOR
================
A gate that cannot fail is a gate that proves nothing.  This tool mutates
each property `tools/consistency_check.py` checks and requires the checker
to FAIL every time.  The mutations are written against the REAL defects the
gates were written from -- three measured transport defects, the SIGSEGV that
took PID 1's init group down, the mailbox ring overrun, and the W5
control-loop properties -- so a green gate here means the gate has teeth.

WHY IT RUNS AGAINST A COPY
===========================
The archive under `docs/evidence/` is NEVER hand-edited, and two of the
mutations target that archive itself.  So the whole repository is copied to
a scratch directory and every mutation happens there.  `consistency_check.py`
derives its repository root from its own `__file__`, so the copy is checked
in its own right.  The real tree is only ever READ, and the tool verifies
that at the end by comparing digests.

WHY IT IS IN THE TREE AND NOT IN /tmp
=====================================
An earlier version of this battery lived in a scratch directory and was
never run again after the transport changed from a PTY pair to the polled
verdict file.  When it was finally run, NINE of its twelve mutations were
SKIPPED because their anchors no longer existed -- and the battery still
printed a "PASSED" line for the three that were left.  A test that stops
testing is worse than no test, because it is still green.  So the battery
lives beside the code it tests, and its own anchors are checked for
uniqueness before every mutation.

USAGE
=====
    python3 tools/mutation_check.py            # every mutation
    python3 tools/mutation_check.py --list     # list the mutations, run none
    python3 tools/mutation_check.py --only W5  # run the mutations whose
                                                # label contains "W5"

Exit status: 0 if the baseline is green and every mutation was caught.
"""

import argparse
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# The directories that hold build output, not source.  They are excluded
# from the scratch copy: the checker's behaviour does not depend on them,
# and a 2 GB copy per run is a cost nobody should pay for a test.
EXCLUDE_DIRS = {".git", "build", "__pycache__", ".pytest_cache", ".mypy_cache"}


# One file the checker reads out of the build tree.  It is copied when it
# exists, so the scratch tree checks the SAME set of properties as the real
# one; when it is missing, the checker reports one property as unchecked and
# the mutation results are unaffected.
OPTIONAL_BUILD_FILES = [
    os.path.join("qnx", "build", "governor-linux-guest-infer.initrd"),
]


def sha256_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ---------------------------------------------------------------------------
# Each mutation is (label, relative-path, [(old, new), ...]).
#
# `old` must occur EXACTLY ONCE in the file, or the mutation is SKIPPED and
# counted as a problem.  A silently skipped mutation is a hole in the proof,
# so a skip is a FAILURE of this tool, not a warning.
#
# An edit may carry a third element: the expected occurrence count (the
# default is 1).
#
# AN ANCHOR MAY BE A CALLABLE.  It is handed the file's text and returns the
# literal string to replace, or None if the anchor is stale.  This is what a
# mutation whose text DEPENDS on a measured value needs: the plan row's U-4
# sample count is the ARCHIVE's own number, and it changes every time the
# 35-minute measurement is re-run, so a literal anchor would be stale the
# next time it is -- and a stale anchor is a hole in the proof, exactly the
# decay this battery exists to prevent.
# ---------------------------------------------------------------------------


def _resolve_edit(edit, text):
    """Return (old, new) for one edit, or None if the anchor is stale.

    A callable anchor is resolved against the file's CURRENT text; a
    callable `new` is resolved against the same text, so a mutation that
    derives its replacement from what it replaces sees the ORIGINAL value.
    """
    old, new = edit[0], edit[1]
    if callable(old):
        old = old(text)
        if old is None:
            return None
    if callable(new):
        new = new(text)
        if new is None:
            return None
    return old, new


def _plan_sample_count(text):
    """The plan row's own sample count, as it stands.

    The row is written by the U-4 write-up script from the ARCHIVE's
    number, so this finds the number the row currently carries -- whatever
    the measurement produced -- and the mutation can change exactly that.
    """
    import re
    m = re.search(r"\*\*(\d+) supervisor ticks\*\* sampled", text)
    return m.group(0) if m else None


def _plan_sample_count_wrong(text):
    """The same phrase, with the count OFF BY ONE.

    Off by one rather than obviously wrong: the gate is supposed to catch a
    row that quotes a measurement nobody made, and a count that is merely
    different is the case that matters.
    """
    import re
    m = re.search(r"\*\*(\d+) supervisor ticks\*\* sampled", text)
    if not m:
        return None
    return "**%d supervisor ticks** sampled" % (int(m.group(1)) + 1)


def _lat_p50_line(text):
    """The archived report's own decision-path p50 line."""
    import re
    m = re.search(r"^Decision-path p50\s+:.*$", text, re.M)
    return m.group(0) if m else None


def _lat_p50_wrong(text):
    """A decision-path p50 line carrying a figure the report never printed.

    This is the defect class the re-derivation gate exists for: a summary
    figure that no longer matches the raw report underneath it.  It reads as
    a complete figure in the archive AND in every index row derived from
    it, and nobody would notice until a judge compared the two.
    """
    return "Decision-path p50                 : [0, 1) cyc ([0, 1) ns)"


def _lat_samples_line(text):
    """The archived report's own sample-count line."""
    import re
    m = re.search(r"^Samples \(every supervisor tick\)\s+:\s*(\d+)$", text, re.M)
    return m.group(0) if m else None


def _sidecar_digest(manifest_rel):
    """The digest a document must quote for a contract, read from its sidecar.

    THE ANCHOR IS DERIVED, NOT LITERAL.  A literal digest written into the
    battery goes STALE the moment a contract changes, and a stale anchor is
    a hole in the proof: the battery would report a SKIP and fail for a
    reason that has nothing to do with the gate, or -- worse -- it would
    mutate nothing and pass.  So the anchor is read from the sidecar at
    the moment the mutation is resolved, exactly as the gate reads it.
    """
    path = os.path.join(REPO_ROOT, manifest_rel)
    with open(path + ".sha256", "r", encoding="utf-8") as f:
        return f.read().strip().split()[0].lower()


def _lat_samples_wrong(text):
    """The same line, with the sample count off by one."""
    import re
    m = re.search(r"^Samples \(every supervisor tick\)\s+:\s*(\d+)$", text, re.M)
    if not m:
        return None
    return "Samples (every supervisor tick) : %d" % (int(m.group(1)) + 1)


MUTATIONS = [
    # ===================== W4: THE TRANSPORT ==============================
    ("W4: the verdict file is opened GUEST-WRITABLE (the guest could forge "
     "its own verdict)",
     "qnx/latch_qemu_fbprobe.qvmconf",
     [("    hostdev </dev/shmem/latch_feedback.img",
       "    hostdev >/dev/shmem/latch_feedback.img")]),

    ("W4: the probe trusts ONE hard-coded device name",
     "guest/latch_fb_transport.h",
     [('    "/dev/vda",\n    "/dev/vdb",\n    "/dev/vdc"',
       '    "/dev/vda"')]),

    ("W4: the freshness rule is removed (the page cache answers every poll)",
     "guest/latch_fb_transport.h",
     [("            long adv = sys_fadvise64((b)->fd, 0, 0, POSIX_FADV_DONTNEED);",
       "            long adv = 0;")]),

    ("W4: the freshness rule becomes a function (it changes the W4 binary, "
     "and the W4 initrd SHA-256 is the zero-regression witness)",
     "guest/latch_fb_transport.h",
     [("#define LATCH_FB_DROP_CACHE(b)",
       "static inline void LATCH_FB_DROP_CACHE(fb_blk_t *b)")]),

    ("W4: the mailbox ring is not a whole number of frames (the 147th enqueue "
     "overruns ring[] by 20 bytes)",
     "qnx/latch_fb_sink.c",
     [("#define FB_RING_BYTES (146u * FB_FRAME_SIZE)",
       "#define FB_RING_BYTES (4096u)")]),

    ("W4: the mailbox is written BEFORE the verdict file (a full mailbox "
     "starves the transport)",
     "qnx/latch_fb_sink.c",
     [("    fb_publish_to_block(frame);\n    pthread_mutex_lock(&g_fb.lock);",
       "    pthread_mutex_lock(&g_fb.lock);"),
      ("    (void)fb_enqueue(frame);",
       "    (void)fb_enqueue(frame);\n    fb_publish_to_block(frame);")]),

    ("W4: the waitfor self-test is removed (the node's existence no longer "
     "proves the FILE's existence)",
     "qnx/latch_qemu_fbprobe.build",
     [("    waitfor /dev/latch/feedback 4\n", "")]),

    ("W4: the probe runs AFTER the session opens",
     "guest/latch_guest_init.c",
     [("    run_feedback_probe();\n    run_governor_demo(hvc_fd);",
       "    run_governor_demo(hvc_fd);\n    run_feedback_probe();")]),

    ("W4: the probe writes to the console twice",
     "guest/latch_guest_init.c",
     [("    phase_marker(report);\n}",
       "    phase_marker(report);\n    phase_marker(\"[FBPROBE] again\\n\");\n}")]),

    ("W4: the experiment's publisher type leaks into the DEPLOYMENT policy",
     "qnx/latch.secpol",
     [("type pipe_t;", "type pipe_t;\ntype latch_fbpump_t;")]),

    # ===================== W5: THE PUBLISHER ==============================
    ("W5: the publisher is ON by default",
     "qnx/latchd.c",
     [("g_feedback_pub_enabled = false;", "g_feedback_pub_enabled = true;")]),

    ("W5: the publish's return value is not discarded (a failed advisory "
     "publish could take the safety core down)",
     "qnx/latchd.c",
     [("        (void)latch_feedback_pub_publish(&verdict);",
       "        if (latch_feedback_pub_publish(&verdict) != 0) { abort(); }")]),

    ("W5: the writer thread runs at the safety core's priority (it could "
     "delay the tick)",
     "qnx/latch_feedback_pub.c",
     [("#define FB_PUB_THREAD_PRIO 40", "#define FB_PUB_THREAD_PRIO 63")]),

    ("W5: the node is opened without O_NONBLOCK (a publisher could stall)",
     "qnx/latch_feedback_pub.c",
     [("open(g_pub.path, O_WRONLY | O_NOCTTY | O_NONBLOCK)",
       "open(g_pub.path, O_WRONLY | O_NOCTTY)")]),

    ("W5: the EAGAIN retry is unbounded",
     "qnx/latch_feedback_pub.c",
     [("#define FB_PUB_MAX_RETRIES 50", "#define FB_PUB_MAX_RETRIES 1000000")]),

    # ===================== W5: THE VERDICT'S MEANING ======================
    ("W5: a verdict is published for HEARTBEATS too (a verdict that answers "
     "nothing)",
     "qnx/latchd.c",
     [("        prop.wire_version == 2u && prop.kind == GOVERNOR_WIRE_CMD_V2) {",
       "        prop.wire_version == 2u) {")]),

    ("W5: a foreign session gets a verdict (the guest could believe another "
     "session's answer)",
     "qnx/latchd.c",
     [("        gov_is_owner && gov_epoch_ok && st->gov_session_epoch_valid &&",
       "        gov_epoch_ok && st->gov_session_epoch_valid &&")]),

    ("W5: ACCEPT is published without the HP condition (the supervisor may "
     "have failed closed and applied nothing)",
     "qnx/latchd.c",
     [("        verdict.verdict = (gov_frame_accepted &&\n"
       "                           st->mode == (uint8_t)LATCH_MODE_HP)",
       "        verdict.verdict = (gov_frame_accepted)")]),

    ("W5: the host and the guest disagree on the verdict numbers",
     "guest/latch_fb_decode.h",
     [("#define LATCH_FB_VERDICT_REJECT  0x02u",
       "#define LATCH_FB_VERDICT_REJECT  0x03u")]),

    ("W5: the host decoder CHECKS the unknown verdict and then passes it "
     "through ('I did not understand' read as 'yes')",
     "qnx/latch_feedback.c",
     [("    if (!latch_feedback_verdict_is_known(frame.verdict)) return -EBADMSG;",
       "    (void)latch_feedback_verdict_is_known(frame.verdict);")]),

    ("W5: the timeout verdict and the timeout flag may disagree",
     "qnx/latch_feedback.c",
     [("        if (frame.verdict != (uint8_t)LATCH_FEEDBACK_VERDICT_TIMEOUT ||",
       "        if (0 ||")]),

    ("W5: the guest's decoder includes a libc header (it is freestanding)",
     "guest/latch_fb_decode.h",
     [("#include <stdint.h>", "#include <stdint.h>\n#include <stdio.h>")]),

    # ===================== W5: THE CORRELATION =============================
    ("W5: the outstanding predicate is STORED rather than derived",
     "guest/latch_fb_decode.h",
     [("    uint32_t last_seq_verdict;",
       "    uint32_t last_seq_verdict;\n    uint32_t awaiting;")]),

    ("W5: the sequence number is published AFTER the frame goes on the wire",
     "guest/latch_guest_init.c",
     [("    g_fb_seq_sent = this_seq;\n"
       "    if (is_cmd) {\n"
       "        g_fb_cmd_seq = this_seq;\n"
       "    }\n"
       "    g_fb_frames_sent++;",
       "    g_fb_frames_sent++;"),
      ("    send_governor_frame(hvc_fd, frame, kind, seq, coherence, value,\n"
       "                        confidence_q8, unit_id);\n}",
       "    send_governor_frame(hvc_fd, frame, kind, seq, coherence, value,\n"
       "                        confidence_q8, unit_id);\n"
       "    g_fb_seq_sent = this_seq;\n"
       "    if (is_cmd) {\n"
       "        g_fb_cmd_seq = this_seq;\n"
       "    }\n}")]),

    ("W5: the fold order is corrupted (note_sent before note_cmd)",
     "guest/latch_guest_init.c",
     [("            latch_fb_note_cmd(&st, cseq);\n"
       "            latch_fb_note_sent(&st, sseq);",
       "            latch_fb_note_sent(&st, sseq);\n"
       "            latch_fb_note_cmd(&st, cseq);")]),

    ("W5: the verdict is published in a 32-bit word (a new sequence number "
     "can be seen with an old verdict)",
     "guest/latch_guest_init.c",
     [("static volatile uint64_t g_fb_verdict_word = 0u;",
       "static volatile uint32_t g_fb_verdict_word = 0u;")]),

    ("W5: the watcher correlates EVERY read, not just a new frame",
     "guest/latch_guest_init.c",
     [("            if (prev_valid == 0u || f.seq != prev_seq) {",
       "            if (1) {")]),

    ("W5: the guest sends NO keepalive while it waits for a verdict (the "
     "dead-man measures liveness, not productivity)",
     "guest/latch_guest_init.c",
     [("        if (((i + 1u) % LATCH_FB_WAIT_KEEPALIVE_POLLS) == 0u) {",
       "        if (0) {")]),

    ("W5: the clone child's stack pointer is at the TOP of its array (the "
     "measured SIGSEGV that took PID 1's init group down)",
     "guest/latch_guest_init.c",
     [("                    (long)(stack + sizeof(stack) - LATCH_FB_STACK_SLACK),",
       "                    (long)(stack + sizeof(stack)),")]),

    # ===================== W5: THE PROFILES ===============================
    ("W5: the W5 build ALSO defines the W4 profile's flag (the two profiles "
     "must be mutually exclusive)",
     "qnx/Makefile",
     [("-DLATCH_GOVERNOR_V2 -DLATCH_GOVERNOR_FEEDBACK_VERDICT",
       "-DLATCH_GOVERNOR_V2 -DLATCH_GOVERNOR_FEEDBACK "
       "-DLATCH_GOVERNOR_FEEDBACK_VERDICT")]),

    ("W5: the W5 image starts the SYNTHETIC publisher (it would measure the "
     "transport again, not the control loop)",
     "qnx/latch_qemu_fbverdict.build",
     [("    on -T latch_fb_sink_t -C 1 /proc/boot/latch_fb_sink",
       "    on -T latch_fb_sink_t -C 1 /proc/boot/latch_fb_pump "
       "/dev/shmem/latch_feedback.img &\n"
       "    on -T latch_fb_sink_t -C 1 /proc/boot/latch_fb_sink")]),

    ("W5: the W5 image does not reuse the W4 qvmconf",
     "qnx/latch_qemu_fbverdict.build",
     [("    on -T latch_guestd_t /proc/boot/latch_guestd -q /proc/boot/qvm "
       "-c /proc/boot/latch_qemu_fbprobe.qvmconf &",
       "    on -T latch_guestd_t /proc/boot/latch_guestd -q /proc/boot/qvm "
       "-c /proc/boot/latch_qemu_fbverdict.qvmconf &")]),

    ("W5: the W5 image does not enable the supervisor's publisher",
     "qnx/latch_qemu_fbverdict.build",
     [(" -n -f /dev/latch/feedback_pub &", " -n &")]),

    ("W5: the harness does not require the completeness sentinel",
     "tools/verify_fbverdict_qemu.py",
     [('if not raw.endswith("end=1"):', 'if not raw.endswith("end=0"):')]),

    ("W5: a marker appears between the warm-up flush and the final silence "
     "(it eats the signed lease)",
     "guest/latch_guest_init.c",
     [("    flush_frames(hvc_fd);\n\n"
       "    /* ---- THE CLEAN PROPOSALS",
       "    flush_frames(hvc_fd);\n\n"
       "    phase_marker(\"[FBVERDICT] a marker inside the supervised window\\n\");\n\n"
       "    /* ---- THE CLEAN PROPOSALS")]),

    # ===================== U-4: THE LATENCY MEASUREMENT ===================
    ("U-4: the measurement image boots a DIFFERENT qvmconf (the static vCPU "
     "pins are the property that makes the number mean anything)",
     "qnx/latch_qemu_latency.build",
     [("-c /proc/boot/latch_qemu_governor.qvmconf",
       "-c /proc/boot/latch_qemu_latency.qvmconf", 1)]),

    ("U-4: the measurement image starts the evidence logger (it perturbs the "
     "very state the measurement is about)",
     "qnx/latch_qemu_latency.build",
     [("    waitfor /dev/latch/actuator 4\n",
       "    waitfor /dev/latch/actuator 4\n"
       "    on -T latchlog_t -C 1 /proc/boot/latchlog "
       "-m /proc/boot/governor_servo.manifest -d /dev/latch/actuator "
       "-o /dev/shmem/governor_tape.csv &\n")]),

    ("U-4: the measurement image enables the feedback publisher (another "
     "concurrent writer of the supervisor's own state)",
     "qnx/latch_qemu_latency.build",
     [("governor_servo.manifest -n &", "governor_servo.manifest -n "
       "-f /dev/latch/feedback_pub &")]),

    ("U-4: the measurement image runs against a DIFFERENT signed contract",
     "qnx/latch_qemu_latency.build",
     [("governor_servo.manifest = ./contracts/governor_servo.manifest",
       "governor_servo.manifest = ./contracts/syringe_governor.manifest")]),

    ("U-4: the Makefile's SOAK_TARGET_HZ disagrees with the guest source's "
     "(the guest's plan marker is stringified out of its own macros, so the "
     "marker would state a rate the build does not use)",
     "qnx/Makefile",
     [("SOAK_TARGET_HZ    ?= 900", "SOAK_TARGET_HZ    ?= 750")]),

    ("U-4: the soak's settling step is too large (the worst-case jerk after "
     "an empty tick exceeds the signed j_max, and the supervisor REFUSES the "
     "command and latches the RATE fault)",
     "guest/latch_guest_init.c",
     [("#define LATCH_GOVERNOR_SOAK_SETTLE_STEP_MRAD 5",
       "#define LATCH_GOVERNOR_SOAK_SETTLE_STEP_MRAD 12")]),

    ("U-4: a marker appears after the warm-up flush (it eats the signed "
     "lease, and the ladder ratchets to LATCH for the wrong reason)",
     "guest/latch_guest_init.c",
     [("    flush_frames(hvc_fd);\n\n"
       "    const uint64_t period_ns = 1000000000ULL",
       "    flush_frames(hvc_fd);\n\n"
       "    phase_marker(\"[LATENCY] a marker inside the supervised window\\n\");\n\n"
       "    const uint64_t period_ns = 1000000000ULL")]),

    ("U-4: the soak's plan grows without the console-drain wait growing with "
     "it (the drain wait has to cover the plan's own console cost)",
     "guest/latch_guest_init.c",
     [('    phase_marker("[LATENCY] the console stays quiet until the soak ends\\n");',
       '    phase_marker("[LATENCY] the console stays quiet until the soak ends\\n");\n'
       '    phase_marker("[LATENCY] and here is a very long extra line of plan '
       'text that makes the console cost of this plan larger than the drain '
       'wait can cover, which is exactly the drift the gate exists to catch, '
       'and it keeps going for a while so that the cost is unambiguous, and '
       'it keeps going still further because the drain wait is a budget and '
       'the budget has to be spent or it is not a budget at all, so here is '
       'the rest of the line to make sure the plan really is more expensive '
       'than the wait that is supposed to be covering it, and here is even '
       'more of it, because the console on this platform costs one and a '
       'half milliseconds for every single character it has to push out '
       'through the PL011 while the host is busy, and the host is always '
       'busy, so a plan that costs more than its drain wait is a plan whose '
       'console traffic is still draining when the session opens\\n");')]),

    ("U-4: the harness infers liveness from the proposal counter instead of "
     "the lease age (the supervisor's CORRECT fail-closed behaviour then "
     "looks like a workload defect)",
     "tools/verify_latency_qemu.py",
     [("                live = lease_age is not None and "
       "lease_age <= LIVE_LEASE_AGE_TICKS",
       "                live = st.get(\"proposals\") is not None")]),

    ("U-4: the harness's million-tick sample floor is lowered (fewer samples "
     "than that is an anecdote, not a distribution)",
     "tools/verify_latency_qemu.py",
     [("DEFAULT_MIN_TICKS = 1_200_000", "DEFAULT_MIN_TICKS = 30_000")]),

    ("U-4: the harness does not recognise the guest's ABORT marker (a soak "
     "that could not be paced burns the whole budget before it fails)",
     "tools/verify_latency_qemu.py",
     [('if "[LATENCY] ABORT" in guest_text:', 'if "[LATENCY] NEVER" in guest_text:')]),

    ("U-4: the deadline pacer accumulates credit again (a host stall becomes a "
     "catch-up burst that overflows the supervisor's proposal ring -- measured "
     "on the target: 186 frames dropped)",
     "guest/latch_soak_pace.h",
     [("        return now;           /* too far behind: DROP the missed deadlines */",
       "        return next;           /* too far behind: KEEP the credit and catch up */")]),

    ("U-4: the deadline pacer drops the credit on ANY lateness (the burst is "
     "gone, but the RATE collapses: measured on the target, 901/s -> 610/s, "
     "so the workload stopped being the one the plan describes)",
     "guest/latch_soak_pace.h",
     [("    if ((now - next) > ((uint64_t)LATCH_SOAK_MAX_LAG_PERIODS * period_ns)) {",
       "    if ((now - next) > 0u) {")]),

    ("U-4: the deadline pacer's lag allowance is ONE period (the first fix's "
     "value -- it drops the credit on ordinary jitter, and the measured rate "
     "fell from 901/s to 610/s)",
     "guest/latch_soak_pace.h",
     [("#define LATCH_SOAK_MAX_LAG_PERIODS 4",
       "#define LATCH_SOAK_MAX_LAG_PERIODS 1")]),

    ("U-4: the deadline pacer loses the 'a little late' branch (the grid is "
     "no longer kept, so ordinary jitter eats the target rate)",
     "guest/latch_soak_pace.h",
     [("    return next;               /* a little late: keep the grid, one frame now */",
       "    return now;                /* a little late: lose the grid too */")]),

    ("U-4: the guest stops using the shared pacing decision (the host test "
     "then tests a copy the guest does not run)",
     "guest/latch_guest_init.c",
     [("    const uint64_t next = latch_soak_next_deadline(*deadline, now, period_ns);",
       "    const uint64_t next = *deadline + period_ns;")]),

    ("U-4: the pacer's host test is removed from the regression suite (the "
     "property is then only asserted by a regex)",
     "qnx/Makefile",
     [("\t$(MAKE) --no-print-directory latch-soak-pace-check\n", "")]),

    ("U-4: the harness's achieved-rate check accepts everything (the run that "
     "produced at 610/s under a '900 Hz' workload line passed every other "
     "criterion, and this is the criterion that would have caught it)",
     "tools/verify_latency_qemu.py",
     [("    if stream_rate < lo or stream_rate > hi:",
       "    if False:")]),

    ("U-4: the harness's rate tolerance is widened to a third (the band stops "
     "discriminating: a run at two thirds of the declared rate would pass)",
     "tools/verify_latency_qemu.py",
     [("RATE_TOLERANCE_FRACTION = 0.05", "RATE_TOLERANCE_FRACTION = 0.30")]),

    ("U-4: the harness stops calling the rate check (a pure function that "
     "nothing calls is a function that proves nothing)",
     "tools/verify_latency_qemu.py",
     [("        rate_ok, rate_msg = rate_verdict(stream_rate, target_hz)",
       "        rate_ok, rate_msg = True, \"\"")]),

    ("U-4: the harness reads the achieved rate over the WHOLE window instead "
     "of the streaming window (the tail after the guest stops dilutes the "
     "figure: a 60-second calibration reads 749/s against a measured 898/s)",
     "tools/verify_latency_qemu.py",
     [("    live = [s for s in samples if s.get(\"live\")]",
       "    live = list(samples)")]),

    ("U-4: the archive's summary stops carrying the achieved rate (the rate "
     "is a result, not an input -- and a summary that omits it cannot be "
     "checked against the measurement it summarises)",
     "tools/capture_evidence.py",
     [('        "producer rate      : %s" % producer_rate,\n', "")]),

    ("U-4: the archived report loses its sample count",
     "docs/evidence/governor/LATENCY.md",
     [("Samples (every supervisor tick)", "Samples (ticks)")]),

    ("U-4: the archived report loses its TCG caveat (a TCG observation "
     "without the caveat reads like a hardware measurement)",
     "docs/evidence/governor/LATENCY.md",
     [("TCG OBSERVATION", "TCG OBSERVATIO")]),

    ("U-4: the archived report calls the figure a WCET",
     "docs/evidence/governor/LATENCY.md",
     [("not a WCET", "a WCET"), ("NOT a WCET", "a WCET")]),

    ("U-4: the archived report loses its p99",
     "docs/evidence/governor/LATENCY.md",
     [("Decision-path p99", "Decision-path p9")]),

    ("U-4: the archived report loses its exact minimum and maximum",
     "docs/evidence/governor/LATENCY.md",
     [("Exact min / max (decision path)", "Exact max (decision path)")]),

    ("U-4: the archived report loses the machine it was measured on",
     "docs/evidence/governor/LATENCY.md",
     [("Target machine", "Target box")]),

    ("U-4: the archived report is the REJECTION notice again (a gate that "
     "cannot tell a measurement from a withdrawal proves nothing)",
     "docs/evidence/governor/LATENCY.md",
     [("--- the achieved rates, as the target reported them ---",
       "REJECTED, moved to quarantine\n"
       "--- the achieved rates, as the target reported them ---")]),

    ("U-4: the archived report's SUMMARY quotes a percentile the raw report "
     "does not carry (the summary drifts away from the measurement and "
     "nobody notices)",
     "docs/evidence/governor/LATENCY.md",
     [(_lat_p50_line, _lat_p50_wrong)]),

    ("U-4: the archived report's sample count is hand-edited (the archive "
     "stops being the measurement it claims to be)",
     "docs/evidence/governor/LATENCY.md",
     [(_lat_samples_line, _lat_samples_wrong)]),

    ("U-4: the README loses its pointer at the measurement (a judge is sent "
     "to a summary instead of to the measurement)",
     "README.md",
     [("`docs/evidence/governor/LATENCY.md`",
       "`docs/evidence/governor/LATENCY-SOMEDAY.md`")]),

    ("U-4: the implementation document loses its pointer at the measurement",
     "docs/LATCH-implementation.md",
     [("`docs/evidence/governor/LATENCY.md`",
       "`docs/evidence/governor/LATENCY-SOMEDAY.md`")]),

    ("U-4: the README copies a latency figure out of the measurement (the "
     "archive is regenerated, so the copy goes stale silently)",
     "README.md",
     [("**Not quoted here on purpose** — the archive is regenerated by",
       "**p50 = 160 cycles (2.6 us)** — the archive is regenerated by")]),

    ("host-sim: the README copies a host-sim latency figure into the cell "
     "NEXT to the pointer (the host-sim's figure is load dependent, so it "
     "must never be quoted)",
     "README.md",
     [("**Not quoted here on purpose.** The same code has produced archived",
       "**max_latency = 999 ns.** The same code has produced archived")]),

    ("U-4: the evidence index's derived row loses the measurement (the "
     "generator's own row would rot the moment the archive is refreshed)",
     "tools/capture_evidence.py",
     [("| **U-4 decision-latency measurement** | The **trusted supervisor's own "
       "per-tick decision latency**",
       "| **U-4 decision-latency measurement** | The **trusted supervisor's own "
       "per-tick decision latency (GONE)", 1)]),

    ("U-4: the plan's U-4 row is left OPEN while the archive carries a "
     "measurement (the plan understates what has been done)",
     "docs/plan/04_CORRECTIONS_ADDENDUM_AND_TIMELINE.md",
     [("**VERIFIED** 2026-11-27: the full 35-minute soak ran",
       "**OPEN** 2026-11-27: the full 35-minute soak ran")]),

    ("U-4: the plan's U-4 row quotes a sample count the archive does not "
     "carry (the plan claims a measurement that was never made)",
     "docs/plan/04_CORRECTIONS_ADDENDUM_AND_TIMELINE.md",
     [(_plan_sample_count, _plan_sample_count_wrong, 2)]),

    # ===================== THE EVIDENCE ARCHIVE ==========================
    ("the archive index does not name the feedback family (an orphan is a "
     "silent lie)",
     "docs/evidence/README.md",
     [("      feedback-transport.txt\n", "")]),

    ("the archived feedback evidence loses the guest's STOP (the control "
     "claim rots silently)",
     "docs/evidence/governor/feedback-transport.txt",
     [("stop=reject", "stop=none", 3)]),

    ("the archived feedback evidence claims a DIRTY correlation (a foreign, "
     "stale or duplicate verdict was counted as an answer)",
     "docs/evidence/governor/feedback-transport.txt",
     [("foreign=0", "foreign=3", 2)]),

    ("the archived feedback evidence loses its 'what this does not prove' "
     "section",
     "docs/evidence/governor/feedback-transport.txt",
     [("WHAT THIS DOES NOT PROVE", "SOME NOTES")]),

    ("the evidence index is HAND-EDITED (the next `make evidence` silently "
     "replaces it, so the commit carrying the edit is wrong in a way nobody "
     "can see)",
     "docs/evidence/README.md",
     [("## 2. What is in here", "## 2. What is in here (hand-edited)")]),

    ("the evidence index's PROSE is hand-edited (the file tree is intact, so "
     "only the generator-reproduction gate can catch it)",
     "docs/evidence/README.md",
     [("archive is the target proof. It is raw console output, not a",
       "archive is a nice proof. It is raw console output, not a")]),

    ("the evidence index's GENERATOR is changed (the committed index is no "
     "longer what the generator produces, so the next `make evidence` would "
     "silently rewrite it -- the generator has to be mutation-covered in its "
     "own direction, not only the committed file)",
     "tools/capture_evidence.py",
     [('L.append("# LATCH — Evidence Archive")',
       'L.append("# LATCH — Evidence Archive (MUTATED)")')]),

    # ===================== THE ATTESTATION ================================
    #
    # These four mutations are the DEFECT THAT SHIPPED: the README and the
    # SBOM quoted `6b62927a...` as the GOVERNOR syringe contract's digest
    # long after the file's digest had become `7378df81...`, the HOMEOSTAT
    # contract was quoted in neither document, and the old gate looked at
    # TWO contracts against TWO documents -- so nothing noticed.  Each
    # mutation is one of the three rules of the attestation gate.
    ("ATTEST: a document quotes a digest that NO FILE in the repository has "
     "(the defect that shipped: the GOVERNOR syringe contract's digest was "
     "stale in the README and the SBOM, and the gate did not look)",
     "README.md",
     [(lambda t: "`%s`" % _sidecar_digest("qnx/contracts/syringe_governor.manifest"),
       "`6b62927a81c2566d1f2d7d0e8ff5047d9f22086f1693044ea9a77de7c142b392`")]),

    ("ATTEST: a document quotes ANOTHER contract's digest beside a "
     "contract's name (both digests are live, so only the name-to-digest "
     "pairing can catch it)",
     "README.md",
     [(lambda t: "`%s`" % _sidecar_digest("qnx/contracts/syringe_governor.manifest"),
       (lambda t2: "`%s`" % _sidecar_digest("qnx/contracts/governor_servo.manifest")))]),

    ("ATTEST: the HOMEOSTAT contract is omitted from the SBOM (a contract "
     "no document mentions is a contract whose integrity nobody is told "
     "about)",
     "docs/SBOM.md",
     [(lambda t: "| **`homeostat_servo.manifest`** | Schema 3 | LATCH Project | "
                 "MIT | Safety Contract | None (JSON) | `%s` |\n"
                 % _sidecar_digest("qnx/contracts/homeostat_servo.manifest"), ""),
      (lambda t: "- `qnx/contracts/homeostat_servo.manifest.sha256`: `%s`\n"
                 % _sidecar_digest("qnx/contracts/homeostat_servo.manifest"), "")]),

    ("ATTEST: the HOMEOSTAT contract is omitted from the README",
     "README.md",
     [(lambda t: "`homeostat_servo.manifest` (HOMEOSTAT Servo): `%s`"
                 % _sidecar_digest("qnx/contracts/homeostat_servo.manifest"), "")]),

    ("ATTEST: the HOMEOSTAT contract is omitted from the implementation "
     "document",
     "docs/LATCH-implementation.md",
     [(lambda t: "| `homeostat_servo.manifest` | servo-horn-1d | 3 | `%s` |\n"
                 % _sidecar_digest("qnx/contracts/homeostat_servo.manifest"), "")]),

    # ===================== THE POST-VERIFY FRAME TOTAL ====================
    #
    # The README's card was checked against the archive and the narrative
    # BELOW it was not, so it said "97 frames ... the guest's 84 plus the
    # harness's own 13" while the archive's own post-verify report says
    # 122, and 84 + 38 = 122.  Two different totals, one of them wrong,
    # and a judge who opened both had no way to tell which the project
    # believed.
    ("FRAMES: the README's post-verify frame total is not the archive's "
     "(the defect that shipped: the README said 97 where the archive says "
     "122)",
     "README.md",
     [("post-verify telemetry reads `122`", "post-verify telemetry reads `97`")]),

    ("FRAMES: the README's split of the post-verify total does not add up",
     "README.md",
     [("the guest's 84 plus the harness's own 38",
       "the guest's 84 plus the harness's own 13")]),

    # ===================== THE FIRST-READER DECISION ====================
    #
    # C-1, and it is a LIVE defect: the archived transcript
    # `docs/evidence/governor/feedback-transport-console.txt` carries the
    # two opens of the READ node in the order they happened --
    #
    #     latch_fb_sink: open READ ioflag=0x8880 (----)   <- the `waitfor` probe
    #     latch_fb_sink: open READ ioflag=0x8881 (RD--)   <- the REAL reader
    #
    # The `waitfor` probe opens the READ node with the access bits CLEARED
    # and it is the FIRST open, so the old rule
    # `rd != 0u && g_fb.read_opens == 1u` was FALSE for the real reader
    # (`read_opens` was already 2) and the backlog was NEVER discarded: the
    # guest's first read was a stale verdict.
    #
    # WORTH NOTING: the consistency gate USED TO REQUIRE the broken
    # expression, so it held the defect in place.  A gate that enforces a
    # bug is worse than no gate, because it makes the bug look like a
    # requirement.
    ("C-1: the resource manager stops calling the shared first-reader "
     "decision (it reimplements it inline, so the host test would prove a "
     "function the shipped code does not use)",
     "qnx/latch_fb_sink.c",
     [("        first_reader = latch_fb_reader_account(&g_fb.reader, rd, wr);",
       "        first_reader = (rd != 0u && wr == 0u && g_fb.reader.opens == 0u);")]),

    ("C-1: the first-reader decision stops rejecting non-readers (the "
     "`waitfor` probe and the refused read+write open would both consume the "
     "first-reader slot, and the real reader would get a stale verdict)",
     "qnx/latch_fb_reader.h",
     [("    if (rd == 0u || wr != 0u) {\n        return 0;\n    }",
       "    if (0) {\n        return 0;\n    }")]),

    ("C-1: the first-reader decision and the backlog discard are split into "
     "TWO critical sections (the channel runs two dispatch threads with "
     "DISPATCH_FLAG_NOLOCK, so two concurrent opens could both believe they "
     "were the first reader and neither would discard the backlog)",
     "qnx/latch_fb_sink.c",
     [("        first_reader = latch_fb_reader_account(&g_fb.reader, rd, wr);\n"
       "        if (first_reader) {",
       "        first_reader = latch_fb_reader_account(&g_fb.reader, rd, wr);\n"
       "        pthread_mutex_unlock(&g_fb.lock);\n"
       "        pthread_mutex_lock(&g_fb.lock);\n"
       "        if (first_reader) {")]),

    ("C-1: the host test is dropped from the regression suite (the "
     "first-reader decision would have no proof at all)",
     "qnx/Makefile",
     [("\t$(MAKE) --no-print-directory latch-fb-reader-check\n", "")]),

    ("C-1: the shipped header is no longer a prerequisite of the host test's "
     "build rule (`make` would not rebuild the test when the decision "
     "changes, so the test would prove a STALE decision)",
     "qnx/Makefile",
     [("$(BUILD_DIR)/host-sim/latch_fb_reader_test: latch_fb_reader.h "
       "latch_fb_reader_test.c | dirs",
       "$(BUILD_DIR)/host-sim/latch_fb_reader_test: latch_fb_reader_test.c "
       "| dirs")]),

    ("C-1: the old, broken first-reader rule comes back (it decides the "
     "first reader from the count of OPENS, and the `waitfor` probe is the "
     "first open, so the real reader's condition was false and the backlog "
     "was never discarded)",
     "qnx/latch_fb_sink.c",
     [("        first_reader = latch_fb_reader_account(&g_fb.reader, rd, wr);",
       "        first_reader = (rd != 0u && g_fb.read_opens == 1u);")]),

    # ===================== THE RESOURCE MANAGER'S ATTRIBUTE LOCK =====
    #
    # C-2.  The QNX iofunc library updates the device's SHARED attribute
    # (the file-use count, the reader and writer counts) with a
    # NON-ATOMIC 16-bit read-modify-write -- MEASURED by disassembling
    # the installed SDP 8.0 library: `iofunc_ocb_attach()` does a `ldrh`
    # and then a `strh` of the incremented value, and
    # `iofunc_ocb_detach()` decrements the same five counters the same
    # way.  LATCH's resource managers dispatch with
    # `DISPATCH_FLAG_NOLOCK` on more than one thread, so two opens of the
    # same node can be in flight at the same time and LOSE an increment.
    #
    # The fix: every iofunc entry point a resource manager calls goes
    # through a wrapper in `qnx/latch_rm_attr.h` that takes the device's
    # attribute lock around the call and FAILS CLOSED.
    #
    # The consistency gate derives the resource managers from the source,
    # so a new one is covered without being listed.
    ("C-2: a resource manager calls the iofunc library directly (the call "
     "updates the device's shared counters without the attribute lock, and "
     "two concurrent opens can lose an increment)",
     "qnx/latchd.c",
     [("    int status = latch_rm_write_verify(ctp, msg, io_ocb, NULL);",
       "    int status = iofunc_write_verify(ctp, msg, io_ocb, NULL);")]),

    ("C-2: the open wrapper takes the attribute lock AFTER the iofunc call "
     "(the shared counters are updated INSIDE the iofunc call, so the lock "
     "has to be held while it runs)",
     "qnx/latch_rm_attr.h",
     [("    int rc = latch_rm_attr_lock(attr);\n"
       "    if (rc != EOK) {\n"
       "        return rc;\n"
       "    }\n"
       "    int status = iofunc_open_default(ctp, msg, attr, extra);\n"
       "    int urc = latch_rm_attr_unlock(attr);",
       "    int status = iofunc_open_default(ctp, msg, attr, extra);\n"
       "    int rc = latch_rm_attr_lock(attr);\n"
       "    if (rc != EOK) {\n"
       "        return rc;\n"
       "    }\n"
       "    int urc = latch_rm_attr_unlock(attr);")]),

    ("C-2: the write wrapper IGNORES the lock's failure (the iofunc call "
     "would then run with the device's shared counters unlocked -- the "
     "operation has to be REFUSED, not performed unlocked)",
     "qnx/latch_rm_attr.h",
     [("    int rc = latch_rm_attr_lock(attr);\n"
       "    if (rc != EOK) {\n"
       "        return rc;\n"
       "    }\n"
       "    int status = iofunc_write_verify(ctp, msg, io_ocb, nonblock);",
       "    int rc = latch_rm_attr_lock(attr);\n"
       "    if (rc != EOK) {\n"
       "        rc = EOK;\n"
       "    }\n"
       "    int status = iofunc_write_verify(ctp, msg, io_ocb, nonblock);")]),

    ("C-2: the devctl wrapper never releases the attribute lock (the node "
     "would deadlock on the next request)",
     "qnx/latch_rm_attr.h",
     [("    int status = iofunc_devctl_default(ctp, msg, io_ocb);\n"
       "    int urc = latch_rm_attr_unlock(attr);",
       "    int status = iofunc_devctl_default(ctp, msg, io_ocb);\n"
       "    int urc = EOK;")]),

    ("C-2: the lock primitive swallows the lock's error and reports "
     "success (a lock that failed and was reported as success would let the "
     "iofunc call run unlocked)",
     "qnx/latch_rm_attr.h",
     [("    int rc = iofunc_attr_lock(attr);\n"
       "    if (rc != EOK) {\n"
       "        return rc;\n"
       "    }\n"
       "    return EOK;",
       "    int rc = iofunc_attr_lock(attr);\n"
       "    (void)rc;\n"
       "    return EOK;")]),

    ("C-2: a resource manager stops including the shared header (it would "
     "have no way to reach the iofunc library under the lock)",
     "qnx/latch_fb_sink.c",
     [("#include \"latch_rm_attr.h\"\n", "")]),

    ("C-2: a resource manager is built against the HOST STUB instead of "
     "QNX's <sys/iofunc.h> (a resource manager that ships with the stub is "
     "one that never touched the real library)",
     "qnx/latch_guestd.c",
     [("#include \"latch_rm_attr.h\"",
       "#define LATCH_RM_ATTR_HOSTED 1\n#include \"latch_rm_attr.h\"")]),

    ("C-2: the host test is dropped from the regression suite (the "
     "attribute-lock discipline would have no proof at all)",
     "qnx/Makefile",
     [("\t$(MAKE) --no-print-directory latch-rm-attr-check\n", "")]),

    ("C-2: the shipped header is no longer a prerequisite of the host test's "
     "build rule (`make` would not rebuild the test when the header changes, "
     "so the test would prove a STALE header)",
     "qnx/Makefile",
     [("$(BUILD_DIR)/host-sim/latch_rm_attr_test: latch_rm_attr.h "
       "latch_rm_attr_host.h latch_rm_attr_test.c | dirs",
       "$(BUILD_DIR)/host-sim/latch_rm_attr_test: latch_rm_attr_host.h "
       "latch_rm_attr_test.c | dirs")]),
]


def _ignore_build_dirs(directory, names):
    """`shutil.copytree`'s ignore hook: skip the build-output directories.

    The rule is PATH-AWARE on purpose.  `docs/evidence/build/` is part of
    the evidence archive -- it holds the mkifs listing -- and skipping it
    would change the archive's file tree, and therefore the generated
    index.  Only the repository's own build-output trees are skipped: the
    cross-build cache at the root and the QNX build tree under `qnx/`.
    """
    ignored = set()
    rel = os.path.relpath(directory, REPO_ROOT)
    parts = [] if rel == "." else rel.split(os.sep)
    for name in names:
        full = os.path.join(directory, name)
        if name in {".git", "__pycache__", ".pytest_cache", ".mypy_cache"}:
            ignored.add(name)
        elif os.path.isdir(full):
            if not parts and name == "build":
                ignored.add(name)          # the repo-root cross-build cache
            elif parts == ["qnx"] and name == "build":
                ignored.add(name)          # the QNX build output
    return ignored


def make_scratch_copy(dst):
    """Copy the repository into `dst`, minus the build output."""
    shutil.copytree(REPO_ROOT, dst, ignore=_ignore_build_dirs,
                    symlinks=True)
    for rel in OPTIONAL_BUILD_FILES:
        src = os.path.join(REPO_ROOT, rel)
        out = os.path.join(dst, rel)
        if os.path.isfile(src):
            os.makedirs(os.path.dirname(out), exist_ok=True)
            shutil.copy2(src, out)


def write_atomic(path, text):
    """Replace a file's contents through a temporary file.

    `open(path, "w")` truncates the existing inode in place, which would
    reach through a hard link into the original tree.  Writing a new file
    and renaming it over the old one never does.
    """
    tmp = path + ".mutation-tmp"
    with io.open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def run_checker(copy_root):
    checker = os.path.join(copy_root, "tools", "consistency_check.py")
    proc = subprocess.run([sys.executable, checker], cwd=copy_root,
                          capture_output=True, text=True)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--list", action="store_true",
                    help="list the mutations and exit without running any")
    ap.add_argument("--only", default=None,
                    help="run only the mutations whose label contains this text")
    args = ap.parse_args()

    if args.list:
        for label, rel, _ in MUTATIONS:
            print("%-8s %s" % (rel, label))
        return 0

    selected = [m for m in MUTATIONS
                if args.only is None or args.only in m[0]]
    if not selected:
        print("[MUTATION] no mutation matches --only %r" % args.only,
              file=sys.stderr)
        return 1

    # The digests of the REAL files, so the tool can prove at the end that
    # it never wrote to the tree it was asked to check.
    real_paths = sorted({os.path.join(REPO_ROOT, rel) for _, rel, _ in selected})
    real_digests = {p: sha256_file(p) for p in real_paths}

    scratch = tempfile.mkdtemp(prefix="latch-mutation-")
    copy_root = os.path.join(scratch, "latch")
    failures = 0
    try:
        make_scratch_copy(copy_root)
        rc, out = run_checker(copy_root)
        if rc != 0:
            print("[MUTATION] the BASELINE is red -- fix that first:")
            print(out[-4000:])
            return 1
        n_pass = out.count("[CONSISTENCY PASS]")
        print("[MUTATION] baseline: the consistency gate is GREEN in the scratch "
              "copy (%d gates)" % n_pass)

        for label, rel, edits in selected:
            path = os.path.join(copy_root, rel)
            with io.open(path, encoding="utf-8") as f:
                text = f.read()
            bad = False
            resolved = []
            for edit in edits:
                r = _resolve_edit(edit, text)
                if r is None:
                    print("[MUTATION][SKIP] %s: the anchor could not be resolved "
                          "in %s -- the mutation is STALE, and a stale mutation "
                          "is a hole in the proof" % (label, rel))
                    bad = True
                    break
                old, new = r
                want = edit[2] if len(edit) > 2 else 1
                n = text.count(old)
                if n != want:
                    print("[MUTATION][SKIP] %s: the anchor %r occurs %d times in "
                          "%s (expected %d) -- the mutation is STALE, and a stale "
                          "mutation is a hole in the proof"
                          % (label, old[:60], n, rel, want))
                    bad = True
                    break
                resolved.append((old, new))
            if bad:
                failures += 1
                continue
            for old, new in resolved:
                text = text.replace(old, new)
            write_atomic(path, text)

            rc, out = run_checker(copy_root)
            if rc == 0:
                print("[MUTATION][FAIL] the gate did NOT notice: %s" % label)
                failures += 1
            else:
                line = [ln for ln in out.splitlines() if "CONSISTENCY ERROR" in ln]
                print("[MUTATION][ok] the gate noticed: %s" % label)
                if line:
                    print("             %s" % line[0][:190])

            # restore this file from the pristine source
            with io.open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
                write_atomic(path, f.read())
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    # The real tree must be untouched.
    for p in real_paths:
        if sha256_file(p) != real_digests[p]:
            print("[MUTATION][FAIL] %s was modified in the REAL tree -- the "
                  "battery must never write to the tree it checks" % p)
            failures += 1
    print("[MUTATION] the real tree is byte-identical to how it started")

    if failures:
        print("[MUTATION BATTERY FAILED] %d problem(s)" % failures)
        return 1
    print("[MUTATION BATTERY PASSED] %d mutations, all caught" % len(selected))
    return 0


if __name__ == "__main__":
    sys.exit(main())
