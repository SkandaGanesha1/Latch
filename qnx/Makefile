# ==============================================================================
# LATCH — Last Authority for Trusted Control Handoff
# QNX SDP 8.0 & Host Simulation Build System
#
# Targets:
#   make rpi4     -> QNX SDP 8.0 AArch64 (qcc -Vgcc_ntoaarch64le)
#   make aarch64  -> QNX SDP 8.0 AArch64 (qcc -Vgcc_ntoaarch64le) [for QEMU virt]
#   make x86_64   -> QNX SDP 8.0 x86_64  (qcc -Vgcc_ntox86_64)
#   make ifs-rpi4         -> Raspberry Pi 4B IFS (requires QNX SDP + GUEST_IMAGE)
#   make ifs-qemu-aarch64 -> QEMU AArch64 virt IFS (requires QNX SDP + GUEST_IMAGE)
#   make ifs-qemu-governor -> opt-in GOVERNOR v2 QEMU/QH experimental profile
#   make host-sim         -> POSIX/Linux Host Simulation (gcc -DLATCH_HOST_SIM)
#   make check            -> Run unit tests + 200-tick end-to-end fault suite
#   make qemu             -> Launch QEMU virtual machine (x86_64 QSTI / AArch64)
# ==============================================================================

export CCACHE_DISABLE ?= 1

TARGET        ?= host-sim
BUILD_DIR     := build
COMMON_CFLAGS := -Wall -Wextra -Werror -Wpedantic -O2 -I.
SECPOLC       ?= secpolcompile
RPI4_I2C_IRQ  ?= 149
GUEST_IMAGE   ?=
GUEST_INITRD  ?= ../guest/linux-guest.initrd

ifeq ($(TARGET),rpi4)
    CC         := qcc
    CFLAGS     := -Vgcc_ntoaarch64le -Wc,-std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE
    LDFLAGS    := -Vgcc_ntoaarch64le -Wl,-z,relro,-z,now
    OUT_DIR    := $(BUILD_DIR)/nto-aarch64-le
    GUESTD_OK  := 1
    STACK_USAGE_FLAG := -Wc,-fstack-usage
else ifeq ($(TARGET),aarch64)
    CC         := qcc
    CFLAGS     := -Vgcc_ntoaarch64le -Wc,-std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE
    LDFLAGS    := -Vgcc_ntoaarch64le -Wl,-z,relro,-z,now
    OUT_DIR    := $(BUILD_DIR)/nto-aarch64-le
    GUESTD_OK  := 1
    STACK_USAGE_FLAG := -Wc,-fstack-usage
else ifeq ($(TARGET),x86_64)
    CC         := qcc
    CFLAGS     := -Vgcc_ntox86_64 -Wc,-std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE
    LDFLAGS    := -Vgcc_ntox86_64 -Wl,-z,relro,-z,now
    OUT_DIR    := $(BUILD_DIR)/nto-x86_64-o
    GUESTD_OK  := 1
    STACK_USAGE_FLAG := -Wc,-fstack-usage
else ifeq ($(TARGET),native)
    CC         := gcc
    CFLAGS     := -std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE
    LDFLAGS    := -lm
    OUT_DIR    := $(BUILD_DIR)/native
    GUESTD_OK  := 0
    STACK_USAGE_FLAG := -fstack-usage
else ifeq ($(TARGET),host-sim)
    CC         := gcc
    # The host-sim is the glibc/POSIX harness, so it can use glibc's
    # _FORTIFY_SOURCE. It is requested EXPLICITLY, at level 3, instead of
    # relying on the toolchain's default: Ubuntu's gcc enables level 3 by
    # itself, Fedora's enables nothing, and the difference is exactly what
    # let a bounds defect compile cleanly on one workstation and fail on
    # another. -U first, so a distro that already defines the macro at a
    # different level does not produce a redefinition warning under -Werror.
    CFLAGS     := -std=c11 $(COMMON_CFLAGS) -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 \
                  -D_POSIX_C_SOURCE=200809L -DLATCH_HOST_SIM
    LDFLAGS    := -lpthread -lrt -lm
    OUT_DIR    := $(BUILD_DIR)/host-sim
    # The guest lifecycle daemon is a QNX resource manager: it uses
    # <sys/resmgr.h>, <sys/iofunc.h> and the libsecpol spawn-attribute API,
    # none of which exist on a POSIX host. It is therefore NOT part of the
    # host-sim build, and the host-sim tests never link it.
    GUESTD_OK  := 0
    STACK_USAGE_FLAG := -fstack-usage
else
    $(error Unknown TARGET '$(TARGET)'. Use rpi4, aarch64, x86_64, native, or host-sim)
endif

LATCHD_BIN    := $(OUT_DIR)/latchd
INGEST_BIN    := $(OUT_DIR)/latch-ingest
LATCHCTL_BIN  := $(OUT_DIR)/latchctl
LATCHLOG_BIN  := $(OUT_DIR)/latchlog
VERIFY_BIN    := $(OUT_DIR)/latch_verify
GUESTD_BIN    := $(OUT_DIR)/latch_guestd
MANIFEST_OBJ  := $(OUT_DIR)/latch_manifest.o
IPC_OBJ       := $(OUT_DIR)/latch_ipc.o

.PHONY: all rpi4 x86_64 native host-sim check check-governor mutation-check clean dirs qemu guest-initrd guest-governor-initrd guest-governor-infer-initrd guest-governor-feedback-initrd guest-governor-feedback-verdict-initrd guest-governor-latency-soak-initrd fb-pump fbprobe-secpol ifs-qemu-fbprobe verify-fb-qemu ifs-qemu-fbverdict verify-fbverdict-qemu ifs-qemu-latency verify-latency-qemu guest-disk-image guest-disk-image-attack check-guest-initrd check-governor-initrd check-latency-initrd check-guest-disk check-guest-disk-attack governor-policy-check governor-wire-check latch-ipc-check governor-gate-check governor-homeostat-check latch-feedback-check latch-fb-decode-check latch-feedback-pub-check latch-manifest-check latch-action-check governor-e2e-check homeostat-e2e-check gov-replay-check verify-governor-qemu verify-governor-qemu-prebuilt ifs-qemu-infer ifs-qemu-infer-attack verify-infer-qemu verify-infer-qemu-attack stack-usage evidence evidence-host-sim evidence-on-target evidence-rederive-on-target evidence-build evidence-history evidence-tape evidence-resolution evidence-governor evidence-governor-qemu evidence-governor-vm-kill evidence-governor-feedback evidence-governor-latency evidence-baseline evidence-index evidence-check secpol-dump evidence-secpol-audit latch-soak-pace-check

ifeq ($(GUESTD_OK),1)
all: $(LATCHD_BIN) $(INGEST_BIN) $(LATCHCTL_BIN) $(LATCHLOG_BIN) $(VERIFY_BIN) $(GUESTD_BIN)
else
all: $(LATCHD_BIN) $(INGEST_BIN) $(LATCHCTL_BIN) $(LATCHLOG_BIN) $(VERIFY_BIN)
endif

dirs:
	@mkdir -p $(OUT_DIR)

$(MANIFEST_OBJ): latch_manifest.c latch_manifest.h | dirs
	$(CC) $(CFLAGS) -c latch_manifest.c -o $@

$(IPC_OBJ): latch_ipc.c latch_ipc.h latch_protocol.h | dirs
	$(CC) $(CFLAGS) -c latch_ipc.c -o $@

$(LATCHD_BIN): latchd.c latch_protocol.h latch_ipc.h governor_policy.c governor_policy.h gov_gate_precheck.c gov_gate_precheck.h gov_homeostat.c gov_homeostat.h latch_feedback.c latch_feedback.h latch_feedback_pub.c latch_feedback_pub.h $(MANIFEST_OBJ) $(IPC_OBJ) | dirs
	$(CC) $(CFLAGS) latchd.c governor_policy.c gov_gate_precheck.c gov_homeostat.c latch_feedback.c latch_feedback_pub.c $(MANIFEST_OBJ) $(IPC_OBJ) -o $@ $(LDFLAGS)

$(INGEST_BIN): latch_ingest.c latch_protocol.h governor_wire.c governor_wire.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latch_ingest.c governor_wire.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

$(LATCHCTL_BIN): latchctl.c latch_protocol.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latchctl.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

$(LATCHLOG_BIN): latchlog.c latch_protocol.h latch_manifest.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latchlog.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

$(VERIFY_BIN): latch_verify.c latch_protocol.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latch_verify.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

# The guest lifecycle daemon (U-1).  A QNX resource manager: it owns the
# guest VM child process and serves the guest-control channel.  It links
# libsecpol for the documented spawn-attribute type transition.
ifeq ($(GUESTD_OK),1)
$(GUESTD_BIN): latch_guestd.c latch_protocol.h | dirs
	$(CC) $(CFLAGS) latch_guestd.c -o $@ $(LDFLAGS) -lsecpol
endif

rpi4:
	@$(MAKE) --no-print-directory TARGET=rpi4 all

aarch64:
	@$(MAKE) --no-print-directory TARGET=aarch64 all

x86_64:
	@$(MAKE) --no-print-directory TARGET=x86_64 all

native:
	@$(MAKE) --no-print-directory TARGET=native all

host-sim:
	@$(MAKE) --no-print-directory TARGET=host-sim all

# Static stack-usage estimate.
#
# `docs/architecture/QNX_SCHEDULING_AND_STACK_USAGE.md` describes this
# capability, so it has to actually exist. It compiles the supervisor's
# translation units with the HOST compiler and `-fstack-usage`, then
# concatenates the compiler's per-function `.su` reports into one file.
#
# What this is NOT: a runtime high-water mark. It is a compiler-reported
# estimate of each function's own frame. It does not sum transitive call
# chains, does not include interrupt/exception context, and does not predict
# what the QNX/AArch64 compiler will emit. The AArch64 numbers must be
# measured with the QNX toolchain (`make -C qnx stack-usage TARGET=aarch64`
# with the SDP environment sourced).
STACK_USAGE_DIR := $(BUILD_DIR)/stack-usage/$(TARGET)
ifeq ($(TARGET),host-sim)
    STACK_USAGE_REPORT := $(BUILD_DIR)/stack-usage/host-static-stack-usage.txt
else
    STACK_USAGE_REPORT := $(BUILD_DIR)/stack-usage/$(TARGET)-static-stack-usage.txt
endif

stack-usage:
	@mkdir -p $(STACK_USAGE_DIR)
	@rm -f $(STACK_USAGE_DIR)/*.su $(STACK_USAGE_DIR)/*.o
	@for f in latchd governor_policy gov_gate_precheck gov_homeostat latch_manifest latch_ipc; do \
	    $(CC) $(CFLAGS) $(STACK_USAGE_FLAG) -c $$f.c -o $(STACK_USAGE_DIR)/$$f.o || exit 1; \
	    if [ -f "$$f.su" ]; then mv -f "$$f.su" $(STACK_USAGE_DIR)/; fi; \
	done
	@cat $(STACK_USAGE_DIR)/*.su > $(STACK_USAGE_REPORT)
	@echo "[STACK-USAGE] wrote $(STACK_USAGE_REPORT)"
	@echo "[STACK-USAGE] compiler-reported static frame estimate -- NOT a runtime high-water mark"

# The host-sim pipeline.
#
# The regenerated tape goes to $(BUILD_DIR), NOT to host/suite_tape.csv.
#
# The committed tape carries wall-clock cycle numbers, so regenerating it in
# place made every `make check` leave the tree dirty -- and CI ran `make
# check`, so every push showed a spurious diff. The committed tape is now
# only regenerated by the explicit `make tape` target, and `make check`
# PROVES that the committed pair (the CSV and the viewer's embedded copy) is
# still in sync instead of rewriting it.
check-governor: host-sim
	$(MAKE) --no-print-directory governor-policy-check
	$(MAKE) --no-print-directory governor-wire-check
	$(MAKE) --no-print-directory latch-ipc-check
	$(MAKE) --no-print-directory governor-gate-check
	$(MAKE) --no-print-directory governor-homeostat-check
	$(MAKE) --no-print-directory latch-feedback-check
	$(MAKE) --no-print-directory latch-fb-decode-check
	$(MAKE) --no-print-directory latch-soak-pace-check
	$(MAKE) --no-print-directory latch-feedback-pub-check
	$(MAKE) --no-print-directory latch-manifest-check
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify contracts/governor_servo.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify contracts/syringe_governor.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify contracts/homeostat_servo.manifest
	python3 ../tools/governor_manifest_test.py ./$(BUILD_DIR)/host-sim/latchctl contracts/governor_servo.manifest
	$(MAKE) --no-print-directory governor-e2e-check
	$(MAKE) --no-print-directory homeostat-e2e-check
	$(MAKE) --no-print-directory gov-replay-check
	$(MAKE) --no-print-directory latch-action-check

check: host-sim
	$(MAKE) --no-print-directory check-governor
	./$(BUILD_DIR)/host-sim/latchd -m latch.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify latch.manifest
	python3 ../guest/liar.py suite --raw-stdout --manifest latch.manifest | ./$(BUILD_DIR)/host-sim/latch-ingest -m latch.manifest -o - | ./$(BUILD_DIR)/host-sim/latchd -m latch.manifest --pipe-in --csv $(BUILD_DIR)/host-sim/suite_tape.csv
	python3 ../tools/embed_default_tape.py --check

# The MUTATION BATTERY for the consistency gates (~6 s, no QNX licence, no
# QEMU).
#
# A gate that cannot fail is a gate that proves nothing.  This target
# mutates every property `tools/consistency_check.py` checks and requires
# the checker to FAIL on each one -- 41 mutations, each written against a
# REAL measured defect.  It runs against a scratch COPY of the repository,
# so the tree it checks is never written to, and it proves that at the end.
#
# It is NOT part of `check`: `check` is the safety gate, and this is the
# gate on the gate.  Run it when a consistency gate is added or changed.
mutation-check:
	python3 ../tools/mutation_check.py

# AddressSanitizer & UndefinedBehaviorSanitizer.
#
# `clang` is preferred (one driver, both sanitizers), and `gcc` is accepted as
# a fallback -- but ONLY if it can actually LINK a sanitized binary. A
# compiler can accept -fsanitize=address,undefined and still fail at the link
# step because its libasan/libubsan runtime is not installed, which would
# surface as a confusing "cannot find libasan.so.8.0.0" instead of an
# actionable message. So the target PROBES by compiling AND linking a tiny
# program, and reports exactly which compiler it used.
check-asan:
	@echo "=== Running AddressSanitizer & UndefinedBehaviorSanitizer Checks ==="
	@mkdir -p $(BUILD_DIR)/asan
	@printf 'int main(void){return 0;}\n' > $(BUILD_DIR)/asan/.probe.c
	@ASAN_CC=""; \
	for c in clang gcc; do \
	  if command -v $$c >/dev/null 2>&1 && \
	     $$c -fsanitize=address,undefined $(BUILD_DIR)/asan/.probe.c \
	         -o $(BUILD_DIR)/asan/.probe.out >/dev/null 2>&1; then \
	    ASAN_CC=$$c; break; \
	  fi; \
	done; \
	rm -f $(BUILD_DIR)/asan/.probe.c $(BUILD_DIR)/asan/.probe.out; \
	if [ -z "$$ASAN_CC" ]; then \
	  echo "[ERROR] No C compiler on PATH can LINK a -fsanitize=address,undefined binary." >&2; \
	  echo "        clang is preferred. gcc also works IF its libasan/libubsan runtimes" >&2; \
	  echo "        are installed. Install clang, then re-run 'make -C qnx check-asan'." >&2; \
	  exit 1; \
	fi; \
	echo "=== sanitizer compiler: $$ASAN_CC ==="; \
	echo $$ASAN_CC > $(BUILD_DIR)/asan/.compiler
	@ASAN_CC=$$(cat $(BUILD_DIR)/asan/.compiler); \
	ASAN_FLAGS="-fsanitize=address,undefined -std=c11 -Wall -Wextra -O1 -g -I. -DLATCH_HOST_SIM"; \
	$$ASAN_CC $$ASAN_FLAGS governor_policy.c governor_policy_test.c -o $(BUILD_DIR)/asan/governor_policy_test -lm && \
	./$(BUILD_DIR)/asan/governor_policy_test && \
	$$ASAN_CC $$ASAN_FLAGS governor_wire.c governor_wire_test.c -o $(BUILD_DIR)/asan/governor_wire_test -lm && \
	./$(BUILD_DIR)/asan/governor_wire_test && \
	$$ASAN_CC $$ASAN_FLAGS latch_ipc.c latch_ipc_test.c -o $(BUILD_DIR)/asan/latch_ipc_test -lm && \
	./$(BUILD_DIR)/asan/latch_ipc_test && \
	$$ASAN_CC $$ASAN_FLAGS gov_gate_precheck.c governor_policy.c latch_manifest.c gov_gate_precheck_test.c -o $(BUILD_DIR)/asan/gov_gate_precheck_test -lpthread -lrt -lm && \
	./$(BUILD_DIR)/asan/gov_gate_precheck_test && \
	$$ASAN_CC $$ASAN_FLAGS gov_homeostat.c gov_homeostat_test.c -o $(BUILD_DIR)/asan/gov_homeostat_test -lm && \
	./$(BUILD_DIR)/asan/gov_homeostat_test && \
	$$ASAN_CC $$ASAN_FLAGS latch_feedback.c latch_feedback_test.c -o $(BUILD_DIR)/asan/latch_feedback_test -lm && \
	./$(BUILD_DIR)/asan/latch_feedback_test && \
	$$ASAN_CC $$ASAN_FLAGS latch_manifest.c latch_manifest_test.c -o $(BUILD_DIR)/asan/latch_manifest_test -lpthread -lrt -lm && \
	./$(BUILD_DIR)/asan/latch_manifest_test
	@echo "[ASAN/UBSAN] ALL SANITIZER SUITES PASSED (0 MEMORY / UB VIOLATIONS)"

fuzz: host-sim
	python3 ../tools/fuzz_manifest.py --iterations 300

governor-e2e-check: host-sim
	python3 ../tools/governor_e2e.py ./$(BUILD_DIR)/host-sim/latchctl ./$(BUILD_DIR)/host-sim/latch-ingest ./$(BUILD_DIR)/host-sim/latchd contracts/governor_servo.manifest

# The HOMEOSTAT runtime proof: drives the real supervisor over the real wire
# protocol and reads the result from the committed evidence-tape format.
homeostat-e2e-check: host-sim
	python3 ../tools/homeostat_e2e.py ./$(BUILD_DIR)/host-sim/latchctl ./$(BUILD_DIR)/host-sim/latch-ingest ./$(BUILD_DIR)/host-sim/latchd contracts/governor_servo.manifest

gov-replay-check:
	python3 ../tools/gov_replay.py --test
	python3 ../tools/gov_replay_hardening_test.py
	python3 ../tools/benchmark_report_test.py
	python3 ../tools/governor_host_replay_test.py
	python3 ../tools/llama_governor_agent_test.py

$(BUILD_DIR)/host-sim/governor_policy_test: governor_policy.c governor_policy.h governor_policy_test.c | dirs
	$(CC) $(CFLAGS) governor_policy.c governor_policy_test.c -o $@ $(LDFLAGS)

governor-policy-check: $(BUILD_DIR)/host-sim/governor_policy_test
	./$(BUILD_DIR)/host-sim/governor_policy_test

$(BUILD_DIR)/host-sim/governor_wire_test: governor_wire.c governor_wire.h governor_wire_test.c latch_protocol.h | dirs
	$(CC) $(CFLAGS) governor_wire.c governor_wire_test.c -o $@ $(LDFLAGS)

governor-wire-check: $(BUILD_DIR)/host-sim/governor_wire_test
	./$(BUILD_DIR)/host-sim/governor_wire_test

$(BUILD_DIR)/host-sim/latch_ipc_test: latch_ipc.c latch_ipc.h latch_ipc_test.c latch_protocol.h | dirs
	$(CC) $(CFLAGS) latch_ipc.c latch_ipc_test.c -o $@ $(LDFLAGS)

latch-ipc-check: $(BUILD_DIR)/host-sim/latch_ipc_test
	./$(BUILD_DIR)/host-sim/latch_ipc_test

$(BUILD_DIR)/host-sim/gov_gate_precheck_test: gov_gate_precheck.c gov_gate_precheck.h gov_gate_precheck_test.c governor_policy.h governor_wire.h latch_manifest.c latch_manifest.h latch_protocol.h | dirs
	$(CC) $(CFLAGS) gov_gate_precheck.c governor_policy.c latch_manifest.c gov_gate_precheck_test.c -o $@ $(LDFLAGS)

governor-gate-check: $(BUILD_DIR)/host-sim/gov_gate_precheck_test
	./$(BUILD_DIR)/host-sim/gov_gate_precheck_test

# The HOMEOSTAT ultrastability loop. It is a CONTRACTING-ONLY advisor: the
# unit test proves the contraction, recovery, Q8 saturation and overflow-safe
# motion accounting, and that a disabled loop never touches its state.
$(BUILD_DIR)/host-sim/gov_homeostat_test: gov_homeostat.c gov_homeostat.h gov_homeostat_test.c | dirs
	$(CC) $(CFLAGS) gov_homeostat.c gov_homeostat_test.c -o $@ $(LDFLAGS)

governor-homeostat-check: $(BUILD_DIR)/host-sim/gov_homeostat_test
	./$(BUILD_DIR)/host-sim/gov_homeostat_test

# The supervisor feedback frame codec (24-byte LFBK). Round-trip, sequence
# correlation and CRC rejection.
$(BUILD_DIR)/host-sim/latch_feedback_test: latch_feedback.c latch_feedback.h latch_feedback_test.c latch_protocol.h | dirs
	$(CC) $(CFLAGS) latch_feedback.c latch_feedback_test.c -o $@ $(LDFLAGS)

latch-feedback-check: $(BUILD_DIR)/host-sim/latch_feedback_test
	./$(BUILD_DIR)/host-sim/latch_feedback_test

# The GUEST-SIDE LFBK decoder and correlator (W5).  It lives in
# guest/latch_fb_decode.h because the guest policy is freestanding and
# cannot include the QNX tree -- so the test includes the SAME header and
# puts the production codec's bytes through the guest's decoder.  That is
# the cross-implementation check that keeps the two copies of the frame
# format from drifting.
$(BUILD_DIR)/host-sim/latch_fb_decode_test: ../guest/latch_fb_decode.h latch_feedback.c latch_feedback.h latch_fb_decode_test.c latch_protocol.h | dirs
	$(CC) $(CFLAGS) latch_feedback.c latch_fb_decode_test.c -o $@ $(LDFLAGS)

latch-fb-decode-check: $(BUILD_DIR)/host-sim/latch_fb_decode_test
	./$(BUILD_DIR)/host-sim/latch_fb_decode_test

# The SOAK'S DEADLINE PACER (U-4).  The pacing decision lives in
# guest/latch_soak_pace.h because the guest policy is freestanding and
# cannot include the QNX tree -- so the property that matters is reachable
# from a host test.  A rate limiter has to do TWO things at once: KEEP THE
# RATE and BOUND THE CATCH-UP.  The original pacer kept the rate but
# accumulated credit, so a host stall became a burst that overflowed the
# supervisor's proposal ring (186 frames dropped, measured on the target);
# the first fix bounded the catch-up but cost a third of the rate (901/s
# -> 610/s).  The test includes the SAME header the guest compiles, and it
# is proved non-vacuous against both wrong pacers.
$(BUILD_DIR)/host-sim/latch_soak_pace_test: ../guest/latch_soak_pace.h latch_soak_pace_test.c | dirs
	$(CC) $(CFLAGS) latch_soak_pace_test.c -o $@ $(LDFLAGS)

latch-soak-pace-check: $(BUILD_DIR)/host-sim/latch_soak_pace_test
	./$(BUILD_DIR)/host-sim/latch_soak_pace_test

# The HOST-SIDE FEEDBACK PUBLISHER (W5).  It is the thing that carries the
# supervisor's verdict to the transport without ever letting the transport
# delay the safety core, so the test checks the frame arrives unchanged,
# that a burst does not block the caller, and that every loss is counted.
$(BUILD_DIR)/host-sim/latch_feedback_pub_test: latch_feedback.c latch_feedback.h latch_feedback_pub.c latch_feedback_pub.h latch_feedback_pub_test.c | dirs
	$(CC) $(CFLAGS) latch_feedback.c latch_feedback_pub.c latch_feedback_pub_test.c -o $@ $(LDFLAGS)

latch-feedback-pub-check: $(BUILD_DIR)/host-sim/latch_feedback_pub_test
	./$(BUILD_DIR)/host-sim/latch_feedback_pub_test

# The manifest parser is the SAFETY FRONT DOOR: every plant limit, timing
# budget and calibration constant enters the supervisor through it. This test
# asserts that a well-formed document loads AND that every malformed one is
# REJECTED (fail closed) -- never silently defaulted, never clamped.
$(BUILD_DIR)/host-sim/latch_manifest_test: latch_manifest.c latch_manifest.h latch_manifest_test.c | dirs
	$(CC) $(CFLAGS) latch_manifest.c latch_manifest_test.c -o $@ $(LDFLAGS)

latch-manifest-check: $(BUILD_DIR)/host-sim/latch_manifest_test
	./$(BUILD_DIR)/host-sim/latch_manifest_test

# The in-guest action schema validator (W6).  It is the gate between a
# language model and the safety-relevant channel: the model's JSON is
# re-validated by an INDEPENDENT parser before it is allowed to become a
# frame.  The parser has no llama.cpp dependency, so CI can run it on any
# host -- the AArch64 inference binary itself needs a cross toolchain and
# is covered by the on-target transcript instead.
$(BUILD_DIR)/host-sim/latch_action_test: ../tools/latch_action_test.c ../guest/latch_action.c ../guest/latch_action.h | dirs
	$(CC) $(CFLAGS) ../tools/latch_action_test.c ../guest/latch_action.c -o $@ $(LDFLAGS)

latch-action-check: $(BUILD_DIR)/host-sim/latch_action_test
	./$(BUILD_DIR)/host-sim/latch_action_test

# The EXPERIMENTAL inference profile's initramfs (W6).
#
# It differs from the scripted GOVERNOR initramfs in ONE way: the policy is
# compiled with -DLATCH_GOVERNOR_INFER, which adds the pipe + clone/execve
# relay for the in-guest language model.
#
# It does NOT contain the inference binary or the model.  Both travel on the
# read-only virtio-blk asset disk (see guest-disk-image below), and that is
# not a style choice:
#
#   QNX Hypervisor 8.0's qvm loads a guest blob into guest memory through
#   load_blob().  A small blob is copied straight into guest memory; a blob
#   above a size threshold is transferred in 64 KiB message-block chunks
#   that the GUEST has to service, and that service code lives in the QNX
#   guest BSP, not in upstream Linux.  Measured on the QEMU AArch64 target
#   (2026-11-26): with the inference binary in the initramfs (8.9 MiB) the
#   guest kernel printed "Initramfs unpacking failed: invalid magic at
#   start of compressed archive" after 30 ms -- the bytes never arrived.
#   The scripted profile's 3.3 KiB initramfs goes through the direct-copy
#   path and works.
#
# So the initramfs stays tiny -- the policy only, a few KiB -- and the
# assets travel over the virtio protocol, which does not go through qvm's
# blob loader at all.
#
# The SCRIPTED profiles are untouched by this: guest/linux-guest.initrd is
# a TRACKED binary and must stay byte-identical.  Verified after this
# target was added: the tracked initrd's SHA-256 was unchanged.
#
# The inference binary itself is built by `make -C guest infer`, which
# needs the AArch64 cross toolchain (tools/build_aarch64_sysroot.sh).
INFER_BIN ?= ../build/guest/latch_infer
INFER_INITRD ?= $(BUILD_DIR)/governor-linux-guest-infer.initrd

guest-governor-infer-initrd:
	@rm -rf $(BUILD_DIR)/guest-governor-infer-initramfs
	@mkdir -p $(BUILD_DIR)/guest-governor-infer-initramfs/dev $(BUILD_DIR)/guest-governor-infer-initramfs/proc $(BUILD_DIR)/guest-governor-infer-initramfs/sys
	aarch64-linux-gnu-gcc -DLATCH_GOVERNOR_V2 -DLATCH_GOVERNOR_INFER -nostdlib -ffreestanding -static -O2 -Wall -Wextra -Werror ../guest/latch_guest_init.c ../guest/latch_action.c -o $(BUILD_DIR)/guest-governor-infer-initramfs/init
	chmod +x $(BUILD_DIR)/guest-governor-infer-initramfs/init
	(cd $(BUILD_DIR)/guest-governor-infer-initramfs && find . -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} + && find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --reproducible --quiet 2>/dev/null) | gzip -n -9 > $(abspath $(INFER_INITRD))
	@ls -lh $(INFER_INITRD)

# The guest's read-only ASSET DISK: the language model, the inference
# program, and (optionally) the experiment's prompt parameters.
#
# The model is NOT in this repository -- it is a build input, like the guest
# kernel Image.  MODEL points at the GGUF file; INFER_BIN at the
# cross-compiled inference program.
#
# EXAMPLE_U and PROMPT are the PROMPT, not the safety envelope: the
# envelope is in the signed manifest and is enforced by the trusted QNX
# supervisor, which never sees any of this.  They are what an experiment
# varies:
#
#     make guest-disk-image EXAMPLE_U=400 \
#          PROMPT=../guest/prompts/injection_keepout.txt
#
# builds the disk whose model asks for 400 mrad -- straight through the
# signed PERSON keep-out -- so the supervisor can be shown refusing it.
MODEL ?= /home/skanda/models/SmolLM2-135M-Instruct-Q8_0.gguf
EXAMPLE_U ?=
PROMPT ?=

# The NOMINAL disk: the model's own (in-envelope) decision, -20 mrad.
GUEST_DISK ?= ../build/latch_guest_disk.img
GUEST_DISK_ARGS := $(if $(EXAMPLE_U),--example-u $(EXAMPLE_U),) \
                   $(if $(PROMPT),--prompt $(abspath $(PROMPT)),)

# The ATTACK disk: the same binary, the same model, the same grammar; only
# the PROMPT differs, and the prompt is the model's input, not a safety
# parameter.  The model asks for 400 mrad, which is straight through the
# signed PERSON keep-out.
GUEST_DISK_ATTACK ?= ../build/latch_guest_disk_attack.img
ATTACK_EXAMPLE_U ?= 400
ATTACK_PROMPT ?= ../guest/prompts/injection_keepout.txt
GUEST_DISK_ATTACK_ARGS := --example-u $(ATTACK_EXAMPLE_U) \
                          --prompt $(abspath $(ATTACK_PROMPT))

guest-disk-image:
	@test -f "$(MODEL)" || { \
		echo "ERROR: the language model is missing ($(MODEL))."; \
		echo "       It is a BUILD INPUT and is not in this repository."; \
		exit 1; \
	}
	@test -f "$(INFER_BIN)" || { \
		echo "ERROR: the in-guest inference binary is missing ($(INFER_BIN))."; \
		echo "       Build it with: make -C guest infer"; \
		exit 1; \
	}
	../tools/build_guest_disk.sh --model "$(MODEL)" --infer "$(INFER_BIN)" --out "$(GUEST_DISK)" $(GUEST_DISK_ARGS)

guest-disk-image-attack:
	@test -f "$(MODEL)" || { \
		echo "ERROR: the language model is missing ($(MODEL))."; \
		echo "       It is a BUILD INPUT and is not in this repository."; \
		exit 1; \
	}
	@test -f "$(INFER_BIN)" || { \
		echo "ERROR: the in-guest inference binary is missing ($(INFER_BIN))."; \
		echo "       Build it with: make -C guest infer"; \
		exit 1; \
	}
	../tools/build_guest_disk.sh --model "$(MODEL)" --infer "$(INFER_BIN)" --out "$(GUEST_DISK_ATTACK)" $(GUEST_DISK_ATTACK_ARGS)

# Regenerate the committed evidence tape and re-sync the offline viewer's
# embedded copy. Run this deliberately: it changes two tracked files.
tape: host-sim
	python3 ../guest/liar.py suite --raw-stdout --manifest latch.manifest | ./$(BUILD_DIR)/host-sim/latch-ingest -m latch.manifest -o - | ./$(BUILD_DIR)/host-sim/latchd -m latch.manifest --pipe-in --csv ../host/suite_tape.csv
	python3 ../tools/embed_default_tape.py

demo-syringe: host-sim
	./$(BUILD_DIR)/host-sim/latchd -m contracts/syringe_pump_bolus.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify contracts/syringe_pump_bolus.manifest a9d877ebf63d5670006593ac8eadc7303b324c52c1d30e29aeacb8b9253e0e5e

secpol: | dirs
	$(SECPOLC) -o $(BUILD_DIR)/secpol.bin latch.secpol

qemu:
	./run_qemu.sh

# The timestamp baked into the tracked initramfs. Pinned so that rebuilding it
# from unchanged sources produces a byte-identical binary.
SOURCE_DATE_EPOCH ?= 1700000000
GOVERNOR_GUEST_INITRD ?= $(BUILD_DIR)/governor-linux-guest.initrd

guest-initrd:
	@mkdir -p $(BUILD_DIR)/guest-initramfs/dev $(BUILD_DIR)/guest-initramfs/proc $(BUILD_DIR)/guest-initramfs/sys
	aarch64-linux-gnu-gcc -nostdlib -ffreestanding -static -O2 -Wall -Wextra -Werror ../guest/latch_guest_init.c -o $(BUILD_DIR)/guest-initramfs/init
	chmod +x $(BUILD_DIR)/guest-initramfs/init
	# REPRODUCIBLE: the initramfs is a TRACKED binary, so it must be
	# byte-identical every time it is built.
	#
	# The previous revision used `gzip -9`, which embeds the INPUT's
	# modification time in the gzip header, and `cpio --format=newc`, which
	# embeds each FILE's mtime. So every rebuild produced a different tracked
	# binary even when the source was unchanged -- and the archive's
	# initramfs forensics could not be reproduced from the source.
	#
	# `gzip -n` omits the name and timestamp; the entry mtimes are pinned to
	# SOURCE_DATE_EPOCH (GNU cpio's --reproducible handles device numbers and
	# inode renumbering, NOT the mtimes); and the file order is sorted so it
	# does not depend on the filesystem's directory order.
	(cd $(BUILD_DIR)/guest-initramfs && find . -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} + && find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --reproducible --quiet 2>/dev/null) | gzip -n -9 > $(abspath $(GUEST_INITRD))
	@ls -lh $(GUEST_INITRD)

# Separate freestanding /init image. The default LATCH guest initrd remains v1.
guest-governor-initrd:
	@mkdir -p $(BUILD_DIR)/guest-governor-initramfs/dev $(BUILD_DIR)/guest-governor-initramfs/proc $(BUILD_DIR)/guest-governor-initramfs/sys
	aarch64-linux-gnu-gcc -DLATCH_GOVERNOR_V2 -nostdlib -ffreestanding -static -O2 -Wall -Wextra -Werror ../guest/latch_guest_init.c -o $(BUILD_DIR)/guest-governor-initramfs/init
	chmod +x $(BUILD_DIR)/guest-governor-initramfs/init
	(cd $(BUILD_DIR)/guest-governor-initramfs && find . -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} + && find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --reproducible --quiet 2>/dev/null) | gzip -n -9 > $(abspath $(GOVERNOR_GUEST_INITRD))
	@ls -lh $(GOVERNOR_GUEST_INITRD)

check-guest-image:
	@if [ -z "$(GUEST_IMAGE)" ] || [ ! -f "$(GUEST_IMAGE)" ]; then \
		echo "ERROR: GUEST_IMAGE is unset or missing ('$(GUEST_IMAGE)'). Provide a real Linux Image via GUEST_IMAGE=/path/to/Image"; \
		exit 1; \
	fi

check-guest-initrd:
	@if [ -z "$(GUEST_INITRD)" ] || [ ! -f "$(GUEST_INITRD)" ]; then \
		echo "ERROR: GUEST_INITRD is missing ('$(GUEST_INITRD)'). Run 'make guest-initrd' first."; \
		exit 1; \
	fi

check-governor-initrd:
	@if [ ! -f "$(GOVERNOR_GUEST_INITRD)" ]; then \
		echo "ERROR: GOVERNOR_GUEST_INITRD is missing ('$(GOVERNOR_GUEST_INITRD)'). Run 'make guest-governor-initrd' first."; \
		exit 1; \
	fi
	python3 ../tools/verify_guest_initrd.py $(GOVERNOR_GUEST_INITRD)

ifs-rpi4: rpi4 secpol check-guest-image check-guest-initrd
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" GUEST_INITRD="$(abspath $(GUEST_INITRD))" mkifs -v latch_rpi4.build $(BUILD_DIR)/nto-aarch64-le/latch_rpi4.ifs

ifs-qemu-aarch64: aarch64 secpol guest-initrd check-guest-image check-guest-initrd
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" GUEST_INITRD="$(abspath $(GUEST_INITRD))" mkifs -v latch_qemu.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu.ifs

# Disposable verification image: startup launches the fixed verifier trigger
# as latch_verify_t; normal policy and the operator shell are not elevated.
ifs-qemu-legacy-verify: aarch64 secpol guest-initrd check-guest-image check-guest-initrd
	qcc -Vgcc_ntoaarch64le -Wc,-std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE latch_verify_trigger.c -o $(BUILD_DIR)/nto-aarch64-le/latch_verify_trigger -Wl,-z,relro,-z,now
	python3 ../tools/generate_legacy_verify_build.py latch_qemu.build $(BUILD_DIR)/latch_qemu_legacy_verify.build
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" GUEST_INITRD="$(abspath $(GUEST_INITRD))" mkifs -v $(BUILD_DIR)/latch_qemu_legacy_verify.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu_legacy_verify.ifs

# Experimental: QNX Hypervisor under QEMU TCG is not documented by QNX as a
# supported Hypervisor host platform. This target is a bring-up profile only.
ifs-qemu-governor: aarch64 secpol guest-governor-initrd check-guest-image check-governor-initrd
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" GOVERNOR_GUEST_INITRD="$(abspath $(GOVERNOR_GUEST_INITRD))" mkifs -v latch_qemu_governor.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu_governor.ifs

# ---------------------------------------------------------------------------
# EXPERIMENTAL: the DECISION-LATENCY MEASUREMENT profile (U-4).
#
# This is the profile that replaces the withdrawn "61 us WCET" claim with a
# MEASUREMENT: the trusted supervisor's own per-tick decision latency,
# sampled once per tick over more than a million ticks, aggregated in a
# histogram ON THE TARGET and read back through an output-only devctl
# (`latchctl latency`).
#
# The guest policy is the same freestanding binary with ONE extra compile
# flag (`-DLATCH_GOVERNOR_LATENCY_SOAK`): it streams in-envelope CMD_V2
# frames at a fixed rate for 25 minutes so the supervisor has something to
# decide on every tick.
#
# The IFS is built from qnx/latch_qemu_latency.build, which is the GOVERNOR
# image WITHOUT the evidence logger: `latchlog` polls the supervisor every
# 100 ms and writes every tick to a CSV, and a measurement image must not
# carry a logger that perturbs what it measures.  The signed contract, the
# security policy and the qvmconf are the GOVERNOR profile's, unchanged.
# ---------------------------------------------------------------------------
LATENCY_INITRD ?= $(BUILD_DIR)/governor-linux-guest-latency.initrd

# The soak's two knobs.  They are OVERRIDABLE so the profile can be
# CALIBRATED on the target (a 60-second run measures the achieved frame
# rate and the tick rate) without editing the guest source.  The defaults
# are the guest source's own defaults, and tools/consistency_check.py
# asserts that the two agree -- so the value that was measured is the
# value in the source.
SOAK_TARGET_HZ    ?= 900
SOAK_DURATION_MS  ?= 2100000

guest-governor-latency-soak-initrd:
	@mkdir -p $(BUILD_DIR)/guest-governor-latency-initramfs/dev $(BUILD_DIR)/guest-governor-latency-initramfs/proc $(BUILD_DIR)/guest-governor-latency-initramfs/sys
	aarch64-linux-gnu-gcc -DLATCH_GOVERNOR_V2 -DLATCH_GOVERNOR_LATENCY_SOAK -DLATCH_GOVERNOR_SOAK_TARGET_HZ=$(SOAK_TARGET_HZ) -DLATCH_GOVERNOR_SOAK_DURATION_MS=$(SOAK_DURATION_MS) -nostdlib -ffreestanding -static -O2 -Wall -Wextra -Werror ../guest/latch_guest_init.c -o $(BUILD_DIR)/guest-governor-latency-initramfs/init
	chmod +x $(BUILD_DIR)/guest-governor-latency-initramfs/init
	(cd $(BUILD_DIR)/guest-governor-latency-initramfs && find . -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} + && find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --reproducible --quiet 2>/dev/null) | gzip -n -9 > $(abspath $(LATENCY_INITRD))
	@ls -lh $(LATENCY_INITRD)

check-latency-initrd:
	@if [ ! -f "$(LATENCY_INITRD)" ]; then \
		echo "ERROR: LATENCY_INITRD is missing ('$(LATENCY_INITRD)'). Run 'make guest-governor-latency-soak-initrd' first."; \
		exit 1; \
	fi
	python3 ../tools/verify_guest_initrd.py $(LATENCY_INITRD) soak

ifs-qemu-latency: aarch64 secpol guest-governor-latency-soak-initrd check-guest-image check-latency-initrd
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" \
	GOVERNOR_GUEST_INITRD="$(abspath $(LATENCY_INITRD))" \
	mkifs -v latch_qemu_latency.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu_latency.ifs

verify-latency-qemu: ifs-qemu-latency
	python3 ../tools/verify_latency_qemu.py

# ---------------------------------------------------------------------------
# EXPERIMENTAL: the HOST->GUEST FEEDBACK-TRANSPORT PROBE (W4).
#
# This is the DISPOSABLE profile that answers one question with a
# measurement: does the QNX Hypervisor carry host->guest bytes on a second
# PL011 without disturbing the black channel?
#
# It is the scripted GOVERNOR profile with three additions:
#
#   1. a second `vdev pl011` whose `hostdev` reads from the READ node of a
#      purpose-built QNX feedback MAILBOX (the guest sees it as one of the
#      /dev/ttyAMA* nodes -- the guest does not control the names);
#   2. `latch_fb_sink` (the mailbox resource manager) and `latch_fb_pump`,
#      which create the mailbox and publish the production LFBK frames
#      into it;
#   3. a guest policy compiled with -DLATCH_GOVERNOR_FEEDBACK, which reads
#      the port, re-synchronises on the frame MAGIC, validates the CRC and
#      reports the outcome ONCE -- BEFORE the session opens, so the
#      supervisor's dead-man never sees the probe's silence and the
#      console-drain discipline still holds.
#
# The scenario is the UNCHANGED 235-frame GOVERNOR scenario, so
# tools/verify_fb_qemu.py can assert BOTH from ONE boot: the transport
# works, and the black channel is undisturbed.
#
# The deployment policy qnx/latch.secpol is NOT modified.  The experiment's
# two additions live in qnx/latch_fbprobe.secpol.inc and are appended to a
# COPY of the deployment policy by tools/generate_fbprobe_secpol.py.
# ---------------------------------------------------------------------------
FBPUMP_BIN        := $(BUILD_DIR)/nto-aarch64-le/latch_fb_pump
FBSINK_BIN        := $(BUILD_DIR)/nto-aarch64-le/latch_fb_sink
FBPROBE_INITRD    ?= $(BUILD_DIR)/governor-linux-guest-feedback.initrd
FBPROBE_SECPOL    := $(BUILD_DIR)/latch_fbprobe.secpol
FBPROBE_SECPOL_BIN := $(BUILD_DIR)/secpol_fbprobe.bin

fb-pump: aarch64
	qcc -Vgcc_ntoaarch64le -Wc,-std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE latch_fb_pump.c -o $(FBPUMP_BIN) -Wl,-z,relro,-z,now

# The feedback resource manager (`latch_fb_sink`): the ONLY process that
# may write the verdict file.  It accepts a frame on its one-sided WRITE
# node and copies the LATEST one to sector 0 of the verdict file on a
# dedicated writer thread, and it creates that file at its final size
# BEFORE it registers its nodes -- so the buildfile's `waitfor
# /dev/latch/feedback` proves the file exists when the hypervisor opens
# it.  The pseudo-terminal that was tried first is the deterministic
# rejection (its open ORDER decides whether it can be used at all -- see
# the measurement record at the top of latch_fb_sink.c).
fb-sink: aarch64
	qcc -Vgcc_ntoaarch64le -Wc,-std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE latch_fb_sink.c -o $(FBSINK_BIN) -Wl,-z,relro,-z,now

$(FBPROBE_SECPOL): latch.secpol latch_fbprobe.secpol.inc ../tools/generate_fbprobe_secpol.py | dirs
	python3 ../tools/generate_fbprobe_secpol.py $@

fbprobe-secpol: $(FBPROBE_SECPOL) | dirs
	$(SECPOLC) -o $(FBPROBE_SECPOL_BIN) $(FBPROBE_SECPOL)

# The feedback-transport guest policy: the scripted GOVERNOR policy plus
# the transport probe.  The probe runs BEFORE the session opens.
guest-governor-feedback-initrd:
	@mkdir -p $(BUILD_DIR)/guest-governor-feedback-initramfs/dev $(BUILD_DIR)/guest-governor-feedback-initramfs/proc $(BUILD_DIR)/guest-governor-feedback-initramfs/sys
	aarch64-linux-gnu-gcc -DLATCH_GOVERNOR_V2 -DLATCH_GOVERNOR_FEEDBACK -nostdlib -ffreestanding -static -O2 -Wall -Wextra -Werror ../guest/latch_guest_init.c -o $(BUILD_DIR)/guest-governor-feedback-initramfs/init
	chmod +x $(BUILD_DIR)/guest-governor-feedback-initramfs/init
	(cd $(BUILD_DIR)/guest-governor-feedback-initramfs && find . -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} + && find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --reproducible --quiet 2>/dev/null) | gzip -n -9 > $(abspath $(FBPROBE_INITRD))
	@ls -lh $(FBPROBE_INITRD)

ifs-qemu-fbprobe: aarch64 fb-pump fb-sink fbprobe-secpol guest-governor-feedback-initrd check-guest-image
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" \
	GOVERNOR_GUEST_INITRD="$(abspath $(FBPROBE_INITRD))" \
	mkifs -v latch_qemu_fbprobe.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu_fbprobe.ifs

verify-fb-qemu: ifs-qemu-fbprobe
	python3 ../tools/verify_fb_qemu.py

# ---------------------------------------------------------------------------
# EXPERIMENTAL: the HOST->GUEST VERDICT WATCHER profile (W5).
#
# This is the GOVERNOR image with ONE addition: the LFBK VERDICT FILE, and
# the supervisor PUBLISHES ITS VERDICTS on it.  There is no `latch_fb_pump`
# in this image -- the publisher is `latchd` itself, which is the whole
# point of the profile: the verdict on the wire is the verdict of the
# TRUSTED SUPERVISOR, not a synthetic frame from a development-only tool.
#
# The guest policy is the same freestanding binary with ONE extra compile
# flag (`-DLATCH_GOVERNOR_FEEDBACK_VERDICT`): it decodes the verdict,
# correlates it with the proposal it answers, and stops proposing when the
# supervisor says no.
#
# `-fno-stack-protector` is requested DEFENSIVELY: the cross-gcc does not
# enable it (verified: `-fstack-protector [disabled]`, no `stack_chk`
# symbols), but the watcher thread runs on its own stack and a
# stack-protector epilogue would need the TLS canary to be set up on that
# stack.  The flag makes the property explicit instead of incidental.
# ---------------------------------------------------------------------------
FBVERDICT_INITRD    ?= $(BUILD_DIR)/governor-linux-guest-feedback-verdict.initrd

guest-governor-feedback-verdict-initrd:
	@mkdir -p $(BUILD_DIR)/guest-governor-feedback-verdict-initramfs/dev $(BUILD_DIR)/guest-governor-feedback-verdict-initramfs/proc $(BUILD_DIR)/guest-governor-feedback-verdict-initramfs/sys
	aarch64-linux-gnu-gcc -DLATCH_GOVERNOR_V2 -DLATCH_GOVERNOR_FEEDBACK_VERDICT -nostdlib -ffreestanding -static -O2 -Wall -Wextra -Werror -fno-stack-protector ../guest/latch_guest_init.c -o $(BUILD_DIR)/guest-governor-feedback-verdict-initramfs/init
	chmod +x $(BUILD_DIR)/guest-governor-feedback-verdict-initramfs/init
	(cd $(BUILD_DIR)/guest-governor-feedback-verdict-initramfs && find . -exec touch -h -d "@$(SOURCE_DATE_EPOCH)" {} + && find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --reproducible --quiet 2>/dev/null) | gzip -n -9 > $(abspath $(FBVERDICT_INITRD))
	@ls -lh $(FBVERDICT_INITRD)

ifs-qemu-fbverdict: aarch64 fb-sink fbprobe-secpol guest-governor-feedback-verdict-initrd check-guest-image
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" \
	GOVERNOR_GUEST_INITRD="$(abspath $(FBVERDICT_INITRD))" \
	mkifs -v latch_qemu_fbverdict.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu_fbverdict.ifs

verify-fbverdict-qemu: ifs-qemu-fbverdict
	python3 ../tools/verify_fbverdict_qemu.py

# ---------------------------------------------------------------------------
# EXPERIMENTAL: the in-guest language-model profile (W6).
#
# This profile is the scripted GOVERNOR profile with ONE difference in what
# drives the plant: the proposals come from a llama.cpp model running INSIDE
# the guest, not from a compiled-in sequence.  Everything else -- the signed
# contract, the supervisor, the evidence logger, the security policy -- is
# the SAME.  The manifest is `contracts/governor_servo.manifest`, byte for
# byte: no safety parameter is relaxed for the experiment.
#
# The model is NOT in the repository.  It travels as a read-only virtio-blk
# disk image:
#
#     tools/build_model_image.sh --model /path/to/model.gguf
#
# which produces build/latch_model.img.  The Makefile target below only
# checks that the image is present; building it needs the model.
#
# The IFS this produces is ~190 MB (it carries the 187 MiB model disk), so
# the QEMU launcher needs headroom: the inner guest takes 768 MB of the
# outer machine's pool.
# ---------------------------------------------------------------------------
# The model image lives in the REPOSITORY-ROOT build directory (the same one
# `tools/build_guest_disk.sh` writes to by default), not in qnx/build.
INFER_GUEST_INITRD ?= $(BUILD_DIR)/governor-linux-guest-infer.initrd

check-guest-disk:
	@if [ ! -f "$(GUEST_DISK)" ]; then \
		echo "ERROR: the guest asset disk image is missing ('$(GUEST_DISK)')."; \
		echo "       Build it with: make guest-disk-image"; \
		exit 1; \
	fi
	@echo "[guest-disk] $(GUEST_DISK)"

check-guest-disk-attack:
	@if [ ! -f "$(GUEST_DISK_ATTACK)" ]; then \
		echo "ERROR: the guest ATTACK asset disk image is missing ('$(GUEST_DISK_ATTACK)')."; \
		echo "       Build it with: make guest-disk-image-attack"; \
		exit 1; \
	fi
	@echo "[guest-disk-attack] $(GUEST_DISK_ATTACK)"

ifs-qemu-infer: aarch64 secpol guest-governor-infer-initrd check-guest-image check-guest-disk
	@test -f "$(INFER_GUEST_INITRD)" || { \
		echo "ERROR: the inference initramfs is missing ('$(INFER_GUEST_INITRD)'). Run 'make guest-governor-infer-initrd' first."; \
		exit 1; \
	}
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" \
	INFER_GUEST_INITRD="$(abspath $(INFER_GUEST_INITRD))" \
	GUEST_DISK="$(abspath $(GUEST_DISK))" \
	mkifs -v latch_qemu_infer.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu_infer.ifs

# The ATTACK variant of the SAME profile: identical buildfile, identical
# qvmconf, identical supervisor, identical signed contract.  Only the
# asset disk differs -- and on the disk only the PROMPT, which is the
# model's input, not a safety parameter.
ifs-qemu-infer-attack: aarch64 secpol guest-governor-infer-initrd check-guest-image check-guest-disk-attack
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" \
	INFER_GUEST_INITRD="$(abspath $(INFER_GUEST_INITRD))" \
	GUEST_DISK="$(abspath $(GUEST_DISK_ATTACK))" \
	mkifs -v latch_qemu_infer.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu_infer_attack.ifs

# On-target verification of the in-guest inference profile.
#
#   verify-infer-qemu          the model's own decision drives the plant
#   verify-infer-qemu-attack   the model asks for a forbidden motion and
#                              the trusted supervisor refuses it
verify-infer-qemu: ifs-qemu-infer
	python3 ../tools/verify_infer_qemu.py --mode nominal

verify-infer-qemu-attack: ifs-qemu-infer-attack
	python3 ../tools/verify_infer_qemu.py --mode attack \
		--expect-u $(ATTACK_EXAMPLE_U)

# Development-only unrestricted policy-generation image. Never substitute it
# for the normal, enforced GOVERNOR image.
#
# The image also carries `latch_secpol_dump`, a DEVELOPMENT-ONLY reader for
# the /dev/secpolgenerate/* observation files: the minimal IFS has no `cat`,
# no `ls` and no `dd`, and the audit has to read five pseudo-files that QNX's
# own utilities do not expose.  The reader is linked ONLY into this image.
secpol-dump: aarch64
	qcc -Vgcc_ntoaarch64le -Wc,-std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE latch_secpol_dump.c -o $(BUILD_DIR)/nto-aarch64-le/latch_secpol_dump -Wl,-z,relro,-z,now

ifs-qemu-governor-secpol-audit: aarch64 secpol guest-governor-initrd secpol-dump check-guest-image check-governor-initrd
	python3 ../tools/generate_secpol_audit_build.py latch_qemu_governor.build $(BUILD_DIR)/latch_qemu_governor_secpol_audit.build
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" GOVERNOR_GUEST_INITRD="$(abspath $(GOVERNOR_GUEST_INITRD))" mkifs -v $(BUILD_DIR)/latch_qemu_governor_secpol_audit.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu_governor_secpol_audit.ifs

verify-governor-qemu: ifs-qemu-governor
	python3 ../tools/verify_governor_qemu.py

# Disposable target verification images; never deploy the unrestricted audit image.
target-probe: aarch64
	qcc -Vgcc_ntoaarch64le -Wc,-std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE latch_target_probe.c -o $(BUILD_DIR)/nto-aarch64-le/latch_target_probe -Wl,-z,relro,-z,now

ifs-qemu-writer-test: target-probe secpol guest-governor-initrd check-guest-image check-governor-initrd
	python3 ../tools/generate_writer_test_build.py latch_qemu_governor.build $(BUILD_DIR)/latch_writer_test.build
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" GOVERNOR_GUEST_INITRD="$(abspath $(GOVERNOR_GUEST_INITRD))" mkifs $(BUILD_DIR)/latch_writer_test.build $(BUILD_DIR)/nto-aarch64-le/latch_writer_test.ifs

ifs-qemu-audit-probe: target-probe secpol guest-governor-initrd check-guest-image check-governor-initrd
	python3 ../tools/generate_secpol_audit_build.py --probe latch_qemu_governor.build $(BUILD_DIR)/latch_audit_probe.build
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" GOVERNOR_GUEST_INITRD="$(abspath $(GOVERNOR_GUEST_INITRD))" mkifs $(BUILD_DIR)/latch_audit_probe.build $(BUILD_DIR)/nto-aarch64-le/latch_audit_probe.ifs

# Run live QEMU AArch64 test directly against the committed prebuilt IFS image
# without requiring QNX SDP host cross-compilation tools (qcc, mkifs).
verify-governor-qemu-prebuilt:
	python3 ../tools/verify_governor_qemu.py

# Uses the disposable typed-launcher image, not the normal deployment image.
# Build first with `make ifs-qemu-legacy-verify GUEST_IMAGE=...`.
verify-qemu:
	python3 ../tools/verify_qemu_aarch64.py

# ---------------------------------------------------------------------------
# Evidence archive
#
# Every file under ../docs/evidence/ is produced by tools/capture_evidence.py.
# Nothing there is hand-edited, so the archive can be regenerated at any time
# and checked for staleness.
# ---------------------------------------------------------------------------

EVIDENCE_TOOL := ../tools/capture_evidence.py
EVIDENCE_OUT  := ../docs/evidence

# Everything except the QEMU boot (~20 s).
evidence:
	python3 $(EVIDENCE_TOOL) --all

# The workstation pipeline only (~5 s). No QNX licence, no QEMU.
evidence-host-sim: host-sim
	python3 $(EVIDENCE_TOOL) host-sim

# A fresh on-target capture: boots QEMU AArch64 `virt` and drives it (~5 min).
evidence-on-target:
	python3 $(EVIDENCE_TOOL) on-target

# Re-derive `derived/on-target-metrics.txt` from the ARCHIVED session's tape
# dump. The tape-window metrics are a pure function of the captured rows, so
# this needs no QEMU, no licence and no guest image. It exists so a change to
# the derived analysis goes through the GENERATOR rather than a hand-edit.
evidence-rederive-on-target:
	python3 $(EVIDENCE_TOOL) rederive-on-target

# The build evidence: the full mkifs listing and the initramfs forensics.
evidence-build:
	python3 $(EVIDENCE_TOOL) build

# The bring-up record: the raw console of every QEMU boot, with counters.
evidence-history:
	python3 $(EVIDENCE_TOOL) history

# The windowed evidence tapes and their analysis.
evidence-tape:
	python3 $(EVIDENCE_TOOL) tape

# The four-defect resolution record.
evidence-resolution:
	python3 $(EVIDENCE_TOOL) resolution

# The GOVERNOR evidence: host-sim, e2e, adversarial attacks, tape, and metrics.
evidence-governor: host-sim
	python3 $(EVIDENCE_TOOL) governor

# The Linux synthetic Python-loop baseline. This is a WORKSTATION
# measurement, not a QNX one: it is regenerated by its own tool and every
# file under docs/evidence/baseline/ is written by that tool.
evidence-baseline:
	python3 ../tools/benchmark_linux_native.py --iterations 1500

# The GOVERNOR VM-kill + restart/resume transcript (~6 min: it boots QEMU AArch64
# `virt`, kills the guest VM, proves the fail-closed containment, and then
# restarts the guest through the narrowly-typed lifecycle daemon).  The
# harness writes the transcript DIRECTLY into the evidence archive, so the
# archived file is always the tool's output and never a hand-edit.  On
# failure the harness exits non-zero WITHOUT touching the archive, so a
# failed run cannot replace good evidence with a partial transcript.
evidence-governor-vm-kill:
	GOVERNOR_VM_KILL_LOG=$(EVIDENCE_OUT)/governor/governor-vm-kill-resume.txt \
	GOVERNOR_QEMU_IFS=$(CURDIR)/build/nto-aarch64-le/latch_qemu_governor.ifs \
	python3 ../tools/qemu_guest_kill.py

# The scripted GOVERNOR profile's ON-TARGET evidence (~8 min: one QEMU boot).
#
# `governor/governor-qemu-verify.txt` and `governor/governor-qemu-console.txt`
# used to be ORPHANS in the archive: they had no generator anywhere in the
# tree, so they went stale exactly the way an orphan does.  This target is
# that generator.  The capture tool writes the archive only when the run
# PASSES: a failed run exits non-zero WITHOUT touching docs/evidence/.
evidence-governor-qemu: ifs-qemu-governor
	python3 $(EVIDENCE_TOOL) governor-qemu

# The security-policy generation audit (U-6 / M-4) (~8 min).
#
# It boots the DISPOSABLE, unrestricted `secpolgenerate` audit image -- never
# the enforced deployment image -- lets the 235-frame guest scenario run, and
# captures the observed DELTA, the ability-check ERRORS and the UNUSED rules.
# The archive is written ONLY when the run passes: a failed run exits
# non-zero WITHOUT touching docs/evidence/.
evidence-secpol-audit: ifs-qemu-governor-secpol-audit
	python3 $(EVIDENCE_TOOL) secpol-audit

# The EXPERIMENTAL in-guest inference evidence (~15 min: two QEMU boots).
#
# It needs the language model and the cross-built inference program, which
# are BUILD INPUTS and are not in this repository, so the asset disks have
# to exist before this target can run.  The capture tool writes the archive
# only when BOTH runs pass: a failed run exits non-zero WITHOUT touching
# docs/evidence/.
evidence-governor-infer: ifs-qemu-infer ifs-qemu-infer-attack
	python3 $(EVIDENCE_TOOL) infer

# The LFBK FEEDBACK-TRANSPORT evidence (U-2) (~10 min: two QEMU boots).
#
# W4 measures the TRANSPORT (a verdict reaches the freestanding guest and the
# guest sees it CHANGE); W5 measures the CONTROL LOOP (the TRUSTED supervisor
# publishes its own verdict, the guest understands it, and the guest STOPS
# when it is told no).  The archive is written ONLY when BOTH runs pass: a
# failed run exits non-zero WITHOUT touching docs/evidence/.
evidence-governor-feedback: ifs-qemu-fbprobe ifs-qemu-fbverdict
	python3 $(EVIDENCE_TOOL) feedback-transport

# U-4: the DECISION-LATENCY MEASUREMENT evidence.  This is the file that
# replaces the withdrawn "61 us WCET" claim with a real measurement: the
# trusted supervisor's own per-tick decision latency, sampled once per tick
# for more than a million ticks, aggregated in a histogram ON THE TARGET.
#
# It boots QEMU once and runs the FULL soak, so it takes ~40 minutes.  The
# archive is written ONLY when the run passes: a failed run exits non-zero
# WITHOUT touching docs/evidence/.
evidence-governor-latency: ifs-qemu-latency
	python3 $(EVIDENCE_TOOL) governor-latency

# The index and the run-output manifest.
evidence-index:
	python3 $(EVIDENCE_TOOL) index

# The anti-rot gate: re-run the host-sim capture and compare the signature
# against the archived one. A mismatch means the code has drifted away from
# the committed evidence, and CI must fail.
evidence-check: host-sim
	@python3 ../tools/check_governor_evidence.py
	@# The previous revision of this target regenerated the signature file and
	@# then grepped its OWN fresh output -- so it overwrote the committed
	@# archive instead of comparing against it, and could never detect drift.
	@#
	@# The capture now goes to a TEMPORARY directory, so this target does not
	@# mutate the archive it is supposed to protect: it re-runs the pipeline
	@# and DIFFS a fresh signature against the committed one.
	@rm -rf /tmp/latch_evidence_check
	@mkdir -p /tmp/latch_evidence_check
	@python3 $(EVIDENCE_TOOL) host-sim --out /tmp/latch_evidence_check >/dev/null
	@if diff -u $(EVIDENCE_OUT)/derived/host-sim-signature.txt \
	         /tmp/latch_evidence_check/derived/host-sim-signature.txt \
	         > /tmp/latch_signature_diff.txt; then \
	  echo "[EVIDENCE CHECK PASS] the archived host-sim signature still matches the code."; \
	else \
	  echo "[EVIDENCE CHECK FAIL] the archived host-sim signature has drifted from the code."; \
	  cat /tmp/latch_signature_diff.txt; \
	  echo "  Re-run: make -C qnx evidence && commit the regenerated archive."; \
	  exit 1; \
	fi

clean:
	rm -rf $(BUILD_DIR)
