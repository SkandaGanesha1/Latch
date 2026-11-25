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
else ifeq ($(TARGET),aarch64)
    CC         := qcc
    CFLAGS     := -Vgcc_ntoaarch64le -Wc,-std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE
    LDFLAGS    := -Vgcc_ntoaarch64le -Wl,-z,relro,-z,now
    OUT_DIR    := $(BUILD_DIR)/nto-aarch64-le
else ifeq ($(TARGET),x86_64)
    CC         := qcc
    CFLAGS     := -Vgcc_ntox86_64 -Wc,-std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE
    LDFLAGS    := -Vgcc_ntox86_64 -Wl,-z,relro,-z,now
    OUT_DIR    := $(BUILD_DIR)/nto-x86_64-o
else ifeq ($(TARGET),native)
    CC         := gcc
    CFLAGS     := -std=c11 $(COMMON_CFLAGS) -D_QNX_SOURCE
    LDFLAGS    := -lm
    OUT_DIR    := $(BUILD_DIR)/native
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
else
    $(error Unknown TARGET '$(TARGET)'. Use rpi4, aarch64, x86_64, native, or host-sim)
endif

LATCHD_BIN    := $(OUT_DIR)/latchd
INGEST_BIN    := $(OUT_DIR)/latch-ingest
LATCHCTL_BIN  := $(OUT_DIR)/latchctl
LATCHLOG_BIN  := $(OUT_DIR)/latchlog
VERIFY_BIN    := $(OUT_DIR)/latch_verify
MANIFEST_OBJ  := $(OUT_DIR)/latch_manifest.o
IPC_OBJ       := $(OUT_DIR)/latch_ipc.o

.PHONY: all rpi4 x86_64 native host-sim check check-governor clean dirs qemu guest-initrd guest-governor-initrd check-guest-initrd check-governor-initrd governor-policy-check governor-wire-check latch-ipc-check governor-gate-check governor-homeostat-check latch-feedback-check latch-manifest-check governor-e2e-check homeostat-e2e-check gov-replay-check verify-governor-qemu verify-governor-qemu-prebuilt stack-usage

all: $(LATCHD_BIN) $(INGEST_BIN) $(LATCHCTL_BIN) $(LATCHLOG_BIN) $(VERIFY_BIN)

dirs:
	@mkdir -p $(OUT_DIR)

$(MANIFEST_OBJ): latch_manifest.c latch_manifest.h | dirs
	$(CC) $(CFLAGS) -c latch_manifest.c -o $@

$(IPC_OBJ): latch_ipc.c latch_ipc.h latch_protocol.h | dirs
	$(CC) $(CFLAGS) -c latch_ipc.c -o $@

$(LATCHD_BIN): latchd.c latch_protocol.h latch_ipc.h governor_policy.c governor_policy.h gov_gate_precheck.c gov_gate_precheck.h gov_homeostat.c gov_homeostat.h $(MANIFEST_OBJ) $(IPC_OBJ) | dirs
	$(CC) $(CFLAGS) latchd.c governor_policy.c gov_gate_precheck.c gov_homeostat.c $(MANIFEST_OBJ) $(IPC_OBJ) -o $@ $(LDFLAGS)

$(INGEST_BIN): latch_ingest.c latch_protocol.h governor_wire.c governor_wire.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latch_ingest.c governor_wire.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

$(LATCHCTL_BIN): latchctl.c latch_protocol.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latchctl.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

$(LATCHLOG_BIN): latchlog.c latch_protocol.h latch_manifest.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latchlog.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

$(VERIFY_BIN): latch_verify.c latch_protocol.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latch_verify.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

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
stack-usage:
	@mkdir -p $(BUILD_DIR)/stack-usage
	@rm -f $(BUILD_DIR)/stack-usage/*.su $(BUILD_DIR)/stack-usage/*.o
	@for f in latchd governor_policy gov_gate_precheck gov_homeostat latch_manifest latch_ipc; do \
	    $(CC) $(CFLAGS) -fstack-usage -c $$f.c -o $(BUILD_DIR)/stack-usage/$$f.o || exit 1; \
	done
	@cat $(BUILD_DIR)/stack-usage/*.su > $(BUILD_DIR)/stack-usage/host-static-stack-usage.txt
	@echo "[STACK-USAGE] wrote $(BUILD_DIR)/stack-usage/host-static-stack-usage.txt"
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
	$(MAKE) --no-print-directory latch-manifest-check
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify contracts/governor_servo.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify contracts/syringe_governor.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify contracts/homeostat_servo.manifest
	python3 ../tools/governor_manifest_test.py ./$(BUILD_DIR)/host-sim/latchctl contracts/governor_servo.manifest
	$(MAKE) --no-print-directory governor-e2e-check
	$(MAKE) --no-print-directory homeostat-e2e-check
	$(MAKE) --no-print-directory gov-replay-check

check: host-sim
	$(MAKE) --no-print-directory check-governor
	./$(BUILD_DIR)/host-sim/latchd -m latch.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify latch.manifest
	python3 ../guest/liar.py suite --raw-stdout --manifest latch.manifest | ./$(BUILD_DIR)/host-sim/latch-ingest -m latch.manifest -o - | ./$(BUILD_DIR)/host-sim/latchd -m latch.manifest --pipe-in --csv $(BUILD_DIR)/host-sim/suite_tape.csv
	python3 ../tools/embed_default_tape.py --check

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

# The manifest parser is the SAFETY FRONT DOOR: every plant limit, timing
# budget and calibration constant enters the supervisor through it. This test
# asserts that a well-formed document loads AND that every malformed one is
# REJECTED (fail closed) -- never silently defaulted, never clamped.
$(BUILD_DIR)/host-sim/latch_manifest_test: latch_manifest.c latch_manifest.h latch_manifest_test.c | dirs
	$(CC) $(CFLAGS) latch_manifest.c latch_manifest_test.c -o $@ $(LDFLAGS)

latch-manifest-check: $(BUILD_DIR)/host-sim/latch_manifest_test
	./$(BUILD_DIR)/host-sim/latch_manifest_test

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

ifs-rpi4: rpi4 secpol check-guest-image
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" mkifs -v latch_rpi4.build $(BUILD_DIR)/nto-aarch64-le/latch_rpi4.ifs

ifs-qemu-aarch64: aarch64 secpol guest-initrd check-guest-image check-guest-initrd
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" GUEST_INITRD="$(abspath $(GUEST_INITRD))" mkifs -v latch_qemu.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu.ifs

# Experimental: QNX Hypervisor under QEMU TCG is not documented by QNX as a
# supported Hypervisor host platform. This target is a bring-up profile only.
ifs-qemu-governor: aarch64 secpol guest-governor-initrd check-guest-image check-governor-initrd
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" GOVERNOR_GUEST_INITRD="$(abspath $(GOVERNOR_GUEST_INITRD))" mkifs -v latch_qemu_governor.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu_governor.ifs

verify-governor-qemu: ifs-qemu-governor
	python3 ../tools/verify_governor_qemu.py

# Run live QEMU AArch64 test directly against the committed prebuilt IFS image
# without requiring QNX SDP host cross-compilation tools (qcc, mkifs).
verify-governor-qemu-prebuilt:
	python3 ../tools/verify_governor_qemu.py

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
