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
#   make host-sim         -> POSIX/Linux Host Simulation (gcc -DLATCH_HOST_SIM)
#   make check            -> Run unit tests + 200-tick end-to-end fault suite
#   make qemu             -> Launch QEMU virtual machine (x86_64 QSTI / AArch64)
# ==============================================================================

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
    CFLAGS     := -std=c11 $(COMMON_CFLAGS) -D_POSIX_C_SOURCE=200809L -DLATCH_HOST_SIM
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

.PHONY: all rpi4 x86_64 native host-sim check clean dirs qemu guest-initrd check-guest-initrd

all: $(LATCHD_BIN) $(INGEST_BIN) $(LATCHCTL_BIN) $(LATCHLOG_BIN) $(VERIFY_BIN)

dirs:
	@mkdir -p $(OUT_DIR)

$(MANIFEST_OBJ): latch_manifest.c latch_manifest.h | dirs
	$(CC) $(CFLAGS) -c latch_manifest.c -o $@

$(LATCHD_BIN): latchd.c latch_protocol.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latchd.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

$(INGEST_BIN): latch_ingest.c latch_protocol.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latch_ingest.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

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

check: host-sim
	./$(BUILD_DIR)/host-sim/latchd -m latch.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify latch.manifest
	python3 ../guest/liar.py suite --raw-stdout --manifest latch.manifest | ./$(BUILD_DIR)/host-sim/latch-ingest -m latch.manifest -o - | ./$(BUILD_DIR)/host-sim/latchd -m latch.manifest --pipe-in --csv ../host/suite_tape.csv
	python3 ../tools/embed_default_tape.py

demo-syringe: host-sim
	./$(BUILD_DIR)/host-sim/latchd -m contracts/syringe_pump_bolus.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify contracts/syringe_pump_bolus.manifest a9d877ebf63d5670006593ac8eadc7303b324c52c1d30e29aeacb8b9253e0e5e

secpol: | dirs
	$(SECPOLC) -o $(BUILD_DIR)/secpol.bin latch.secpol

qemu:
	./run_qemu.sh

guest-initrd:
	@mkdir -p $(BUILD_DIR)/guest-initramfs/dev $(BUILD_DIR)/guest-initramfs/proc $(BUILD_DIR)/guest-initramfs/sys
	aarch64-linux-gnu-gcc -nostdlib -ffreestanding -static -O2 -Wall -Wextra -Werror ../guest/latch_guest_init.c -o $(BUILD_DIR)/guest-initramfs/init
	chmod +x $(BUILD_DIR)/guest-initramfs/init
	(cd $(BUILD_DIR)/guest-initramfs && find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > $(abspath $(GUEST_INITRD)))
	@ls -lh $(GUEST_INITRD)

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

ifs-rpi4: rpi4 secpol check-guest-image
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" mkifs -v latch_rpi4.build $(BUILD_DIR)/nto-aarch64-le/latch_rpi4.ifs

ifs-qemu-aarch64: aarch64 secpol guest-initrd check-guest-image check-guest-initrd
	GUEST_IMAGE="$(abspath $(GUEST_IMAGE))" GUEST_INITRD="$(abspath $(GUEST_INITRD))" mkifs -v latch_qemu.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu.ifs

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

# The index and the run-output manifest.
evidence-index:
	python3 $(EVIDENCE_TOOL) index

# The anti-rot gate: re-run the host-sim capture and compare the signature
# against the archived one. A mismatch means the code has drifted away from
# the committed evidence, and CI must fail.
evidence-check: host-sim
	@python3 $(EVIDENCE_TOOL) host-sim >/dev/null
	@python3 -c "import sys, re; \
	txt = open('$(EVIDENCE_OUT)/derived/host-sim-signature.txt').read(); \
	m = re.search(r'RESULT: (PASS|FAIL)', txt); \
	sys.exit(0 if (m and m.group(1) == 'PASS') else 1)" \
	  && echo "[EVIDENCE CHECK PASS] the archived host-sim signature still matches the code." \
	  || (echo "[EVIDENCE CHECK FAIL] the archived host-sim signature has drifted from the code."; \
	      echo "  Re-run: make -C qnx evidence && commit the regenerated archive."; exit 1)

clean:
	rm -rf $(BUILD_DIR)
