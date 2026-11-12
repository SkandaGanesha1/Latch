# ==============================================================================
# LATCH — Last Authority for Trusted Control Handoff
# QNX SDP 8.0 & Host Simulation Build System
#
# Targets:
#   make rpi4     -> QNX SDP 8.0 AArch64 (qcc -Vgcc_ntoaarch64le)
#   make x86_64   -> QNX SDP 8.0 x86_64  (qcc -Vgcc_ntox86_64)
#   make host-sim -> POSIX/Linux Host Simulation (gcc -DLATCH_HOST_SIM)
#   make check    -> Run unit tests + 200-tick end-to-end fault suite
#   make qemu     -> Launch QEMU AArch64 virtual machine
# ==============================================================================

TARGET        ?= host-sim
BUILD_DIR     := build
COMMON_CFLAGS := -Wall -Wextra -Werror -Wpedantic -O2 -I.
GUEST_IMAGE   ?= $(BUILD_DIR)/linux-guest.Image

ifeq ($(TARGET),rpi4)
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
    $(error Unknown TARGET '$(TARGET)'. Use rpi4, x86_64, or host-sim)
endif

LATCHD_BIN    := $(OUT_DIR)/latchd
INGEST_BIN    := $(OUT_DIR)/latch-ingest
LATCHCTL_BIN  := $(OUT_DIR)/latchctl
LATCHLOG_BIN  := $(OUT_DIR)/latchlog
VERIFY_BIN    := $(OUT_DIR)/latch_verify
MANIFEST_OBJ  := $(OUT_DIR)/latch_manifest.o

.PHONY: all rpi4 x86_64 native host-sim check clean dirs qemu

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

$(LATCHLOG_BIN): latchlog.c latch_protocol.h | dirs
	$(CC) $(CFLAGS) latchlog.c -o $@ $(LDFLAGS)

$(VERIFY_BIN): latch_verify.c latch_protocol.h | dirs
	$(CC) $(CFLAGS) latch_verify.c -o $@ $(LDFLAGS)

rpi4:
	@$(MAKE) --no-print-directory TARGET=rpi4 all

x86_64:
	@$(MAKE) --no-print-directory TARGET=x86_64 all

native:
	@$(MAKE) --no-print-directory TARGET=native all

host-sim:
	@$(MAKE) --no-print-directory TARGET=host-sim all

check: host-sim
	./$(BUILD_DIR)/host-sim/latchd -m latch.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify latch.manifest
	python3 ../guest/liar.py suite --raw-stdout | ./$(BUILD_DIR)/host-sim/latch-ingest -m latch.manifest -o - | ./$(BUILD_DIR)/host-sim/latchd -m latch.manifest --pipe-in --csv ../host/suite_tape.csv

demo-syringe: host-sim
	./$(BUILD_DIR)/host-sim/latchd -m contracts/syringe_pump_bolus.manifest
	./$(BUILD_DIR)/host-sim/latchctl manifest-verify contracts/syringe_pump_bolus.manifest 36f082454cf416f784d81fb85c0983ff9ad72a3fe8ce0b9c091a0cb96b8af0a3

secpol: | dirs
	secpolc -v -o $(BUILD_DIR)/secpol.bin latch.secpol

qemu:
	./run_qemu.sh

$(GUEST_IMAGE): | dirs
	@if [ ! -f "$@" ]; then \
		echo "[LATCH] Initializing guest image stub for IFS packaging..."; \
		dd if=/dev/zero of="$@" bs=1024 count=4 2>/dev/null; \
	fi

ifs-rpi4: rpi4 secpol $(GUEST_IMAGE)
	mkifs -v -DGUEST_IMAGE=$(GUEST_IMAGE) latch_rpi4.build $(BUILD_DIR)/nto-aarch64-le/latch_rpi4.ifs

ifs-qemu: rpi4 secpol $(GUEST_IMAGE)
	mkifs -v -DGUEST_IMAGE=$(GUEST_IMAGE) latch_qemu.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu.ifs

clean:
	rm -rf $(BUILD_DIR)
