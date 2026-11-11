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
else ifeq ($(TARGET),host-sim)
    CC         := gcc
    CFLAGS     := -std=c11 $(COMMON_CFLAGS) -D_POSIX_C_SOURCE=200809L -DLATCH_HOST_SIM
    LDFLAGS    := -lpthread
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

.PHONY: all rpi4 x86_64 host-sim check clean dirs qemu

all: $(LATCHD_BIN) $(INGEST_BIN) $(LATCHCTL_BIN) $(LATCHLOG_BIN) $(VERIFY_BIN)

dirs:
	@mkdir -p $(OUT_DIR)

$(MANIFEST_OBJ): latch_manifest.c latch_manifest.h | dirs
	$(CC) $(CFLAGS) -c latch_manifest.c -o $@

$(LATCHD_BIN): latchd.c latch_protocol.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latchd.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

$(INGEST_BIN): latch_ingest.c latch_protocol.h $(MANIFEST_OBJ) | dirs
	$(CC) $(CFLAGS) latch_ingest.c $(MANIFEST_OBJ) -o $@ $(LDFLAGS)

$(LATCHCTL_BIN): latchctl.c latch_protocol.h | dirs
	$(CC) $(CFLAGS) latchctl.c -o $@ $(LDFLAGS)

$(LATCHLOG_BIN): latchlog.c latch_protocol.h | dirs
	$(CC) $(CFLAGS) latchlog.c -o $@ $(LDFLAGS)

$(VERIFY_BIN): latch_verify.c latch_protocol.h | dirs
	$(CC) $(CFLAGS) latch_verify.c -o $@ $(LDFLAGS)

rpi4:
	@$(MAKE) --no-print-directory TARGET=rpi4 all

x86_64:
	@$(MAKE) --no-print-directory TARGET=x86_64 all

host-sim:
	@$(MAKE) --no-print-directory TARGET=host-sim all

check: host-sim
	./$(BUILD_DIR)/host-sim/latchd
	python3 ../guest/liar.py suite --raw-stdout | ./$(BUILD_DIR)/host-sim/latch-ingest -o - | ./$(BUILD_DIR)/host-sim/latchd --pipe-in --csv ../host/suite_tape.csv

qemu:
	./run_qemu.sh

ifs-rpi4: rpi4
	mkifs -v latch_rpi4.build $(BUILD_DIR)/nto-aarch64-le/latch_rpi4.ifs

ifs-qemu: rpi4
	mkifs -v latch_qemu.build $(BUILD_DIR)/nto-aarch64-le/latch_qemu.ifs

clean:
	rm -rf $(BUILD_DIR)
