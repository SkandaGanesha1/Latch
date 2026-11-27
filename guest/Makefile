# guest/Makefile -- the guest-side binaries.
#
# TWO BINARIES LIVE IN THE GUEST, AND THEY HAVE DIFFERENT ROLES:
#
#   1. latch_guest_init  -- the POLICY.  A freestanding (-nostdlib
#      -ffreestanding) static AArch64 binary that is PID 1 inside the
#      guest.  It owns the virtio-console and is the ONLY writer of
#      frames on that channel.  It has no libc, no shell and no Python.
#
#   2. latch_infer       -- the INFERENCE.  A statically linked AArch64
#      C++ program that loads a GGUF model with llama.cpp, constrains the
#      model's output to the action schema with a GBNF grammar,
#      re-validates the model's JSON independently, and writes the
#      resulting 32-byte wire-v2 frame to a FIFO.
#
# The split matters for the safety story: the model runs in the UNTRUSTED
# guest, and the trusted QNX supervisor never sees the model's raw output.
# The freestanding policy stays the single writer of the actuator-facing
# channel, and it relays only frames that passed the inference binary's
# own schema check.
#
# This Makefile builds #2.  #1 is built by qnx/Makefile (it needs the
# QNX cross toolchain and the initramfs plumbing).

LLAMA_CPP_DIR ?= /home/skanda/tools/llama.cpp
LLAMA_CPP_REV ?= 44d50873b

# Every path here is ABSOLUTE.  A relative path is a trap in this
# Makefile: the cmake recipe `cd`s into the build directory and then
# passes -B, so a relative -B is resolved against the NEW working
# directory and lands in build/build/... .
REPO_ROOT := $(abspath $(CURDIR)/..)
BUILD_DIR := $(REPO_ROOT)/build
SYSROOT      := $(BUILD_DIR)/aarch64-sysroot
LLAMA_BUILD  := $(BUILD_DIR)/llama-aarch64
GUEST_BUILD  := $(BUILD_DIR)/guest

CXX      := aarch64-linux-gnu-g++
CXXFLAGS := --sysroot=$(SYSROOT) -B$(SYSROOT)/usr/lib/gcc/aarch64-redhat-linux/16/ \
            -I$(SYSROOT)/usr/include/c++/16 \
            -I$(SYSROOT)/usr/include/c++/16/aarch64-redhat-linux \
            -I$(SYSROOT)/usr/include/c++/16/backward \
            -O2 -std=c++17 -fno-plt -Wall -Wextra -Wno-unused-function
LDFLAGS  := -static -pthread

# llama.cpp build options.
#
#   GGML_NATIVE=OFF       the host is x86_64; native tuning would emit
#                          x86 instructions into an AArch64 binary
#   GGML_OPENMP=OFF       no libgomp for the cross target; llama.cpp
#                          falls back to its own thread pool
#   BUILD_SHARED_LIBS=OFF everything is linked into the executable
#   LLAMA_BUILD_* = OFF   only the library is built, no examples/tools
#
# NOTE: the compiler flags are NOT passed with -DCMAKE_C_FLAGS /
# -DCMAKE_CXX_FLAGS here.  A -D on the command line creates a CACHE
# entry that shadows CMAKE_C_FLAGS_INIT, and the -B that points the
# compiler at the sysroot's gcc runtime directory would then be lost --
# which is exactly how the first attempt failed with
# "cannot find -latomic_asneeded".  The flags live in the toolchain
# file, where nothing can shadow them.
llama_cmake_args := \
	-DCMAKE_TOOLCHAIN_FILE=$(CURDIR)/aarch64-toolchain.cmake \
	-DCMAKE_BUILD_TYPE=Release \
	-DBUILD_SHARED_LIBS=OFF \
	-DGGML_STATIC=ON \
	-DGGML_NATIVE=OFF \
	-DGGML_OPENMP=OFF \
	-DGGML_BACKEND_DL=OFF \
	-DGGML_CPU_ALL_VARIANTS=OFF \
	-DGGML_CPU_REPACK=OFF \
	-DGGML_ACCELERATE=OFF \
	-DLLAMA_BUILD_IS_DEV=OFF \
	-DLLAMA_BUILD_COMMON=OFF \
	-DLLAMA_BUILD_TESTS=OFF \
	-DLLAMA_BUILD_TOOLS=OFF \
	-DLLAMA_BUILD_EXAMPLES=OFF \
	-DLLAMA_BUILD_SERVER=OFF \
	-DLLAMA_BUILD_APP=OFF \
	-DLLAMA_BUILD_UI=OFF \
	-DLLAMA_USE_PREBUILT_UI=OFF \
	-DLLAMA_OPENSSL=OFF \
	-DLLAMA_CURL=OFF

.PHONY: all sysroot llama infer clean

all: infer

# --------------------------------------------------------------------------
# The sysroot.  Built on demand so a clean checkout works with one command.
# --------------------------------------------------------------------------
sysroot:
	@if [ ! -f "$(SYSROOT)/flags.env" ]; then \
		$(REPO_ROOT)/tools/build_aarch64_sysroot.sh --dest $(SYSROOT); \
	else \
		echo "[guest] sysroot already present: $(SYSROOT)"; \
	fi

# --------------------------------------------------------------------------
# llama.cpp, cross-compiled to static AArch64 libraries.
# --------------------------------------------------------------------------
llama: $(LLAMA_BUILD)/CMakeCache.txt

$(LLAMA_BUILD)/CMakeCache.txt: | sysroot
	@test -d "$(LLAMA_CPP_DIR)" || { \
		echo "ERROR: llama.cpp source not found at $(LLAMA_CPP_DIR)."; \
		echo "       Clone it and set LLAMA_CPP_DIR=<path>:"; \
		echo "         git clone https://github.com/ggml-org/llama.cpp"; \
		echo "         git -C <path> checkout $(LLAMA_CPP_REV)"; \
		exit 1; }
	@mkdir -p $(LLAMA_BUILD)
	cd $(LLAMA_BUILD) && LATCH_SYSROOT=$(SYSROOT) \
		cmake -S $(LLAMA_CPP_DIR) -B $(LLAMA_BUILD) $(llama_cmake_args)
	cmake --build $(LLAMA_BUILD) --target llama -- -j4

# --------------------------------------------------------------------------
# The inference binary.
# --------------------------------------------------------------------------
infer: latch_infer

latch_infer: latch_infer.cpp latch_action.c latch_action.h $(LLAMA_BUILD)/CMakeCache.txt
	@mkdir -p $(GUEST_BUILD)
	$(CXX) $(CXXFLAGS) -I$(LLAMA_CPP_DIR)/include -I$(LLAMA_CPP_DIR)/ggml/include \
		-o $(GUEST_BUILD)/latch_infer latch_infer.cpp latch_action.c \
		$(LLAMA_BUILD)/src/libllama.a \
		$(LLAMA_BUILD)/ggml/src/libggml.a \
		$(LLAMA_BUILD)/ggml/src/libggml-base.a \
		$(LLAMA_BUILD)/ggml/src/libggml-cpu.a \
		$(LDFLAGS) -lm -ldl -lpthread
	@file $(GUEST_BUILD)/latch_infer
	@echo "[guest] inference binary: $(GUEST_BUILD)/latch_infer"

clean:
	rm -rf $(GUEST_BUILD) $(LLAMA_BUILD)
