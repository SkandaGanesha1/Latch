# guest/aarch64-toolchain.cmake -- CMake cross-compilation for the guest.
#
# This file cross-compiles for aarch64-linux-gnu (the guest's ABI) using
# the self-contained sysroot that tools/build_aarch64_sysroot.sh builds.
#
# The sysroot path comes from the LATCH_SYSROOT environment variable (or a
# -DLATCH_SYSROOT=... cache entry), so nothing machine-specific is baked
# into the repository.
#
# WHY THE EXPLICIT -I FLAGS
# -------------------------
# The sysroot holds the C++ headers at
#   $LATCH_SYSROOT/usr/include/c++/<major>/
# but the cross compiler does not look there by itself: it only searches
# $SYSROOT/usr/include and its own gcc include directory. The three -I
# flags below are therefore REQUIRED, and the first of them (the arch
# directory) is required too, because the headers include
# <bits/c++config.h> from the target-specific subdirectory.
#
# WHY -B
# ------
# -B points the compiler at the sysroot's gcc runtime directory, which is
# where crtbeginT.o/crtend.o and libstdc++.a live. It also puts that
# directory on the library search path.

if(NOT DEFINED LATCH_SYSROOT)
  if(DEFINED ENV{LATCH_SYSROOT})
    set(LATCH_SYSROOT "$ENV{LATCH_SYSROOT}")
  else()
    message(FATAL_ERROR
      "LATCH_SYSROOT is not set. Run tools/build_aarch64_sysroot.sh first, "
      "then export LATCH_SYSROOT=<its output directory>.")
  endif()
endif()

set(LATCH_GCC_TRIPLE "aarch64-redhat-linux")
set(LATCH_GCC_MAJOR "16")

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER   aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)

set(CMAKE_SYSROOT "${LATCH_SYSROOT}")
set(CMAKE_FIND_ROOT_PATH "${LATCH_SYSROOT}")

# Programs are host programs: never look for them in the target sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

set(LATCH_GCC_LIBDIR
    "${LATCH_SYSROOT}/usr/lib/gcc/${LATCH_GCC_TRIPLE}/${LATCH_GCC_MAJOR}")
set(LATCH_CXX_INCLUDE_DIR
    "${LATCH_SYSROOT}/usr/include/c++/${LATCH_GCC_MAJOR}")

# Static linking: the guest has no dynamic loader and no shared library
# tree, so the binary must be self-contained.
#
# -static lives in the *_FLAGS_INIT variables (not in a -DCMAKE_C_FLAGS
# cache entry) because a -D on the cmake command line shadows the _INIT
# variable and would silently drop the -B that puts the sysroot's gcc
# runtime directory on the library search path.
set(CMAKE_C_FLAGS_INIT   "-B${LATCH_GCC_LIBDIR}/ -static")
set(CMAKE_CXX_FLAGS_INIT "-B${LATCH_GCC_LIBDIR}/ -I${LATCH_CXX_INCLUDE_DIR} -I${LATCH_CXX_INCLUDE_DIR}/${LATCH_GCC_TRIPLE} -I${LATCH_CXX_INCLUDE_DIR}/backward -static")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CMAKE_POSITION_INDEPENDENT_CODE OFF)
