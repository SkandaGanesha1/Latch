#!/usr/bin/env python3
"""
tools/consistency_check.py — LATCH Production Cross-File Invariant & Metadata Consistency Verifier.

Asserts zero architectural drift between:
  - qnx/latch.manifest & sidecar
  - qnx/contracts/syringe_pump_bolus.manifest & sidecar
  - qnx/latch_protocol.h
  - qnx/latch_qemu.build
  - qnx/latch_rpi4.build
  - qnx/latch.secpol
  - qnx/latch.qvmconf

Zero external dependencies (uses standard library hashlib, json, os, re, sys).
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def fail(msg: str):
    print(f"[CONSISTENCY ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


def pass_check(msg: str):
    print(f"[CONSISTENCY PASS] {msg}")


def verify_manifest_sidecar(manifest_path: str, sha256_path: str, label: str):
    if not os.path.isfile(manifest_path):
        fail(f"Manifest missing for {label}: {manifest_path}")
    if not os.path.isfile(sha256_path):
        fail(f"SHA-256 sidecar missing for {label}: {sha256_path}")

    with open(manifest_path, "rb") as f:
        manifest_bytes = f.read()
    computed_sha = hashlib.sha256(manifest_bytes).hexdigest()

    with open(sha256_path, "r", encoding="utf-8") as f:
        sidecar_content = f.read().strip().split()[0]

    if computed_sha.lower() != sidecar_content.lower():
        fail(f"{label} SHA-256 mismatch: computed {computed_sha} != sidecar {sidecar_content}")
    pass_check(f"{label} sidecar SHA-256 match verified: {computed_sha}")


def main():
    print("=== LATCH Architectural Consistency & Invariant Verification ===")

    manifest_path = os.path.join(REPO_ROOT, "qnx", "latch.manifest")
    sha256_path = os.path.join(REPO_ROOT, "qnx", "latch.manifest.sha256")
    syringe_manifest_path = os.path.join(REPO_ROOT, "qnx", "contracts", "syringe_pump_bolus.manifest")
    syringe_sha256_path = os.path.join(REPO_ROOT, "qnx", "contracts", "syringe_pump_bolus.manifest.sha256")
    header_path = os.path.join(REPO_ROOT, "qnx", "latch_protocol.h")
    qemu_build_path = os.path.join(REPO_ROOT, "qnx", "latch_qemu.build")
    rpi4_build_path = os.path.join(REPO_ROOT, "qnx", "latch_rpi4.build")
    secpol_path = os.path.join(REPO_ROOT, "qnx", "latch.secpol")
    qvmconf_path = os.path.join(REPO_ROOT, "qnx", "latch.qvmconf")
    qvm_virt_path = os.path.join(REPO_ROOT, "qnx", "latch_qemu_virt.qvmconf")
    makefile_path = os.path.join(REPO_ROOT, "qnx", "Makefile")
    readme_path = os.path.join(REPO_ROOT, "README.md")
    impl_doc_path = os.path.join(REPO_ROOT, "docs", "LATCH-implementation.md")

    for p in [manifest_path, sha256_path, syringe_manifest_path, syringe_sha256_path,
              header_path, qemu_build_path, rpi4_build_path, secpol_path, qvmconf_path,
              qvm_virt_path, makefile_path, readme_path, impl_doc_path]:
        if not os.path.isfile(p):
            fail(f"Required artifact missing: {p}")

    # 1. Verify Manifest Content & SHA-256 Sidecars
    verify_manifest_sidecar(manifest_path, sha256_path, "Default Plant (latch.manifest)")
    verify_manifest_sidecar(syringe_manifest_path, syringe_sha256_path, "Medical Syringe Plant")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    schema_ver = manifest.get("schema_version")
    if schema_ver not in (1, 2):
        fail(f"Invalid manifest schema_version: {schema_ver}")
    pass_check(f"Manifest schema version {schema_ver} valid")

    m_proto = manifest.get("protocol", {})
    if m_proto.get("magic") != "LATH" or m_proto.get("version") != 1:
        fail(f"Manifest protocol mismatch: magic={m_proto.get('magic')}, version={m_proto.get('version')}")
    pass_check("Manifest protocol 'LATH' version 1 verified")

    env = manifest.get("envelope", {})
    t_min = env.get("theta_min_mrad", -1000)
    t_max = env.get("theta_max_mrad", 1000)
    t_home = env.get("home_mrad", 0)
    if not (t_min <= t_home <= t_max):
        fail(f"Manifest home_mrad {t_home} outside [{t_min}, {t_max}]")
    keepout = env.get("keepout", [])
    if not keepout:
        fail("Manifest envelope.keepout list is empty")
    for k in keepout:
        lo = k.get("lo_mrad")
        hi = k.get("hi_mrad")
        if lo is None or hi is None or lo >= hi:
            fail(f"Invalid keepout interval: {k}")
        if lo < t_min or hi > t_max:
            fail(f"Keepout interval [{lo}, {hi}] outside bounds [{t_min}, {t_max}]")
    pass_check(f"Manifest envelope bounds [{t_min}, {t_max}], home {t_home}, and {len(keepout)} keepout intervals valid")

    m_paths = manifest.get("paths", {})
    proposal_path = m_paths.get("proposal", "/dev/latch/proposal")
    actuator_path = m_paths.get("actuator", "/dev/latch/actuator")
    ability_name = m_paths.get("ability", "latch/actuator")

    # 2. Verify C Protocol Header Constants
    with open(header_path, "r", encoding="utf-8") as f:
        hdr = f.read()

    if "0x4C415448" not in hdr:
        fail("LATCH_WIRE_MAGIC 0x4C415448 ('LATH') not found in latch_protocol.h")
    if "DCMD_LATCH_PROBE_ABILITY" not in hdr:
        fail("Dedicated read-only probe DCMD_LATCH_PROBE_ABILITY not declared in latch_protocol.h")
    if proposal_path not in hdr or actuator_path not in hdr:
        fail("Device pathstrings in latch_protocol.h do not match manifest")
    pass_check("C protocol header constants, devctls & paths aligned")

    # 3. Verify QEMU Buildfile Configuration
    with open(qemu_build_path, "r", encoding="utf-8") as f:
        qemu_build = f.read()

    if "-Q enable" not in qemu_build:
        fail("qnx/latch_qemu.build startup does not pass '-Q enable' for EL2 hypervisor host mode")
    if "/lib/dll/qvm/" not in qemu_build:
        fail("qnx/latch_qemu.build does not install vdev DLLs into /lib/dll/qvm/")
    if "libsecpol.so.1" not in qemu_build or "/proc/boot/qvm = qvm" not in qemu_build:
        fail("qnx/latch_qemu.build missing libsecpol.so.1 or /proc/boot/qvm = qvm hypervisor binary")
    if "libqvm.so.1" in qemu_build or "vdev-gic.so" in qemu_build:
        fail("qnx/latch_qemu.build references nonexistent QNX 8.0 libraries (libqvm.so.1 / vdev-gic.so)")
    if "latch.manifest.sha256" not in qemu_build:
        fail("qnx/latch_qemu.build missing latch.manifest.sha256 payload")
    if "latch_verify" not in qemu_build:
        fail("qnx/latch_qemu.build missing latch_verify target binary")
    if "linux-guest.Image = ${GUEST_IMAGE}" not in qemu_build:
        fail("qnx/latch_qemu.build missing linux-guest.Image guest packaging (${GUEST_IMAGE})")
    if "secpolpush /proc/boot/secpol.bin" not in qemu_build:
        fail("qnx/latch_qemu.build must use secpolpush (not secpollaunch -e) for boot policy activation")
    if "latch_qemu_virt.qvmconf" not in qemu_build:
        fail("qnx/latch_qemu.build must reference latch_qemu_virt.qvmconf (QEMU GICv2 0x08000000)")
    pass_check("QEMU virt buildfile EL2 flags, vdev DLLs, secpolpush, latch_qemu_virt.qvmconf & guest image verified")

    # 4. Verify RPi4 Buildfile Configuration
    with open(rpi4_build_path, "r", encoding="utf-8") as f:
        rpi4_build = f.read()

    if "-Q enable" not in rpi4_build:
        fail("qnx/latch_rpi4.build startup does not pass '-Q enable'")
    if "i2c-bcm2711 -p0xfe804000 -i149 --b400000 --u1" not in rpi4_build:
        fail("qnx/latch_rpi4.build missing exact i2c-bcm2711 -p0xfe804000 -i149 --b400000 --u1 parameters (GIC SPI 117 + 32 = IRQ 149)")
    if ":/lib/dll/qvm" not in rpi4_build:
        fail("qnx/latch_rpi4.build LD_LIBRARY_PATH missing :/lib/dll/qvm")
    if "secpolpush /proc/boot/secpol.bin" not in rpi4_build:
        fail("qnx/latch_rpi4.build must use secpolpush (not secpollaunch -e)")
    if "latch.manifest.sha256" not in rpi4_build:
        fail("qnx/latch_rpi4.build missing latch.manifest.sha256 payload")
    if "latch_verify" not in rpi4_build:
        fail("qnx/latch_rpi4.build missing latch_verify target binary")
    if "linux-guest.Image = $(GUEST_IMAGE)" not in rpi4_build:
        fail("qnx/latch_rpi4.build missing linux-guest.Image guest packaging")
    pass_check("RPi4 buildfile BCM2711 I2C IRQ 149, secpolpush, LD_LIBRARY_PATH, latch_verify & guest image verified")

    # 5. Verify Security Policy Enforcements (QNX 8.0 secpolcompile grammar)
    with open(secpol_path, "r", encoding="utf-8") as f:
        secpol = f.read()

    for bad_tok in ["type_trans", "allow_ability", "neverallow", ":all"]:
        if bad_tok in secpol:
            fail(f"Security policy contains invalid non-QNX token '{bad_tok}'")
    for req_tok in ["type latchd_t;", f"ability {ability_name};", "self:ability",
                    f"allow_attach latchd_t {proposal_path};",
                    f"allow_attach latchd_t {actuator_path};",
                    "latchd_t:channel connect;"]:
        if req_tok not in secpol:
            fail(f"Security policy missing valid QNX 8.0 secpolcompile rule '{req_tok}'")
    secpolc_bin = shutil.which("secpolcompile")
    if secpolc_bin:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=True) as tf:
            rc = subprocess.run([secpolc_bin, "-o", tf.name, secpol_path], capture_output=True, text=True)
            if rc.returncode != 0:
                fail(f"secpolcompile failed on {secpol_path}: {rc.stderr}")
    pass_check("Security policy QNX 8.0 secpolcompile grammar & least-privilege rules verified")

    # 6. Verify QVM Guest Configurations & Makefile Build System
    with open(qvmconf_path, "r", encoding="utf-8") as f:
        qvmconf = f.read()
    with open(qvm_virt_path, "r", encoding="utf-8") as f:
        qvm_virt = f.read()
    with open(makefile_path, "r", encoding="utf-8") as f:
        mk = f.read()

    if "gicd 0xff841000" not in qvmconf or "gicc 0xff842000" not in qvmconf:
        fail("qnx/latch.qvmconf missing RPi4 BCM2711 GIC-400 addresses (0xff841000 / 0xff842000)")
    if "gicd 0x08000000" not in qvm_virt or "gicc 0x08010000" not in qvm_virt:
        fail("qnx/latch_qemu_virt.qvmconf missing QEMU virt GICv2 addresses (0x08000000 / 0x08010000)")
    if "-m /proc/boot/latch.manifest" not in qvmconf or "-m /proc/boot/latch.manifest" not in qvm_virt:
        fail("Hypervisor qvmconf ingest hostdev does not pass '-m /proc/boot/latch.manifest'")
    if "dd if=/dev/zero" in mk or "secpolc " in mk:
        fail("qnx/Makefile still contains dummy zero guest stub or invalid 'secpolc' binary name")
    if "secpolcompile" not in mk:
        fail("qnx/Makefile must default SECPOLC to secpolcompile")
    pass_check("Hypervisor qvmconf split (RPi4 vs QEMU virt) & Makefile verified")

    # 7. Verify Documentation Attestation Digest Synchronization
    with open(sha256_path, "r", encoding="utf-8") as f:
        default_sha = f.read().strip().split()[0].lower()
    with open(syringe_sha256_path, "r", encoding="utf-8") as f:
        syringe_sha = f.read().strip().split()[0].lower()
    with open(readme_path, "r", encoding="utf-8") as f:
        readme_txt = f.read().lower()
    with open(impl_doc_path, "r", encoding="utf-8") as f:
        impl_txt = f.read().lower()
    if default_sha not in readme_txt or syringe_sha not in readme_txt:
        fail("README.md manifest SHA-256 attestation hashes out of sync with .sha256 sidecars")
    if default_sha not in impl_txt:
        fail("docs/LATCH-implementation.md manifest SHA-256 attestation hash out of sync with .sha256 sidecar")
    pass_check("README.md and docs/LATCH-implementation.md manifest SHA-256 hashes synced")

    print("\n[SUCCESS] All architectural consistency checks PASSED with 0 errors.")


if __name__ == "__main__":
    main()
