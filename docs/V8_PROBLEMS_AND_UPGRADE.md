# LATCH v8 problems and upgrade

The v8 planning documents describe an earlier tree. The active tree already contains a medical interval check, Governor capture target, A3/A7 attack scripts and a deadline counter. Their presence does not establish complete coverage.

Priority issues identified in review:

1. Medical window accounting must represent accepted motion, use the documented window semantics and treat expiry, rejected proposals and resets explicitly. This is a simulated contract, not a clinically validated pump.
2. DOSE and CONSIST have shared bit 15 in the legacy mask. A compatible wider interface requires end-to-end representation and migration; do not silently relabel existing recordings.
3. The event chain is computed after export. Empty evidence must be rejected, pagination and contract parameters validated, and a separately retained checkpoint required to substantiate completeness after sealing.
4. The earlier timing comparison contained fixed QNX figures and guessed cycle conversions. Use only measured samples and their recorded frequency and provenance; do not claim WCET from an observed maximum.
5. Evidence capture and consistency checks must propagate subprocess failures and identify stale contract digests. Capture QNX and VM-recovery results from the image actually built, and distinguish them from host simulation.

Maintain the existing schema-2 regression oracle and run `make -C qnx check`, `make -C qnx check-governor`, `python3 tools/attacks/run_attacks.py`, and `python3 tools/consistency_check.py` after changes. Rebuild and verify the QNX image when the installed toolchain and guest image are available.
