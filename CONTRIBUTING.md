# Contributing

LATCH is a prototype; keep changes reviewable and claims tied to their
evidence. Read the architecture in `docs/LATCH-implementation.md` and the
envelope in `docs/envelope.md` before changing safety behavior.

Run `make -C qnx check` and `python3 tools/consistency_check.py`. For a
consistency-gate change, also run `make -C qnx mutation-check`. For target
behavior, record the SDK, image, command, target, and actual output; host
simulation does not demonstrate QNX target behavior. Report failures rather
than replacing them with expected output.

Manifests and their SHA-256 sidecars must remain synchronized. Sidecars are
checksums, not signatures. Do not commit build products, credentials, model
weights, or private target details. Evidence under `docs/evidence/` is
generated: change its generator and regenerate it instead of editing it by
hand. Clearly identify any hardware or timing claims that remain unverified.
