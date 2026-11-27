# GOVERNOR wire v2 and ingest IPC specification

**Status:** Wire parsing, IPC decoding, ingest dispatch, supervisor policy, lease, prechecks, and host end-to-end path are implemented. QNX link/boot and target runtime evidence are archived (`docs/evidence/governor/governor-qemu-verify.txt`, `governor-qemu-console.txt`, `governor-status-transition.txt`).  
**Compatibility target:** preserve the checked-in 32-byte wire-v1 frame and 24-byte `LPRP` proposal exactly.

## 1. Trust model

All guest input is untrusted. CRC checks detect accidental corruption and framing errors; CRC is not authentication and does not make a guest claim trustworthy. `latchd` owns time, the lease, fault severity, GOVERNOR rung transitions, and the final envelope decision. A guest may propose a command or request less authority. It cannot set plant state or widen host-configured limits.

Protocol parsing uses byte offsets and explicit little-endian decode helpers. Do not dereference the packed wire frame as a host-native structure at the trust boundary. Any CMD, CMD_V2, or normalized candidate still passes the existing envelope validator before actuation.

## 2. Wire frame

The transport remains exactly 32 bytes. The v2 frame uses the existing field offsets and version-gates byte 7. Wire-v1 behavior, including `SILENCE=0x80`, remains unchanged.

| Offset | Width | v1 | v2 |
|---:|---:|---|---|
| 0 | 4 | magic `0x4C415448` (`LATH`) | same |
| 4 | 2 | version `1` | version `2` |
| 6 | 1 | joint `0` | joint `0` |
| 7 | 1 | flags (`DEMO`, live `SILENCE`) | kind: `CMD=0`, `HEARTBEAT=1`, `CMD_V2=2`, `SHRINK_REQ=3` |
| 8 | 4 | monotonic sequence | same sequence space for all v2 kinds in a session |
| 12 | 4 | signed command in manifest units | signed command or kind-specific value below |
| 16 | 4 | IEEE CRC32 over bytes `[0,16)` | version-2 CRC over concatenated bytes `[0,16)` and `[20,32)` |
| 20 | 4 | reserved, all zero | `confidence_q8` as LE u32, valid values 0–255 |
| 24 | 1 | reserved, zero | `agent_state`: 0 boot, 1 nominal, 2 degraded, 3 recovering, 4 unknown |
| 25 | 3 | reserved, zero | `coherence_ctr` as LE uint24 |
| 28 | 4 | reserved, zero | `unit_id` for CMD_V2; zero for message kinds without command units |

The v2 CRC uses the same reflected IEEE polynomial, initial value, and final XOR as v1, but feeds the first 16 bytes and then the final 12 bytes into one CRC stream; the checksum field `[16,20)` is excluded. This protects the v2 metadata tail against transmission corruption while preserving the v1 checksum algorithm and bytes.

### 2.1 Kind-specific constraints

- `CMD`: `u_mrad` is the proposal. Confidence, agent state, coherence counter, and unit ID must be zero. It uses the contract's canonical unit and cannot start or renew a lease.
- `HEARTBEAT`: `u_mrad` and confidence must be zero. Agent state is 0–4. The coherence counter must advance within the contract's maximum gap to renew the host-owned lease. A heartbeat has no plant authority.
- `CMD_V2`: `u_mrad` is the proposal. Confidence is unsigned Q0.8 in 0–255, so 255 means 255/256. Agent state is 0–4, coherence is uint24, and `unit_id` must name a unit declared by the contract. The contract maps alternate IDs to exact rational conversions into its canonical unit. Unknown IDs, non-integral conversions, or overflow are rejected; command magnitude is never used to guess units. A valid message may renew the lease but does not bypass the command gate.
- `SHRINK_REQ`: `u_mrad` carries a proposed maximum velocity in the contract's canonical integer unit; confidence carries a Q0.8 scale in 1–255. Unit ID must be zero. The frame must carry valid coherent progress, but cannot create a session or renew the lease. The host accepts only values no greater than current effective limits; a request that would widen is rejected and classified as a policy fault.
- Unknown v2 kinds, nonzero reserved bytes, invalid agent states, invalid kind-specific fields, or an invalid v2 CRC are structural failures. Ingest maps these to existing wire fault bits so the current `LATCH_FAULT_WIRE_MASK` forwarding contract is not silently bypassed.
- The first valid heartbeat or CMD_V2 establishes the guest counter baseline. Subsequent v2 messages require a modulo-2^24 forward delta in `[1, coherence_max_gap]`; this supports normal 24-bit wrap while rejecting duplicate, backwards, and excessive jumps. A genuine writer-session transition establishes a new baseline.
- The proposal resource manager permits one writer at a time; a concurrent writer open returns `EBUSY`. The producer tag in the IPC payload is sender supplied and is not authentication. This change requires fresh QNX target validation.

### 2.2 Sequence and session handling

The monotonically increasing wire sequence is checked by `latchd` as today and applies to every v2 frame kind, including heartbeats. Ingest validates framing, CRC, kind and reserved bytes; it does not establish session authority. `latchd` starts lease state only after the first structurally valid, sequence-valid v2 heartbeat or CMD_V2 in a new session. V1 continues to use the existing watchdog and silence behavior.

Lease time is counted by the trusted supervisor's ticks. Guest coherence is only a progress signal and is never used as a clock. HEARTBEAT and valid CMD_V2 renew the lease; coherent SHRINK_REQ updates the counter baseline but does not refresh lease time. A missing, frozen, replayed, or out-of-window coherence count does not renew the lease. Lease expiry, invalid coherence, and WIDEN each cause one immediate rung demotion. If the lease remains expired, each subsequent lease window causes one further rung demotion; SAFE_STOP reaches LATCH after its next expiry unless an authorized operator release occurs. This cadence is deliberate and makes the demotion rate independent of guest message volume. Repeated UNIT-class faults use `demote_faults_per_rung`.

Recovery streaks require fresh coherent commands that passed structural, sequence, unit, and envelope validation. An idle supervisor tick with no input frame preserves the accepted-command streak; a received HEARTBEAT, SHRINK_REQ, or rejected frame clears it. HEARTBEAT may renew a lease and update health metadata, but never counts as a clean recovery frame and never promotes a rung. Status exposes age since the last lease renewal; valid SHRINK_REQ activity does not make the lease appear fresher.

The versioned GOVERNOR status devctl keeps the legacy status prefix unchanged. Extension version 2 includes the current clean-command recovery streak so an operator can distinguish rejected commands, heartbeat-only traffic, and a rung waiting for its configured recovery threshold.

## 3. Internal IPC

The LPRP v1 message remains 24 bytes with its current layout and magic. V2 uses a distinct 56-byte LPR2 message. The supplied proposal listed 20 bytes of appended fields after a 24-byte prefix, which totals 44 bytes; this layout adds explicit padding/reserved bytes to satisfy the intended 48-byte ABI and makes offsets checkable. The session epoch (RT-02, below) appended two further 32-bit fields, taking the message to 56 bytes; every offset remains checkable by a compile-time assertion.

| Offset | Width | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | `ipc_magic` | `0x4C505232` (`LPR2`) |
| 4 | 4 | `seq` | checked sequence |
| 8 | 4 | `u_mrad` | validated payload or zero when structurally discarded |
| 12 | 2 | `wire_flags` | v2 kind in low byte; high byte zero |
| 14 | 2 | `pre_fault_bits` | only existing wire mask bits from ingest |
| 16 | 8 | `ingest_cycles` | host ingest observation |
| 24 | 2 | `ipc_version` | `2` |
| 26 | 1 | `wire_version` | `2` |
| 27 | 1 | `kind` | 0–3 |
| 28 | 1 | `confidence_q8` | 0–255 |
| 29 | 1 | `agent_state` | 0–4 |
| 30 | 2 | `producer_tag` | identity of the bridge that produced the frame; `0` is reserved and rejected |
| 32 | 4 | `coherence_ctr` | low 24 bits used; high byte zero |
| 36 | 4 | `shrink_v` | only SHRINK_REQ; otherwise zero |
| 40 | 4 | `shrink_scale_q8` | only SHRINK_REQ; otherwise zero |
| 44 | 4 | `unit_id` | CMD_V2 source unit; zero for other kinds |
| 48 | 4 | `session_epoch` | producer-chosen session epoch; `0` is reserved and rejected |
| 52 | 4 | `reserved1` | zero |

Both IPC structs have compile-time size and offset assertions. `latchd` accepts exactly 24 bytes with LPRP or exactly 56 bytes with LPR2; all other lengths and mismatched magic/version pairs are rejected. The ring payload must represent either message without modifying its odd/even seqlock publication protocol. V1 publishes zeroed v2 fields.

### 3.1 Session epoch (RT-02)

The supervisor re-bases its sequence baseline whenever a session opens, so the sequence number alone cannot distinguish a frame that belongs to this session from a frame captured in an earlier one. The epoch makes the session's identity explicit.

- The **producer** chooses a fresh epoch for every session it opens and stamps it on every frame it forwards (`latch-ingest --session-epoch N`; the default is a fresh value derived from the monotonic clock, the wall clock and the pid).
- The **supervisor** binds the epoch of the session it is running and rejects every frame that names a different one. The rejection is a `LATCH_FAULT_SEQ` fault: the epoch is the session's sequence namespace, and the fault taxonomy already has a bit for it. A rejected frame cannot move the plant, advance the sequence, renew the lease or earn warm-up credit.
- The epoch is bound **only after** the frame has passed the sequence check, so a stale frame that happens to arrive first cannot become the session's identity.
- The supervisor keeps a ring of the **16 most recently used epochs**. An epoch that has already been spent can never be bound again, so a producer that restarts and reuses its previous epoch is rejected rather than being allowed to resume the old session's identity. The ring outlives the session: it is the supervisor's memory of which epochs are spent, not part of the session.
- The **first frame of a session opened by a new producer must carry `seq == 1`.** A session's sequence space starts at 1, so this is the only frame that can legitimately open one. Without the rule, a frame captured mid-session in an earlier session — say one carrying `seq = 999999` — was accepted as the first frame of the new session, became the new baseline, and could move the plant.
- A **takeover** by an already-running producer rebases to that producer's own sequence space, which does not start at 1; it is protected by the epoch ring instead. The old epoch stays bound until the takeover frame is accepted, and a takeover epoch that has already been spent cannot be bound.

What the epoch is **not**: it is an identifier, not a secret and not an authentication mechanism. It protects against *stale* frames — frames captured in an earlier session — not against a peer that can forge a frame carrying the current epoch. The `producer_tag` has the same property: it scopes the lease, it does not authenticate the sender.

## 4. Fault namespace decision

Existing fault bits 0–11 remain unchanged. For this protocol milestone, reserve the upper four bits as:

| Bit | Name | Classification |
|---:|---|---|
| 12 | `UNIT` | unknown or invalid unit metadata; may be advisory only when explicitly enabled by contract |
| 13 | `HEARTBEAT` | lease/coherence fault; rung demotion |
| 14 | `WIDEN` | shrink request would increase authority; rung demotion |
| 15 | `DOSE` | Dose/step-rate limit exceeded for the active rung (medical `LATCH_FAULT_DOSE`); medical contracts treat it as a hard fault even when the advisory mask includes it. Backward-compatibility alias: `CONSIST`. |

This assignment follows the implementation plan. Bit 15 is live as `DOSE` — the medical syringe contract asserts it on over-infusion (`0x8000`), and the servo contract may enable it via its advisory mask; `LATCH_FAULT_CONSIST` remains as a source-compatibility alias for `DOSE`. No existing fault meaning is renumbered.

**Medical dose faults fail closed.** For a medical contract, the supervisor removes `DOSE` from the effective advisory mask and treats a dose violation as a hard fault requiring operator release, even if the manifest mask contains that bit. The manifest mask alone therefore does not soften medical dose faults. For nonmedical contracts, the configured advisory mask governs classification. The `CONSIST` name is a compatibility alias for bit 15, not a separate fault.

## 5. Test vectors and required checks

The protocol implementation must provide tests for:

- v1 byte-for-byte encoding and live `SILENCE=0x80` behavior;
- valid v2 CMD, HEARTBEAT, CMD_V2, and SHRINK_REQ frames;
- byte-order, size, magic, version, joint, kind, CRC, reserved, and kind-specific field failures;
- corrupted bytes in both v2 header and metadata tail;
- sequence replay/gap/wrap and coherence duplicate/gap/wrap/session reset;
- invalid or overflowing shrink limits, confidence values, and boundary conversions;
- ingest mapping only to allowed wire-mask bits;
- exact 24-byte/56-byte IPC acceptance and wrong-size/magic/version rejection;
- a v2 frame with no session epoch, a zero reserved word, or a mismatched epoch is rejected;
- the first frame of a new session must carry `seq == 1`, a frame naming another session is rejected without moving the plant, and an epoch that has already been spent cannot be bound again;
- v1 scenario tape remains identical and mode remains in `{0,1,2}`.

Host tests cover v2 framing, CRC and kind constraints, exact LPRP/LPR2 sizes, schema-3 positive/negative cases, and a full v2 wire → ingest → LPR2 → latchd pipe scenario. `latch_ingest` dispatches v2 only when the loaded schema-3 contract selects protocol v2 and enables GOVERNOR; `latchd` repeats that authorization check before publishing an LPR2 message. The enabled example contract remains opt-in: the default schema-2 servo manifest continues to use wire v1. QNX resource-manager handling is validated on the QNX AArch64 target run (payload-length checks against the QNX receive buffer are enforced per the [QNX resource-manager security guidance](https://qnx.com/developers/docs/8.0/com.qnx.doc.security.system/topic/manual/write_resource_manager.html)).
