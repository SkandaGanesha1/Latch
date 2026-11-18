# LATCH Safety Envelope & Simplex Decision Specification

## 1. Commanded-Position Plant & Trust Boundary

LATCH (**Last Authority for Trusted Control Handoff**) governs a 1-DOF rotary servo horn driven by an external **PCA9685** 12-bit hardware PWM controller at I2C address `0x40` on the Raspberry Pi 4B (`i2c-bcm2711`).

Because a hobby servo (SG90) has no shaft encoder, this is a **commanded-position plant**:
- The guest policy on `_cpu-2` and `_cpu-3` sends only an integer angle proposal `u_mrad` in a 32-byte little-endian `LATH` frame (`0x4C415448`).
- The guest never supplies plant state (`theta_mrad`, `omega_mrad_s`) or clock timestamps.
- `latchd` on `_cpu-0` integrates its own committed commands, stamps arrival time with `ClockCycles()`, and is the only process on the board with an open file descriptor to `/dev/i2c1`.

## 2. Default Reference Envelope Parameters (`qnx/latch.manifest`)

All spatial and kinematic checks in `latchd` use 32-bit signed integers (`int32_t`) configured dynamically from `qnx/latch.manifest` (no compile-time `THETA_*` / `KEEPOUT_*` macros remain in `latch_protocol.h`):

| Manifest Key | Default Reference Value (`mrad`) | Degrees | Physical Meaning |
| --- | --- | --- | --- |
| `envelope.theta_min_mrad` | `-1000` | `-57.3°` | Lower mechanical endstop on the bench |
| `envelope.theta_max_mrad` | `+1000` | `+57.3°` | Upper mechanical endstop on the bench |
| `envelope.keepout[0].lo_mrad` | `+250` | `+14.3°` | Lower edge of the taped keep-out box |
| `envelope.keepout[0].hi_mrad` | `+650` | `+37.2°` | Upper edge of the taped keep-out box |

Rate, acceleration, and timing manifest fields:

| Manifest Key | Reference Value | Meaning |
| --- | --- | --- |
| `envelope.v_max` | `25` mrad/tick | Maximum slew step per tick |
| `envelope.a_max` | `10` mrad/tick² | Maximum velocity change per tick |
| `envelope.j_max` | `20` mrad/tick³ | Maximum allowable jerk step per tick |
| `envelope.v_home` | `10` mrad/tick | Retraction speed in `HA-HOME` |
| `envelope.lookahead_ticks` | `10` ticks | Forward lookahead horizon |
| `timing.watchdog_ticks` | `2` ticks | Maximum ticks without an accepted frame before `HOLD` |
| `recovery.hysteresis_clean_frames` | `25` frames | Consecutive clean frames required before restoring `HP` |
| `recovery.hold_to_home_ticks` | `50` ticks | Ticks in `HOLD` before transitioning to `HA-HOME` |

## 3. 10-Tick Forward Lookahead & Braking Invariance

Before accepting any proposal `u_mrad`, `latchd` verifies:

1. **Wire integrity**: `magic == 0x4C415448`, `version == 1`, `joint == 0`, `reserved[12] == 0`, IEEE 802.3 CRC32 (`0xEDB88320`) over bytes `[0, 16)`, `u_mrad != INT32_MIN`, and monotonic sequence advancement `seq > last_seq` (with `last_seq == 0` accepting any non-zero initial sequence), supporting frame coalescing under latest-wins delivery.
2. **Instantaneous step bounds**: `|u_mrad - theta_mrad| <= v_max`, `|(u_mrad - theta_mrad) - velocity_mrad_tick| <= a_max`, and third-order jerk bound `|a_step - accel_mrad_tick2| <= j_max`.
3. **Forward constant-`u` rollout** (`lookahead_ticks`, reference `10` ticks):
   ```c
   theta_next = sim_theta + clamp(u_mrad - sim_theta, -v_max, +v_max);
   ```
   repeated for `lookahead_ticks`. If any sample lands inside `[lo_mrad, hi_mrad]`, crosses a keep-out interval, or exits `[theta_min_mrad, theta_max_mrad]`, the proposal is rejected.
4. **Braking rollout**: Starting from the first step, `latchd` simulates maximum deceleration (`a_max`) to zero velocity and rejects the proposal if stopping momentum would enter a keep-out interval or exceed mechanical bounds.

## 4. Mode Switch & Two High-Assurance Candidates (`HA-HOLD`, `HA-HOME`)

```text
HP   -- bad frame, silence (>=2 ticks), or envelope violation --> HOLD
HOLD -- >= 50 ticks in HOLD, theta != 0, and legal path to 0 ---> HOME
HOLD -- 25 consecutive clean frames and legal trajectory -------> HP
HOME -- reached 0 mrad -----------------------------------------> HOLD
HOME -- new explicit violation ---------------------------------> HOLD
```

- **`HA-HOLD` (`latch_ha_hold`)**: Commands zero velocity (`next_theta = theta_mrad`), freezing the servo horn in place within one tick.
- **`HA-HOME` (`latch_ha_home`)**: Steps `theta_mrad` toward the manifest's `envelope.home_mrad` by at most `envelope.v_home` mrad per tick along the legal side of the keep-out box (a retraction that would cross a keep-out interval is refused), latching back into `HOLD` once `theta_mrad` reaches the home pose.

## 5. GOVERNOR Wire v2 Framing & Supervisory Gate Pipeline

When the schema-3 contract specifies `"protocol": "ieee32-v2"` with `"governor.enabled": 1`, the proposal wire interface upgrades to the 32-byte Wire v2 layout:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Magic (0x4C415448 'LATH')                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Version (=2)         |  Kind (CMD/HB)| Agent State   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number (seq)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Target Proposal Value (u_raw)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    IEEE 802.3 CRC32 Digest                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Coherence Counter (24-bit)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Engineering Unit ID (unit_id)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Conf Q8 (0..255)| Wire Flags  |           Reserved            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 5.1 CRC32 Disjoint Coverage
Unlike v1 which checks only the first 16 bytes, Wire v2 covers both header and metadata payloads across disjoint slices:
$$\text{CRC32}( \text{payload}[0..16) \mathbin{\Vert} \text{payload}[20..32) )$$
Byte slice `[16..20)` stores the CRC32 digest itself and is excluded from computation.

### 5.2 Supervisory Validation Gates
Every incoming proposal traverses four deterministic gates before touching the kinematic envelope:

1. **Unit Sanity Gate**: Manifest-declared rational table transforms engineering units:
   $$u_{\text{canonical}} = \frac{u_{\text{raw}} \times \text{num}}{\text{den}}$$
   Any unmapped `unit_id` trips `LATCH_FAULT_UNIT` (`0x1000`) and rejects the proposal.
2. **Token Bucket Rate Smoother**: Enforces burst and sustained slew rate limit:
   - Capacity: `burst_tokens` (default 40).
   - Refill: `refill_tokens_per_tick` (default 1).
   - Exceeding burst capacity asserts `LATCH_FAULT_RATE` (`0x0080`) and clamps step.
3. **Discrete-Time Control Barrier Function (DT-CBF)**:
   Verifies forward invariance condition:
   $$h(\theta_{k+1}, \dot{\theta}_{k+1}) \ge (1 - \gamma) h(\theta_k, \dot{\theta}_k), \quad \gamma \in (0, 1]$$
   Guaranteeing zero penetration of keepout intervals under full deceleration authority.
4. **Confidence-Driven Envelope Shrink**:
   When AI agent confidence `confidence_q8` drops or voluntary `SHRINK_REQ` arrives:
   $$v_{\text{max, effective}} = \frac{v_{\text{max}} \times \text{scale\_q8}}{256}$$
   Narrowing allowable operational slew boundaries proportional to uncertainty.

### 5.3 Graded Supervisory Degrade Ladder
Faults degrade the supervisor across discrete rungs rather than causing abrupt shutdowns:
$$\text{HP} \xrightarrow[\text{fault}]{\text{advisory}} \text{ADVISE} \xrightarrow[\Delta \ge K]{} \text{CLAMP} \xrightarrow{} \text{SLOW} \xrightarrow{} \text{SAFE\_STOP} \xrightarrow{} \text{LATCH}$$
- **Hysteresis Recovery**: Demoted rungs require exactly 25 consecutive clean, advancing command frames to promote back up by one rung.
- **Fail-Closed LATCH**: Hard envelope violations or sequence tampering drop immediately to `LATCH`, locking actuation in `HOLD` mode until authorized operator reset.

