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
- **`HA-HOME` (`latch_ha_home`)**: Steps `theta_mrad` toward `0` mrad by at most `V_HOME_MRAD_TICK` (`10` mrad/tick) along the legal side of the keep-out box (`theta_mrad < KEEPOUT_LO_MRAD`), latching back into `HOLD` once `theta_mrad == 0`.
