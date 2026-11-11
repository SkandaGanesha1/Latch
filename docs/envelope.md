# LATCH Safety Envelope & Simplex Decision Specification

## 1. Commanded-Position Plant & Trust Boundary

LATCH (**Last Authority for Trusted Control Handoff**) governs a 1-DOF rotary servo horn driven by an external **PCA9685** 12-bit hardware PWM controller at I2C address `0x40` on the Raspberry Pi 4B (`i2c-bcm2711`).

Because a hobby servo (SG90) has no shaft encoder, this is a **commanded-position plant**:
- The guest policy on `_cpu-2` and `_cpu-3` sends only an integer angle proposal `u_mrad` in a 32-byte little-endian `LATH` frame (`0x4C415448`).
- The guest never supplies plant state (`theta_mrad`, `omega_mrad_s`) or clock timestamps.
- `latchd` on `_cpu-0` integrates its own committed commands, stamps arrival time with `ClockCycles()`, and is the only process on the board with an open file descriptor to `/dev/i2c1`.

## 2. The Four Integer Envelope Boundaries

All spatial and kinematic checks in `latchd` use 32-bit signed integers (`int32_t`) in milliradians (`mrad`):

| Constant | Value (`mrad`) | Degrees | Physical Meaning |
| --- | --- | --- | --- |
| `THETA_MIN_MRAD` | `-1000` | `-57.3°` | Lower mechanical endstop on the bench |
| `THETA_MAX_MRAD` | `+1000` | `+57.3°` | Upper mechanical endstop on the bench |
| `KEEPOUT_LO_MRAD` | `+250` | `+14.3°` | Lower edge of the taped keep-out box |
| `KEEPOUT_HI_MRAD` | `+650` | `+37.2°` | Upper edge of the taped keep-out box |

Rate, acceleration, and timing constants:

| Constant | Value | Meaning |
| --- | --- | --- |
| `V_MAX_MRAD_TICK` | `25` mrad/tick | Maximum slew step per tick |
| `A_MAX_MRAD_TICK2` | `10` mrad/tick² | Maximum velocity change per tick |
| `V_HOME_MRAD_TICK` | `10` mrad/tick | Retraction speed in `HA-HOME` |
| `HORIZON_TICKS` | `10` ticks | Forward lookahead horizon |
| `WATCHDOG_TICKS` | `2` ticks | Maximum ticks without an accepted frame before `HOLD` |
| `HYSTERESIS_CLEAN_FRAMES` | `25` frames | Consecutive clean frames required before restoring `HP` |
| `HOLD_TO_HOME_TICKS` | `50` ticks | Ticks in `HOLD` before transitioning to `HA-HOME` |

## 3. 10-Tick Forward Lookahead & Braking Invariance

Before accepting any proposal `u_mrad`, `latchd` verifies:

1. **Wire integrity**: `magic == 0x4C415448`, `version == 1`, `joint == 0`, `reserved[12] == 0`, IEEE 802.3 CRC32 (`0xEDB88320`) over bytes `[0, 16)`, `u_mrad != INT32_MIN`, and `seq == last_seq + 1`.
2. **Instantaneous step bounds**: `|u_mrad - theta_mrad| <= V_MAX_MRAD_TICK` and `|(u_mrad - theta_mrad) - velocity_mrad_tick| <= A_MAX_MRAD_TICK2`.
3. **10-tick constant-`u` rollout**:
   ```c
   theta_next = sim_theta + clamp(u_mrad - sim_theta, -V_MAX_MRAD_TICK, +V_MAX_MRAD_TICK);
   ```
   repeated for 10 ticks. If any sample lands inside `[KEEPOUT_LO_MRAD, KEEPOUT_HI_MRAD]` (`[250, 650]`), crosses the keep-out interval, or exits `[THETA_MIN_MRAD, THETA_MAX_MRAD]` (`[-1000, +1000]`), the proposal is rejected.
4. **10-tick braking rollout**: Starting from the first step, `latchd` simulates maximum deceleration (`A_MAX_MRAD_TICK2 = 10`) to zero velocity and rejects the proposal if stopping momentum would enter the keep-out box or exceed mechanical bounds.

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
