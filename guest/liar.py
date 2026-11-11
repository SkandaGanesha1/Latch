#!/usr/bin/env python3
"""
guest/liar.py — Untrusted Guest Policy & Fault-Injection Generator for LATCH.

Uses ONLY the Python 3 standard library (`struct`, `zlib`, `time`, `sys`,
`argparse`, `math`, `os`). Packs 32-byte little-endian `LATH` frames matching
`qnx/latch_protocol.h` (`<IHBBiII12s` / `<IHBBIiI12s`).

Supported modes:
  - nominal  : Smooth trajectory in [-600, +150] mrad (outside keep-out [250, 650])
  - keepout  : Proposes +450 mrad directly inside the taped keep-out box [250, 650]
  - corrupt  : Flips 1 bit in `u_mrad` after computing IEEE CRC32
  - replay   : Repeats the previous `seq` and then stops sending (watchdog fault)
  - nan      : Sends `u_mrad = INT32_MIN` (-2147483648) NaN-equivalent sentinel
  - suite    : Deterministic 200-tick end-to-end verification stream exercising all
               faults, 25-frame hysteresis recovery, and 50-tick HOLD -> HOME ramp.
"""

import argparse
import json
import math
import os
import struct
import sys
import time
import zlib

LATCH_WIRE_MAGIC = 0x4C415448  # 'LATH'
LATCH_WIRE_VERSION = 1
LATCH_WIRE_JOINT = 0
LATCH_NAN_MRAD = -2147483648
LATCH_WIRE_FLAG_NONE = 0x00
LATCH_WIRE_FLAG_SILENCE = 0x80

HEADER_PREFIX_FMT = "<IHBBIi"   # 16 bytes covered by CRC32
WIRE_FRAME_FMT = "<IHBBIiI12s"  # 32 bytes total


def pack_wire_frame(
    seq: int,
    u_mrad: int,
    flags: int = LATCH_WIRE_FLAG_NONE,
    corrupt_bit: bool = False,
    bad_reserved: bool = False,
) -> bytes:
    prefix = struct.pack(
        HEADER_PREFIX_FMT,
        LATCH_WIRE_MAGIC,
        LATCH_WIRE_VERSION,
        LATCH_WIRE_JOINT,
        flags & 0xFF,
        seq & 0xFFFFFFFF,
        int(u_mrad),
    )
    crc = zlib.crc32(prefix) & 0xFFFFFFFF
    u_wire = int(u_mrad) ^ 0x00000100 if corrupt_bit else int(u_mrad)
    reserved = b"\x01" + (b"\x00" * 11) if bad_reserved else (b"\x00" * 12)
    return struct.pack(
        WIRE_FRAME_FMT,
        LATCH_WIRE_MAGIC,
        LATCH_WIRE_VERSION,
        LATCH_WIRE_JOINT,
        flags & 0xFF,
        seq & 0xFFFFFFFF,
        u_wire,
        crc,
        reserved,
    )


def generate_suite_frames() -> list:
    """
    Generates a deterministic 200-tick verification sequence:
      - Ticks 1..25   : Nominal tracking (0 -> -150 mrad, smooth steps <= 10 mrad/tick)
      - Ticks 26..32  : Fault #1 — Keep-out box proposal (+450 mrad inside [250, 650])
      - Ticks 33..62  : 25-clean-frame hysteresis recovery at -150 mrad, then step to -180 mrad
      - Ticks 63..66  : Fault #2 — CRC bit-flip corruption on the wire
      - Ticks 67..70  : NaN sentinel fault (u_mrad = INT32_MIN)
      - Ticks 71..80  : 10 clean frames (partial streak < 25, stays in HOLD)
      - Ticks 81..84  : Fault #3 — Sequence replay (repeats seq from tick 80)
      - Ticks 85..200 : Fault #4 — Guest killed / silent (`kill -9` simulation):
                        Watchdog trips at tick 86 (2 ticks silent),
                        stays in HOLD until 50 ticks in HOLD complete,
                        transitions to HA-HOME and retracts from -180 mrad to 0 mrad
                        at V_HOME = 10 mrad/tick, then latches safely in HOLD at 0 mrad.
    """
    frames = []
    seq = 1
    theta = 0

    # 1. Ticks 1..25: Nominal tracking in HP mode
    for t in range(1, 26):
        if theta > -150:
            theta -= 10
        frames.append(pack_wire_frame(seq=seq, u_mrad=theta))
        seq += 1

    # 2. Ticks 26..32: Fault #1 — Keep-out violation (+450 mrad inside [250, 650])
    for t in range(26, 33):
        frames.append(pack_wire_frame(seq=seq, u_mrad=450))
        seq += 1

    # 3. Ticks 33..57: 25 consecutive clean frames at current held pose (-150 mrad)
    for t in range(33, 58):
        frames.append(pack_wire_frame(seq=seq, u_mrad=-150))
        seq += 1

    # 4. Ticks 58..62: Restored HP mode tracking (-150 -> -180 mrad)
    for t in range(58, 63):
        if theta > -180:
            theta -= 10
        frames.append(pack_wire_frame(seq=seq, u_mrad=theta))
        seq += 1

    # 5. Ticks 63..66: Fault #2 — Flip one bit after CRC calculation
    for t in range(63, 67):
        frames.append(pack_wire_frame(seq=seq, u_mrad=-180, corrupt_bit=True))
        seq += 1

    # 6. Ticks 67..70: NaN sentinel (INT32_MIN)
    for t in range(67, 71):
        frames.append(pack_wire_frame(seq=seq, u_mrad=LATCH_NAN_MRAD))
        seq += 1

    # 7. Ticks 71..80: 10 clean frames (tests hysteresis does not restore early)
    last_good_seq = seq
    for t in range(71, 81):
        last_good_seq = seq
        frames.append(pack_wire_frame(seq=seq, u_mrad=-180))
        seq += 1

    # 8. Ticks 81..84: Fault #3 — Replay previous sequence number
    for t in range(81, 85):
        frames.append(pack_wire_frame(seq=last_good_seq, u_mrad=-180))

    # 9. Ticks 85..200: Fault #4 — Silence / guest killed (watchdog -> HA-HOLD -> HA-HOME -> 0)
    for t in range(85, 201):
        frames.append(
            pack_wire_frame(seq=last_good_seq, u_mrad=0, flags=LATCH_WIRE_FLAG_SILENCE)
        )

    return frames


def main() -> int:
    parser = argparse.ArgumentParser(description="LATCH Untrusted Guest Policy / Liar")
    parser.add_argument(
        "mode",
        choices=["nominal", "keepout", "corrupt", "replay", "nan", "suite"],
        default="suite",
        nargs="?",
        help="Fault injection mode",
    )
    parser.add_argument(
        "--device",
        default="-",
        help="Output device path (e.g. /dev/hvc0) or '-' for stdout",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="Number of frames to emit in single-fault mode",
    )
    parser.add_argument(
        "--period-ms",
        type=float,
        default=1.0,
        help="Sleep interval between frames in ms (default: 1.0 ms for 1 kHz paced execution; 0.0 for burst stress test)",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="Path to latch.manifest for dynamic plant geometry",
    )
    parser.add_argument(
        "--raw-stdout",
        action="store_true",
        help="Write raw 32-byte binary frames to stdout",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Continuously stream frames in an endless loop until process killed",
    )
    args = parser.parse_args()

    keepout_target = 450
    if args.manifest and os.path.exists(args.manifest):
        try:
            with open(args.manifest, "r") as mf:
                mdata = json.load(mf)
                klist = mdata.get("envelope", {}).get("keepout", [])
                if klist:
                    keepout_target = (klist[0].get("lo_mrad", 250) + klist[0].get("hi_mrad", 650)) // 2
        except Exception as e:
            sys.stderr.write(f"Warning: could not parse manifest: {e}\n")

    if args.mode == "suite":
        frames = generate_suite_frames()
    else:
        frames = []
        seq = 1
        theta = 0
        vel = 0
        for i in range(args.count):
            if args.mode == "nominal":
                target = int(-200 + 150 * math.sin(i * 0.1))
                desired_vel = max(-25, min(25, target - theta))
                dv = max(-10, min(10, desired_vel - vel))
                vel += dv
                theta += vel
                frames.append(pack_wire_frame(seq=seq, u_mrad=theta))
                seq += 1
            elif args.mode == "keepout":
                frames.append(pack_wire_frame(seq=seq, u_mrad=keepout_target))
                seq += 1
            elif args.mode == "corrupt":
                frames.append(pack_wire_frame(seq=seq, u_mrad=-100, corrupt_bit=True))
                seq += 1
            elif args.mode == "replay":
                if i < 4:
                    theta -= 10
                    frames.append(pack_wire_frame(seq=seq, u_mrad=theta))
                    seq += 1
                elif i == 4:
                    frames.append(pack_wire_frame(seq=seq - 1, u_mrad=theta))
                else:
                    frames.append(
                        pack_wire_frame(seq=seq, u_mrad=0, flags=LATCH_WIRE_FLAG_SILENCE)
                    )
            elif args.mode == "nan":
                frames.append(pack_wire_frame(seq=seq, u_mrad=LATCH_NAN_MRAD))
                seq += 1

    def send_frames(dest_stream, dest_fd):
        for f in frames:
            if dest_stream:
                dest_stream.write(f)
                if args.period_ms > 0:
                    dest_stream.flush()
                    time.sleep(args.period_ms / 1000.0)
            elif dest_fd is not None:
                os.write(dest_fd, f)
                if args.period_ms > 0:
                    time.sleep(args.period_ms / 1000.0)
        if dest_stream:
            dest_stream.flush()

    if args.device == "-" or args.raw_stdout:
        out = sys.stdout.buffer
        while True:
            send_frames(out, None)
            if not args.loop:
                break
    else:
        fd = os.open(args.device, os.O_WRONLY)
        try:
            while True:
                send_frames(None, fd)
                if not args.loop:
                    break
        finally:
            os.close(fd)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
