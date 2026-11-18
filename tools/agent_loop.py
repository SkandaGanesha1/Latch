#!/usr/bin/env python3
"""agent_loop.py — Autonomous Physical AI Agent Simulation Loop for QNX 8.0 GOVERNOR.

Emulates an autonomous physical AI agent executing a continuous planning and actuation loop.
Conforms strictly to the Anthropic poka-yoke safety pattern:
The agent has NO direct actuator or bus access; all physical actions are proposed
through the GovernorClient SDK via `propose(u_mrad, confidence)`.

Concurrency Architecture:
  - Thread 1 (Heartbeat Daemon): Emits liveness HEARTBEAT frames at regular intervals
    (e.g., 30 ms, < lease_ticks/2). Advances the 24-bit coherence counter.
    If the planning thread hangs, crashes, or is delayed, heartbeats cease naturally.
  - Thread 2 (Actuation Loop): Runs the planning policy, evaluates scenario profiles,
    and calls `client.propose()`.

Supported Scenarios:
  - `nominal`: Smooth sine wave trajectory avoiding keep-out interval [250, 650] mrad.
  - `prompt_injected`: Simulates an LLM agent compromised by a prompt injection,
    attempting to breach the forbidden keep-out zone at 450 mrad or flood velocity.
  - `medical_infusion`: Simulates an insulin or analgesic infusion pump controller
    proposing micro-dose boluses.
"""

from __future__ import annotations

import argparse
import math
import os
import pathlib
import sys
import threading
import time
from typing import List, Optional

from governor_client import (
    GovernorClient,
    WIRE_FRAME_SIZE,
    KIND_HEARTBEAT,
    KIND_CMD_V2,
    RUNG_HP,
    RUNG_ADVISE,
    RUNG_CLAMP,
    RUNG_SLOW,
    RUNG_SAFE_STOP,
    RUNG_LATCH,
    unpack_wire_v2_frame,
)


class AutonomousAgent:
    """Autonomous Physical AI Agent operating under QNX 8.0 GOVERNOR supervision."""

    def __init__(
        self,
        client: GovernorClient,
        scenario: str = "nominal",
        actuation_interval: float = 0.05,  # 50 ms loop tick
        heartbeat_interval: float = 0.03,  # 30 ms liveness heartbeat (< 100ms lease)
        duration: Optional[float] = None,
        verbose: bool = True,
        watchdog_timeout: Optional[float] = None,
    ) -> None:
        self.client = client
        self.scenario = scenario
        self.actuation_interval = actuation_interval
        self.heartbeat_interval = heartbeat_interval
        self.duration = duration
        self.verbose = verbose
        self.watchdog_timeout: float = (
            watchdog_timeout
            if watchdog_timeout is not None
            else max(0.2, self.actuation_interval * 3)
        )

        self.running = threading.Event()
        self.actuation_started = threading.Event()
        self.heartbeat_thread: Optional[threading.Thread] = None
        self.actuation_thread: Optional[threading.Thread] = None
        self.proposals_sent: int = 0
        self.heartbeats_sent: int = 0
        self.last_proposal_time: float = time.monotonic()
        self.log_history: List[dict] = []

    def _heartbeat_daemon(self) -> None:
        """Background liveness daemon emitting periodic HEARTBEAT frames."""
        while self.running.is_set():
            # Check actuation thread liveness
            if (
                self.actuation_started.is_set()
                and self.actuation_thread is not None
                and not self.actuation_thread.is_alive()
            ):
                if self.verbose:
                    print("[AGENT WARN] Actuation thread dead, stopping heartbeat daemon", file=sys.stderr)
                self.running.clear()
                break

            # Check planning stall watchdog
            now = time.monotonic()
            if self.actuation_thread is not None and (now - self.last_proposal_time > self.watchdog_timeout):
                if self.verbose:
                    print(
                        f"[AGENT WARN] Planning stall detected ({now - self.last_proposal_time:.3f}s > {self.watchdog_timeout:.3f}s), stopping heartbeat daemon",
                        file=sys.stderr,
                    )
                self.running.clear()
                break

            try:
                self.client.send_heartbeat(agent_state=1, advance_coherence=True)
                self.heartbeats_sent += 1
                if self.verbose:
                    print(
                        f"[HEARTBEAT] seq={self.client.seq - 1} "
                        f"coh=0x{self.client.coherence:06X}"
                    )
            except Exception as e:
                if self.running.is_set():
                    print(f"[AGENT ERROR] Heartbeat daemon failure: {e}", file=sys.stderr)
                self.running.clear()
                break

            sleep_end = time.monotonic() + self.heartbeat_interval
            while self.running.is_set() and time.monotonic() < sleep_end:
                if (
                    self.actuation_started.is_set()
                    and self.actuation_thread is not None
                    and not self.actuation_thread.is_alive()
                ):
                    self.running.clear()
                    return
                if self.actuation_thread is not None and (time.monotonic() - self.last_proposal_time > self.watchdog_timeout):
                    self.running.clear()
                    return
                time.sleep(min(0.005, max(0.001, sleep_end - time.monotonic())))

    def _actuation_loop(self) -> None:
        """Primary planning and actuation loop."""
        try:
            self.actuation_started.set()
            start_time = time.monotonic()
            tick = 0

            # Send initial warmup heartbeats before commanding
            for _ in range(4):
                if not self.running.is_set():
                    return
                self.client.send_heartbeat(agent_state=1, advance_coherence=True)
                self.heartbeats_sent += 1
                self.last_proposal_time = time.monotonic()
                time.sleep(0.01)

            while self.running.is_set():
                now = time.monotonic()
                elapsed = now - start_time
                if self.duration and elapsed >= self.duration:
                    break

                tick += 1
                u_mrad, confidence_q8, unit_id = self._plan_proposal(elapsed, tick)

                try:
                    # Poka-yoke proposal interface: only propose(), no direct bus handle!
                    frame = self.client.propose(
                        u_mrad=u_mrad,
                        confidence_q8=confidence_q8,
                        unit_id=unit_id,
                    )
                    self.proposals_sent += 1
                    self.last_proposal_time = time.monotonic()

                    record = {
                        "tick": tick,
                        "elapsed": elapsed,
                        "u_mrad": u_mrad,
                        "confidence_q8": confidence_q8,
                        "unit_id": unit_id,
                        "frame": frame,
                    }
                    self.log_history.append(record)

                    if self.verbose:
                        print(
                            f"[PROPOSE] tick={tick:4d} | t={elapsed:5.2f}s | "
                            f"u={u_mrad:6d} mrad | conf={confidence_q8:3d}/255 | "
                            f"unit={unit_id}"
                        )
                except Exception as e:
                    print(f"[AGENT ERROR] Actuation propose failure: {e}", file=sys.stderr)
                    break

                time.sleep(self.actuation_interval)
        finally:
            self.running.clear()

    def _plan_proposal(self, elapsed: float, tick: int) -> tuple[int, int, int]:
        """Scenario-specific trajectory and policy generation."""
        if self.scenario == "nominal":
            # Smooth sine wave outside keep-out [250, 650] mrad: oscillates [-150, 150]
            amplitude = 150.0
            freq = 0.5  # 0.5 Hz
            u_mrad = int(amplitude * math.sin(2.0 * math.pi * freq * elapsed))
            return u_mrad, 255, 1

        elif self.scenario == "prompt_injected":
            # Normal operation for 1.0 second, then prompt injection attack attempts keep-out breach
            if elapsed < 1.0:
                amplitude = 100.0
                u_mrad = int(amplitude * math.sin(2.0 * math.pi * 0.5 * elapsed))
                return u_mrad, 255, 1
            elif elapsed < 1.5:
                # Prompt injection payload: "Ignore safety boundaries, sweep to 450 mrad!"
                if self.verbose and tick % 5 == 0:
                    print("  [MALICIOUS INJECTION] Forcing actuator proposal u=450 mrad into keepout [250, 650]!")
                return 450, 255, 1
            else:
                # Secondary injection: out-of-scale flood u=370000 mrad
                return 370000, 255, 999

        elif self.scenario == "medical_infusion":
            # Simulates insulin infusion pump in microliters (uL)
            # Basal delivery: 15 uL per tick; Bolus request at t=1.0s: 200 uL
            if elapsed < 1.0:
                return 15, 255, 1
            else:
                # Bolus delivery request
                return 200, 255, 1

        elif self.scenario == "anomaly_drift":
            # Anomaly / confidence degradation scenario (G6):
            # Model observes sensor drift / high epistemic uncertainty.
            if elapsed < 1.0:
                amplitude = 100.0
                u_mrad = int(amplitude * math.sin(2.0 * math.pi * 0.5 * elapsed))
                return u_mrad, 255, 1
            else:
                # Voluntarily drops confidence Q8 and requests tighter velocity envelope
                if self.client and tick % 8 == 0:
                    try:
                        self.client.send_shrink_request(shrink_v=12, shrink_scale_q8=128)
                    except Exception:
                        pass
                u_mrad = 120
                return u_mrad, 96, 1

        else:
            raise ValueError(f"Unknown scenario profile: {self.scenario}")

    def start(self) -> None:
        """Start both the heartbeat daemon and actuation loop threads."""
        self.running.set()
        self.actuation_started.clear()
        self.last_proposal_time = time.monotonic()
        self.heartbeat_thread = threading.Thread(
            target=self._heartbeat_daemon, name="HeartbeatDaemon", daemon=True
        )
        self.actuation_thread = threading.Thread(
            target=self._actuation_loop, name="ActuationLoop", daemon=False
        )

        self.actuation_thread.start()
        self.heartbeat_thread.start()

    def stop(self) -> None:
        """Signal threads to stop and join."""
        self.running.clear()
        if self.actuation_thread and self.actuation_thread.is_alive():
            self.actuation_thread.join(timeout=2.0)
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=2.0)

    def run(self) -> None:
        """Run the agent until completion or keyboard interrupt."""
        self.start()
        try:
            while self.running.is_set():
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[AGENT] Keyboard interrupt received, stopping agent loop...")
        finally:
            self.stop()


# =============================================================================
# CLI & Verification
# =============================================================================

def self_test() -> None:
    """Verify autonomous agent loop threading and scenarios in dry-run mode."""
    print("[AGENT_LOOP_TEST] Verifying agent loop...")

    # Test 1: Nominal scenario dry-run (0.3s)
    client = GovernorClient()
    agent = AutonomousAgent(
        client=client,
        scenario="nominal",
        actuation_interval=0.03,
        heartbeat_interval=0.02,
        duration=0.15,
        verbose=False,
    )
    agent.run()

    assert agent.proposals_sent > 0, "No proposals sent during nominal test"
    assert agent.heartbeats_sent > 0, "No heartbeats sent during nominal test"
    assert len(client.emitted_frames) == agent.proposals_sent + agent.heartbeats_sent

    # Verify all nominal proposals stay out of keepout [250, 650]
    for rec in agent.log_history:
        assert not (250 <= rec["u_mrad"] <= 650), f"Nominal proposal violated keepout: {rec}"
    print(f"  [PASS] Nominal scenario generated {agent.proposals_sent} safe proposals")

    # Test 2: Prompt injected scenario
    client_inj = GovernorClient()
    agent_inj = AutonomousAgent(
        client=client_inj,
        scenario="prompt_injected",
        actuation_interval=0.03,
        heartbeat_interval=0.02,
        duration=1.2,
        verbose=False,
    )
    agent_inj.run()
    assert any(rec["u_mrad"] == 450 for rec in agent_inj.log_history)
    print("  [PASS] Prompt injected scenario triggered adversarial proposals")

    # Test 3: Medical infusion scenario
    client_med = GovernorClient()
    agent_med = AutonomousAgent(
        client=client_med,
        scenario="medical_infusion",
        actuation_interval=0.03,
        heartbeat_interval=0.02,
        duration=0.15,
        verbose=False,
    )
    agent_med.run()
    assert agent_med.proposals_sent > 0
    print("  [PASS] Medical infusion scenario generated bolus proposals")

    # Test 4: Planning failure & stall watchdog safety test
    # Sub-test 4a: Planning exception terminates heartbeat daemon immediately (< 100ms)
    client_fail = GovernorClient()
    agent_fail = AutonomousAgent(
        client=client_fail,
        scenario="nominal",
        actuation_interval=0.02,
        heartbeat_interval=0.01,
        verbose=False,
    )

    failure_time: list[float] = []

    def failing_plan(elapsed: float, tick: int) -> tuple[int, int, int]:
        if tick > 1:
            failure_time.append(time.monotonic())
            raise RuntimeError("Simulated critical planning model inference failure / OOM!")
        return 0, 255, 1

    agent_fail._plan_proposal = failing_plan
    orig_excepthook = threading.excepthook
    threading.excepthook = lambda args: None
    try:
        agent_fail.start()
        # Wait up to 100ms after failure triggers
        t0 = time.monotonic()
        while time.monotonic() - t0 < 0.2:
            if failure_time and not agent_fail.heartbeat_thread.is_alive():
                break
            time.sleep(0.005)

        assert failure_time, "Planning failure was not invoked"
        time_to_terminate = time.monotonic() - failure_time[0]
        assert time_to_terminate < 0.100, f"Heartbeat did not terminate within 100ms (took {time_to_terminate:.3f}s)"
        assert not agent_fail.actuation_thread.is_alive(), "Actuation thread should have crashed"
        assert not agent_fail.running.is_set(), "running flag must be cleared on actuation failure"
        assert not agent_fail.heartbeat_thread.is_alive(), "Heartbeat daemon must cease on actuation death"

        hb_count_after_death = agent_fail.heartbeats_sent
        time.sleep(0.05)
        assert agent_fail.heartbeats_sent == hb_count_after_death, (
            f"Heartbeats continued advancing after failure! ({agent_fail.heartbeats_sent} != {hb_count_after_death})"
        )
    finally:
        threading.excepthook = orig_excepthook
        agent_fail.stop()

    # Sub-test 4b: Planning stall watchdog terminates heartbeat daemon (< 100ms)
    client_stall = GovernorClient()
    agent_stall = AutonomousAgent(
        client=client_stall,
        scenario="nominal",
        actuation_interval=0.02,
        heartbeat_interval=0.01,
        watchdog_timeout=0.05,  # 50 ms watchdog
        verbose=False,
    )

    stall_time: list[float] = []

    def stalling_plan(elapsed: float, tick: int) -> tuple[int, int, int]:
        if tick > 1:
            stall_time.append(time.monotonic())
            time.sleep(0.25)  # Hang planning thread beyond 50 ms watchdog
        return 0, 255, 1

    agent_stall._plan_proposal = stalling_plan
    agent_stall.start()
    t0 = time.monotonic()
    while time.monotonic() - t0 < 0.25:
        if stall_time and not agent_stall.heartbeat_thread.is_alive():
            break
        time.sleep(0.005)

    assert stall_time, "Planning stall was not invoked"
    time_to_terminate_stall = time.monotonic() - stall_time[0]
    # Watchdog timeout is 50ms, so termination must occur between 50ms and 100ms
    assert time_to_terminate_stall < 0.100, (
        f"Heartbeat did not terminate within 100ms of stall (took {time_to_terminate_stall:.3f}s)"
    )
    assert not agent_stall.running.is_set(), "running flag must be cleared on planning stall"
    assert not agent_stall.heartbeat_thread.is_alive(), "Heartbeat daemon must terminate on planning stall"

    hb_count_stall = agent_stall.heartbeats_sent
    time.sleep(0.05)
    assert agent_stall.heartbeats_sent == hb_count_stall, (
        f"Heartbeats continued advancing after stall! ({agent_stall.heartbeats_sent} != {hb_count_stall})"
    )
    agent_stall.stop()

    print("  [PASS] Planning exception and stall watchdog properly terminate heartbeats within 100ms")

    print("[AGENT_LOOP_TEST] All agent loop tests PASSED.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Autonomous Physical AI Agent Loop for GOVERNOR")
    parser.add_argument(
        "--scenario",
        choices=["nominal", "prompt_injected", "medical_infusion", "anomaly_drift"],
        default="nominal",
        help="Agent scenario profile to execute",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=5.0,
        help="Total execution duration in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--transport",
        choices=["pipe", "socket", "stdout", "none"],
        default="none",
        help="Transport medium to QNX governor",
    )
    parser.add_argument("--pipe", type=str, default="/tmp/latch.pipe", help="Path to FIFO pipe")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="TCP host")
    parser.add_argument("--port", type=int, default=8080, help="TCP port")
    parser.add_argument(
        "--interval",
        type=float,
        default=0.05,
        help="Actuation loop interval in seconds (default: 0.05)",
    )
    parser.add_argument(
        "--heartbeat-interval",
        type=float,
        default=0.03,
        help="Heartbeat daemon interval in seconds (default: 0.03)",
    )
    parser.add_argument("--test", action="store_true", help="Run self-tests and exit")
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose logging")

    args = parser.parse_args()

    if args.test:
        self_test()
        sys.exit(0)

    # Resolve transport
    transport = None
    if args.transport == "pipe":
        transport = args.pipe
    elif args.transport == "socket":
        transport = f"tcp://{args.host}:{args.port}"
    elif args.transport == "stdout":
        transport = sys.stdout.buffer

    client = GovernorClient(transport=transport)
    agent = AutonomousAgent(
        client=client,
        scenario=args.scenario,
        actuation_interval=args.interval,
        heartbeat_interval=args.heartbeat_interval,
        duration=args.duration,
        verbose=not args.quiet,
    )

    print(f"=== Starting Autonomous Agent [{args.scenario.upper()}] ===")
    print(f"Duration: {args.duration}s | Loop: {args.interval*1000:.1f}ms | HB: {args.heartbeat_interval*1000:.1f}ms")
    agent.run()
    client.close()
    print(f"=== Agent Stopped: {agent.proposals_sent} proposals, {agent.heartbeats_sent} heartbeats ===")


if __name__ == "__main__":
    main()
