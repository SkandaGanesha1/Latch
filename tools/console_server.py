#!/usr/bin/env python3
"""
LATCH GOVERNOR — Live Operator Console & Forensics HTTP Bridge (G5)

Serves the offline HTML5 Canvas console (host/console.html) and evidence tape (host/tape.html)
and provides an HTTP REST API to stream live telemetry from latchctl or replay blackbox tapes.

Zero external dependencies (uses standard library http.server).
Usage:
  python3 tools/console_server.py [--port 8088] [--tape path/to/tape.csv]
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import socketserver
import subprocess
import sys
from pathlib import Path


class GovernorConsoleHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        root = Path(__file__).resolve().parent.parent
        self.directory = str(root / "host")
        self.root_dir = root
        super().__init__(*args, directory=self.directory, **kwargs)

    def do_GET(self) -> None:
        if self.path == "/" or self.path == "/index.html":
            self.path = "/console.html"
            return super().do_GET()

        if self.path.startswith("/api/status"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            # Attempt to query live latchctl if available in host-sim
            latchctl_bin = self.root_dir / "qnx/build/host-sim/latchctl"
            status_data = {
                "active": False,
                "rung": "HP",
                "mode": "HP",
                "theta_mrad": 0,
                "u_mrad": 0,
                "faults": "0x0000",
                "coherence": 0,
                "lease_remaining": 100,
                "deadline_misses": 0,
            }
            if latchctl_bin.is_file():
                try:
                    res = subprocess.run(
                        [str(latchctl_bin), "status"],
                        capture_output=True, text=True, timeout=1.0
                    )
                    if res.returncode == 0:
                        status_data["active"] = True
                        for line in res.stdout.splitlines():
                            if "Actuator Angle" in line:
                                status_data["theta_mrad"] = int(line.split(":")[1].split()[0])
                            elif "rung=" in line:
                                status_data["rung"] = line.split("rung=")[1].split()[0]
                            elif "Active Fault Bits" in line:
                                status_data["faults"] = line.split(":")[1].split()[0]
                            elif "counter=" in line:
                                status_data["coherence"] = int(line.split("counter=")[1].strip())
                            elif "Deadline Misses" in line:
                                status_data["deadline_misses"] = int(line.split(":")[1].split()[0])
                except Exception:
                    pass

            self.wfile.write(json.dumps(status_data).encode("utf-8"))
            return

        if self.path.startswith("/api/health"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "OK", "governor": "active"}\n')
            return

        return super().do_GET()


def main() -> int:
    parser = argparse.ArgumentParser(description="LATCH GOVERNOR Console Web Server")
    parser.add_argument("--port", type=int, default=8088, help="Port to listen on (default: 8088)")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    host_dir = root / "host"

    print("================================================================================")
    print(" LATCH GOVERNOR — Live Operator Console & HTTP Bridge Server (G5)               ")
    print("================================================================================")
    print(f" Serving dashboard from: {host_dir}")
    print(f" Console Dashboard URL : http://localhost:{args.port}/console.html")
    print(f" Evidence Tape URL     : http://localhost:{args.port}/tape.html")
    print(f" Telemetry API Endpoint: http://localhost:{args.port}/api/status")
    print(" Press Ctrl+C to terminate.")
    print("================================================================================")

    socketserver.TCPServer.allow_reuse_address = True
    try:
        with socketserver.TCPServer(("", args.port), GovernorConsoleHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[CONSOLE SERVER] Server stopped cleanly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
