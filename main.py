"""
Ransomware Detection System — Main Entry Point

Starts:
  1. Honeypot directory (creates decoy files if not present)
  2. File system monitor (watchdog)
  3. Web dashboard (Flask on port 8080)

Usage:
    python main.py
"""

import os
import sys
import signal
import threading

import config
from honeypot_setup import setup_honeypot
from detector import DetectionEngine
from monitor import HoneypotMonitor
from dashboard import run_dashboard, set_engine
from alert import send_alert


# ── ANSI ──
C = "\033[96m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[1m"
D = "\033[2m"
X = "\033[0m"

BANNER = f"""
{C}{B}
 ██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║
 ██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║
 ██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║
 ██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝
  {Y}G U A R D{X}  {D}— Ransomware Detection System{X}
{X}"""


def main():
    print(BANNER)

    # ── 1. Setup honeypot ──
    print(f"{C}[1/3]{X} Setting up honeypot directory...")
    baseline = setup_honeypot()
    file_count = len(baseline)
    print(f"  {G}✓{X} {file_count} decoy files ready in {D}{config.HONEYPOT_DIR}{X}\n")

    # ── 2. Initialize detection engine ──
    print(f"{C}[2/3]{X} Initializing detection engine...")
    engine = DetectionEngine(baseline_entropy=baseline)
    set_engine(engine)
    print(f"  {G}✓{X} Detection engine ready")
    print(f"     Thresholds: Rate={config.RATE_THRESHOLD} files/{config.RATE_WINDOW_SECONDS}s, "
          f"Entropy Δ≥{config.ENTROPY_SPIKE_DELTA}, "
          f"Delete={config.DELETE_THRESHOLD}/{config.DELETE_WINDOW_SECONDS}s\n")

    # ── 3. Start file monitor ──
    print(f"{C}[3/3]{X} Starting file system monitor...")
    mon = HoneypotMonitor(config.HONEYPOT_DIR, engine)
    mon.start()

    # ── Graceful shutdown ──
    def shutdown(sig, frame):
        print(f"\n{Y}[!]{X} Shutting down...")
        mon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── 4. Start dashboard ──
    print(f"\n{'─' * 55}")
    print(f" {G}{B}Dashboard:{X}  http://localhost:{config.DASHBOARD_PORT}")
    print(f" {Y}{B}Honeypot:{X}   {config.HONEYPOT_DIR}")
    print(f" {C}{B}Logs:{X}       {config.ALERT_LOG_FILE}")
    print(f"{'─' * 55}")
    print(f"\n{D}To simulate an attack, open another terminal and run:{X}")
    print(f"  {B}python simulate_attack.py{X}\n")

    # Run Flask in main thread (blocks)
    run_dashboard()


if __name__ == "__main__":
    main()
