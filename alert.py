"""
Ransomware Detection System — Alert System
Multi-channel alerting: terminal (colored), log file (JSON), desktop notification.
"""

import os
import json
import time
import subprocess
from datetime import datetime
import config

# ANSI colour codes for terminal output
_COLORS = {
    "INFO":     "\033[96m",     # Cyan
    "WARNING":  "\033[93m",     # Yellow
    "CRITICAL": "\033[91m",     # Red
    "SUCCESS":  "\033[92m",     # Green
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}

# Track cooldowns to avoid spamming
_last_alert_time = {}

# In-memory alert history for the dashboard
alert_history = []
MAX_HISTORY = 200


def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _cooldown_ok(key: str) -> bool:
    """Return True if enough time has passed since the last alert with this key."""
    now = time.time()
    last = _last_alert_time.get(key, 0)
    if now - last < config.ALERT_COOLDOWN_SECONDS:
        return False
    _last_alert_time[key] = now
    return True


def send_alert(severity: str, title: str, message: str,
               filepath: str = "", process_info: dict = None):
    """
    Dispatch an alert through all channels.
    Severity: INFO | WARNING | CRITICAL
    """
    cooldown_key = f"{severity}:{title}:{filepath}"
    if not _cooldown_ok(cooldown_key):
        return

    timestamp = _now_str()

    # ── 1. Terminal output ──
    col  = _COLORS.get(severity, _COLORS["INFO"])
    rst  = _COLORS["RESET"]
    bold = _COLORS["BOLD"]
    dim  = _COLORS["DIM"]

    severity_badge = f"{col}{bold}[{severity}]{rst}"
    print(f"\n{severity_badge} {bold}{title}{rst}")
    print(f"  {dim}Time:{rst}    {timestamp}")
    if filepath:
        print(f"  {dim}File:{rst}    {filepath}")
    print(f"  {dim}Detail:{rst}  {message}")
    if process_info:
        print(f"  {dim}Process:{rst} PID={process_info.get('pid','?')} "
              f"Name={process_info.get('name','?')} "
              f"User={process_info.get('user','?')}")
    print()

    # ── 2. JSON log file ──
    log_entry = {
        "timestamp": timestamp,
        "severity":  severity,
        "title":     title,
        "message":   message,
        "filepath":  filepath,
        "process":   process_info,
    }

    os.makedirs(config.LOG_DIR, exist_ok=True)
    try:
        with open(config.ALERT_LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except IOError:
        pass

    # ── 3. In-memory history for dashboard ──
    alert_history.append(log_entry)
    if len(alert_history) > MAX_HISTORY:
        alert_history.pop(0)

    # ── 4. Desktop notification (Linux) ──
    if config.DESKTOP_NOTIFY and severity in ("WARNING", "CRITICAL"):
        urgency = "critical" if severity == "CRITICAL" else "normal"
        try:
            subprocess.Popen(
                ["notify-send", "-u", urgency,
                 f"🛡️ Ransomware Detector — {severity}",
                 f"{title}\n{message}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            pass  # notify-send not installed
