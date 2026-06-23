"""
Ransomware Detection System — Process Inspector
Identifies which process is modifying files inside the honeypot.
Uses psutil to scan running processes and match open file handles.
"""

import os
import psutil
import config


def get_suspicious_processes(honeypot_dir: str = None) -> list:
    """
    Scan all running processes and find any that have open file handles
    pointing into the honeypot directory.

    Returns a list of dicts with process info.
    """
    if honeypot_dir is None:
        honeypot_dir = os.path.abspath(config.HONEYPOT_DIR)

    suspicious = []

    for proc in psutil.process_iter(["pid", "name", "username", "cmdline",
                                      "cpu_percent", "memory_info"]):
        try:
            pname = proc.info["name"] or ""

            # Skip whitelisted processes
            if pname.lower() in config.PROCESS_WHITELIST:
                continue

            # Check open files
            try:
                open_files = proc.open_files()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                continue

            touching = []
            for fobj in open_files:
                if fobj.path.startswith(honeypot_dir):
                    touching.append(fobj.path)

            if touching:
                mem = proc.info.get("memory_info")
                suspicious.append({
                    "pid":      proc.info["pid"],
                    "name":     pname,
                    "user":     proc.info.get("username", "?"),
                    "cmdline":  " ".join(proc.info.get("cmdline") or []),
                    "cpu":      proc.info.get("cpu_percent", 0),
                    "mem_mb":   round(mem.rss / (1024 * 1024), 1) if mem else 0,
                    "files":    touching,
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return suspicious


def find_process_by_pid(pid: int) -> dict:
    """Get detailed info for a specific PID."""
    try:
        proc = psutil.Process(pid)
        mem = proc.memory_info()
        return {
            "pid":      pid,
            "name":     proc.name(),
            "user":     proc.username(),
            "cmdline":  " ".join(proc.cmdline()),
            "cpu":      proc.cpu_percent(interval=0.1),
            "mem_mb":   round(mem.rss / (1024 * 1024), 1),
            "status":   proc.status(),
            "cwd":      proc.cwd(),
            "created":  proc.create_time(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"pid": pid, "name": "unknown", "status": "not found"}


def kill_process(pid: int) -> bool:
    """Attempt to terminate a suspicious process."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=3)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
        return False
