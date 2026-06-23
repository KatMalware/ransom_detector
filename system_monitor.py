"""
Ransomware Detection System — Process & System Monitor
Monitors running processes for suspicious behavior:
  - High RAM / CPU usage
  - Rapid file I/O (system calls)
  - Suspicious process names and command lines
Uses psutil and /proc filesystem on Linux.
"""

import os
import time
import psutil


# ── Known suspicious process patterns ──
SUSPICIOUS_PROCESS_NAMES = {
    "cryptor", "locker", "encrypt", "ransom", "wncry", "wcry",
    "locky", "cerber", "dharma", "ryuk", "conti", "lockbit",
    "blackcat", "revil", "sodinokibi", "maze", "phobos",
}

SUSPICIOUS_EXTENSIONS_IN_CMDLINE = {
    ".encrypted", ".locked", ".crypted", ".enc", ".ransom",
    ".wncry", ".locky", ".cerber",
}


def get_system_overview() -> dict:
    """Get current system resource usage."""
    mem = psutil.virtual_memory()
    cpu = psutil.cpu_percent(interval=0.5)
    disk = psutil.disk_io_counters()

    return {
        "ram_total_gb":     round(mem.total / (1024**3), 2),
        "ram_used_gb":      round(mem.used / (1024**3), 2),
        "ram_percent":      mem.percent,
        "ram_available_gb": round(mem.available / (1024**3), 2),
        "cpu_percent":      cpu,
        "cpu_count":        psutil.cpu_count(),
        "disk_read_mb":     round(disk.read_bytes / (1024**2), 1) if disk else 0,
        "disk_write_mb":    round(disk.write_bytes / (1024**2), 1) if disk else 0,
        "disk_read_count":  disk.read_count if disk else 0,
        "disk_write_count": disk.write_count if disk else 0,
    }


def get_process_details(pid: int) -> dict:
    """Get full details about a specific PID."""
    try:
        p = psutil.Process(pid)
        mem = p.memory_info()
        io = None
        try:
            io = p.io_counters()
        except (psutil.AccessDenied, AttributeError):
            pass

        # Read open files
        open_files = []
        try:
            open_files = [f.path for f in p.open_files()]
        except (psutil.AccessDenied, psutil.ZombieProcess):
            pass

        # Read /proc/<pid>/syscall for current system call (Linux only)
        current_syscall = _read_proc_syscall(pid)

        return {
            "pid":            pid,
            "name":           p.name(),
            "status":         p.status(),
            "user":           p.username(),
            "cmdline":        " ".join(p.cmdline()),
            "cpu_percent":    p.cpu_percent(interval=0.1),
            "ram_mb":         round(mem.rss / (1024**2), 2),
            "ram_percent":    round(p.memory_percent(), 2),
            "threads":        p.num_threads(),
            "open_files":     open_files,
            "open_file_count": len(open_files),
            "io_read_bytes":  io.read_bytes if io else None,
            "io_write_bytes": io.write_bytes if io else None,
            "io_read_count":  io.read_count if io else None,
            "io_write_count": io.write_count if io else None,
            "current_syscall": current_syscall,
            "create_time":    p.create_time(),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {"pid": pid, "name": "N/A", "status": "not found"}


def _read_proc_syscall(pid: int) -> str:
    """Read the current system call from /proc/<pid>/syscall (Linux only)."""
    try:
        with open(f"/proc/{pid}/syscall", "r") as f:
            data = f.read().strip()
            if data == "running":
                return "running"
            parts = data.split()
            if parts:
                return _syscall_name(int(parts[0]))
            return data
    except (FileNotFoundError, PermissionError, ValueError):
        return "N/A"


def _syscall_name(num: int) -> str:
    """Map common x86_64 syscall numbers to names (top file I/O related ones)."""
    syscall_map = {
        0: "read", 1: "write", 2: "open", 3: "close",
        4: "stat", 5: "fstat", 6: "lstat", 7: "poll",
        8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
        17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev",
        21: "access", 22: "pipe", 41: "socket",
        56: "clone", 57: "fork", 59: "execve",
        72: "fcntl", 76: "truncate", 77: "ftruncate",
        78: "getdents", 79: "getcwd", 80: "chdir",
        82: "rename", 83: "mkdir", 84: "rmdir",
        85: "creat", 86: "link", 87: "unlink",
        89: "readlink", 90: "chmod",
        217: "getdents64", 257: "openat", 262: "fstatat",
        263: "unlinkat", 264: "renameat",
        316: "renameat2", 332: "statx",
    }
    return syscall_map.get(num, f"syscall_{num}")


# ── Dangerous I/O syscalls used during ransomware encryption ──
DANGEROUS_SYSCALLS = {"read", "write", "open", "openat", "unlink", "unlinkat",
                      "rename", "renameat", "renameat2", "creat", "truncate",
                      "ftruncate", "rmdir"}


# Global cache to track process I/O rates (pid -> (write_bytes, timestamp))
_PROCESS_IO_CACHE = {}


def scan_suspicious_processes() -> list:
    """
    Scan all running processes and flag suspicious ones based on:
      1. Known suspicious names
      2. Suspicious command line arguments
      3. High write rates (real-time delta or startup average)
      4. Combined high CPU + high RAM + active write rates
    """
    global _PROCESS_IO_CACHE
    suspicious = []
    current_time = time.time()
    
    # Keep track of active PIDs in this scan to clean up dead ones from cache
    active_pids = set()

    for proc in psutil.process_iter(["pid", "name", "username", "cmdline",
                                      "cpu_percent", "memory_info"]):
        try:
            pid = proc.info["pid"]
            active_pids.add(pid)
            pname = (proc.info.get("name") or "").lower()
            cmdline = " ".join(proc.info.get("cmdline") or []).lower()
            mem = proc.info.get("memory_info")
            cpu = proc.info.get("cpu_percent", 0)
            ram_mb = round(mem.rss / (1024**2), 2) if mem else 0

            # Calculate write rate
            write_rate_mbs = 0.0
            lifetime_rate_mbs = 0.0
            create_time = 0.0
            try:
                io = proc.io_counters()
                curr_write = io.write_bytes
                
                # 1. Lifetime average rate
                create_time = proc.create_time()
                age = current_time - create_time
                if age > 0.5:
                    lifetime_rate_mbs = (curr_write / (1024**2)) / age
                
                # 2. Instant rate (from cache)
                if pid in _PROCESS_IO_CACHE:
                    last_write, last_time = _PROCESS_IO_CACHE[pid]
                    dt = current_time - last_time
                    if dt > 0.2:
                        write_rate_mbs = ((curr_write - last_write) / (1024**2)) / dt
                
                # Update cache
                _PROCESS_IO_CACHE[pid] = (curr_write, current_time)
            except (psutil.AccessDenied, AttributeError):
                pass

            flags = []
            is_suspicious = False

            # Check 1: Known suspicious process names
            for pattern in SUSPICIOUS_PROCESS_NAMES:
                if pattern in pname:
                    flags.append(f"Suspicious name match: '{pattern}'")
                    is_suspicious = True
                    break

            # Check 2: Suspicious extensions in command line
            for ext in SUSPICIOUS_EXTENSIONS_IN_CMDLINE:
                if ext in cmdline:
                    flags.append(f"Ransomware extension in cmdline: '{ext}'")
                    is_suspicious = True
                    break

            # Check 3: High Write Rate (Ransomware signature behavior)
            # Threshold: > 5.0 MB/s instant rate OR > 3.0 MB/s lifetime rate for recently started processes
            if write_rate_mbs > 5.0:
                flags.append(f"High real-time write rate: {write_rate_mbs:.2f} MB/s")
                is_suspicious = True
            elif lifetime_rate_mbs > 3.0 and create_time and (current_time - create_time) < 300:
                flags.append(f"High startup write rate: {lifetime_rate_mbs:.2f} MB/s (avg)")
                is_suspicious = True

            # Check 4: Combined Resource Anomaly (High CPU + High RAM + Active Writes)
            if cpu and cpu > 80 and ram_mb > 800 and write_rate_mbs > 1.0:
                flags.append(f"Resource anomaly: High CPU ({cpu}%) + RAM ({ram_mb} MB) + Write Rate ({write_rate_mbs:.2f} MB/s)")
                is_suspicious = True

            # If marked suspicious, append additional resource context
            if is_suspicious:
                if ram_mb > 500 and not any("RAM" in f for f in flags):
                    flags.append(f"High RAM usage: {ram_mb} MB")
                if cpu and cpu > 50 and not any("CPU" in f for f in flags):
                    flags.append(f"High CPU usage: {cpu}%")
                if write_rate_mbs > 0.01 and not any("write rate" in f.lower() for f in flags):
                    flags.append(f"Disk write rate: {write_rate_mbs:.2f} MB/s")

                suspicious.append({
                    "pid":      pid,
                    "name":     proc.info.get("name", "?"),
                    "user":     proc.info.get("username", "?"),
                    "cmdline":  " ".join(proc.info.get("cmdline") or []),
                    "ram_mb":   ram_mb,
                    "cpu":      cpu,
                    "flags":    flags,
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Clean up stale processes from cache
    for cached_pid in list(_PROCESS_IO_CACHE.keys()):
        if cached_pid not in active_pids:
            _PROCESS_IO_CACHE.pop(cached_pid, None)

    return suspicious


def monitor_process_io(pid: int, duration: float = 2.0) -> dict:
    """
    Monitor a specific process's I/O over a short duration.
    Returns the rate of reads/writes per second.
    """
    try:
        proc = psutil.Process(pid)
        io_start = proc.io_counters()
        time.sleep(duration)
        io_end = proc.io_counters()

        return {
            "pid": pid,
            "duration_sec": duration,
            "reads_per_sec":  round((io_end.read_count - io_start.read_count) / duration, 1),
            "writes_per_sec": round((io_end.write_count - io_start.write_count) / duration, 1),
            "read_mb_sec":    round((io_end.read_bytes - io_start.read_bytes) / (1024**2 * duration), 2),
            "write_mb_sec":   round((io_end.write_bytes - io_start.write_bytes) / (1024**2 * duration), 2),
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"pid": pid, "error": "Process not accessible"}
