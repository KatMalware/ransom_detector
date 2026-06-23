"""
Ransomware Detection System — Detection Engine
Core brain: analyses file events for ransomware patterns.
"""

import os
import time
from collections import deque
from threading import Lock

import config
from entropy import file_entropy, entropy_delta
from alert import send_alert
from process_inspector import get_suspicious_processes
from dl_analyzer import DLAnalyzer


class DetectionEngine:
    """
    Stateful detection engine that correlates file events over time
    to identify ransomware-like behaviour.
    """

    def __init__(self, baseline_entropy: dict = None):
        # Sliding window of recent events: (timestamp, event_type, filepath)
        self._modify_times   = deque()
        self._delete_times   = deque()
        self._lock           = Lock()

        # Baseline entropy map: filepath → float
        self.baseline = baseline_entropy or {}

        # Counters for the dashboard
        self.stats = {
            "total_events":     0,
            "modifications":    0,
            "deletions":        0,
            "creations":        0,
            "moves":            0,
            "alerts_fired":     0,
            "entropy_spikes":   0,
            "ext_changes":      0,
            "ransom_notes":     0,
            "rapid_mods":       0,
            "rapid_dels":       0,
            "ai_detections":    0,
            "threat_level":     "SAFE",     # SAFE | SUSPICIOUS | CRITICAL
        }
        
        self.dl_analyzer = DLAnalyzer()
        self.stats["dl_enabled"] = self.dl_analyzer.enabled

    # ─── Public API ───────────────────────────────────

    def on_modified(self, filepath: str):
        """Called when a file in the honeypot is modified."""
        self.stats["total_events"] += 1
        self.stats["modifications"] += 1
        now = time.time()

        with self._lock:
            self._modify_times.append(now)
            self._prune(self._modify_times, config.RATE_WINDOW_SECONDS)

        # Check 1: Rapid modification rate
        if len(self._modify_times) >= config.RATE_THRESHOLD:
            self._alert_rapid_modification(len(self._modify_times))

        # Check 2: Entropy spike (file might have been encrypted)
        self._check_entropy(filepath)

        # Check 3: Deep Learning Analysis
        self._check_dl(filepath)

    def on_created(self, filepath: str):
        """Called when a new file appears in the honeypot."""
        self.stats["total_events"] += 1
        self.stats["creations"] += 1

        # Check: Is it a ransom note?
        basename = os.path.basename(filepath).lower()
        if basename in config.RANSOM_NOTE_NAMES:
            self._alert_ransom_note(filepath, basename)

    def on_deleted(self, filepath: str):
        """Called when a file in the honeypot is deleted."""
        self.stats["total_events"] += 1
        self.stats["deletions"] += 1
        now = time.time()

        with self._lock:
            self._delete_times.append(now)
            self._prune(self._delete_times, config.DELETE_WINDOW_SECONDS)

        # Check: Mass deletion
        if len(self._delete_times) >= config.DELETE_THRESHOLD:
            self._alert_mass_deletion(len(self._delete_times))

    def on_moved(self, src_path: str, dest_path: str):
        """Called when a file in the honeypot is renamed/moved."""
        self.stats["total_events"] += 1
        self.stats["moves"] += 1

        # Check: Renamed to a ransomware extension?
        _, ext = os.path.splitext(dest_path)
        if ext.lower() in config.RANSOMWARE_EXTENSIONS:
            self._alert_suspicious_extension(src_path, dest_path, ext)

    # ─── Internal Checks ─────────────────────────────

    @staticmethod
    def _prune(dq: deque, window: float):
        """Remove entries older than `window` seconds from the deque."""
        cutoff = time.time() - window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _check_entropy(self, filepath: str):
        """Compare current entropy to baseline and alert on spike."""
        if not os.path.isfile(filepath):
            return
        try:
            current = file_entropy(filepath)
        except Exception:
            return

        old = self.baseline.get(filepath, None)
        if old is not None:
            delta = entropy_delta(old, current)
            if delta >= config.ENTROPY_SPIKE_DELTA:
                self.stats["entropy_spikes"] += 1
                self._set_threat("CRITICAL")
                procs = get_suspicious_processes()
                pinfo = procs[0] if procs else None
                send_alert(
                    "CRITICAL",
                    "🔒 ENTROPY SPIKE — File Likely Encrypted!",
                    f"Entropy jumped from {old:.2f} → {current:.2f} "
                    f"(Δ = +{delta:.2f}).  Threshold: {config.ENTROPY_SPIKE_DELTA}",
                    filepath=filepath,
                    process_info=pinfo,
                )
                self.stats["alerts_fired"] += 1

        # Update baseline
        self.baseline[filepath] = current

    def _check_dl(self, filepath: str):
        """Pass the file to the Deep Learning model for analysis."""
        if not self.dl_analyzer.enabled:
            return
            
        confidence = self.dl_analyzer.predict(filepath)
        if confidence > 0.90:  # 90% confidence threshold
            # Avoid spamming if we already triggered an alert for this recently
            self.stats["ai_detections"] += 1
            self._set_threat("CRITICAL")
            procs = get_suspicious_processes()
            pinfo = procs[0] if procs else None
            send_alert(
                "CRITICAL",
                "🤖 AI RANSOMWARE DETECTION",
                f"Deep Learning model is {confidence*100:.1f}% confident this file is malicious/encrypted.",
                filepath=filepath,
                process_info=pinfo,
            )
            self.stats["alerts_fired"] += 1

    def _alert_rapid_modification(self, count: int):
        self.stats["rapid_mods"] += 1
        self._set_threat("CRITICAL")
        procs = get_suspicious_processes()
        pinfo = procs[0] if procs else None
        send_alert(
            "CRITICAL",
            "⚡ RAPID FILE MODIFICATION DETECTED!",
            f"{count} files modified in {config.RATE_WINDOW_SECONDS}s "
            f"(threshold: {config.RATE_THRESHOLD}). "
            "This matches ransomware encryption patterns.",
            process_info=pinfo,
        )
        self.stats["alerts_fired"] += 1

    def _alert_mass_deletion(self, count: int):
        self.stats["rapid_dels"] += 1
        self._set_threat("CRITICAL")
        procs = get_suspicious_processes()
        pinfo = procs[0] if procs else None
        send_alert(
            "CRITICAL",
            "🗑️ MASS FILE DELETION DETECTED!",
            f"{count} files deleted in {config.DELETE_WINDOW_SECONDS}s "
            f"(threshold: {config.DELETE_THRESHOLD}). "
            "Possible ransomware wiping originals.",
            process_info=pinfo,
        )
        self.stats["alerts_fired"] += 1

    def _alert_suspicious_extension(self, src: str, dest: str, ext: str):
        self.stats["ext_changes"] += 1
        self._set_threat("CRITICAL")
        procs = get_suspicious_processes()
        pinfo = procs[0] if procs else None
        send_alert(
            "CRITICAL",
            "📛 SUSPICIOUS FILE EXTENSION CHANGE!",
            f"'{os.path.basename(src)}' → '{os.path.basename(dest)}' "
            f"(extension '{ext}' is a known ransomware marker).",
            filepath=dest,
            process_info=pinfo,
        )
        self.stats["alerts_fired"] += 1

    def _alert_ransom_note(self, filepath: str, name: str):
        self.stats["ransom_notes"] += 1
        self._set_threat("CRITICAL")
        procs = get_suspicious_processes()
        pinfo = procs[0] if procs else None
        send_alert(
            "CRITICAL",
            "💀 RANSOM NOTE DETECTED!",
            f"A known ransomware note file '{name}' appeared in the honeypot!",
            filepath=filepath,
            process_info=pinfo,
        )
        self.stats["alerts_fired"] += 1

    def _set_threat(self, level: str):
        """Escalate threat level (never downgrade automatically)."""
        priority = {"SAFE": 0, "SUSPICIOUS": 1, "CRITICAL": 2}
        if priority.get(level, 0) > priority.get(self.stats["threat_level"], 0):
            self.stats["threat_level"] = level
