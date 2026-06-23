"""
Ransomware Detection System — File System Monitor
Uses `watchdog` to watch the honeypot directory for all file events
and routes them to the DetectionEngine.
"""

import os
from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileModifiedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileMovedEvent,
)

from alert import send_alert


class HoneypotHandler(FileSystemEventHandler):
    """Watchdog handler that routes events to the detection engine."""

    def __init__(self, engine):
        super().__init__()
        self.engine = engine

    def on_modified(self, event):
        if event.is_directory:
            return
        self.engine.on_modified(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self.engine.on_created(event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            return
        self.engine.on_deleted(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self.engine.on_moved(event.src_path, event.dest_path)


class HoneypotMonitor:
    """
    Sets up watchdog Observer on the honeypot directory.
    Call .start() to begin monitoring in a background thread.
    """

    def __init__(self, honeypot_dir: str, engine):
        self.honeypot_dir = os.path.abspath(honeypot_dir)
        self.engine       = engine
        self.handler      = HoneypotHandler(engine)
        self.observer     = Observer()

    def start(self):
        """Start watching (non-blocking — runs in a daemon thread)."""
        self.observer.schedule(self.handler, self.honeypot_dir, recursive=True)
        self.observer.daemon = True
        self.observer.start()
        send_alert(
            "INFO",
            "👁️  Honeypot Monitor ACTIVE",
            f"Watching: {self.honeypot_dir}",
        )

    def stop(self):
        """Stop the observer gracefully."""
        self.observer.stop()
        self.observer.join(timeout=3)
        send_alert("INFO", "Monitor Stopped", "File system watcher has been shut down.")
