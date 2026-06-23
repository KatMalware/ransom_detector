#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  RansomGuard — Real-Time Download Folder Watcher             ║
║  Monitors downloads and automatically runs AI Agent analysis ║
║  on newly downloaded files.                                 ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python download_watcher.py
"""

import os
import sys
import time
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ── Rich Imports ──
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

# ── Import AI Agent modules ──
from dl_analyzer import DLAnalyzer
from agent_engine import AgenticEngine

console = Console()

# Target Folder: Default to ~/Downloads
WATCH_DIR = os.path.expanduser("~/Downloads")
QUARANTINE_DIR = os.path.join(WATCH_DIR, "Quarantine")

# Ignore list for browser temp files
TEMP_EXTENSIONS = {'.crdownload', '.part', '.tmp', '.download'}

class DownloadHandler(FileSystemEventHandler):
    def __init__(self, agent, dl):
        super().__init__()
        self.agent = agent
        self.dl = dl
        # Track already scanned files to prevent duplicate scans
        self.scanned_files = set()

    def wait_for_file_to_settle(self, filepath: str, max_wait: int = 15) -> bool:
        """Wait for browser download to finish writing (checks size stability)."""
        last_size = -1
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                if not os.path.exists(filepath):
                    return False
                current_size = os.path.getsize(filepath)
                # If size is stable and not 0, download is likely complete
                if current_size == last_size and current_size > 0:
                    return True
                last_size = current_size
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def handle_new_file(self, filepath: str):
        filepath = os.path.abspath(filepath)
        _, ext = os.path.splitext(filepath)

        # Ignore directories, temp files, and already scanned files
        if os.path.isdir(filepath) or ext.lower() in TEMP_EXTENSIONS or filepath in self.scanned_files:
            return
            
        # Ignore files inside Quarantine directory
        if filepath.startswith(QUARANTINE_DIR):
            return

        self.scanned_files.add(filepath)

        console.print(f"\n[bold cyan]📥 New File Detected:[/] {os.path.basename(filepath)}")
        console.print("[dim]Waiting for download to complete...[/]")

        if not self.wait_for_file_to_settle(filepath):
            # If it's still being written or got deleted, skip
            return

        # Run AI Agentic Analysis
        console.print("[cyan]Running AI Agent Analysis pipeline...[/]")
        verdict = self.agent.analyze_file(filepath)

        # Print verdict panel
        self.print_verdict_panel(verdict)

        # Take protective action if CRITICAL or SUSPICIOUS
        if verdict.verdict in ("CRITICAL", "SUSPICIOUS"):
            self.quarantine_file(filepath, verdict)

    def on_created(self, event):
        if not event.is_directory:
            # Direct files created
            self.handle_new_file(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            # Browsers rename files from filename.crdownload -> filename when done
            self.handle_new_file(event.dest_path)

    def print_verdict_panel(self, verdict):
        color = "green"
        emoji = "✅ SAFE"
        
        if verdict.verdict == "CRITICAL":
            color = "red"
            emoji = "🚨 CRITICAL THREAT"
        elif verdict.verdict == "SUSPICIOUS":
            color = "yellow"
            emoji = "⚠️  SUSPICIOUS"

        table = Table(box=box.SIMPLE, show_header=False)
        table.add_column("Property", style="bold")
        table.add_column("Value")

        table.add_row("File Path", verdict.filepath)
        table.add_row("Risk Score", f"[{color}]{verdict.risk_score:.1f}/100.0[/]")
        
        # Add Factors
        for factor_name, data in verdict.factors.items():
            if factor_name == "entropy":
                table.add_row("Shannon Entropy", f"{data['value']:.3f}/8.0 (Risk: {data['risk']:.2f})")
            elif factor_name == "dl_model" and data['confidence'] != "N/A":
                table.add_row("Deep Learning", f"{data['confidence']}% Malicious Confidence")
            elif factor_name == "magic_bytes":
                table.add_row("Magic Signature", f"{data['status']}")
            elif factor_name == "extension":
                table.add_row("Extension Anomaly", f"{data['ext']}")

        panel = Panel(
            table,
            title=f"[bold {color}]{emoji}[/]",
            border_style=color,
            subtitle="AI Agent Multi-Factor Assessment",
        )
        console.print(panel)

    def quarantine_file(self, filepath: str, verdict):
        """Move malicious files to a isolated Quarantine folder and strip run permissions."""
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        fname = os.path.basename(filepath)
        dest_path = os.path.join(QUARANTINE_DIR, fname)

        try:
            # Remove execution permissions first
            os.chmod(filepath, 0o000)
            # Move to quarantine
            shutil.move(filepath, dest_path)
            
            console.print(Panel(
                f"[bold red]🛡️  QUARANTINED:[/] Moved malicious file to safety.\n"
                f"[bold]Original:[/] {filepath}\n"
                f"[bold]Isolated to:[/] {dest_path}\n"
                f"[dim]Execution permissions revoked (chmod 000).[/]",
                border_style="red",
                title="Active Protection Triggered"
            ))
        except Exception as e:
            console.print(f"[bold red]Error quarantining file: {e}[/]")

def main():
    console.print("""[bold cyan]
  ██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║
  ██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║
  ██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║
  ██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝[/]
  [bold yellow]🛡️  REAL-TIME DOWNLOAD SHIELD[/]
  [dim]Monitoring: {0}[/]
  [dim]Quarantine: {1}[/]
    """.format(WATCH_DIR, QUARANTINE_DIR))

    os.makedirs(WATCH_DIR, exist_ok=True)

    # Initialize AI Engines
    console.print("[cyan]Initializing AI Engines...[/]")
    dl = DLAnalyzer()
    agent = AgenticEngine(dl_analyzer=dl)
    console.print("[green]✓ Deep Learning Model loaded.[/]")
    console.print("[green]✓ Agentic Decision Engine ready.[/]\n")

    event_handler = DownloadHandler(agent, dl)
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)
    observer.start()

    console.print(Panel(
        f"[green]🟢 Shield ACTIVE and watching your downloads directory![/]\n"
        f"Try downloading/saving any file to [bold]{WATCH_DIR}[/]. It will be automatically scanned.\n"
        f"Press [bold yellow]Ctrl+C[/] to stop the watcher.",
        border_style="green"
    ))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping Download Watcher...[/]")
        observer.stop()
    observer.join()
    console.print("[dim]Watcher stopped.[/]")

if __name__ == "__main__":
    main()
