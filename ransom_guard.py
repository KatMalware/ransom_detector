#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║  RansomGuard — Unified Command Center                        ║
║  One single entry point to run all features of the project:  ║
║    1. Start Download Shield (Background Watcher)             ║
║    2. Scan any file or folder                                ║
║    3. Monitor running system processes (Sysmon)              ║
║    4. Sandbox testing (Setup, Attack, Restore, Clean)        ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python ransom_guard.py             — Start the interactive menu
    python ransom_guard.py scan <path> — Scan a file or directory
    python ransom_guard.py sysmon      — Run system process monitor
    python ransom_guard.py shield      — Run download watcher directly
"""

import os
import sys
import time
import threading

# ── Rich Imports for Console UI ──
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from rich import box

# ── Project Module Imports ──
from dl_analyzer import DLAnalyzer
from agent_engine import AgenticEngine
from scanner import cmd_scan, cmd_sysmon
from test_ransom_sim import cmd_setup, cmd_attack, cmd_restore, cmd_clean
from download_watcher import DownloadHandler

# Watchdog imports for background thread
from watchdog.observers import Observer

console = Console()
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Global states
shield_thread = None
shield_observer = None


def start_shield_in_background():
    """Start the download watcher in a background thread so it doesn't block the menu."""
    global shield_thread, shield_observer
    
    watch_dir = os.path.expanduser("~/Downloads")
    quarantine_dir = os.path.join(watch_dir, "Quarantine")
    os.makedirs(watch_dir, exist_ok=True)

    # Initialize AI Engines
    dl = DLAnalyzer()
    agent = AgenticEngine(dl_analyzer=dl)
    
    event_handler = DownloadHandler(agent, dl)
    shield_observer = Observer()
    shield_observer.schedule(event_handler, watch_dir, recursive=False)
    
    def run_observer():
        shield_observer.start()
        try:
            while shield_observer.is_alive():
                time.sleep(1)
        except Exception:
            pass

    shield_thread = threading.Thread(target=run_observer, daemon=True)
    shield_thread.start()
    console.print(f"\n[bold green]🛡️  Real-Time Download Shield is now active in the background![/]")
    console.print(f"[dim]Watching: {watch_dir}[/]\n")


def print_header():
    console.print("""[bold cyan]
  ██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║
  ██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║
  ██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║
  ██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝[/]
  [bold yellow]Unified Command Center — CLI Control Panel[/]
    """)


def show_menu():
    global shield_observer
    
    while True:
        console.clear()
        print_header()
        
        # Shield status indicator
        shield_status = "[red]OFFLINE 🔴[/]"
        if shield_observer and shield_observer.is_alive():
            shield_status = "[green]ACTIVE 🟢 (Running in background)[/]"

        menu_text = (
            f"Shield Status: {shield_status}\n\n"
            "[bold yellow]1.[/] 🛡️  Start/Status of Download Shield\n"
            "[bold yellow]2.[/] 🔍 Scan a File or Folder\n"
            "[bold yellow]3.[/] 🖥️  Live System & Process Monitor (Sysmon)\n"
            "[bold yellow]4.[/] 🧪 Sandbox Testing Options (Setup, Attack, Restore)\n"
            "[bold yellow]5.[/] ❌ Exit"
        )
        
        console.print(Panel(menu_text, title="[bold cyan]Select an Option[/]", border_style="cyan"))
        
        try:
            choice = IntPrompt.ask("\nEnter choice", choices=["1", "2", "3", "4", "5"], default=5)
        except KeyboardInterrupt:
            break

        if choice == 1:
            if shield_observer and shield_observer.is_alive():
                console.print("\n[green]Shield is already running in the background monitoring ~/Downloads.[/]")
            else:
                console.print("\n[cyan]Starting Download Shield...[/]")
                start_shield_in_background()
            time.sleep(2)

        elif choice == 2:
            path = Prompt.ask("\nEnter path of file/folder to scan")
            if not os.path.exists(path):
                console.print(f"[bold red]Error: Path '{path}' does not exist.[/]")
            else:
                console.print(f"\n[cyan]Scanning path: {path}...[/]")
                cmd_scan(path)
            Prompt.ask("\nPress Enter to return to menu")

        elif choice == 3:
            console.print("\n[cyan]Starting System Monitor... Press Ctrl+C to exit monitor.[/]")
            time.sleep(1)
            try:
                cmd_sysmon()
            except KeyboardInterrupt:
                pass

        elif choice == 4:
            show_sandbox_menu()

        elif choice == 5:
            break

    # Clean shutdown
    if shield_observer:
        console.print("\n[yellow]Shutting down background shield observer...[/]")
        shield_observer.stop()
        shield_observer.join(timeout=2)
    console.print("[bold green]Goodbye![/]")


def show_sandbox_menu():
    while True:
        console.clear()
        print_header()
        
        menu_text = (
            "[bold yellow]1.[/] 📂 Setup Sandbox (Create dummy test files)\n"
            "[bold yellow]2.[/] 💀 Attack Sandbox (Simulate ransomware encryption)\n"
            "[bold yellow]3.[/] 🔄 Restore Sandbox (Recover original files)\n"
            "[bold yellow]4.[/] 🧹 Clean Sandbox (Delete test folders)\n"
            "[bold yellow]5.[/] 🔙 Back to Main Menu"
        )
        
        console.print(Panel(menu_text, title="[bold magenta]🧪 Sandbox Testing Suite[/]", border_style="magenta"))
        
        try:
            choice = IntPrompt.ask("\nEnter choice", choices=["1", "2", "3", "4", "5"], default=5)
        except KeyboardInterrupt:
            break

        if choice == 1:
            cmd_setup()
            Prompt.ask("\nPress Enter to continue")
        elif choice == 2:
            cmd_attack()
            Prompt.ask("\nPress Enter to continue")
        elif choice == 3:
            cmd_restore()
            Prompt.ask("\nPress Enter to continue")
        elif choice == 4:
            cmd_clean()
            Prompt.ask("\nPress Enter to continue")
        elif choice == 5:
            break


def run_direct_cli():
    """Handle direct command-line arguments if passed."""
    cmd = sys.argv[1].lower()

    if cmd == "scan":
        if len(sys.argv) < 3:
            console.print("[bold red]Error:[/] Please provide a file or folder path.\nUsage: python ransom_guard.py scan <path>")
            sys.exit(1)
        cmd_scan(sys.argv[2])
        
    elif cmd == "sysmon":
        try:
            cmd_sysmon()
        except KeyboardInterrupt:
            console.print("\n[yellow]Monitor stopped.[/]")
            
    elif cmd == "shield":
        # Launch watcher directly (blocking mode)
        os.system(f"python {os.path.join(SCRIPT_DIR, 'download_watcher.py')}")
        
    elif cmd in ("setup", "attack", "restore", "clean"):
        os.system(f"python {os.path.join(SCRIPT_DIR, 'test_ransom_sim.py')} {cmd}")
        
    else:
        console.print(f"[bold red]Unknown command:[/] {cmd}")
        console.print("Available CLI commands: scan, sysmon, shield, setup, attack, restore, clean")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_direct_cli()
    else:
        show_menu()
