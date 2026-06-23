#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  RansomGuard CLI — Ransomware Detection System                  ║
║  Deep Learning + Agentic AI + System Call Analysis               ║
║                                                                  ║
║  Usage:                                                          ║
║    python scanner.py scan  /path/to/dir                          ║
║    python scanner.py sysmon                                      ║
║    python scanner.py full  /path/to/dir                          ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import argparse
import psutil

# ── Rich imports for beautiful CLI ──
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich.columns import Columns
from rich.live import Live
from rich.layout import Layout
from rich import box

# ── Our modules ──
from entropy import file_entropy, shannon_entropy
from magic_bytes import verify_magic_bytes
from dl_analyzer import DLAnalyzer
from agent_engine import AgenticEngine
from system_monitor import (
    get_system_overview,
    scan_suspicious_processes,
    get_process_details,
)
import config

console = Console()

# ═══════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════
BANNER = """[bold cyan]
 ██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║
 ██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║
 ██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║
 ██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝[/]
[bold yellow]  G U A R D[/]  [dim]— CLI Ransomware Detection System[/]
[dim]  Deep Learning │ Agentic AI │ System Call Analysis[/]
"""


def show_banner():
    console.print(BANNER)


# ═══════════════════════════════════════════════════════
#  COMMAND 1: SCAN — Scan files or directories for ransomware
# ═══════════════════════════════════════════════════════
def cmd_scan(target_path: str):
    """Scan all files in a directory recursively or scan a single file."""
    show_banner()

    target_path = os.path.expanduser(target_path)
    is_dir = os.path.isdir(target_path)
    is_file = os.path.isfile(target_path)

    if not (is_dir or is_file):
        console.print(f"[bold red]Error:[/] '{target_path}' is not a valid file or directory.")
        sys.exit(1)

    title = "📂 Directory Scan" if is_dir else "📄 File Scan"
    console.print(Panel(
        f"[bold]Target:[/] {os.path.abspath(target_path)}",
        title=f"[bold cyan]{title}[/]",
        border_style="cyan",
    ))

    # Collect files to scan
    all_files = []
    if is_file:
        all_files.append(target_path)
    else:
        for root, _, files_list in os.walk(target_path):
            for fname in files_list:
                all_files.append(os.path.join(root, fname))

    if not all_files:
        console.print("[yellow]No files found to scan.[/]")
        return

    console.print(f"  [dim]Analyzing [bold]{len(all_files)}[/bold] file(s)...[/]\n")

    # Load DL model
    console.print("[cyan][1/2][/] Loading Deep Learning model...")
    dl = DLAnalyzer()
    agent = AgenticEngine(dl_analyzer=dl)
    console.print()

    # Scan with progress bar
    results = {"SAFE": [], "SUSPICIOUS": [], "CRITICAL": []}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Scanning files...", total=len(all_files))

        for fpath in all_files:
            verdict = agent.analyze_file(fpath)
            results[verdict.verdict].append(verdict)
            progress.update(task, advance=1)

    # ── Summary Table ──
    console.print()
    _print_summary(results, target_path)

    # ── Detailed Results for CRITICAL and SUSPICIOUS ──
    threats = results["CRITICAL"] + results["SUSPICIOUS"]
    if threats:
        console.print()
        _print_threat_details(threats, target_path)
    else:
        console.print(Panel(
            "[bold green]✅ No threats detected! All files appear clean.[/]",
            border_style="green",
        ))


def _print_summary(results: dict, base_dir: str):
    """Print scan summary table."""
    total = sum(len(v) for v in results.values())

    table = Table(
        title="[bold]Scan Summary[/]",
        box=box.ROUNDED,
        border_style="dim",
        show_lines=True,
    )
    table.add_column("Verdict", style="bold", width=14)
    table.add_column("Count", justify="center", width=8)
    table.add_column("Percentage", justify="center", width=12)
    table.add_column("Status", width=8)

    safe_count = len(results["SAFE"])
    susp_count = len(results["SUSPICIOUS"])
    crit_count = len(results["CRITICAL"])

    table.add_row(
        "[green]SAFE[/]", str(safe_count),
        f"{safe_count/total*100:.1f}%" if total else "0%",
        "✅"
    )
    table.add_row(
        "[yellow]SUSPICIOUS[/]", str(susp_count),
        f"{susp_count/total*100:.1f}%" if total else "0%",
        "⚠️"
    )
    table.add_row(
        "[red]CRITICAL[/]", str(crit_count),
        f"{crit_count/total*100:.1f}%" if total else "0%",
        "🚨"
    )
    table.add_row(
        "[bold]TOTAL[/]", f"[bold]{total}[/]", "100%", ""
    )

    console.print(table)


def _print_threat_details(threats: list, base_dir: str):
    """Print detailed analysis for flagged files."""
    console.print(Panel(
        f"[bold red]⚠️  {len(threats)} Threat(s) Detected — Detailed Analysis[/]",
        border_style="red",
    ))

    for i, v in enumerate(threats, 1):
        rel_path = os.path.relpath(v.filepath, base_dir)
        color = "red" if v.verdict == "CRITICAL" else "yellow"
        badge = "🚨 CRITICAL" if v.verdict == "CRITICAL" else "⚠️  SUSPICIOUS"

        console.print(f"\n[bold {color}]━━━ [{i}/{len(threats)}] {badge} ━━━[/]")
        console.print(f"  [bold]File:[/]       {rel_path}")
        console.print(f"  [bold]Risk Score:[/] [{color}]{v.risk_score:.1f}/100[/]")

        # Factors
        factors = v.factors
        if "entropy" in factors:
            ent_val = factors["entropy"]["value"]
            ent_bar = "█" * int(ent_val / 8 * 20) + "░" * (20 - int(ent_val / 8 * 20))
            ent_color = "red" if ent_val >= 7.5 else "yellow" if ent_val >= 6.0 else "green"
            console.print(f"  [bold]Entropy:[/]    [{ent_color}]{ent_bar} {ent_val:.3f}/8.0[/]")

        if "dl_model" in factors:
            dl_conf = factors["dl_model"].get("confidence", "N/A")
            if isinstance(dl_conf, (int, float)):
                dl_color = "red" if dl_conf >= 90 else "yellow" if dl_conf >= 60 else "green"
                console.print(f"  [bold]AI Model:[/]   [{dl_color}]{dl_conf:.1f}% malicious confidence[/]")
            else:
                console.print(f"  [bold]AI Model:[/]   [dim]{dl_conf}[/]")

        if "magic_bytes" in factors:
            mb_status = factors["magic_bytes"]["status"]
            mb_color = "red" if mb_status == "MISMATCH" else "green" if mb_status == "MATCH" else "dim"
            console.print(f"  [bold]Signature:[/]  [{mb_color}]{mb_status}[/]")

        if "extension" in factors:
            ext = factors["extension"]["ext"]
            ext_risk = factors["extension"]["risk"]
            ext_color = "red" if ext_risk > 0 else "green"
            console.print(f"  [bold]Extension:[/]  [{ext_color}]{ext}[/]")

        # Reasoning
        console.print(f"\n  [bold]Agent Reasoning:[/]")
        for reason in v.reasons:
            console.print(f"    {reason}")


# ═══════════════════════════════════════════════════════
#  COMMAND 2: SYSMON — System & Process Monitor
# ═══════════════════════════════════════════════════════
def cmd_sysmon():
    """Real-time system monitoring: RAM, CPU, disk I/O, suspicious processes."""
    show_banner()
    console.print(Panel(
        "[bold]Real-time System & Process Monitor[/]\n"
        "[dim]Monitoring RAM, CPU, Disk I/O, and scanning for suspicious processes...[/]\n"
        "[dim]Press Ctrl+C to stop.[/]",
        title="[bold cyan]🖥️  System Monitor[/]",
        border_style="cyan",
    ))

    try:
        while True:
            console.clear()
            show_banner()

            # ── System Overview ──
            sys_info = get_system_overview()

            sys_table = Table(
                title="[bold]System Resources[/]",
                box=box.ROUNDED,
                border_style="cyan",
                show_lines=True,
            )
            sys_table.add_column("Metric", style="bold", width=22)
            sys_table.add_column("Value", justify="right", width=18)
            sys_table.add_column("Visual", width=25)

            # RAM
            ram_pct = sys_info["ram_percent"]
            ram_color = "red" if ram_pct > 85 else "yellow" if ram_pct > 60 else "green"
            ram_bar = "█" * int(ram_pct / 5) + "░" * (20 - int(ram_pct / 5))
            sys_table.add_row(
                "RAM Usage",
                f"{sys_info['ram_used_gb']:.1f} / {sys_info['ram_total_gb']:.1f} GB",
                f"[{ram_color}]{ram_bar} {ram_pct}%[/]"
            )

            # CPU
            cpu_pct = sys_info["cpu_percent"]
            cpu_color = "red" if cpu_pct > 85 else "yellow" if cpu_pct > 60 else "green"
            cpu_bar = "█" * int(cpu_pct / 5) + "░" * (20 - int(cpu_pct / 5))
            sys_table.add_row(
                "CPU Usage",
                f"{cpu_pct}% ({sys_info['cpu_count']} cores)",
                f"[{cpu_color}]{cpu_bar} {cpu_pct}%[/]"
            )

            # Disk I/O
            sys_table.add_row(
                "Disk Reads",
                f"{sys_info['disk_read_mb']:.0f} MB total",
                f"[dim]{sys_info['disk_read_count']} operations[/]"
            )
            sys_table.add_row(
                "Disk Writes",
                f"{sys_info['disk_write_mb']:.0f} MB total",
                f"[dim]{sys_info['disk_write_count']} operations[/]"
            )

            console.print(sys_table)
            console.print()

            # ── Suspicious Processes ──
            suspects = scan_suspicious_processes()

            if suspects:
                proc_table = Table(
                    title=f"[bold red]🚨 {len(suspects)} Suspicious Process(es) Detected[/]",
                    box=box.HEAVY_EDGE,
                    border_style="red",
                    show_lines=True,
                )
                proc_table.add_column("PID", style="bold", width=8)
                proc_table.add_column("Name", width=18)
                proc_table.add_column("User", width=12)
                proc_table.add_column("RAM (MB)", justify="right", width=10)
                proc_table.add_column("CPU %", justify="right", width=8)
                proc_table.add_column("Flags", width=40)

                for s in suspects[:15]:  # Top 15
                    flags_str = " │ ".join(s["flags"])
                    proc_table.add_row(
                        str(s["pid"]),
                        s["name"],
                        s["user"],
                        f"{s['ram_mb']:.1f}",
                        f"{s['cpu']:.1f}" if s['cpu'] else "N/A",
                        f"[red]{flags_str}[/]",
                    )
                console.print(proc_table)
            else:
                console.print(Panel(
                    "[bold green]✅ No suspicious processes detected.[/]",
                    border_style="green",
                ))

            # ── Top Processes by RAM ──
            console.print()
            top_table = Table(
                title="[bold]Top 10 Processes by RAM[/]",
                box=box.SIMPLE,
                border_style="dim",
            )
            top_table.add_column("PID", width=8)
            top_table.add_column("Name", width=22)
            top_table.add_column("RAM (MB)", justify="right", width=10)
            top_table.add_column("CPU %", justify="right", width=8)
            top_table.add_column("Syscall", width=14)
            top_table.add_column("Status", width=10)

            procs = []
            for p in psutil.process_iter(["pid", "name", "memory_info", "cpu_percent", "status"]):
                try:
                    mem = p.info.get("memory_info")
                    if mem:
                        procs.append({
                            "pid": p.info["pid"],
                            "name": p.info.get("name", "?"),
                            "ram_mb": mem.rss / (1024**2),
                            "cpu": p.info.get("cpu_percent", 0),
                            "status": p.info.get("status", "?"),
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            procs.sort(key=lambda x: x["ram_mb"], reverse=True)
            for p in procs[:10]:
                from system_monitor import _read_proc_syscall
                syscall = _read_proc_syscall(p["pid"])
                ram_color = "red" if p["ram_mb"] > 500 else "yellow" if p["ram_mb"] > 200 else "white"
                top_table.add_row(
                    str(p["pid"]),
                    p["name"][:22],
                    f"[{ram_color}]{p['ram_mb']:.1f}[/]",
                    f"{p['cpu']:.1f}" if p["cpu"] else "0.0",
                    f"[cyan]{syscall}[/]",
                    p["status"],
                )

            console.print(top_table)
            console.print(f"\n[dim]Refreshing in 3 seconds... (Ctrl+C to stop)[/]")
            time.sleep(3)

    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped.[/]")


# ═══════════════════════════════════════════════════════
#  COMMAND 3: FULL — Scan + System Monitor combined
# ═══════════════════════════════════════════════════════
def cmd_full(target_path: str):
    """Run a file scan AND system monitor report together."""
    show_banner()

    target_path = os.path.expanduser(target_path)
    # Part 1: System overview
    console.print(Panel(
        "[bold]Phase 1: System Health Check[/]",
        title="[bold cyan]🖥️  System Analysis[/]",
        border_style="cyan",
    ))

    sys_info = get_system_overview()
    sys_table = Table(box=box.ROUNDED, border_style="cyan")
    sys_table.add_column("Metric", style="bold")
    sys_table.add_column("Value", justify="right")

    ram_pct = sys_info["ram_percent"]
    ram_color = "red" if ram_pct > 85 else "yellow" if ram_pct > 60 else "green"
    sys_table.add_row("RAM", f"[{ram_color}]{sys_info['ram_used_gb']:.1f}/{sys_info['ram_total_gb']:.1f} GB ({ram_pct}%)[/]")
    sys_table.add_row("CPU", f"{sys_info['cpu_percent']}% ({sys_info['cpu_count']} cores)")
    sys_table.add_row("Disk Reads", f"{sys_info['disk_read_mb']:.0f} MB ({sys_info['disk_read_count']} ops)")
    sys_table.add_row("Disk Writes", f"{sys_info['disk_write_mb']:.0f} MB ({sys_info['disk_write_count']} ops)")
    console.print(sys_table)

    # Part 2: Suspicious processes
    console.print()
    suspects = scan_suspicious_processes()
    if suspects:
        console.print(f"[bold red]🚨 Found {len(suspects)} suspicious process(es)![/]")
        for s in suspects[:5]:
            console.print(f"  PID {s['pid']} ({s['name']}) — {', '.join(s['flags'])}")
    else:
        console.print("[green]✅ No suspicious processes detected.[/]")

    # Part 3: File scan
    console.print()
    console.print(Panel(
        f"[bold]Phase 2: Target Scan[/]\n[dim]Target: {os.path.abspath(target_path)}[/]",
        title="[bold cyan]🔍 Target Analysis[/]",
        border_style="cyan",
    ))
    cmd_scan(target_path)


# ═══════════════════════════════════════════════════════
#  MAIN — CLI Entry Point
# ═══════════════════════════════════════════════════════
def main():
    import psutil as _psutil_check  # noqa: ensure psutil available

    if len(sys.argv) < 2:
        show_banner()
        console.print(Panel(
            "[bold]Available Commands:[/]\n\n"
            "  [cyan]python scanner.py scan  /path/to/file_or_dir[/]   — Scan target for ransomware\n"
            "  [cyan]python scanner.py sysmon[/]                         — Live system & process monitor\n"
            "  [cyan]python scanner.py full  /path/to/file_or_dir[/]   — Full analysis (system + files)\n",
            title="[bold cyan]Usage[/]",
            border_style="cyan",
        ))
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "scan":
        if len(sys.argv) < 3:
            console.print("[red]Error: Please provide a file or directory path.[/]")
            console.print("[dim]Usage: python scanner.py scan /path/to/file_or_dir[/]")
            sys.exit(1)
        cmd_scan(sys.argv[2])

    elif command == "sysmon":
        cmd_sysmon()

    elif command == "full":
        if len(sys.argv) < 3:
            console.print("[red]Error: Please provide a file or directory path.[/]")
            console.print("[dim]Usage: python scanner.py full /path/to/file_or_dir[/]")
            sys.exit(1)
        cmd_full(sys.argv[2])

    else:
        console.print(f"[red]Unknown command: '{command}'[/]")
        console.print("[dim]Use: scan, sysmon, or full[/]")
        sys.exit(1)


if __name__ == "__main__":
    main()
