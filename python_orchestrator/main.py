"""
Main CLI Orchestrator Entrypoint for Autonomous Malware Sandbox & Code Analyzer.

Modes:
  scan <path>           Scan a single file or directory
  demo                  Run an interactive end-to-end multi-sample benchmark
  live-agent            Launch low-level C agent and stream events over Named Pipe IPC
  retrain               Retrain localized ML classifier model
"""

import os
import sys
import time
import argparse
import subprocess
import threading
from typing import List

from .bindings_loader import engine
from .scanner_queue import ScannerQueue, ScanResult
from .reporting import export_json_report, export_markdown_report
from .cli_dashboard import render_banner, render_scan_dashboard, console
from .ipc_client import IPCClient, DEFAULT_PIPE_NAME


def handle_scan_file(filepath: str, export_reports: bool = True) -> ScanResult:
    if not os.path.exists(filepath):
        console.print(f"[bold red][-] Error: File not found: {filepath}[/bold red]")
        sys.exit(1)

    scanner = ScannerQueue()
    task = scanner.enqueue_file(filepath)
    # Synchronously process for single scan
    from .scanner_queue import ScanTask
    result = scanner.process_task(ScanTask("FILE", filepath))

    result_dict = result.to_dict()
    render_scan_dashboard(result_dict)

    if export_reports:
        json_path = export_json_report(result_dict)
        md_path = export_markdown_report(result_dict)
        console.print(f"\n[bold green][+] Structured Security Audit Reports Generated:[/bold green]")
        console.print(f"  [cyan]* JSON Report:[/cyan] [dim]{json_path}[/dim]")
        console.print(f"  [cyan]* Markdown Audit:[/cyan] [dim]{md_path}[/dim]\n")

    return result


def handle_scan_dir(directory: str):
    if not os.path.isdir(directory):
        console.print(f"[bold red][-] Error: Not a directory: {directory}[/bold red]")
        sys.exit(1)

    files = [
        os.path.join(directory, f)
        for f in os.listdir(directory)
        if os.path.isfile(os.path.join(directory, f))
    ]

    console.print(f"[bold cyan][*] Found {len(files)} target files in {directory}[/bold cyan]\n")
    for f in files:
        console.print(f"[dim]{'-'*70}[/dim]")
        handle_scan_file(f, export_reports=True)


def handle_demo():
    render_banner(engine.mode)
    console.print("[bold yellow]>>> RUNNING AUTONOMOUS MALWARE SANDBOX BENCHMARK SUITE <<<[/bold yellow]\n")

    sample_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")
    test_files = [
        "clean_utility.exe",
        "simulated_packer.exe",
        "simulated_trojan.exe",
        "simulated_ransomware.exe",
        "malicious_script.ps1"
    ]

    for fname in test_files:
        fpath = os.path.join(sample_dir, fname)
        if os.path.exists(fpath):
            console.print(f"\n[bold white on blue] >>> TESTING SAMPLE: {fname} <<< [/bold white on blue]")
            handle_scan_file(fpath, export_reports=True)
            time.sleep(0.5)


def handle_live_agent(watch_dir: str, pipe_name: str = DEFAULT_PIPE_NAME):
    render_banner(engine.mode)
    os.makedirs(watch_dir, exist_ok=True)

    c_agent_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "c_agent", "c_agent.exe")
    if not os.path.exists(c_agent_bin):
        console.print(f"[bold red][-] C Agent binary not found at: {c_agent_bin}[/bold red]")
        console.print("[yellow]Please compile it first using build script or gcc.[/yellow]")
        sys.exit(1)

    console.print(f"[bold green][+] Starting Low-Level C Agent in background...[/bold green]")
    console.print(f"    Monitored Directory : [bold cyan]{watch_dir}[/bold cyan]")
    console.print(f"    IPC Pipe Endpoint   : [bold cyan]{pipe_name}[/bold cyan]\n")

    # Spawn C Agent in background
    agent_proc = subprocess.Popen([
        c_agent_bin,
        "--watch", watch_dir,
        "--pipe", pipe_name
    ])

    time.sleep(1.0) # Allow C server to initialize Named Pipe

    ipc_client = IPCClient(pipe_name)
    console.print(f"[bold cyan][*] Python Orchestrator connecting to C Agent Named Pipe...[/bold cyan]")

    if not ipc_client.connect(timeout_sec=8.0):
        console.print(f"[bold red][-] Failed to connect to C Agent Named Pipe.[/bold red]")
        agent_proc.terminate()
        sys.exit(1)

    console.print(f"[bold green][+] IPC Connection Established! Monitoring directory in real-time...[/bold green]")
    console.print(f"[dim]Drop any binary or script into '{watch_dir}' to trigger instant hardware-speed analysis.[/dim]\n")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    scanner = ScannerQueue()
    scanner.start()

    def on_ipc_event(pkt: dict):
        fpath = pkt["file_path"]
        console.print(f"\n[bold yellow]>>> [C AGENT EVENT] New File Intercepted:[/bold yellow] {fpath}")
        console.print(f"   Size: {pkt['file_size']} bytes | PE: {pkt['is_pe']} | ELF: {pkt['is_elf']}")
        
        # Analyze using high-speed pipeline
        result = scanner.process_task(from_scanner_task(pkt))
        render_scan_dashboard(result.to_dict())
        export_json_report(result.to_dict())
        export_markdown_report(result.to_dict())

    def from_scanner_task(pkt: dict):
        from .scanner_queue import ScanTask
        fpath = pkt["file_path"]
        if os.path.exists(fpath):
            return ScanTask("FILE", fpath)
        else:
            return ScanTask("BUFFER", pkt["header_preview"], {"name": fpath})

    try:
        ipc_client.listen_loop(on_ipc_event)
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Stopping monitor...[/yellow]")
    finally:
        ipc_client.close()
        agent_proc.terminate()
        scanner.stop()
        console.print("[bold green][+] Live monitor shutdown clean.[/bold green]")


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous AI-Powered Malware Sandbox & Code Analyzer (C/C++/Python Hybrid)"
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan
    scan_p = subparsers.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("path", help="Path to binary or directory")

    # demo
    subparsers.add_parser("demo", help="Run multi-sample test benchmark suite")

    # live-agent
    live_p = subparsers.add_parser("live-agent", help="Launch C Agent & connect via IPC")
    live_p.add_argument("--watch", default=os.path.join(os.getcwd(), "sandbox_dropzone"), help="Directory to monitor")
    live_p.add_argument("--pipe", default=DEFAULT_PIPE_NAME, help="Named Pipe endpoint")

    # retrain
    subparsers.add_parser("retrain", help="Retrain localized ML classifier model")

    args = parser.parse_args()

    if args.command == "scan":
        if os.path.isdir(args.path):
            handle_scan_dir(args.path)
        else:
            handle_scan_file(args.path)
    elif args.command == "demo":
        handle_demo()
    elif args.command == "live-agent":
        handle_live_agent(args.watch, args.pipe)
    elif args.command == "retrain":
        from .ai_classifier import ThreatClassifier, MODEL_PATH
        if os.path.exists(MODEL_PATH):
            os.remove(MODEL_PATH)
        tc = ThreatClassifier()
        console.print("[bold green][✓] Local ML Classifier retrained and saved to disk.[/bold green]")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
