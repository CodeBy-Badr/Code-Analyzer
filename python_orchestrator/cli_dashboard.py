"""
Rich CLI Dashboard for Autonomous Malware Sandbox & Code Analyzer.
Renders visual threat reports, entropy gauges, IOC tables, and AI insights.
"""

import os
from typing import Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn
from rich.text import Text
from rich.layout import Layout
from rich import box

console = Console()

BANNER_ART = r"""
 [bold cyan]   ___      _               ___ _     _      _     _  [/bold cyan]
 [bold cyan]  / __\   _| |__   ___ _ __/ __\ |__ (_) ___| | __| | [/bold cyan]
 [bold cyan] / / | | | | '_ \ / _ \ '__\__ \ '_ \| |/ _ \ |/ _` | [/bold cyan]
 [bold cyan]/ /__| |_| | |_) |  __/ |  ___/ / | | | |  __/ | (_| | [/bold cyan]
 [bold cyan]\____/\__, |_.__/ \___|_|  \___/|_| |_|_|\___|_|\__,_| [/bold cyan]
 [bold cyan]      |___/                                            [/bold cyan]
 [bold yellow] Autonomous AI-Powered Malware Sandbox & Code Analyzer [/bold yellow]
 [bold green] Hybrid Engine: [C System Probe] + [C++ Feature Engine] + [Python AI] [/bold green]
"""


def render_banner(engine_mode: str = "PYBIND11"):
    console.print(BANNER_ART)
    console.print(f"[dim]Binding Status: [bold green]{engine_mode}[/bold green] active | Architecture: x86_64 native[/dim]\n")


def render_scan_dashboard(result_dict: Dict[str, Any]):
    verdict = result_dict.get("verdict", "UNKNOWN")
    confidence = result_dict.get("confidence", 0.0)
    threat_score = result_dict.get("threat_score", 0)
    entropy = result_dict.get("entropy", 0.0)
    is_packed = result_dict.get("is_packed", False)
    duration_ms = result_dict.get("analysis_duration_ms", 0.0)
    file_path = result_dict.get("file_path", "unknown")
    file_size = result_dict.get("file_size", 0)
    is_pe = result_dict.get("is_pe", False)
    is_elf = result_dict.get("is_elf", False)
    iocs = result_dict.get("iocs", {})
    rules = result_dict.get("rule_matches", [])
    forensics = result_dict.get("forensics", {})

    fmt_str = "PE Windows Executable" if is_pe else ("ELF Linux Binary" if is_elf else "Script / Raw File")

    # 1. Header Information Table
    meta_table = Table(box=box.ROUNDED, show_header=False, expand=True)
    meta_table.add_column("Field", style="bold cyan", width=18)
    meta_table.add_column("Value", style="white")

    meta_table.add_row("Target File", f"[bold]{file_path}[/bold]")
    meta_table.add_row("File Size", f"{file_size:,} bytes")
    meta_table.add_row("Format", fmt_str)
    meta_table.add_row("Scan Latency", f"[yellow]{duration_ms:.2f} ms[/yellow] (C++ accelerated)")

    # Entropy visualization bar (ASCII compatible for Windows console)
    ent_ratio = min(1.0, entropy / 8.0)
    ent_bars = int(ent_ratio * 20)
    ent_bar_str = "[" + ("#" * ent_bars) + ("-" * (20 - ent_bars)) + "]"
    ent_color = "red" if is_packed or entropy > 7.1 else ("yellow" if entropy > 6.4 else "green")
    packed_badge = "[bold red][!] PACKED / ENCRYPTED[/bold red]" if is_packed else "[bold green][+] UNPACKED[/bold green]"

    meta_table.add_row(
        "Shannon Entropy",
        f"[{ent_color}]{ent_bar_str}[/{ent_color}] {entropy:.4f} / 8.00 ({packed_badge})"
    )

    console.print(Panel(meta_table, title="[bold white]Binary Inspection Telemetry[/bold white]", border_style="cyan"))

    # 2. Verdict Panel
    verdict_colors = {
        "CLEAN": "bold green",
        "SUSPICIOUS": "bold yellow",
        "MALICIOUS": "bold red",
        "CRITICAL": "bold white on red"
    }
    v_style = verdict_colors.get(verdict, "bold white")
    v_text = Text()
    v_text.append(f"VERDICT: {verdict}\n", style=v_style)
    v_text.append(f"AI Confidence: {confidence:.1f}%  |  Threat Score: {threat_score}/100\n", style="white")

    score_ratio = threat_score / 100.0
    s_bars = int(score_ratio * 30)
    s_bar_str = "[" + ("#" * s_bars) + ("-" * (30 - s_bars)) + "]"
    s_color = "red" if threat_score >= 60 else ("yellow" if threat_score >= 30 else "green")
    v_text.append(f"Threat Meter: [{s_color}]{s_bar_str}[/{s_color}]", style=s_color)

    console.print(Panel(v_text, title="[bold white]Machine Learning Security Classification[/bold white]", border_style=s_color))

    # 3. Rule Matches & MITRE ATT&CK Table
    if rules:
        rule_table = Table(title="[bold red]Structural Signatures & Behavioral Rule Hits[/bold red]", box=box.HEAVY_EDGE, expand=True)
        rule_table.add_column("Rule Name", style="bold yellow")
        rule_table.add_column("Category", style="cyan")
        rule_table.add_column("MITRE ATT&CK", style="bold magenta")
        rule_table.add_column("Severity", justify="center")
        rule_table.add_column("Description", style="white")

        sev_map = {1: "[green]LOW[/green]", 2: "[yellow]MED[/yellow]", 3: "[red]HIGH[/red]", 4: "[bold red]CRIT[/bold red]"}
        for r in rules:
            rule_table.add_row(
                r.get("rule_name", ""),
                r.get("category", ""),
                r.get("mitre", "N/A"),
                sev_map.get(r.get("severity", 1), "N/A"),
                r.get("description", "")
            )
        console.print(rule_table)

    # 4. Indicators of Compromise (IOCs) Table
    ioc_table = Table(title="[bold yellow]Extracted Indicators of Compromise (IOCs)[/bold yellow]", box=box.SIMPLE_HEAD, expand=True)
    ioc_table.add_column("IOC Type", style="bold cyan", width=22)
    ioc_table.add_column("Detected Values", style="white")

    has_ioc_rows = False
    if iocs.get("suspicious_apis"):
        has_ioc_rows = True
        ioc_table.add_row("High-Risk APIs", ", ".join(f"[red]{api}[/red]" for api in iocs["suspicious_apis"][:10]))
    if iocs.get("urls"):
        has_ioc_rows = True
        ioc_table.add_row("C2 Network URLs", "\n".join(f"[underline blue]{u}[/underline blue]" for u in iocs["urls"][:5]))
    if iocs.get("ip_addresses"):
        has_ioc_rows = True
        ioc_table.add_row("Remote IP Addresses", ", ".join(f"[bold]{ip}[/bold]" for ip in iocs["ip_addresses"][:8]))
    if iocs.get("onion_domains"):
        has_ioc_rows = True
        ioc_table.add_row("Tor Onion Endpoints", ", ".join(f"[magenta]{o}[/magenta]" for o in iocs["onion_domains"][:3]))
    if iocs.get("suspicious_commands"):
        has_ioc_rows = True
        ioc_table.add_row("Execution Strings", "\n".join(f"[yellow]{c}[/yellow]" for c in iocs["suspicious_commands"][:5]))
    if iocs.get("registry_keys"):
        has_ioc_rows = True
        ioc_table.add_row("Registry Persistence", "\n".join(f"[cyan]{k}[/cyan]" for k in iocs["registry_keys"][:5]))

    if has_ioc_rows:
        console.print(ioc_table)

    # 5. Forensic Reasoning & Remediation Panel
    forensic_panel_text = Text()
    forensic_panel_text.append(f"AI Reasoning Summary:\n", style="bold cyan")
    forensic_panel_text.append(f"{forensics.get('summary', 'No summary.')}\n\n", style="white")

    if forensics.get("remediation_steps"):
        forensic_panel_text.append(f"Actionable Incident Response Steps:\n", style="bold green")
        for idx, step in enumerate(forensics["remediation_steps"], 1):
            forensic_panel_text.append(f" {idx}. {step}\n", style="italic white")

    console.print(Panel(forensic_panel_text, title="[bold white]AI Forensic Analyst Insights[/bold white]", border_style="blue"))
