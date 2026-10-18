"""
Structured Security Report Generator.
Outputs:
1. JSON Report (for SIEM / automation pipelines)
2. Formatted Markdown Security Audit Report
"""

import os
import json
import time
from typing import Dict, Any


def ensure_reports_dir() -> str:
    reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


def export_json_report(result_dict: Dict[str, Any], filepath: str = "") -> str:
    reports_dir = ensure_reports_dir()
    base_name = os.path.basename(result_dict.get("file_path", "scan"))
    base_name = "".join(c for c in base_name if c.isalnum() or c in ("-", "_", "."))
    timestamp = int(time.time())

    out_file = filepath or os.path.join(reports_dir, f"report_{base_name}_{timestamp}.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result_dict, f, indent=2)

    return out_file


def export_markdown_report(result_dict: Dict[str, Any], filepath: str = "") -> str:
    reports_dir = ensure_reports_dir()
    base_name = os.path.basename(result_dict.get("file_path", "scan"))
    base_name = "".join(c for c in base_name if c.isalnum() or c in ("-", "_", "."))
    timestamp = int(time.time())

    out_file = filepath or os.path.join(reports_dir, f"security_audit_{base_name}_{timestamp}.md")

    verdict = result_dict.get("verdict", "UNKNOWN")
    confidence = result_dict.get("confidence", 0.0)
    threat_score = result_dict.get("threat_score", 0)
    entropy = result_dict.get("entropy", 0.0)
    is_packed = result_dict.get("is_packed", False)
    iocs = result_dict.get("iocs", {})
    rules = result_dict.get("rule_matches", [])
    forensics = result_dict.get("forensics", {})

    status_badge = {
        "CLEAN": "🟢 **BENIGN / CLEAN**",
        "SUSPICIOUS": "🟡 **SUSPICIOUS (ANOMALY DETECTED)**",
        "MALICIOUS": "🔴 **MALICIOUS THREAT DETECTED**",
        "CRITICAL": "🚨 **CRITICAL HIGH-SEVERITY MALWARE**"
    }.get(verdict, "⚪ UNKNOWN")

    md = []
    md.append(f"# Automated Malware Security Audit Report\n")
    md.append(f"> **Generated at**: `{time.strftime('%Y-%m-%d %H:%M:%S')}`  \n")
    md.append(f"> **Analysis Engine**: Autonomous AI-Powered Malware Sandbox & Code Analyzer  \n")
    md.append(f"> **Verdict**: {status_badge} (Confidence: **{confidence:.1f}%**) | Threat Score: **{threat_score}/100**\n")
    md.append(f"---\n")

    md.append(f"## 1. Target Metadata & Binary Characteristics\n")
    md.append(f"| Attribute | Value |")
    md.append(f"| :--- | :--- |")
    md.append(f"| **Target Path** | `{result_dict.get('file_path')}` |")
    md.append(f"| **File Size** | `{result_dict.get('file_size')} bytes` |")
    md.append(f"| **Format** | `{'PE Windows Executable' if result_dict.get('is_pe') else ('ELF Linux Binary' if result_dict.get('is_elf') else 'Script / Data')}` |")
    md.append(f"| **Shannon Entropy** | `{entropy:.4f} / 8.0000` |")
    md.append(f"| **Packing State** | `{'⚠️ PACKED / ENCRYPTED' if is_packed else 'Standard / Unpacked'}` |")
    md.append(f"| **Scan Latency** | `{result_dict.get('analysis_duration_ms', 0)} ms` |\n")

    md.append(f"## 2. AI Forensic Assessment & Threat Summary\n")
    md.append(f"{forensics.get('summary', 'No summary provided.')}\n")

    if forensics.get("attack_vectors"):
        md.append(f"### Detected Attack Vectors\n")
        for av in forensics["attack_vectors"]:
            md.append(f"- ⚠️ **{av}**")
        md.append("")

    if forensics.get("mitre_matrix"):
        md.append(f"## 3. MITRE ATT&CK Mapping\n")
        md.append(f"| Technique ID | Technique Name | Status |")
        md.append(f"| :--- | :--- | :--- |")
        for m in forensics["mitre_matrix"]:
            md.append(f"| `{m.get('technique')}` | {m.get('name')} | **Triggered** |")
        md.append("")

    md.append(f"## 4. Indicators of Compromise (IOCs)\n")
    has_iocs = False

    if iocs.get("suspicious_apis"):
        has_iocs = True
        md.append(f"### High-Risk Windows API Imports\n")
        for api in iocs["suspicious_apis"]:
            md.append(f"- 📌 `{api}`")
        md.append("")

    if iocs.get("urls") or iocs.get("ip_addresses") or iocs.get("onion_domains"):
        has_iocs = True
        md.append(f"### Network Endpoints (C2 Communication)\n")
        for url in iocs.get("urls", []):
            md.append(f"- 🌐 URL: `{url}`")
        for ip in iocs.get("ip_addresses", []):
            md.append(f"- 📡 IP: `{ip}`")
        for onion in iocs.get("onion_domains", []):
            md.append(f"- 🧅 Tor: `{onion}`")
        md.append("")

    if iocs.get("suspicious_commands"):
        has_iocs = True
        md.append(f"### Obfuscated & Execution Commands\n")
        for cmd in iocs["suspicious_commands"]:
            md.append(f"- 💻 `{cmd}`")
        md.append("")

    if not has_iocs:
        md.append(f"_No high-risk indicators of compromise extracted from binary headers or strings._\n")

    md.append(f"## 5. Recommended Remediation & Incident Response Steps\n")
    remediation = forensics.get("remediation_steps", ["File cleared; no action needed."])
    for step in remediation:
        md.append(f"1. {step}")
    md.append("")

    content = "\n".join(md)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(content)

    return out_file

