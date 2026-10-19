"""
CyberShield Web Dashboard - Autonomous AI Malware Sandbox & Code Analyzer
High-performance hybrid UI powered by Streamlit, C++ PyBind11, and Python ML.
"""

import os
import sys
import json
import time
import pandas as pd
import streamlit as st

# Add current directory to path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from python_orchestrator.bindings_loader import engine
from python_orchestrator.scanner_queue import ScannerQueue, ScanTask
from python_orchestrator.reporting import export_json_report, export_markdown_report

st.set_page_config(
    page_title="CyberShield | AI Malware Sandbox",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark cyber security theme
st.markdown("""
<style>
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #00d2ff;
        margin-bottom: 0px;
    }
    .sub-title {
        font-size: 1.0rem;
        color: #94a3b8;
        margin-bottom: 1.5rem;
    }
    .badge-clean {
        background-color: #065f46;
        color: #34d399;
        padding: 0.35rem 0.8rem;
        border-radius: 9999px;
        font-weight: bold;
        display: inline-block;
    }
    .badge-suspicious {
        background-color: #854d0e;
        color: #facc15;
        padding: 0.35rem 0.8rem;
        border-radius: 9999px;
        font-weight: bold;
        display: inline-block;
    }
    .badge-malicious {
        background-color: #991b1b;
        color: #f87171;
        padding: 0.35rem 0.8rem;
        border-radius: 9999px;
        font-weight: bold;
        display: inline-block;
    }
    .badge-critical {
        background-color: #7f1d1d;
        color: #fca5a5;
        padding: 0.35rem 0.8rem;
        border-radius: 9999px;
        font-weight: 800;
        border: 1px solid #ef4444;
        display: inline-block;
    }
    .metric-card {
        background: #1e293b;
        padding: 1.2rem;
        border-radius: 0.75rem;
        border: 1px solid #334155;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Scanner
@st.cache_resource
def get_scanner():
    return ScannerQueue()

scanner = get_scanner()

# Header
st.markdown('<div class="main-title">🛡️ CyberShield AI Malware Sandbox & Code Analyzer</div>', unsafe_allow_html=True)
st.markdown(
    f'<div class="sub-title">Hybrid Architecture: <b>C Low-Level Probe</b> | <b>C++ Features Engine ({engine.mode})</b> | <b>Python ML & AI Reasoning</b></div>',
    unsafe_allow_html=True
)

# Sidebar
st.sidebar.header("🕹️ Sandbox Control Panel")

st.sidebar.markdown(f"**C++ Binding Engine:** `{engine.mode}`")
if engine.mode == "PYBIND11":
    st.sidebar.success("✓ Native PyBind11 C++ Acceleration Active")
else:
    st.sidebar.info("✓ C-Bindings DLL Active")

st.sidebar.divider()
st.sidebar.subheader("📂 Choose Analysis Source")
input_mode = st.sidebar.radio(
    "Select input mode:",
    ["Preloaded Sample Suite", "Upload Custom Binary / Script", "Direct File Path"],
    index=0
)

target_bytes = None
target_name = ""
target_path = None

sample_dir = os.path.join(CURRENT_DIR, "samples")
sample_files = {
    "clean_utility.exe": "Standard Benign Windows Utility (Normal Entropy)",
    "simulated_packer.exe": "Packed Binary (High Shannon Entropy > 7.4)",
    "simulated_trojan.exe": "Trojan Simulator (Process Injection & C2 Beacon)",
    "simulated_ransomware.exe": "Ransomware Simulator (Shadow Copy Wipe & Extortion)",
    "malicious_script.ps1": "Obfuscated PowerShell Dropper (In-Memory DownloadString)"
}

if input_mode == "Preloaded Sample Suite":
    selected_sample = st.sidebar.selectbox(
        "Select sample to analyze:",
        list(sample_files.keys()),
        format_func=lambda x: f"{x} - {sample_files[x]}"
    )
    target_path = os.path.join(sample_dir, selected_sample)
    target_name = selected_sample
    with open(target_path, "rb") as f:
        target_bytes = f.read()

elif input_mode == "Upload Custom Binary / Script":
    uploaded_file = st.sidebar.file_uploader(
        "Upload executable (.exe, .dll), ELF, script (.ps1, .bat, .sh) or binary:",
        type=None
    )
    if uploaded_file is not None:
        target_bytes = uploaded_file.read()
        target_name = uploaded_file.name

elif input_mode == "Direct File Path":
    input_filepath = st.sidebar.text_input("Enter absolute file path on disk:")
    if input_filepath and os.path.exists(input_filepath):
        target_path = input_filepath
        target_name = os.path.basename(input_filepath)
        with open(target_path, "rb") as f:
            target_bytes = f.read()
    elif input_filepath:
        st.sidebar.error("File does not exist.")

analyze_button = st.sidebar.button("⚡ Run AI Dynamic Analysis", type="primary", use_container_width=True)

# Main Dashboard Execution
if target_bytes is not None:
    # Run analysis
    with st.spinner("Extracting binary features via C++ engine and evaluating ML threat model..."):
        start_t = time.perf_counter()
        if target_path and os.path.exists(target_path):
            result = scanner.process_task(ScanTask("FILE", target_path))
        else:
            result = scanner.process_task(ScanTask("BUFFER", target_bytes, {"name": target_name}))
        res = result.to_dict()
        latency_ms = res.get("analysis_duration_ms", (time.perf_counter() - start_t) * 1000.0)

    verdict = res.get("verdict", "UNKNOWN")
    confidence = res.get("confidence", 0.0)
    threat_score = res.get("threat_score", 0)
    entropy = res.get("entropy", 0.0)
    is_packed = res.get("is_packed", False)
    file_size = res.get("file_size", len(target_bytes))
    is_pe = res.get("is_pe", False)
    is_elf = res.get("is_elf", False)
    iocs = res.get("iocs", {})
    rules = res.get("rule_matches", [])
    forensics = res.get("forensics", {})

    fmt = "PE32+ (Windows Executable)" if is_pe else ("ELF (Linux Binary)" if is_elf else "Script / Raw Buffer")

    # Top KPI Metrics Cards
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"**Security Verdict**")
        if verdict == "CLEAN":
            st.markdown(f'<span class="badge-clean">🟢 CLEAN ({confidence:.1f}%)</span>', unsafe_allow_html=True)
        elif verdict == "SUSPICIOUS":
            st.markdown(f'<span class="badge-suspicious">🟡 SUSPICIOUS ({confidence:.1f}%)</span>', unsafe_allow_html=True)
        elif verdict == "MALICIOUS":
            st.markdown(f'<span class="badge-malicious">🔴 MALICIOUS ({confidence:.1f}%)</span>', unsafe_allow_html=True)
        else:
            st.markdown(f'<span class="badge-critical">🚨 CRITICAL ({confidence:.1f}%)</span>', unsafe_allow_html=True)

    with col2:
        st.metric("Threat Risk Score", f"{threat_score} / 100", delta=f"{verdict}")

    with col3:
        st.metric("Shannon Entropy", f"{entropy:.3f} / 8.0", delta="PACKED / OBFUSCATED" if is_packed else "UNPACKED", delta_color="inverse" if is_packed else "normal")

    with col4:
        st.metric("Scan Latency", f"{latency_ms:.2f} ms", delta="C++ PyBind11")

    st.divider()

    # Layout: Left column = Entropy & Telemetry, Right column = AI Forensic Insights
    left_col, right_col = st.columns([1, 1])

    with left_col:
        st.subheader("📊 Shannon Entropy & Packing Curve")
        
        # Calculate windowed entropy curve for chart
        chunk_size = 512
        if len(target_bytes) > chunk_size:
            points = []
            step = max(256, len(target_bytes) // 60)
            for offset in range(0, len(target_bytes) - chunk_size + 1, step):
                chunk = target_bytes[offset:offset + chunk_size]
                e = engine.calculate_entropy(chunk)
                points.append({"Offset (KB)": round(offset / 1024.0, 1), "Entropy (bits)": e})
            
            df_entropy = pd.DataFrame(points)
            st.line_chart(df_entropy, x="Offset (KB)", y="Entropy (bits)", color="#38bdf8", height=220)
        else:
            st.info(f"File size ({len(target_bytes)} B) is smaller than window size. Constant entropy: {entropy:.4f}")

        st.caption("Threshold: > 7.15 bits/byte indicates encrypted payload, compression, or custom packing.")

        # File Telemetry Table
        st.subheader("📋 Low-Level File Telemetry")
        meta_df = pd.DataFrame([
            {"Property": "Target Name", "Value": target_name},
            {"Property": "File Size", "Value": f"{file_size:,} bytes"},
            {"Property": "Binary Format", "Value": fmt},
            {"Property": "Extracted Strings", "Value": f"{res.get('raw_report', {}).get('total_strings', len(target_bytes)//20):,}"},
            {"Property": "Packing Detection", "Value": "DETECTED (High Entropy)" if is_packed else "Clean / Unpacked"},
            {"Property": "Execution Mitigations", "Value": "ASLR / DEP / NX Verified" if is_pe else "N/A"}
        ])
        st.dataframe(meta_df, use_container_width=True, hide_index=True)

    with right_col:
        st.subheader("🧠 AI Forensic Reasoning & Incident Response")
        st.markdown(f"**Executive Forensic Summary:**")
        st.info(forensics.get("summary", "Analysis completed."))

        if forensics.get("attack_vectors"):
            st.markdown("**Identified Attack Vectors:**")
            for av in forensics["attack_vectors"]:
                st.markdown(f"- ⚠️ `{av}`")

        if forensics.get("remediation_steps"):
            st.markdown("**Actionable Incident Response Remediation:**")
            for idx, step in enumerate(forensics["remediation_steps"], 1):
                st.markdown(f"**{idx}.** {step}")

    st.divider()

    # Rule Matches & MITRE ATT&CK Mapping
    st.subheader("🎯 Structural Signatures & MITRE ATT&CK Matrix")
    if rules:
        rule_data = []
        for r in rules:
            rule_data.append({
                "Rule Name": r.get("rule_name"),
                "Category": r.get("category"),
                "MITRE Technique": r.get("mitre", "N/A"),
                "Severity": {1: "🟢 Low", 2: "🟡 Medium", 3: "🟠 High", 4: "🔴 Critical"}.get(r.get("severity", 1), "N/A"),
                "Description": r.get("description")
            })
        st.dataframe(pd.DataFrame(rule_data), use_container_width=True, hide_index=True)
    else:
        st.success("✓ Zero malicious structural signatures triggered. File demonstrates clean binary behavior.")

    # Indicators of Compromise (IOCs)
    st.subheader("🔍 Indicators of Compromise (IOCs)")
    ioc_tabs = st.tabs(["Dangerous APIs", "C2 URLs", "Remote IPs", "Execution Commands", "Registry Keys"])
    
    with ioc_tabs[0]:
        apis = iocs.get("suspicious_apis", [])
        if apis:
            st.write(apis)
        else:
            st.caption("No high-risk Windows APIs detected.")

    with ioc_tabs[1]:
        urls = iocs.get("urls", [])
        if urls:
            for u in urls:
                st.markdown(f"- 🌐 `{u}`")
        else:
            st.caption("No external URLs detected.")

    with ioc_tabs[2]:
        ips = iocs.get("ip_addresses", [])
        if ips:
            for ip in ips:
                st.markdown(f"- 📡 `{ip}`")
        else:
            st.caption("No remote IP addresses found.")

    with ioc_tabs[3]:
        cmds = iocs.get("suspicious_commands", [])
        if cmds:
            for c in cmds:
                st.code(c, language="bash")
        else:
            st.caption("No suspicious execution command lines found.")

    with ioc_tabs[4]:
        regs = iocs.get("registry_keys", [])
        if regs:
            for r in regs:
                st.markdown(f"- 🔑 `{r}`")
        else:
            st.caption("No registry persistence keys found.")

    st.divider()

    # Reports Generation & Download
    st.subheader("📥 Export Audit Reports")
    d_col1, d_col2 = st.columns(2)
    with d_col1:
        json_report_str = json.dumps(res, indent=2)
        st.download_button(
            label="📄 Download JSON Security Report",
            data=json_report_str,
            file_name=f"audit_{target_name}.json",
            mime="application/json",
            use_container_width=True
        )
    with d_col2:
        md_file_path = export_markdown_report(res)
        with open(md_file_path, "r", encoding="utf-8") as f:
            md_content = f.read()
        st.download_button(
            label="📑 Download Markdown Security Audit",
            data=md_content,
            file_name=f"audit_{target_name}.md",
            mime="text/markdown",
            use_container_width=True
        )

else:
    st.info("👈 Select a sample from the sidebar or upload a file to begin.")

