"""SecureOps Offensive Security Threat Intelligence Platform.

Run with: streamlit run app.py
"""
from __future__ import annotations

import os
import re
import json
import subprocess
import tempfile
from pathlib import Path
import streamlit as st
from groq import Groq

# --- 1. SECUREOPS PAGE CONFIGURATION ---
st.set_page_config(
    page_title="SecureOps | Threat Intelligence",
    page_icon="🐉",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Core Threat DB mapping with CWE / Impact mapping & Full Compliance Frameworks
THREAT_DB = {
    "dockerfile.root-user": {"category": "Container Hardening", "impact": "HIGH", "cwe": "CWE-250", "frameworks": ["CIS Benchmarks", "NIST CSF"]},
    "env.permissions": {"category": "Secrets Management", "impact": "HIGH", "cwe": "CWE-732", "frameworks": ["CIS Benchmarks", "PCI-DSS", "GDPR"]},
    "dependency.log4j-core": {"category": "Supply Chain Vulnerability", "impact": "CRITICAL", "cwe": "CWE-502", "frameworks": ["OWASP Top 10", "NIST CSF", "CISA KEV"]},
    "dependency.spring-web": {"category": "Supply Chain Vulnerability", "impact": "MEDIUM", "cwe": "CWE-94", "frameworks": ["OWASP Top 10", "NIST CSF"]},
    "python.code.injection": {"category": "Injection Vulnerability", "impact": "CRITICAL", "cwe": "CWE-94", "frameworks": ["OWASP Top 10", "GDPR", "PCI-DSS"]},
    "python.crypto.weak": {"category": "Cryptographic Failures", "impact": "MEDIUM", "cwe": "CWE-327", "frameworks": ["OWASP Top 10", "PCI-DSS", "HIPAA", "NIST SP 800-52"]},
    "python.os.system": {"category": "Command Injection", "impact": "HIGH", "cwe": "CWE-78", "frameworks": ["OWASP Top 10", "PCI-DSS"]},
    "yaml.unsafe.load": {"category": "Insecure Deserialization", "impact": "HIGH", "cwe": "CWE-502", "frameworks": ["OWASP Top 10", "NIST CSF"]},
    "js.code.injection": {"category": "Injection Vulnerability", "impact": "CRITICAL", "cwe": "CWE-94", "frameworks": ["OWASP Top 10", "PCI-DSS"]},
    "js.xss.dom": {"category": "Cross-Site Scripting (XSS)", "impact": "HIGH", "cwe": "CWE-79", "frameworks": ["OWASP Top 10", "PCI-DSS", "HIPAA"]},
    "php.sqli.xss": {"category": "SQL Injection / XSS", "impact": "HIGH", "cwe": "CWE-89", "frameworks": ["OWASP Top 10", "PCI-DSS", "GDPR"]},
    "html.xss": {"category": "Cross-Site Scripting (XSS)", "impact": "CRITICAL", "cwe": "CWE-79", "frameworks": ["OWASP Top 10", "PCI-DSS"]},
    "secrets.aws": {"category": "Credential Leak", "impact": "CRITICAL", "cwe": "CWE-798", "frameworks": ["PCI-DSS", "HIPAA", "CIS Benchmarks"]},
    "secrets.stripe": {"category": "Credential Leak", "impact": "CRITICAL", "cwe": "CWE-798", "frameworks": ["PCI-DSS", "GDPR"]},
    "secrets.github": {"category": "Credential Leak", "impact": "CRITICAL", "cwe": "CWE-798", "frameworks": ["CIS Benchmarks", "NIST CSF", "SOC 2"]},
    "secrets.generic_token": {"category": "Credential Leak", "impact": "HIGH", "cwe": "CWE-798", "frameworks": ["PCI-DSS", "GDPR", "HIPAA"]}
}

def inject_secureops_styles() -> None:
    """Polished Matrix Terminal UX: Bug fixes and reduced eye-strain."""
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600;800&display=swap');
        
        /* Fixed Typography - Removed 'span' to restore Streamlit Sidebar Icons */
        .stApp { font-family: 'Fira Code', monospace; }
        h1, h2, h3, p, li, div { font-family: 'Fira Code', monospace !important; }
        
        /* Header Styling */
        .secureops-header { 
            padding: 1rem 0; 
            border-bottom: 1px dashed #00FF41; 
            margin-bottom: 2rem; 
        }
        /* Bright green for main titles only */
        .secureops-title { 
            font-size: 2.2rem; 
            margin: 0; 
            color: #00FF41 !important; 
            text-shadow: 0 0 5px rgba(0, 255, 65, 0.3);
            letter-spacing: -1px;
        }
        /* Softer, readable green for subtitles and text */
        .secureops-subtitle { 
            font-size: 0.95rem; 
            color: #00CC33 !important; 
            margin-top: 0.2rem; 
        }

        /* Grade Box UI - Sharp Edges */
        .grade-box { 
            text-align: center; 
            padding: 1.5rem 0; 
            background: #030303; 
            border: 1px solid #00CC33; 
            border-radius: 0px; 
            box-shadow: inset 0 0 10px rgba(0, 204, 51, 0.1);
        }
        .grade-letter { font-size: 3.5rem; font-weight: 800; line-height: 1.1; margin: 0; }
        
        /* Threat Colors */
        .grade-CRITICAL { color: #FF003C; text-shadow: 0 0 10px rgba(255,0,60,0.4); } 
        .grade-HIGH { color: #FF9D00; } 
        .grade-MEDIUM { color: #FFEA00; } 
        .grade-LOW { color: #00CC33; }
        .grade-SECURE { color: #00CC33; }
        .grade-label { color: #008F11; font-size: 0.75rem; font-weight: 600; letter-spacing: 1px; margin-top: 0.5rem; text-transform: uppercase; }
        
        /* Input Fields - Softer Terminal Style */
        div[data-baseweb="input"] > div {
            background-color: #050505;
            border: 1px solid #008F11;
            border-radius: 0px;
        }
        div[data-baseweb="input"] > div:hover {
            border-color: #00CC33;
        }
        
        /* Primary Action Button */
        button[kind="primary"] { 
            background-color: #000000 !important; 
            color: #00FF41 !important; 
            border: 1px solid #00CC33 !important; 
            font-weight: 800; 
            border-radius: 0px !important;
            text-transform: uppercase;
            letter-spacing: 1px;
            transition: all 0.2s ease-in-out;
        }
        button[kind="primary"]:hover { 
            background-color: #00FF41 !important; 
            color: #000000 !important; 
        }
        
        /* System Idle Box (Overrides Streamlit's native blue info box) */
        div[data-testid="stSidebar"] div.stAlert {
            background-color: #000000;
            border: 1px solid #008F11;
            color: #00CC33;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

def sanitize_github_url(url: str) -> bool:
    pattern = r'^https://github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(\.git)?/?$'
    return re.match(pattern, url.strip()) is not None

def calculate_nist_severity(findings: list[dict[str, str]]) -> tuple[str, str, str]:
    if not findings: return ("SECURE", "grade-SECURE", "NO THREATS DETECTED")
    severities = [f["severity"].upper() for f in findings]
    if "CRITICAL" in severities: return ("CRITICAL", "grade-CRITICAL", "CVSS 9.0 - 10.0")
    elif "HIGH" in severities: return ("HIGH", "grade-HIGH", "CVSS 7.0 - 8.9")
    elif "MEDIUM" in severities: return ("MEDIUM", "grade-MEDIUM", "CVSS 4.0 - 6.9")
    else: return ("LOW", "grade-LOW", "CVSS 0.1 - 3.9")

def run_universal_scanner(target_dir: str) -> str:
    output = ""
    target_path = Path(target_dir)
    
    rules = {
        ".py": [
            ("eval(", "python.code.injection", "CRITICAL", "Arbitrary code execution risk via eval()."),
            ("exec(", "python.code.injection", "CRITICAL", "Arbitrary code execution risk via exec()."),
            ("hashlib.md5(", "python.crypto.weak", "MEDIUM", "Weak MD5 hashing algorithm detected."),
            ("hashlib.sha1(", "python.crypto.weak", "LOW", "Weak SHA-1 hashing algorithm detected."),
            ("pickle.loads(", "python.code.injection", "CRITICAL", "Insecure deserialization using pickle.loads()."),
            ("yaml.unsafe_load(", "python.code.injection", "CRITICAL", "Insecure deserialization using yaml.unsafe_load()."),
            ("os.system(", "python.os.system", "HIGH", "Command execution risk via os.system()."),
            ("subprocess.Popen(..., shell=True)", "python.os.system", "HIGH", "Shell commands run with shell=True are vulnerable to execution bypasses.")
        ],
        ".js": [
            ("eval(", "js.code.injection", "CRITICAL", "Arbitrary code execution risk via eval()."),
            ("innerHTML", "js.xss.dom", "HIGH", "Potential DOM-based XSS using innerHTML assignment."),
            ("document.write(", "js.xss.dom", "HIGH", "Insecure document.write() usage prone to DOM XSS."),
            ("child_process.exec(", "js.code.injection", "CRITICAL", "Arbitrary system command execution risk.")
        ],
        ".php": [
            ("$_GET[", "php.sqli.xss", "HIGH", "Direct use of $_GET without sanitization."),
            ("$_POST[", "php.sqli.xss", "HIGH", "Direct use of $_POST without sanitization."),
            ("eval(", "php.sqli.xss", "CRITICAL", "Insecure PHP eval execution.")
        ],
        ".html": [
            ("<script>eval(", "html.xss", "CRITICAL", "Inline script with eval() detected."),
            ("onload=", "html.xss", "MEDIUM", "Inline event handlers can be vectors for XSS.")
        ],
        ".yaml": [("!!python/object", "yaml.unsafe.load", "HIGH", "Insecure YAML tag structure found.")],
        ".yml": [("!!python/object", "yaml.unsafe.load", "HIGH", "Insecure YAML tag structure found.")]
    }
    
    filename_rules = {
        "Dockerfile": [
            ("USER root", "dockerfile.root-user", "HIGH", "Final USER instruction runs the image as root.")
        ],
        "pom.xml": [
            ("log4j-core", "dependency.log4j-core", "CRITICAL", "Vulnerable log4j-core (CVE-2021-44228) detected."),
            ("spring-web", "dependency.spring-web", "MEDIUM", "Outdated and vulnerable spring-web dependency.")
        ]
    }
    
    secrets_regex = {
        "secrets.aws": (r"AKIA[0-9A-Z]{16}", "CRITICAL", "Exposed AWS Access Key detected."),
        "secrets.stripe": (r"sk_live_[0-9a-zA-Z]{24}", "CRITICAL", "Exposed Stripe Live API Key detected."),
        "secrets.github": (r"ghp_[a-zA-Z0-9]{36}", "CRITICAL", "Exposed GitHub Personal Access Token detected."),
        "secrets.generic_token": (r"(?i)(password|secret|passwd|api_key|private_key)\s*=\s*['\"][a-zA-Z0-9_\-+=/]{16,}['\"]", "HIGH", "Suspected hardcoded high-entropy secret detected.")
    }

    for file_path in target_path.rglob("*"):
        if file_path.is_file():
            try:
                content = file_path.read_text(errors="ignore")
                if file_path.suffix in rules:
                    for search_str, rule_id, severity, desc in rules[file_path.suffix]:
                        if search_str in content:
                            output += f"FINDING|{rule_id}|{severity}|{file_path.name}|{desc}\n"
                if file_path.name in filename_rules:
                    for search_str, rule_id, severity, desc in filename_rules[file_path.name]:
                        if search_str in content:
                            output += f"FINDING|{rule_id}|{severity}|{file_path.name}|{desc}\n"
                for rule_id, (pattern, severity, desc) in secrets_regex.items():
                    if re.search(pattern, content):
                        output += f"FINDING|{rule_id}|{severity}|{file_path.name}|{desc}\n"
            except Exception:
                pass
                
    return output

def run_sandboxed_scanners(target_dir: str) -> str:
    root_dir = Path(__file__).resolve().parent
    combined_output = "STATUS|scanner|started\n"
    combined_output += run_universal_scanner(target_dir)
    combined_output += "STATUS|docker_daemon|absent_using_native_sandbox\n"
    
    # Run Shell Scanner with a timeout for DoS protection
    bash_script = root_dir / "scan.sh"
    if bash_script.exists():
        bash_script.chmod(0o755)
        try:
            # Added timeout=10 to prevent hanging
            bash_res = subprocess.run([str(bash_script)], cwd=target_dir, capture_output=True, text=True, timeout=10)
            combined_output += bash_res.stdout + "\n"
        except Exception: pass
            
    java_source = root_dir / "DependencyScanner.java"
    if java_source.exists():
        try:
            # -Xmx64m prevents memory exhaustion; timeout=10 prevents CPU exhaustion
            java_res = subprocess.run(["java", "-Xmx64m", "-cp", str(root_dir), "DependencyScanner", str(target_dir)], 
                                      cwd=root_dir, capture_output=True, text=True, timeout=10)
            combined_output += java_res.stdout + "\n"
        except Exception: pass

    return combined_output

def parse_findings(engine_output: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for line in engine_output.splitlines():
        parts = line.split("|", 4)
        if len(parts) != 5 or parts[0] != "FINDING": continue
        _, rule_id, severity, resource, description = parts
        sev = severity.strip().upper()
        if sev not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]: sev = "HIGH"
        findings.append({"rule_id": rule_id.strip(), "severity": sev, "resource": resource.strip(), "description": description.strip()})
    return findings

def extract_json_from_response(text: str) -> dict[str, str]:
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1).strip())
            except json.JSONDecodeError:
                pass
        try:
            cleaned = text.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[1]
            if cleaned.endswith("```"):
                cleaned = cleaned.rsplit("\n", 1)[0]
            return json.loads(cleaned.strip())
        except Exception:
            raise ValueError("Failed to parse JSON response payload from Llama Model.")
@st.cache_data(show_spinner=False)
def get_ai_remediation(finding: dict[str, str], api_key: str) -> dict[str, str]:
    try:
        if not api_key:
            return {
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cia_impact": "Requires active Groq API credential.",
                "compliance_violations": "GDPR / PCI-DSS",
                "risk_explanation": "Critical security posture violation. Action required.",
                "remediation_steps": "# Configure active GROQ_API_KEY to fetch automated payloads."
            }
        
        client = Groq(api_key=api_key)
        
        # MERGED PROMPT: Combines Triage Verification with Strict JSON Output
        prompt = f"""
        You are a CISO and Senior Security Architect. Analyze this static application security testing (SAST) finding:
        {json.dumps(finding)}

        STEP 1: Verify if this is a real vulnerability or a false positive (e.g., the dangerous keyword is just inside a code comment or print statement). 
        
        STEP 2: Respond ONLY with a valid JSON object matching this exact schema:
        {{
            "cvss_vector": "Generate the exact CVSS v3.1 vector string. (If false positive, output 'N/A - False Positive')",
            "cia_impact": "Assess impact on Confidentiality, Integrity, and Availability. (If false positive, output 'None')",
            "compliance_violations": "Map to OWASP Top 10, GDPR, HIPAA, PCI-DSS, ISO 27001, or NIST CSF. (If false positive, output 'None')",
            "risk_explanation": "Explain the attack vector using the STRIDE threat model. If it is a false positive, explain exactly why it is safe.",
            "remediation_steps": "Provide exact terminal command or secure code replacement. If false positive, output '# No remediation required. Code is safe.'"
        }}
        """
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"},
            temperature=0.2
        )
        return extract_json_from_response(response.choices[0].message.content)
    except Exception as e:
        return {"cvss_vector": "CVSS Calculation Failed", "cia_impact": "Unknown", "compliance_violations": "Unknown", "risk_explanation": f"API Error: {str(e)}", "remediation_steps": "# Manual review required."}
def render_finding(finding: dict[str, str], api_key: str) -> None:
    severity = finding["severity"]
    icon = {"CRITICAL": "☠️", "HIGH": "🔥", "MEDIUM": "⚠️", "LOW": "ℹ️"}.get(severity, "⚪")
    color = "#FF003C" if severity in ["CRITICAL", "HIGH"] else ("#FFEA00" if severity == "MEDIUM" else "#00FF41")
    
    # 1. THE HOOK (Outside the expander)
    # Main Title: Severity + Rule ID
    st.markdown(f"**<span style='color:{color};'>{icon} {severity}</span> | `{finding['rule_id']}`**", unsafe_allow_html=True)
    
    # Subtitle: Target + Compliance Mapping on one clean line
    compliance = THREAT_DB.get(finding["rule_id"], {}).get("frameworks", ["Standard Security"])
    st.caption(f"🎯 **TARGET:** `{finding['resource']}` &nbsp;|&nbsp; 🛡️ **COMPLIANCE:** {', '.join(compliance)}")

    # 2. THE DETAILS (Inside the expander)
    with st.expander("🧠 AI THREAT REMEDIATION & VISUAL PATH", expanded=False):
        with st.spinner("Calculating CVSS vectors and compliance frameworks..."):
            ai_data = get_ai_remediation(finding, api_key)
            
        # --- VISUAL ATTACK PATH ---
        st.markdown("**🚨 VISUAL ATTACK PATH**")
        col1, col2, col3 = st.columns([1, 0.1, 1])
        col1.info(f"**ENTRY:** `{finding['resource']}`")
        
        # Center the arrow for better UI alignment
        col2.markdown("<h3 style='text-align: center; margin-top: 5px;'>➔</h3>", unsafe_allow_html=True)
        
        col3.error(f"**VULN:** `{finding['rule_id']}`")
        st.markdown(f"> *{finding['description']}*")
        
        st.divider()
        
        # --- AI TELEMETRY ---
        st.markdown(f"<span class='cvss-pill'>{ai_data.get('cvss_vector', 'N/A')}</span>", unsafe_allow_html=True)
        
        c1, c2 = st.columns(2)
        c1.caption("CIA TRIAD IMPACT")
        c1.write(ai_data.get('cia_impact', 'Pending'))
        c2.caption("COMPLIANCE VIOLATIONS (PCI/HIPAA/ISO/NIST)")
        c2.write(ai_data.get('compliance_violations', 'Pending'))
        
        st.divider()
        
        # --- REMEDIATION ---
        st.caption("⚠️ RISK MODELING")
        st.write(ai_data.get("risk_explanation", "Manual review required."))
        
        st.caption("✅ REMEDIATION PAYLOAD")
        st.code(ai_data.get("remediation_steps", "# Manual review required."), language="bash")
        
    st.write("---")

# --- 4. DASHBOARD INITIALIZATION ---
inject_secureops_styles()

if "findings" not in st.session_state:
    st.session_state.findings = []
    st.session_state.raw_engine_output = ""
    st.session_state.has_run = False

# API Key Resolution: Prioritizes Streamlit Secrets, falls back to environment
try:
    api_key = st.secrets["GROQ_API_KEY"]
except Exception:
    api_key = os.environ.get("GROQ_API_KEY", "")

with st.sidebar:
    st.markdown("### 📋 RISK LEVEL ASSESSMENT")
    
    # Properly indented state check for the grade box
    if st.session_state.has_run:
        grade, css_class, label = calculate_nist_severity(st.session_state.findings)
        st.markdown(f"""
            <div class="grade-box">
                <p class="grade-letter {css_class}">{grade}</p>
                <p class="grade-label">{label}</p>
            </div>
        """, unsafe_allow_html=True)
        
        crits = sum(1 for f in st.session_state.findings if f["severity"] == "CRITICAL")
        highs = sum(1 for f in st.session_state.findings if f["severity"] == "HIGH")
        meds = sum(1 for f in st.session_state.findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in st.session_state.findings if f["severity"] == "LOW")
        
        st.write(f"☠️ **CRITICAL:** {crits}")
        st.write(f"🔥 **HIGH:** {highs}")
        st.write(f"⚠️ **MEDIUM:** {meds}")
        st.write(f"ℹ️ **LOW:** {low}")
    else:
        st.markdown("""
            <div style="border: 1px solid #008F11; padding: 1rem; background: #050505; color: #00CC33; font-size: 0.9rem; text-align: center;">
                System idle.<br><br>Awaiting target to begin.
            </div>
        """, unsafe_allow_html=True)
    
    st.divider()
    st.markdown("### ⚙️ SYSTEM SPECS")
    st.markdown("""
    * ⚙️ **Core:** `SecureOps Native Engine`
    * 🛡️ **Environment:** `Local Sandbox`
    * 🔍 **Analysis:** `Static Code Analysis`
    * 🔑 **Secrets:** `API Key & Credential Hunting`
    * 🧠 **Intelligence:** `Compliance AI`
    """)

# SECUREOPS HEADER
st.markdown(
    """<div class="secureops-header">
        <h1 class="secureops-title">🐉 SecureOps Engine</h1>
        <p class="secureops-subtitle">Offensive Security & Automated Compliance Framework</p>
    </div>""",
    unsafe_allow_html=True,
)

t1, t2 = st.tabs(["[ TARGET: GITHUB ]", "[ TARGET: RAW PAYLOAD ]"])
with t1:
    github_url = st.text_input("Repository URL", placeholder="https://github.com/username/repo-name", label_visibility="collapsed")
with t2:
    language_map = {"Python": "script.py", "JavaScript": "script.js", "Java/Maven": "pom.xml", "PHP": "index.php", "HTML": "index.html", "Docker": "Dockerfile", "Environment": ".env"}
    selected_language = st.selectbox("Payload Architecture:", list(language_map.keys()))
    paste_filename = language_map[selected_language]
    pasted_code = st.text_area("Source Code", height=150, placeholder="Inject raw code...", label_visibility="collapsed")

if st.button("INITIATE THREAT AUDIT", type="primary", use_container_width=True):
    with st.spinner("Provisioning isolated sandbox and acquiring targets..."):
        with tempfile.TemporaryDirectory(prefix="secureops-sandbox-") as temp_workspace:
            workspace_path = Path(temp_workspace)
            
            # --- 1. TARGET ACQUISITION ---
            if github_url:
                if not sanitize_github_url(github_url):
                    st.error("ACCESS DENIED: Malformed or malicious GitHub URL detected.")
                    st.stop()
                try: 
                    subprocess.run(["git", "clone", github_url, "."], cwd=workspace_path, capture_output=True, check=True)
                except subprocess.CalledProcessError:
                    st.error("Target unreachable. Ensure repository is public.")
                    st.stop()
            elif pasted_code:
                (workspace_path / paste_filename).write_text(pasted_code)
            else:
                st.warning("No target provided.")
                st.stop()

            # --- 2. SECURITY FILTERING ---
            # Delete anything suspicious before the scanner touches it
            safe_extensions = {'.py', '.js', '.java', '.xml', '.yml', '.yaml', 'Dockerfile', '.php', '.html'}
            for path in workspace_path.rglob("*"):
                if path.is_file() and path.suffix not in safe_extensions and path.name != "Dockerfile":
                    path.unlink()

            # --- 3. SCAN EXECUTION ---
            raw_output = run_sandboxed_scanners(str(workspace_path))
            
            st.session_state.raw_engine_output = raw_output
            st.session_state.findings = parse_findings(raw_output)
            st.session_state.has_run = True
            st.rerun()

# --- RESULTS ENGINE ---
if st.session_state.has_run:
    findings = st.session_state.findings
    if findings:
        st.subheader("IDENTIFIED THREAT VECTORS")
        col1, col2 = st.columns([3, 1])
        with col2: st.download_button(label="[ EXPORT JSON REPORT ]", data=json.dumps(findings, indent=4), file_name="threat_report.json", mime="application/json", use_container_width=True)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            for f in findings:
                if f["severity"] == severity:
                    render_finding(f, api_key)
    else:
        st.success("✅ ZERO-DAY MITIGATED. No active signatures triggered.")

    with st.expander("[ RAW KERNEL LOGS ]"):
        st.code(st.session_state.raw_engine_output, language="text")
