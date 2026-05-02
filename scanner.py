import os
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from shutil import which
from fpdf import FPDF

from modules import bruteforce, subdomains


ADVISORY_DB = {
    "openssh": [
        {
            "max_major": 7,
            "cve": "CVE-2018-15473",
            "severity": "medium",
            "summary": "User enumeration issue in older OpenSSH releases.",
            "cvss": 5.3,
            "recommendation": "Upgrade OpenSSH to a supported release and disable password auth where possible.",
        }
    ],
    "apache httpd": [
        {
            "max_major": 2,
            "cve": "CVE-2021-41773",
            "severity": "high",
            "summary": "Path traversal in vulnerable Apache 2.4.x configurations.",
            "cvss": 7.5,
            "recommendation": "Patch Apache to latest stable and enforce secure path normalization.",
        }
    ],
    "nginx": [
        {
            "max_major": 1,
            "cve": "CVE-2019-20372",
            "severity": "medium",
            "summary": "HTTP/2 implementation issue affecting specific old NGINX builds.",
            "cvss": 6.1,
            "recommendation": "Upgrade NGINX and disable unnecessary protocols/modules.",
        }
    ],
    "samba": [
        {
            "max_major": 4,
            "cve": "CVE-2021-44142",
            "severity": "high",
            "summary": "Out-of-bounds heap read/write in Samba vfs_fruit module.",
            "cvss": 8.1,
            "recommendation": "Upgrade Samba and disable unused VFS modules.",
        }
    ],
}


def _parse_major(version: str) -> int | None:
    match = re.search(r"(\d+)", version or "")
    if not match:
        return None
    return int(match.group(1))


def resolve_nmap_command() -> str | None:
    """Return the best available Nmap executable path, or None if missing."""
    env_path = os.environ.get("NMAP_PATH")
    if env_path and os.path.exists(env_path):
        return env_path

    found = which("nmap")
    if found:
        return found

    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    return None


def run_nmap_scan(target: str, speed: str = "-T4", profile: str = "full") -> list[dict]:
    """Run an authorized Nmap scan and return open service data."""
    nmap_command = resolve_nmap_command()
    if not nmap_command:
        raise RuntimeError(
            "Nmap is not installed or not on PATH. Install it or set NMAP_PATH to nmap.exe."
        )

    if profile == "health":
        # Fast profile for quick service health visibility.
        cmd = [nmap_command, speed, "-F", "-sV", "--version-light", "-oX", "-", target]
    else:
        cmd = [nmap_command, speed, "-sV", "-sC", "-oX", "-", target]

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if not result.stdout:
        return []

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise RuntimeError("Nmap output could not be parsed.") from exc

    services = []
    for host in root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            srv = port.find("service")
            services.append(
                {
                    "port": port.get("portid", ""),
                    "protocol": port.get("protocol", ""),
                    "name": srv.get("name") if srv is not None else "unknown",
                    "product": srv.get("product") if srv is not None else "N/A",
                    "version": srv.get("version") if srv is not None else "",
                    "extrainfo": srv.get("extrainfo") if srv is not None else "",
                }
            )
    return services


def map_services_to_advisories(services: list[dict]) -> list[dict]:
    """Map discovered service versions to a lightweight advisory/CVE reference set."""
    findings = []
    for service in services:
        product = (service.get("product") or "").lower().strip()
        version = service.get("version") or ""
        major = _parse_major(version)

        for key, advisories in ADVISORY_DB.items():
            if key not in product:
                continue
            for advisory in advisories:
                max_major = advisory.get("max_major")
                if major is None or max_major is None or major > max_major:
                    continue
                findings.append(
                    {
                        "port": service.get("port", ""),
                        "service": service.get("name", "unknown"),
                        "product": service.get("product", "N/A"),
                        "version": version,
                        "cve": advisory["cve"],
                        "severity": advisory["severity"],
                        "cvss": advisory["cvss"],
                        "summary": advisory["summary"],
                        "recommendation": advisory["recommendation"],
                    }
                )
    return findings


def run_modules(target: str, services: list[dict]) -> dict:
    """Execute optional defensive modules and return their outputs."""
    outputs = {}

    try:
        outputs["subdomains"] = subdomains.run(target)
    except Exception as exc:
        outputs["subdomains"] = [{"error": f"subdomains module failed: {exc}"}]

    try:
        outputs["hardening"] = bruteforce.run(target, services)
    except Exception as exc:
        outputs["hardening"] = [{"error": f"hardening module failed: {exc}"}]

    return outputs


def generate_pdf_report(
    target: str,
    services: list[dict],
    advisories: list[dict],
    module_outputs: dict,
    output_dir: str = "exports",
) -> str:
    """Generate a PDF summary report and return the saved file path."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"xrecon_report_{timestamp}.pdf")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 15)
    pdf.cell(0, 10, "X-RECON Defensive Audit Report", ln=True)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Target: {target}", ln=True)
    pdf.cell(0, 8, f"Generated: {datetime.now().isoformat(timespec='seconds')}", ln=True)

    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Open Services", ln=True)
    pdf.set_font("Helvetica", "", 10)
    if services:
        for item in services:
            line = (
                f"{item.get('port', '')}/{item.get('protocol', '')} "
                f"{item.get('product', 'N/A')} {item.get('version', '')}".strip()
            )
            pdf.multi_cell(0, 6, line)
    else:
        pdf.cell(0, 6, "No open services discovered.", ln=True)

    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Advisory Matches", ln=True)
    pdf.set_font("Helvetica", "", 10)
    if advisories:
        for item in advisories:
            line = (
                f"{item['cve']} | {item['product']} {item['version']} | "
                f"{item['severity']} (CVSS {item['cvss']})"
            )
            pdf.multi_cell(0, 6, line)
            pdf.multi_cell(0, 6, f"  Recommendation: {item['recommendation']}")
    else:
        pdf.cell(0, 6, "No advisory matches in local knowledge base.", ln=True)

    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Module Outputs", ln=True)
    pdf.set_font("Helvetica", "", 10)
    for module_name, rows in module_outputs.items():
        pdf.multi_cell(0, 6, f"{module_name}:")
        if not rows:
            pdf.multi_cell(0, 6, "  No findings.")
            continue
        for row in rows[:20]:
            pdf.multi_cell(0, 6, f"  - {row}")

    pdf.output(output_path)
    return output_path