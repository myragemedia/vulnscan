"""Nmap integration.

Drives `nmap` with service/version detection and, optionally, the `vuln`
script category. Findings (including CVE ids surfaced by scripts like
`vulners`) are parsed from the grepable-ish stdout as it streams.
"""
from __future__ import annotations

import re

from .base import BasePlugin

PORT_RE = re.compile(r"^(\d+)/tcp\s+(\w+)\s+(\S+)(?:\s+(.*))?")
CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)
# vulners script lines look like:  |     CVE-2021-1234   7.5   https://...
VULNERS_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+([\d.]+)")


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


class NmapPlugin(BasePlugin):
    slug = "nmap"
    name = "Nmap"
    description = "Port, service and version discovery with optional vuln scripts."
    category = "Network"
    binary = "nmap"

    options_schema = [
        {"key": "ports", "label": "Ports", "type": "text", "default": "top-1000",
         "hint": "e.g. 1-1024, 80,443, or top-1000"},
        {"key": "vuln_scripts", "label": "Run vuln scripts (NSE)",
         "type": "checkbox", "default": True},
        {"key": "timing", "label": "Timing", "type": "select",
         "default": "T4", "choices": ["T2", "T3", "T4", "T5"]},
    ]

    def build_command(self, target: str, options: dict) -> list[str]:
        cmd = ["nmap", "-sV", "-Pn", f"-{options.get('timing', 'T4')}"]

        ports = str(options.get("ports", "top-1000")).strip()
        if ports and ports != "top-1000":
            cmd += ["-p", ports]
        else:
            cmd += ["--top-ports", "1000"]

        if options.get("vuln_scripts", True):
            cmd += ["--script", "vuln,vulners"]

        cmd += ["-v", target]
        return cmd

    def parse_line(self, line: str) -> list[dict]:
        line = line.rstrip()
        findings: list[dict] = []

        # vulners-style line carrying a CVE and a CVSS score
        m = VULNERS_RE.search(line)
        if m:
            cve, score = m.group(1).upper(), float(m.group(2))
            findings.append({
                "name": f"{cve} reported by nmap vulners",
                "severity": _cvss_to_severity(score),
                "cve": cve,
                "description": f"nmap NSE flagged {cve} (CVSS {score}).",
                "evidence": line.strip(" |"),
            })
            return findings

        # bare CVE reference from other vuln scripts
        if "CVE-" in line and not m:
            for cve in CVE_RE.findall(line):
                findings.append({
                    "name": f"{cve.upper()} referenced by nmap script",
                    "severity": "medium",
                    "cve": cve.upper(),
                    "description": "Referenced by an nmap NSE vuln script.",
                    "evidence": line.strip(" |"),
                })

        return findings

    def finalize(self, lines: list[str], target: str) -> list[dict]:
        # Record open services as informational findings for the asset picture.
        findings: list[dict] = []
        for raw in lines:
            m = PORT_RE.match(raw.strip())
            if m and m.group(2) == "open":
                port, _state, service, ver = m.groups()
                findings.append({
                    "name": f"Open service: {service} on {port}/tcp",
                    "severity": "info",
                    "port": port,
                    "description": f"{service} {ver or ''}".strip(),
                    "evidence": raw.strip(),
                })
        return findings
