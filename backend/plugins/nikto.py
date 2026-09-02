"""Nikto integration.

Runs the `nikto` web server scanner with CSV output on stdout and turns each
reported item into a finding. CVE/OSVDB references in the message are lifted
into the finding where present.
"""
from __future__ import annotations

import re

from .base import BasePlugin

CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)


class NiktoPlugin(BasePlugin):
    slug = "nikto"
    name = "Nikto"
    description = "Web server misconfiguration and known-issue scanner."
    category = "Web"
    binary = "nikto"

    options_schema = [
        {"key": "ssl", "label": "Force SSL", "type": "checkbox", "default": False},
        {"key": "port", "label": "Port", "type": "text", "default": "80"},
    ]

    def build_command(self, target: str, options: dict) -> list[str]:
        cmd = ["nikto", "-host", target, "-Format", "csv", "-output", "-",
               "-nointeractive"]
        if options.get("port"):
            cmd += ["-port", str(options["port"])]
        if options.get("ssl"):
            cmd += ["-ssl"]
        return cmd

    def parse_line(self, line: str) -> list[dict]:
        line = line.strip()
        # Nikto CSV rows are quoted, comma separated; the message is the last field.
        if not line.startswith('"') or line.count('","') < 3:
            return []
        parts = [p.strip('"') for p in line.split('","')]
        message = parts[-1] if parts else line
        if not message:
            return []

        cve_match = CVE_RE.search(message)
        severity = "medium" if cve_match else "low"
        return [{
            "name": message[:120],
            "severity": severity,
            "cve": cve_match.group(1).upper() if cve_match else None,
            "description": message,
            "evidence": parts[3] if len(parts) > 3 else "",
        }]
