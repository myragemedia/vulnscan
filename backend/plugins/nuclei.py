"""Nuclei integration.

Runs ProjectDiscovery's `nuclei` with JSONL output so each template match is
parsed into a finding as it streams. Nuclei maps cleanly onto CVE reporting:
templates carry severity and, frequently, the CVE id in their classification.
"""
from __future__ import annotations

import json

from .base import BasePlugin


class NucleiPlugin(BasePlugin):
    slug = "nuclei"
    name = "Nuclei"
    description = "Template-based CVE and misconfiguration detection."
    category = "Vulnerability"
    binary = "nuclei"

    options_schema = [
        {"key": "severity", "label": "Minimum severity", "type": "select",
         "default": "low", "choices": ["info", "low", "medium", "high", "critical"]},
        {"key": "tags", "label": "Template tags", "type": "text", "default": "",
         "hint": "comma separated, e.g. cve,exposure,misconfig"},
    ]

    def build_command(self, target: str, options: dict) -> list[str]:
        cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-no-color"]

        sev = options.get("severity")
        if sev:
            order = ["info", "low", "medium", "high", "critical"]
            if sev in order:
                cmd += ["-severity", ",".join(order[order.index(sev):])]

        tags = str(options.get("tags", "")).strip()
        if tags:
            cmd += ["-tags", tags]

        return cmd

    def parse_line(self, line: str) -> list[dict]:
        line = line.strip()
        if not line.startswith("{"):
            return []
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return []

        info = obj.get("info", {})
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []
        cve = cve_ids[0].upper() if cve_ids else None

        return [{
            "name": info.get("name", obj.get("template-id", "nuclei match")),
            "severity": (info.get("severity") or "info").lower(),
            "cve": cve,
            "port": obj.get("port"),
            "description": info.get("description", "") or "",
            "evidence": obj.get("matched-at") or obj.get("host", ""),
        }]
