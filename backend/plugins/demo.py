"""A self-contained demo scanner.

Requires no external binary — it streams realistic-looking output and emits a
spread of findings so you can exercise the realtime console and reporting
before installing real tools. Use it as a reference for the plugin contract.
"""
from __future__ import annotations

import asyncio
import random

from .base import BasePlugin, RunContext


class DemoPlugin(BasePlugin):
    slug = "demo"
    name = "Demo Scanner"
    description = "Simulated scan for testing the console. No binary required."
    category = "Demo"
    simulated = True

    options_schema = [
        {"key": "intensity", "label": "Intensity", "type": "select",
         "default": "normal", "choices": ["quick", "normal", "thorough"]},
    ]

    _CATALOGUE = [
        ("critical", "CVE-2021-44228", "Log4Shell RCE in Apache Log4j",
         "8080", "JNDI lookup string reflected in HTTP response headers."),
        ("high", "CVE-2017-0144", "SMB Remote Code Execution (EternalBlue)",
         "445", "Host responds to SMBv1 negotiation; MS17-010 not applied."),
        ("high", "CVE-2014-0160", "OpenSSL Heartbleed information disclosure",
         "443", "TLS heartbeat returned 64KB of process memory."),
        ("medium", None, "Weak TLS cipher suites accepted",
         "443", "Server negotiates TLS_RSA_WITH_3DES_EDE_CBC_SHA."),
        ("medium", "CVE-2020-1938", "Apache Tomcat AJP Ghostcat",
         "8009", "AJP connector exposed and permits file read."),
        ("low", None, "SSH permits password authentication",
         "22", "Server advertises 'password' in auth methods."),
        ("info", None, "HTTP server banner discloses version",
         "80", "Server: nginx/1.18.0 (Ubuntu)."),
    ]

    async def simulate(self, ctx: RunContext) -> None:
        intensity = ctx.options.get("intensity", "normal")
        depth = {"quick": 3, "normal": 5, "thorough": 7}.get(intensity, 5)

        await ctx.log(f"Starting {intensity} assessment of {ctx.target}")
        await ctx.log("Resolving host and probing common ports ...")
        await asyncio.sleep(0.6)

        ports = [22, 80, 443, 445, 3306, 8080, 8009][:depth]
        for port in ports:
            await asyncio.sleep(random.uniform(0.2, 0.6))
            state = random.choice(["open", "open", "open", "filtered"])
            await ctx.log(f"  {ctx.target}:{port}/tcp  {state}")

        await ctx.log("Running vulnerability checks against discovered services ...")
        await asyncio.sleep(0.5)

        for severity, cve, name, port, evidence in self._CATALOGUE[:depth]:
            await asyncio.sleep(random.uniform(0.3, 0.9))
            label = cve or name
            await ctx.log(f"  [+] {severity.upper():<8} {label}")
            await ctx.finding(
                name=name, severity=severity, cve=cve, port=port,
                description=f"Detected on {ctx.target}:{port}.",
                evidence=evidence,
            )

        await ctx.log("Assessment complete.")
