"""The add-on contract.

Every integrated tool is a subclass of BasePlugin. To add a pentesting tool
to the console you implement, at minimum:

  - build_command(target, options)  -> argv list to execute, and
  - parse_line(line) and/or finalize(lines, target) -> structured findings.

The scan manager handles process spawning, realtime streaming, cancellation
and persistence, so a plugin only describes *how to invoke a tool* and *how to
read its output*. Drop the file in this package and it self-registers.
"""
from __future__ import annotations

import shutil
from abc import ABC
from typing import Any, Awaitable, Callable


class RunContext:
    """Handed to simulated plugins so they can push output and findings."""

    def __init__(self, scan, emit_log: Callable[[str], Awaitable], emit_finding):
        self.scan = scan
        self.target = scan.target
        self.options = scan.options
        self._emit_log = emit_log
        self._emit_finding = emit_finding

    async def log(self, line: str) -> None:
        await self._emit_log(line)

    async def finding(self, **data: Any) -> None:
        await self._emit_finding(data)


class BasePlugin(ABC):
    # Identity — override these in every plugin.
    slug: str = ""
    name: str = ""
    description: str = ""
    category: str = "General"

    # Name of the executable this plugin drives (checked on $PATH). Leave as
    # None for plugins that don't shell out (e.g. the built-in demo).
    binary: str | None = None

    # True for plugins that generate their own output instead of running a
    # binary. Such plugins implement simulate() instead of build_command().
    simulated: bool = False

    # Declarative options rendered as form controls in the UI. Each entry:
    #   {"key", "label", "type": text|number|select|checkbox, "default", "choices"?}
    options_schema: list[dict] = []

    # ------------------------------------------------------------------ meta
    def is_available(self) -> bool:
        if self.simulated:
            return True
        if not self.binary:
            return True
        return shutil.which(self.binary) is not None

    def describe(self) -> dict:
        return {
            "slug": self.slug,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "binary": self.binary,
            "available": self.is_available(),
            "simulated": self.simulated,
            "options_schema": self.options_schema,
        }

    # ------------------------------------------------------------- execution
    def build_command(self, target: str, options: dict) -> list[str]:
        """Return the argv to execute. Override for real tools."""
        raise NotImplementedError(f"{self.slug} does not define build_command")

    def parse_line(self, line: str) -> list[dict]:
        """Parse a single streamed output line into zero or more findings.

        Use this for tools that report findings incrementally (e.g. nuclei).
        Return a list of finding dicts: {name, severity, cve?, port?,
        description?, evidence?}.
        """
        return []

    def finalize(self, lines: list[str], target: str) -> list[dict]:
        """Parse the complete captured output once the tool exits.

        Use this for tools whose results are only parseable as a whole
        (e.g. nmap producing structured output at the end).
        """
        return []

    async def simulate(self, ctx: RunContext) -> None:
        """Full-control execution for simulated plugins (no subprocess)."""
        raise NotImplementedError(f"{self.slug} is not a simulated plugin")
