"""Scan orchestration.

Runs a plugin against a target, streams its output to the event hub in real
time, extracts findings, and persists everything for reporting. Handles both
subprocess-backed tools and simulated plugins through one code path.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

import plugins
from config import ALLOW_EXTERNAL, MAX_CONCURRENT_SCANS, PRIVATE_CIDRS
from models import Scan, now_iso, store
from plugins.base import RunContext
from ws import hub


class AuthorizationError(Exception):
    """Raised when a target is outside the permitted assessment scope."""


def _extract_host(target: str) -> str:
    target = target.strip()
    if "://" in target:
        return urlparse(target).hostname or target
    # strip any :port suffix for bare host:port
    if target.count(":") == 1 and "/" not in target:
        return target.split(":")[0]
    return target


def _in_scope(target: str) -> bool:
    """Guard rail: only assess private/internal ranges unless explicitly allowed."""
    if ALLOW_EXTERNAL:
        return True
    host = _extract_host(target)

    # A bare CIDR is in scope if it sits within a permitted range.
    try:
        net = ipaddress.ip_network(host, strict=False)
        return any(net.subnet_of(ipaddress.ip_network(c)) for c in PRIVATE_CIDRS)
    except ValueError:
        pass

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (socket.gaierror, ValueError):
            return False

    return any(ip in ipaddress.ip_network(c) for c in PRIVATE_CIDRS)


class ScanManager:
    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task] = {}
        self._procs: dict[str, asyncio.subprocess.Process] = {}
        self._sem = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

    # -------------------------------------------------------------- lifecycle
    def start(self, plugin_slug: str, target: str, options: dict) -> Scan:
        plugin = plugins.get(plugin_slug)
        if plugin is None:
            raise ValueError(f"Unknown plugin: {plugin_slug}")
        if not plugin.is_available():
            raise ValueError(f"{plugin.name} is not installed on this host "
                             f"(missing binary: {plugin.binary}).")
        if not _in_scope(target):
            raise AuthorizationError(
                f"Target '{target}' is outside the permitted scope. Only "
                f"internal ranges are allowed unless ALLOW_EXTERNAL is set. "
                f"Only assess systems you are authorised to test."
            )

        scan = store.create_scan(plugin_slug, target, options)
        task = asyncio.create_task(self._run(scan, plugin))
        self._tasks[scan.id] = task
        return scan

    async def cancel(self, scan_id: str) -> bool:
        proc = self._procs.get(scan_id)
        if proc and proc.returncode is None:
            proc.terminate()
        task = self._tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    # ------------------------------------------------------------------- core
    async def _run(self, scan: Scan, plugin) -> None:
        async with self._sem:
            captured: list[str] = []

            async def emit_log(line: str) -> None:
                captured.append(line)
                await hub.emit("log", scan.id, line=line)

            async def emit_finding(data: dict) -> None:
                f = store.add_finding(scan.id, scan.target, data)
                await hub.emit("finding", scan.id, finding=f.model_dump())

            store.update_scan(scan.id, status="running", started_at=now_iso())
            await hub.emit("status", scan.id, status="running",
                           plugin=plugin.name, target=scan.target)

            exit_code = 0
            try:
                if plugin.simulated:
                    ctx = RunContext(scan, emit_log, emit_finding)
                    await plugin.simulate(ctx)
                else:
                    exit_code = await self._run_subprocess(
                        scan, plugin, captured, emit_log, emit_finding
                    )
                status = "completed"
            except asyncio.CancelledError:
                status = "cancelled"
                await emit_log("Scan cancelled by operator.")
            except Exception as exc:  # noqa: BLE001 — surface any tool failure
                status = "failed"
                exit_code = 1
                await emit_log(f"Scan error: {exc}")
            finally:
                self._procs.pop(scan.id, None)
                self._tasks.pop(scan.id, None)

            store.update_scan(scan.id, status=status, exit_code=exit_code,
                              finished_at=now_iso())
            counts = store.severity_counts(scan.id)
            await hub.emit("status", scan.id, status=status,
                           exit_code=exit_code, counts=counts)

    async def _run_subprocess(self, scan, plugin, captured, emit_log, emit_finding) -> int:
        cmd = plugin.build_command(scan.target, scan.options)
        await emit_log(f"$ {' '.join(cmd)}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self._procs[scan.id] = proc

        assert proc.stdout is not None
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").rstrip("\n")
            if not line:
                continue
            await emit_log(line)
            for finding in plugin.parse_line(line):
                await emit_finding(finding)

        await proc.wait()

        for finding in plugin.finalize(captured, scan.target):
            await emit_finding(finding)

        return proc.returncode or 0


manager = ScanManager()
