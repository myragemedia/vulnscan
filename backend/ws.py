"""Realtime event fan-out over WebSockets.

Every scan emits typed events (log lines, findings, status changes, progress).
Clients connect once and receive the full stream; the frontend filters by
scan id. Keeping it broadcast-simple avoids per-topic subscription bookkeeping.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import WebSocket


class EventHub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def emit(self, event_type: str, scan_id: str | None = None, **payload: Any) -> None:
        message = json.dumps({"type": event_type, "scan_id": scan_id, "data": payload})
        dead: list[WebSocket] = []
        async with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)


hub = EventHub()
