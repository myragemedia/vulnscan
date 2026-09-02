"""FastAPI application — REST API, realtime WebSocket, and static frontend."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import plugins
from config import FRONTEND_DIR
from models import ScanRequest, store
from scanner import AuthorizationError, manager
from ws import hub

app = FastAPI(title="VulnScan Console", version="0.1.0")


# --------------------------------------------------------------------- API
@app.get("/api/plugins")
async def list_plugins():
    return {"plugins": plugins.catalogue()}


@app.get("/api/scans")
async def list_scans():
    return {"scans": [s.model_dump() for s in store.list_scans()]}


@app.post("/api/scans")
async def create_scan(req: ScanRequest):
    try:
        scan = manager.start(req.plugin, req.target, req.options)
    except AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return scan.model_dump()


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = store.list_findings(scan_id)
    return {
        "scan": scan.model_dump(),
        "findings": [f.model_dump() for f in findings],
        "counts": store.severity_counts(scan_id),
    }


@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    ok = await manager.cancel(scan_id)
    if not ok:
        raise HTTPException(status_code=409, detail="Scan is not running")
    return {"cancelled": True}


@app.get("/api/report")
async def report(scan_id: str | None = None):
    """CVE-oriented report payload. Groups findings and lists distinct CVEs."""
    findings = store.list_findings(scan_id)
    cves = sorted({f.cve for f in findings if f.cve})
    return {
        "scan_id": scan_id,
        "counts": store.severity_counts(scan_id),
        "cve_count": len(cves),
        "cves": cves,
        "findings": [f.model_dump() for f in findings],
    }


# --------------------------------------------------------------- WebSocket
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await hub.connect(ws)
    try:
        while True:
            # We don't require inbound messages; keep the socket alive.
            await ws.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(ws)
    except Exception:
        await hub.disconnect(ws)


# ------------------------------------------------------------------ static
@app.get("/")
async def index():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")


@app.exception_handler(404)
async def not_found(_request, _exc):
    return JSONResponse(status_code=404, content={"detail": "Not found"})
