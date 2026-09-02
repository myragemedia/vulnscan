"""Data schemas and a small SQLite-backed store for scans and findings."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from config import DB_PATH, SEVERITY_ORDER


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex[:12]


# ----------------------------------------------------------------------------
# API schemas
# ----------------------------------------------------------------------------
class ScanRequest(BaseModel):
    plugin: str = Field(..., description="Slug of the tool plugin to run")
    target: str = Field(..., description="Host, IP, CIDR or URL to assess")
    options: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    scan_id: str
    target: str
    name: str
    severity: str = "info"
    cve: Optional[str] = None
    port: Optional[str] = None
    description: str = ""
    evidence: str = ""
    created_at: str


class Scan(BaseModel):
    id: str
    plugin: str
    target: str
    options: dict[str, Any] = Field(default_factory=dict)
    status: str = "queued"  # queued | running | completed | failed | cancelled
    exit_code: Optional[int] = None
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    findings_count: int = 0


# ----------------------------------------------------------------------------
# Store
# ----------------------------------------------------------------------------
class Store:
    """Thread-safe SQLite wrapper. Simple by design — swap for Postgres later."""

    def __init__(self, path=DB_PATH):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    plugin TEXT NOT NULL,
                    target TEXT NOT NULL,
                    options TEXT NOT NULL,
                    status TEXT NOT NULL,
                    exit_code INTEGER,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cve TEXT,
                    port TEXT,
                    description TEXT,
                    evidence TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );
                """
            )
            self._conn.commit()

    # -- scans ---------------------------------------------------------------
    def create_scan(self, plugin: str, target: str, options: dict) -> Scan:
        scan = Scan(
            id=new_id(),
            plugin=plugin,
            target=target,
            options=options,
            status="queued",
            created_at=now_iso(),
        )
        with self._lock:
            self._conn.execute(
                "INSERT INTO scans (id, plugin, target, options, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (scan.id, plugin, target, json.dumps(options), scan.status, scan.created_at),
            )
            self._conn.commit()
        return scan

    def update_scan(self, scan_id: str, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self._lock:
            self._conn.execute(
                f"UPDATE scans SET {cols} WHERE id = ?",
                (*fields.values(), scan_id),
            )
            self._conn.commit()

    def get_scan(self, scan_id: str) -> Optional[Scan]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            count = self._conn.execute(
                "SELECT COUNT(*) c FROM findings WHERE scan_id = ?", (scan_id,)
            ).fetchone()["c"]
        return self._row_to_scan(row, count) if row else None

    def list_scans(self, limit: int = 100) -> list[Scan]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT s.*, (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) fc "
                "FROM scans s ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_scan(r, r["fc"]) for r in rows]

    # -- findings ------------------------------------------------------------
    def add_finding(self, scan_id: str, target: str, data: dict) -> Finding:
        finding = Finding(
            id=new_id(),
            scan_id=scan_id,
            target=target,
            name=data.get("name", "Unnamed finding"),
            severity=data.get("severity", "info").lower(),
            cve=data.get("cve"),
            port=data.get("port"),
            description=data.get("description", ""),
            evidence=data.get("evidence", ""),
            created_at=now_iso(),
        )
        with self._lock:
            self._conn.execute(
                "INSERT INTO findings (id, scan_id, target, name, severity, cve, port, "
                "description, evidence, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    finding.id, scan_id, target, finding.name, finding.severity,
                    finding.cve, finding.port, finding.description, finding.evidence,
                    finding.created_at,
                ),
            )
            self._conn.commit()
        return finding

    def list_findings(self, scan_id: Optional[str] = None) -> list[Finding]:
        query = "SELECT * FROM findings"
        params: tuple = ()
        if scan_id:
            query += " WHERE scan_id = ?"
            params = (scan_id,)
        with self._lock:
            rows = self._conn.execute(query, params).fetchall()
        findings = [Finding(**dict(r)) for r in rows]
        findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity)
                      if f.severity in SEVERITY_ORDER else len(SEVERITY_ORDER))
        return findings

    def severity_counts(self, scan_id: Optional[str] = None) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.list_findings(scan_id):
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _row_to_scan(self, row: sqlite3.Row, findings_count: int = 0) -> Scan:
        return Scan(
            id=row["id"],
            plugin=row["plugin"],
            target=row["target"],
            options=json.loads(row["options"]),
            status=row["status"],
            exit_code=row["exit_code"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            findings_count=findings_count,
        )


store = Store()
