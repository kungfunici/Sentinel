"""
sentinel/core/database.py

Async SQLite storage for all Sentinel events.

Tables:
    events      — every event from the bus
    dns_queries — parsed DNS detail (query name, type, blocked?)
    packets     — lightweight packet summary (src, dst, proto, size)
    devices     — discovered hosts on the network

Usage:
    db = Database("sentinel.db")
    await db.setup()
    await db.write_event(event)
    rows = await db.query_events(severity="critical", limit=50)
"""

import json
import time
import aiosqlite
from pathlib import Path
from typing import Optional

from sentinel.core.event_bus import Event, EventType


DDL = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT    NOT NULL,
    severity    TEXT    NOT NULL DEFAULT 'info',
    source      TEXT    NOT NULL DEFAULT 'unknown',
    data        TEXT    NOT NULL,           -- JSON blob
    timestamp   REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

CREATE TABLE IF NOT EXISTS dns_queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER REFERENCES events(id) ON DELETE CASCADE,
    src_ip      TEXT    NOT NULL,
    query_name  TEXT    NOT NULL,
    query_type  TEXT    NOT NULL DEFAULT 'A',
    blocked     INTEGER NOT NULL DEFAULT 0,  -- boolean
    timestamp   REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dns_name    ON dns_queries(query_name);
CREATE INDEX IF NOT EXISTS idx_dns_blocked ON dns_queries(blocked);

CREATE TABLE IF NOT EXISTS packets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER REFERENCES events(id) ON DELETE CASCADE,
    src_ip      TEXT,
    dst_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    size        INTEGER,
    flags       TEXT,
    timestamp   REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip);

CREATE TABLE IF NOT EXISTS devices (
    ip          TEXT    PRIMARY KEY,
    mac         TEXT,
    hostname    TEXT,
    vendor      TEXT,
    first_seen  REAL    NOT NULL,
    last_seen   REAL    NOT NULL,
    flagged     INTEGER NOT NULL DEFAULT 0
);
"""


class Database:
    def __init__(self, db_path: str | Path = "sentinel.db"):
        self.path = Path(db_path)
        self._conn: Optional[aiosqlite.Connection] = None

    async def setup(self) -> None:
        """Open connection and apply schema."""
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(DDL)
        await self._conn.commit()

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def __aenter__(self):
        await self.setup()
        return self

    async def __aexit__(self, *_):
        await self.close()

    # ------------------------------------------------------------------ #
    #  Write                                                               #
    # ------------------------------------------------------------------ #

    async def write_event(self, event: Event) -> int:
        """
        Persist an Event. Returns the new row id.
        Also calls the appropriate detail-writer based on event type.
        """
        assert self._conn, "Database not initialised — call setup() first"

        cursor = await self._conn.execute(
            """
            INSERT INTO events (type, severity, source, data, timestamp)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event.type.value,
                event.severity,
                event.source,
                json.dumps(event.data),
                event.timestamp,
            ),
        )
        event_id = cursor.lastrowid

        if event.type == EventType.DNS_QUERY:
            await self._write_dns(event_id, event)
        elif event.type == EventType.DNS_BLOCKED:
            await self._write_dns(event_id, event, blocked=True)
        elif event.type == EventType.PACKET_CAPTURED:
            await self._write_packet(event_id, event)
        elif event.type == EventType.NEW_DEVICE:
            await self._upsert_device(event)

        await self._conn.commit()
        return event_id

    async def _write_dns(self, event_id: int, event: Event, blocked: bool = False) -> None:
        d = event.data
        await self._conn.execute(
            """
            INSERT INTO dns_queries (event_id, src_ip, query_name, query_type, blocked, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                d.get("src_ip", ""),
                d.get("query_name", ""),
                d.get("query_type", "A"),
                int(blocked or d.get("blocked", False)),
                event.timestamp,
            ),
        )

    async def _write_packet(self, event_id: int, event: Event) -> None:
        d = event.data
        await self._conn.execute(
            """
            INSERT INTO packets
                (event_id, src_ip, dst_ip, src_port, dst_port, protocol, size, flags, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                d.get("src_ip"),
                d.get("dst_ip"),
                d.get("src_port"),
                d.get("dst_port"),
                d.get("protocol"),
                d.get("size"),
                d.get("flags"),
                event.timestamp,
            ),
        )

    async def _upsert_device(self, event: Event) -> None:
        d = event.data
        now = event.timestamp
        await self._conn.execute(
            """
            INSERT INTO devices (ip, mac, hostname, vendor, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen = excluded.last_seen,
                mac       = COALESCE(excluded.mac, mac),
                hostname  = COALESCE(excluded.hostname, hostname),
                vendor    = COALESCE(excluded.vendor, vendor)
            """,
            (
                d.get("ip", ""),
                d.get("mac"),
                d.get("hostname"),
                d.get("vendor"),
                now,
                now,
            ),
        )

    # ------------------------------------------------------------------ #
    #  Read                                                                #
    # ------------------------------------------------------------------ #

    async def query_events(
        self,
        severity:  Optional[str] = None,
        event_type: Optional[str] = None,
        since:     Optional[float] = None,
        limit:     int = 100,
    ) -> list[dict]:
        assert self._conn
        clauses, params = [], []

        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if event_type:
            clauses.append("type = ?")
            params.append(event_type)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        rows = await self._conn.execute_fetchall(
            f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        )
        return [dict(r) for r in rows]

    async def query_dns(
        self,
        blocked_only: bool = False,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> list[dict]:
        assert self._conn
        clauses, params = [], []
        if blocked_only:
            clauses.append("blocked = 1")
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = await self._conn.execute_fetchall(
            f"SELECT * FROM dns_queries {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        )
        return [dict(r) for r in rows]

    async def query_devices(self, flagged_only: bool = False) -> list[dict]:
        assert self._conn
        where = "WHERE flagged = 1" if flagged_only else ""
        rows = await self._conn.execute_fetchall(
            f"SELECT * FROM devices {where} ORDER BY last_seen DESC"
        )
        return [dict(r) for r in rows]

    async def stats(self) -> dict:
        assert self._conn
        tables = ["events", "dns_queries", "packets", "devices"]
        result = {}
        for t in tables:
            row = await self._conn.execute_fetchall(f"SELECT COUNT(*) as n FROM {t}")
            result[t] = row[0]["n"]
        blocked = await self._conn.execute_fetchall(
            "SELECT COUNT(*) as n FROM dns_queries WHERE blocked=1"
        )
        result["dns_blocked"] = blocked[0]["n"]
        return result

    async def cleanup_old_events(self, retention_days: int) -> dict:
        cutoff = time.time() - (retention_days * 86400)
        result = {}
        for table in ("events", "dns_queries", "packets"):
            cursor = await self._conn.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff,))
            result[table] = cursor.rowcount
        await self._conn.commit()
        return result

    async def flag_device(self, ip: str, flagged: bool = True) -> None:
        assert self._conn
        await self._conn.execute(
            "UPDATE devices SET flagged = ? WHERE ip = ?",
            (int(flagged), ip),
        )
        await self._conn.commit()