"""
sentinel/api/app.py

FastAPI application — REST endpoints + WebSocket live feed.

Endpoints:
    GET  /                    → Dashboard
    GET  /devices             → Devices page
    GET  /events              → Events page
    GET  /dns                 → DNS page
    GET  /api/stats           → JSON stats
    GET  /api/devices         → JSON devices
    GET  /api/events          → JSON events
    GET  /api/dns             → JSON DNS queries
    POST /api/devices/{ip}/flag  → Flag/unflag a device
    WS   /ws/events           → Live event stream
"""

import asyncio
import json
import time
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from sentinel.core.database import Database
from sentinel.core.event_bus import EventBus, Event, EventType

log = logging.getLogger("sentinel.api")

TEMPLATES_DIR = Path(__file__).parent / "templates"
templates     = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Shared state injected by main.py at startup
_db:  Optional[Database] = None
_bus: Optional[EventBus] = None


def init(db: Database, bus: EventBus) -> None:
    global _db, _bus
    _db  = db
    _bus = bus


app = FastAPI(title="Sentinel", version="0.1.0")


# ------------------------------------------------------------------ #
#  WebSocket manager                                                   #
# ------------------------------------------------------------------ #

class ConnectionManager:
    def __init__(self):
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.append(ws)
        log.info("WS client connected (%d total)", len(self._clients))

    def disconnect(self, ws: WebSocket) -> None:
        self._clients.remove(ws)
        log.info("WS client disconnected (%d total)", len(self._clients))

    async def broadcast(self, data: dict) -> None:
        dead = []
        for ws in self._clients:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._clients.remove(ws)

    @property
    def count(self) -> int:
        return len(self._clients)


manager = ConnectionManager()


# ------------------------------------------------------------------ #
#  Background task: bus → WebSocket broadcast                         #
# ------------------------------------------------------------------ #

async def event_broadcaster() -> None:
    """Subscribes to EventBus and broadcasts events to all WS clients."""
    if not _bus:
        return
    async with _bus.subscribe(min_severity="info") as sub:
        async for event in sub:
            if manager.count == 0:
                continue
            # Skip raw packet spam — only notable events
            if event.type == EventType.PACKET_CAPTURED and event.severity == "info":
                continue
            await manager.broadcast({
                "type":      event.type.value,
                "severity":  event.severity,
                "source":    event.source,
                "timestamp": event.timestamp,
                "data":      event.data,
            })


# ------------------------------------------------------------------ #
#  HTML pages                                                          #
# ------------------------------------------------------------------ #

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    stats = await _db.stats() if _db else {}
    return templates.TemplateResponse(request, "index.html", {"stats": stats, "title": "Dashboard"})


@app.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request):
    devices = await _db.query_devices() if _db else []
    return templates.TemplateResponse(request, "devices.html", {"devices": devices, "title": "Devices"})


@app.get("/events", response_class=HTMLResponse)
async def events_page(request: Request, severity: Optional[str] = None):
    events = await _db.query_events(severity=severity, limit=100) if _db else []
    return templates.TemplateResponse(request, "events.html", {"events": events, "severity": severity, "title": "Events"})


@app.get("/dns", response_class=HTMLResponse)
async def dns_page(request: Request, blocked: bool = False):
    rows = await _db.query_dns(blocked_only=blocked, limit=100) if _db else []
    return templates.TemplateResponse(request, "dns.html", {"queries": rows, "blocked": blocked, "title": "DNS"})


# ------------------------------------------------------------------ #
#  REST API                                                            #
# ------------------------------------------------------------------ #

@app.get("/api/stats")
async def api_stats():
    return await _db.stats() if _db else {}


@app.get("/api/devices")
async def api_devices(flagged: bool = False):
    return await _db.query_devices(flagged_only=flagged) if _db else []


@app.get("/api/events")
async def api_events(
    severity:   Optional[str] = None,
    event_type: Optional[str] = Query(None, alias="type"),
    limit:      int = 100,
):
    return await _db.query_events(severity=severity, event_type=event_type, limit=limit) if _db else []


@app.get("/api/dns")
async def api_dns(blocked: bool = False, limit: int = 100):
    return await _db.query_dns(blocked_only=blocked, limit=limit) if _db else []


@app.post("/api/devices/{ip}/flag")
async def flag_device(ip: str, flagged: bool = True):
    if _db:
        await _db.flag_device(ip, flagged)
    return {"ip": ip, "flagged": flagged}


# ------------------------------------------------------------------ #
#  WebSocket                                                           #
# ------------------------------------------------------------------ #

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            # Keep connection alive — client sends ping
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ------------------------------------------------------------------ #
#  HTMX partials — for live-refresh without full page reload          #
# ------------------------------------------------------------------ #

@app.get("/htmx/stats", response_class=HTMLResponse)
async def htmx_stats(request: Request):
    stats = await _db.stats() if _db else {}
    return templates.TemplateResponse(request, "partials/stats.html", {"stats": stats})


@app.get("/htmx/alerts", response_class=HTMLResponse)
async def htmx_alerts(request: Request):
    events = await _db.query_events(severity="warning", limit=10) if _db else []
    critical = await _db.query_events(severity="critical", limit=10) if _db else []
    return templates.TemplateResponse(request, "partials/alerts.html", {"alerts": critical + events})


@app.get("/htmx/devices", response_class=HTMLResponse)
async def htmx_devices(request: Request):
    devices = await _db.query_devices() if _db else []
    return templates.TemplateResponse(request, "partials/devices.html", {"devices": devices[:10]})