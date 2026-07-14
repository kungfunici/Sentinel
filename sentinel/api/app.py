import time
import logging
import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, Body
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from sentinel.core.database import Database
from sentinel.core.event_bus import EventBus, EventType

log = logging.getLogger("sentinel.api")

_db:             Optional[Database] = None
_bus:            Optional[EventBus] = None
_blocklist_path: Optional[Path] = None
_whitelist_path: Optional[Path] = None


def init(db: Database, bus: EventBus, blocklist_path: Optional[Path] = None, whitelist_path: Optional[Path] = None) -> None:
    global _db, _bus, _blocklist_path, _whitelist_path
    _db  = db
    _bus = bus
    _blocklist_path = blocklist_path
    _whitelist_path = whitelist_path


app = FastAPI(title="Sentinel", version="0.1.0")


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


async def event_broadcaster() -> None:
    if not _bus:
        return
    async with _bus.subscribe(min_severity="info") as sub:
        async for event in sub:
            if manager.count == 0:
                continue
            if event.type == EventType.PACKET_CAPTURED and event.severity == "info":
                continue
            await manager.broadcast({
                "type":      event.type.value,
                "severity":  event.severity,
                "source":    event.source,
                "timestamp": event.timestamp,
                "data":      event.data,
            })


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


@app.get("/api/topology")
async def api_topology():
    devices = await _db.query_devices() if _db else []
    connections = []
    if _db:
        rows = await _db._conn.execute_fetchall(
            "SELECT src_ip, dst_ip, COUNT(*) as count FROM packets GROUP BY src_ip, dst_ip ORDER BY count DESC LIMIT 200"
        )
        connections = [dict(r) for r in rows]

    gateway_ip = None
    ip_connections = {}
    for c in connections:
        ip_connections[c["src_ip"]] = ip_connections.get(c["src_ip"], 0) + c["count"]
        ip_connections[c["dst_ip"]] = ip_connections.get(c["dst_ip"], 0) + c["count"]
    if ip_connections:
        gateway_ip = max(ip_connections, key=ip_connections.get)

    device_list = []
    for d in devices:
        device_list.append({
            "ip": d["ip"],
            "mac": d.get("mac"),
            "hostname": d.get("hostname"),
            "vendor": d.get("vendor"),
            "flagged": bool(d["flagged"]),
            "is_gateway": d["ip"] == gateway_ip,
        })

    return {"devices": device_list, "connections": connections}


@app.post("/api/devices/{ip}/flag")
async def flag_device(ip: str, flagged: bool = True):
    if _db:
        await _db.flag_device(ip, flagged)
    return {"ip": ip, "flagged": flagged}


@app.get("/api/blocklist")
async def api_blocklist():
    if not _blocklist_path or not _blocklist_path.exists():
        return {"domains": []}
    try:
        lines = _blocklist_path.read_text(encoding="utf-8").splitlines()
        domains = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        return {"domains": domains}
    except Exception as e:
        log.warning("Failed to read blocklist: %s", e)
        return {"domains": []}


@app.post("/api/blocklist")
async def api_blocklist_add(domain: str = Body(..., embed=True)):
    if not _blocklist_path:
        return {"error": "No blocklist file configured"}, 400
    domain = domain.strip().lower()
    if not domain or domain in (".", "*"):
        return {"error": "Invalid domain"}, 400
    try:
        with open(_blocklist_path, "a", encoding="utf-8") as f:
            f.write(domain + "\n")
        log.info("Blocklist: added %s", domain)
        return {"added": domain}
    except OSError as e:
        return {"error": str(e)}, 500


@app.delete("/api/blocklist")
async def api_blocklist_remove(domain: str = Query(...)):
    if not _blocklist_path or not _blocklist_path.exists():
        return {"error": "No blocklist file"}, 400
    try:
        lines = _blocklist_path.read_text(encoding="utf-8").splitlines()
        filtered = [l for l in lines if l.strip().lower() != domain.strip().lower()]
        _blocklist_path.write_text("\n".join(filtered) + "\n", encoding="utf-8")
        log.info("Blocklist: removed %s", domain)
        return {"removed": domain}
    except Exception as e:
        return {"error": str(e)}, 500


@app.get("/api/whitelist")
async def api_whitelist():
    if not _whitelist_path or not _whitelist_path.exists():
        return {"patterns": []}
    try:
        lines = _whitelist_path.read_text(encoding="utf-8").splitlines()
        patterns = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        return {"patterns": patterns}
    except Exception as e:
        log.warning("Failed to read whitelist: %s", e)
        return {"patterns": []}


@app.post("/api/whitelist")
async def api_whitelist_add(pattern: str = Body(..., embed=True)):
    if not _whitelist_path:
        return {"error": "No whitelist file configured"}, 400
    p = pattern.strip().lower()
    if not p:
        return {"error": "Invalid pattern"}, 400
    _whitelist_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(_whitelist_path, "a", encoding="utf-8") as f:
            f.write(p + "\n")
        log.info("Whitelist: added %s", p)
        return {"added": p}
    except OSError as e:
        return {"error": str(e)}, 500


@app.delete("/api/whitelist")
async def api_whitelist_remove(pattern: str = Query(...)):
    if not _whitelist_path or not _whitelist_path.exists():
        return {"error": "No whitelist file"}, 400
    try:
        lines = _whitelist_path.read_text(encoding="utf-8").splitlines()
        filtered = [l for l in lines if l.strip().lower() != pattern.strip().lower()]
        _whitelist_path.write_text("\n".join(filtered) + "\n", encoding="utf-8")
        log.info("Whitelist: removed %s", pattern)
        return {"removed": pattern}
    except Exception as e:
        return {"error": str(e)}, 500


@app.get("/api/events/{id}/detail")
async def api_event_detail(id: int):
    if not _db:
        return {}
    rows = await _db.query_events(limit=1)
    for r in rows:
        if r["id"] == id:
            return {"detail": _fmt_event_description(r)}
    return {}


def _fmt_event_description(row: dict) -> str:
    try:
        d = json.loads(row["data"]) if isinstance(row["data"], str) else row["data"]
    except Exception:
        d = row.get("data", {})
    ev_type = row.get("type", "")
    if ev_type == "packet.captured":
        flags = f" [{d.get('flags', '')}]" if d.get("flags") else ""
        port = f":{d['dst_port']}" if d.get("dst_port") else ""
        return f"{d.get('src_ip','?')} -> {d.get('dst_ip','?')}{port} {d.get('protocol','')}{flags}"
    if ev_type in ("dns.query", "dns.blocked"):
        blocked = " [BLOCKED]" if d.get("blocked") else ""
        return f"{d.get('src_ip','?')} queried {d.get('query_name','?')} ({d.get('query_type','')}){blocked}"
    if ev_type == "device.new":
        mac = f" mac={d['mac']}" if d.get("mac") else ""
        return f"New device: {d.get('ip','?')}{mac}"
    if ev_type == "tls.handshake":
        return f"TLS {d.get('src_ip','?')} -> {d.get('dst_ip','?')} SNI={d.get('sni','?')}"
    if ev_type == "http.request":
        return d.get("description", "")
    if ev_type == "dns.anomaly":
        return d.get("description", "")
    if ev_type == "arp.anomaly":
        return d.get("description", "")
    if ev_type == "dhcp.anomaly":
        return d.get("description", "")
    if ev_type == "icmp.anomaly":
        return d.get("description", "")
    if ev_type == "port.scan_result":
        return d.get("description", "")
    if ev_type == "bandwidth.report":
        return d.get("description", "")
    return str(d)[:120]


def fmt_data(raw: str) -> str:
    try:
        d = json.loads(raw)
        if "src_ip" in d and "dst_ip" in d and "sni" in d:
            return f"TLS {d['src_ip']} -> {d['dst_ip']} SNI={d['sni']}"
        if "src_ip" in d and "dst_ip" in d:
            port  = f":{d['dst_port']}" if d.get("dst_port") else ""
            flags = f" [{d['flags']}]" if d.get("flags") else ""
            return f"{d['src_ip']} -> {d['dst_ip']}{port} {d.get('protocol','')}{flags}"
        if "query_name" in d:
            blocked = " [BLOCKED]" if d.get("blocked") else ""
            return f"{d.get('src_ip','?')} queried {d['query_name']} ({d.get('query_type','')}){blocked}"
        if "ip" in d and "mac" in d:
            return f"New device: ip={d['ip']} mac={d.get('mac','?')}"
        if "description" in d:
            return d["description"]
        return json.dumps(d)[:120]
    except Exception:
        return raw[:120]


@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ------------------------------------------------------------------
#  Frontend (SPA) — serve built Vite app from frontend/dist/
# ------------------------------------------------------------------
_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if _FRONTEND_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(_FRONTEND_DIR / "assets")), name="frontend-assets")

    @app.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
    async def serve_frontend(full_path: str):
        if full_path.startswith(("api/", "ws/", "htmx/")):
            from fastapi.responses import JSONResponse
            return JSONResponse({"error": "Not found"}, status_code=404)
        index = _FRONTEND_DIR / "index.html"
        if index.exists():
            return HTMLResponse(index.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>Frontend not built — run `cd frontend && npm run build`</h1>", status_code=200)
else:
    log.info("Frontend build not found at %s — API-only mode", _FRONTEND_DIR)