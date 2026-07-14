import asyncio
import logging
import re
import time
from pathlib import Path
from typing import Optional

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.http")

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "account", "verify", "password",
    "paypal", "banking", "secure", "update", "confirm",
]

SUSPICIOUS_UA = [
    "curl", "wget", "python-requests", "go-http-client",
    "nikto", "nmap", "sqlmap", "masscan", "zgrab",
]

DEFAULT_WHITELIST: list[str] = [
    "*.windowsupdate.com",
    "*.microsoft.com",
    "*.office.com",
    "*.office.net",
]


def _match_whitelist(host: str, patterns: list[str]) -> bool:
    for p in patterns:
        if p.startswith("*.") and host.endswith(p[1:]):
            return True
        if host == p:
            return True
    return False


class HttpMonitor:
    def __init__(
        self,
        bus: EventBus,
        iface: Optional[str] = None,
        suspicious_keywords: Optional[list[str]] = None,
        whitelist_path: Optional[Path] = None,
    ):
        self.bus = bus
        self.iface = iface
        self._suspicious_keywords = suspicious_keywords or SUSPICIOUS_KEYWORDS
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._total_requests = 0
        self._whitelist_path = whitelist_path
        self._whitelist_mtime: float = 0.0
        self._whitelist_patterns = self._load_whitelist(whitelist_path)

    def _load_whitelist(self, path: Optional[Path]) -> list[str]:
        if not path:
            return list(DEFAULT_WHITELIST)
        try:
            mtime = path.stat().st_mtime if path.exists() else 0
            if mtime == self._whitelist_mtime:
                return self._whitelist_patterns
            patterns = list(DEFAULT_WHITELIST)
            if path.exists():
                lines = path.read_text(encoding="utf-8").splitlines()
                for l in lines:
                    l = l.strip().lower()
                    if l and not l.startswith("#") and l not in patterns:
                        patterns.append(l)
            self._whitelist_mtime = mtime
            log.info("Whitelist loaded: %d patterns (%d from file %s)", len(patterns), len(patterns) - len(DEFAULT_WHITELIST), path)
            return patterns
        except Exception as e:
            log.warning("Failed to load whitelist %s: %s", path, e)
            return list(DEFAULT_WHITELIST)

    async def _whitelist_reload_loop(self) -> None:
        while self._running:
            await asyncio.sleep(30)
            if self._whitelist_path:
                self._whitelist_patterns = self._load_whitelist(self._whitelist_path)

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._running = True
        if self._whitelist_path:
            asyncio.create_task(self._whitelist_reload_loop())
        log.info("HTTP monitor starting")
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter="tcp port 80",
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

    async def stop(self) -> None:
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
        log.info("HTTP monitor stopped. total_requests=%d", self._total_requests)

    def _on_packet(self, pkt) -> None:
        if not self._running:
            return
        try:
            ev = self._parse(pkt)
            if ev:
                asyncio.run_coroutine_threadsafe(self.bus.publish(ev), self._loop)
        except Exception as exc:
            log.debug("HTTP parse error: %s", exc)

    def _parse(self, pkt) -> Optional[Event]:
        if TCP not in pkt or IP not in pkt or Raw not in pkt:
            return None

        ip = pkt[IP]
        tcp = pkt[TCP]
        src_ip = ip.src
        dst_ip = ip.dst
        dst_port = tcp.dport

        if dst_port != 80:
            return None

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            return None

        if not payload:
            return None

        first_line = payload.split("\r\n")[0]
        match = re.match(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/(\d+\.\d+)", first_line)
        if not match:
            return None

        method = match.group(1)
        path = match.group(2)
        http_ver = match.group(3)

        headers = {}
        for line in payload.split("\r\n")[1:]:
            if ": " in line:
                key, val = line.split(": ", 1)
                headers[key.lower()] = val

        host = headers.get("host", dst_ip)
        ua = headers.get("user-agent", "unknown")
        referer = headers.get("referer", "")

        self._total_requests += 1
        now = time.time()
        severity = "info"
        flags: list[str] = []

        path_lower = path.lower()
        if not _match_whitelist(host, self._whitelist_patterns):
            for kw in self._suspicious_keywords:
                if kw in path_lower:
                    flags.append(f"keyword:{kw}")
        if referer and host not in referer and referer != "":
            flags.append("cross_origin_referer")
        if any(bot in ua.lower() for bot in SUSPICIOUS_UA):
            flags.append("suspicious_ua")
            severity = "warning"

        url = f"http://{host}{path}"
        if flags:
            severity = "warning"
            log.warning("HTTP [%s] %s %s — %s", severity, method, url, ", ".join(flags))

        return Event(
            type=EventType.HTTP_REQUEST,
            severity=severity,
            source="http_monitor",
            timestamp=now,
            data={
                "method": method,
                "url": url,
                "host": host,
                "path": path,
                "user_agent": ua,
                "referer": referer,
                "src_ip": src_ip,
                "flags": flags,
                "description": f"{method} {url} from {src_ip} [{', '.join(flags) or 'ok'}]",
            },
        )