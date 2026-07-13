import asyncio
import ipaddress
import logging
import time
from typing import Optional

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.port_scanner")

DEFAULT_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    143,
    443,
    445,
    3306,
    3389,
    5900,
    6379,
    8080,
    8443,
    9200,
    27017,
]

HIGH_RISK_PORTS = {22, 23, 3389, 5900, 445, 6379, 27017}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

CONNECT_TIMEOUT = 0.5
MAX_CONCURRENT  = 50


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


class PortScanner:
    def __init__(
        self,
        bus: EventBus,
        ports: Optional[list[int]] = None,
        interval: int = 300,
        connect_timeout: float = CONNECT_TIMEOUT,
        max_concurrent: int = MAX_CONCURRENT,
        own_ip: Optional[str] = None,
    ):
        self.bus             = bus
        self.ports           = ports or DEFAULT_PORTS
        self.interval        = interval
        self.connect_timeout = connect_timeout
        self._sem            = asyncio.Semaphore(max_concurrent)

        self._known_open: dict[str, set[int]] = {}
        self._last_scan: dict[str, float] = {}
        self._targets: set[str] = set()

        self.own_ip   = own_ip
        self._running = False
        self._task:   Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._running = True
        self._task    = asyncio.create_task(self._scan_loop(), name="port-scanner")
        log.info(
            "Port scanner starting (ports=%d, interval=%ds)",
            len(self.ports), self.interval,
        )

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("Port scanner stopped. Known hosts: %d", len(self._known_open))

    def add_target(self, ip: str) -> None:
        if is_private(ip) and ip != self.own_ip:
            self._targets.add(ip)

    async def _scan_loop(self) -> None:
        await asyncio.sleep(35)

        while self._running:
            targets = list(self._targets)
            if targets:
                log.info("Port scanner — scanning %d LAN hosts", len(targets))
                await self._scan_all(targets)
            else:
                log.debug("Port scanner — no LAN targets yet, waiting...")

            for _ in range(self.interval):
                if not self._running:
                    return
                await asyncio.sleep(1)

    async def _scan_all(self, targets: list[str]) -> None:
        tasks = [self._scan_host(ip) for ip in targets]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _scan_host(self, ip: str) -> None:
        now   = time.time()
        tasks = [self._check_port(ip, p) for p in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports: set[int] = set()
        for port, result in zip(self.ports, results):
            if result is True:
                open_ports.add(port)

        self._last_scan[ip] = now
        await self._process_results(ip, open_ports, now)

    async def _check_port(self, ip: str, port: int) -> bool:
        async with self._sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.connect_timeout,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except Exception:
                return False

    async def _process_results(self, ip: str, open_ports: set[int], now: float) -> None:
        known = self._known_open.get(ip)

        if known is None:
            self._known_open[ip] = open_ports
            if open_ports:
                log.info("Port scan %s — first scan, open: %s", ip, sorted(open_ports))
                await self.bus.publish(Event(
                    type      = EventType.PORT_SCAN_RESULT,
                    severity  = "info",
                    source    = "port_scanner",
                    timestamp = now,
                    data      = {
                        "ip":         ip,
                        "open_ports": sorted(open_ports),
                        "new_ports":  [],
                        "closed_ports": [],
                        "first_scan": True,
                        "description": f"{ip} — first scan: {len(open_ports)} open port(s): {sorted(open_ports)}",
                    },
                ))
            return

        new_ports    = open_ports - known
        closed_ports = known - open_ports

        if new_ports or closed_ports:
            self._known_open[ip] = open_ports

        if new_ports:
            high_risk = new_ports & HIGH_RISK_PORTS
            severity  = "critical" if high_risk else "warning"
            label     = f"HIGH RISK port(s) opened" if high_risk else "New port(s) opened"

            log.warning("%s on %s: %s", label, ip, sorted(new_ports))
            await self.bus.publish(Event(
                type      = EventType.PORT_SCAN_RESULT,
                severity  = severity,
                source    = "port_scanner",
                timestamp = now,
                data      = {
                    "ip":           ip,
                    "open_ports":   sorted(open_ports),
                    "new_ports":    sorted(new_ports),
                    "closed_ports": sorted(closed_ports),
                    "high_risk":    sorted(high_risk),
                    "first_scan":   False,
                    "description":  (
                        f"{label} on {ip}: {sorted(new_ports)}"
                        + (f" ← HIGH RISK: {sorted(high_risk)}" if high_risk else "")
                    ),
                },
            ))

        elif closed_ports:
            log.info("Port(s) closed on %s: %s", ip, sorted(closed_ports))
            await self.bus.publish(Event(
                type      = EventType.PORT_SCAN_RESULT,
                severity  = "info",
                source    = "port_scanner",
                timestamp = now,
                data      = {
                    "ip":           ip,
                    "open_ports":   sorted(open_ports),
                    "new_ports":    [],
                    "closed_ports": sorted(closed_ports),
                    "high_risk":    [],
                    "first_scan":   False,
                    "description":  f"Port(s) closed on {ip}: {sorted(closed_ports)}",
                },
            ))

    @property
    def stats(self) -> dict:
        total_open = sum(len(p) for p in self._known_open.values())
        return {
            "targets":      len(self._targets),
            "scanned_hosts": len(self._known_open),
            "total_open_ports": total_open,
            "interval":     self.interval,
        }

    def open_ports_for(self, ip: str) -> list[int]:
        return sorted(self._known_open.get(ip, set()))