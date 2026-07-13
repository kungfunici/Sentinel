import asyncio
import logging
import time
from typing import Optional

from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import AsyncSniffer

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.icmp")

FLOOD_WINDOW    = 10
FLOOD_THRESHOLD = 20
TUNNEL_MIN_SIZE = 1000
SMURF_THRESHOLD = 5


class IcmpMonitor:
    def __init__(
        self,
        bus: EventBus,
        iface: Optional[str] = None,
    ):
        self.bus = bus
        self.iface = iface
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._echo_counts: dict[str, list[float]] = {}
        self._smurf_counts: dict[str, list[float]] = {}
        self._total_icmp = 0
        self._total_anomaly = 0

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._running = True
        log.info("ICMP monitor starting")
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter="icmp",
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

    async def stop(self) -> None:
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
        log.info("ICMP monitor stopped. total=%d anomalies=%d", self._total_icmp, self._total_anomaly)

    def _on_packet(self, pkt) -> None:
        if not self._running:
            return
        try:
            events = self._analyze(pkt)
            for ev in events:
                asyncio.run_coroutine_threadsafe(self.bus.publish(ev), self._loop)
        except Exception as exc:
            log.debug("ICMP parse error: %s", exc)

    def _analyze(self, pkt) -> list[Event]:
        if ICMP not in pkt or IP not in pkt:
            return []

        ip = pkt[IP]
        icmp = pkt[ICMP]
        now = time.time()
        events: list[Event] = []

        src_ip = ip.src
        dst_ip = ip.dst
        size = len(pkt)
        icmp_type = icmp.type
        icmp_code = icmp.code

        self._total_icmp += 1

        if icmp_type == 8:
            times = self._echo_counts.setdefault(src_ip, [])
            times.append(now)
            cutoff = now - FLOOD_WINDOW
            self._echo_counts[src_ip] = [t for t in times if t > cutoff]
            count = len(self._echo_counts[src_ip])

            if size > TUNNEL_MIN_SIZE:
                self._total_anomaly += 1
                log.warning("ICMP tunnel detected from %s: %d bytes", src_ip, size)
                events.append(Event(
                    type=EventType.ICMP_ANOMALY,
                    severity="critical",
                    source="icmp_monitor",
                    timestamp=now,
                    data={
                        "anomaly": "icmp_tunnel",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "size": size,
                        "description": f"ICMP tunnel: {src_ip} → {dst_ip}, payload {size}b",
                    },
                ))

            if count == FLOOD_THRESHOLD:
                self._total_anomaly += 1
                log.warning("Ping flood from %s: %d requests in %ds", src_ip, count, FLOOD_WINDOW)
                events.append(Event(
                    type=EventType.ICMP_ANOMALY,
                    severity="warning",
                    source="icmp_monitor",
                    timestamp=now,
                    data={
                        "anomaly": "ping_flood",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "count": count,
                        "window_secs": FLOOD_WINDOW,
                        "description": f"Ping flood: {count} echo requests from {src_ip} in {FLOOD_WINDOW}s",
                    },
                ))

            if dst_ip.endswith(".255") or dst_ip == "255.255.255.255":
                smurf_times = self._smurf_counts.setdefault(src_ip, [])
                smurf_times.append(now)
                smurf_cutoff = now - FLOOD_WINDOW
                self._smurf_counts[src_ip] = [t for t in smurf_times if t > smurf_cutoff]
                smurf_count = len(self._smurf_counts[src_ip])
                if smurf_count == SMURF_THRESHOLD:
                    self._total_anomaly += 1
                    log.warning("Smurf attack from %s: %d echo requests to %s", src_ip, smurf_count, dst_ip)
                    events.append(Event(
                        type=EventType.ICMP_ANOMALY,
                        severity="critical",
                        source="icmp_monitor",
                        timestamp=now,
                        data={
                            "anomaly": "smurf_attack",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "count": smurf_count,
                            "description": f"Smurf attack: {src_ip} sending echo requests to {dst_ip}",
                        },
                    ))

        return events