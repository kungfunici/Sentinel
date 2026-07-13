import asyncio
import logging
import time
from pathlib import Path
from typing import Optional

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP, IP
from scapy.sendrecv import AsyncSniffer

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.dns")

BUILTIN_BLOCKLIST: set[str] = {
    "malware-c2.ru",
    "evil-tracker.cn",
    "phishing-login.tk",
    "doubleclick.net",
    "ads.google.com",
    "tracking.example.com",
}


class DnsMonitor:
    def __init__(
        self,
        bus: EventBus,
        blocklist_path: Optional[Path] = None,
        iface: Optional[str] = None,
        mode: str = "active",
    ):
        self.bus   = bus
        self.iface = iface
        self.mode  = mode

        self._blocklist: set[str]    = set(BUILTIN_BLOCKLIST)
        self._wildcards: list[str]   = []
        self._blocklist_path         = blocklist_path
        self._blocklist_mtime: float = 0.0

        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._loop:   Optional[asyncio.AbstractEventLoop] = None

        self._total_queries = 0
        self._total_blocked = 0

        if blocklist_path:
            self._load_blocklist(blocklist_path)

    async def start(self) -> None:
        self._loop    = asyncio.get_running_loop()
        self._running = True
        log.info("DNS monitor starting (mode=%s)", self.mode)

        if self.mode == "active":
            self._sniffer = AsyncSniffer(
                iface=self.iface,
                filter="udp port 53",
                prn=self._on_packet,
                store=False,
            )
            self._sniffer.start()
            log.info("DNS sniffer active (udp port 53, IPv4 + IPv6)")
        else:
            asyncio.create_task(self._passive_loop())

        if self._blocklist_path:
            asyncio.create_task(self._blocklist_reload_loop())

    async def stop(self) -> None:
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
        log.info(
            "DNS monitor stopped. queries=%d blocked=%d",
            self._total_queries, self._total_blocked,
        )

    def _on_packet(self, pkt) -> None:
        if not self._running:
            return
        try:
            events = self._parse_dns(pkt)
            for ev in events:
                asyncio.run_coroutine_threadsafe(self.bus.publish(ev), self._loop)
        except Exception as exc:
            log.debug("DNS parse error: %s", exc)

    def _parse_dns(self, pkt) -> list[Event]:
        if DNS not in pkt:
            return []

        try:
            from scapy.layers.inet6 import IPv6
            if IP in pkt:
                src_ip = pkt[IP].src
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
            else:
                return []
        except ImportError:
            if IP not in pkt:
                return []
            src_ip = pkt[IP].src

        dns = pkt[DNS]
        if dns.qr != 0:
            return []

        now    = time.time()
        events = []

        node = dns.qd
        while node and isinstance(node, DNSQR):
            try:
                name  = node.qname.decode().rstrip(".")
                qtype = self._qtype_name(node.qtype)

                blocked  = self._is_blocked(name)
                ev_type  = EventType.DNS_BLOCKED if blocked else EventType.DNS_QUERY
                severity = "warning" if blocked else "info"

                if blocked:
                    self._total_blocked += 1
                    log.warning("DNS BLOCKED: %s (%s) from %s", name, qtype, src_ip)
                else:
                    self._total_queries += 1
                    log.info("DNS query: %s (%s) from %s", name, qtype, src_ip)

                events.append(Event(
                    type      = ev_type,
                    severity  = severity,
                    source    = "dns_monitor",
                    timestamp = now,
                    data = {
                        "src_ip":     src_ip,
                        "query_name": name,
                        "query_type": qtype,
                        "blocked":    blocked,
                        "dns_id":     dns.id,
                    },
                ))
            except Exception as exc:
                log.debug("DNSQR parse error: %s", exc)

            next_node = node.payload
            node = next_node if isinstance(next_node, DNSQR) else None

        return events

    async def _passive_loop(self) -> None:
        async with self.bus.subscribe() as sub:
            async for event in sub:
                if not self._running:
                    break
                if event.type != EventType.PACKET_CAPTURED:
                    continue
                d = event.data
                if d.get("dst_port") == 53 or d.get("src_port") == 53:
                    log.debug("Passive DNS traffic: %s -> %s", d.get("src_ip"), d.get("dst_ip"))

    def _is_blocked(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        if domain in self._blocklist:
            return True
        for wildcard in self._wildcards:
            if domain.endswith("." + wildcard) or domain == wildcard:
                return True
        return False

    def _load_blocklist(self, path: Path) -> None:
        try:
            mtime = path.stat().st_mtime
            if mtime == self._blocklist_mtime:
                return
            domains: set[str] = set(BUILTIN_BLOCKLIST)
            wildcards: list[str] = []
            for line in path.read_text().splitlines():
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("*."):
                    wildcards.append(line[2:])
                else:
                    domains.add(line)
            self._blocklist       = domains
            self._wildcards       = wildcards
            self._blocklist_mtime = mtime
            log.info("Blocklist loaded: %d exact, %d wildcard", len(domains), len(wildcards))
        except Exception as exc:
            log.error("Failed to load blocklist %s: %s", path, exc)

    async def _blocklist_reload_loop(self) -> None:
        while self._running:
            await asyncio.sleep(60)
            if self._blocklist_path:
                self._load_blocklist(self._blocklist_path)

    def add_domain(self, domain: str) -> None:
        self._blocklist.add(domain.lower().strip())
        log.info("Blocklist: added %s", domain)

    def remove_domain(self, domain: str) -> None:
        self._blocklist.discard(domain.lower().strip())

    @property
    def stats(self) -> dict:
        return {
            "total_queries":  self._total_queries,
            "total_blocked":  self._total_blocked,
            "blocklist_size": len(self._blocklist) + len(self._wildcards),
        }

    @staticmethod
    def _qtype_name(qtype: int) -> str:
        return {
            1: "A", 28: "AAAA", 5: "CNAME",
            15: "MX", 2: "NS", 16: "TXT", 12: "PTR",
        }.get(qtype, str(qtype))