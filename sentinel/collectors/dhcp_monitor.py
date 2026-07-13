import asyncio
import logging
import time
from typing import Optional

from scapy.layers.inet import IP, UDP
from scapy.sendrecv import AsyncSniffer

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.dhcp")

LEARN_WINDOW    = 30
FLOOD_WINDOW    = 10
FLOOD_THRESHOLD = 30

DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST",
    4: "ACK", 5: "NAK", 6: "DECLINE",
    7: "RELEASE", 8: "INFORM",
}


class DhcpMonitor:
    def __init__(
        self,
        bus: EventBus,
        iface: Optional[str] = None,
        known_servers: Optional[set[str]] = None,
    ):
        self.bus = bus
        self.iface = iface
        self._known_servers: set[str] = set(known_servers or [])
        self._learn_until = 0.0
        self._discover_counts: dict[str, list[float]] = {}
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._total_dhcp = 0
        self._total_anomaly = 0

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._running = True
        self._learn_until = time.time() + LEARN_WINDOW
        log.info("DHCP monitor starting — learning mode for %ds", LEARN_WINDOW)
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter="udp port 67 or udp port 68",
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

    async def stop(self) -> None:
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
        log.info("DHCP monitor stopped. total=%d anomalies=%d", self._total_dhcp, self._total_anomaly)

    def _on_packet(self, pkt) -> None:
        if not self._running:
            return
        try:
            events = self._analyze(pkt)
            for ev in events:
                asyncio.run_coroutine_threadsafe(self.bus.publish(ev), self._loop)
        except Exception as exc:
            log.debug("DHCP parse error: %s", exc)

    def _analyze(self, pkt) -> list[Event]:
        try:
            from scapy.layers.dhcp import BOOTP
            bootp = pkt[BOOTP]
        except ImportError:
            return []
        except Exception:
            return []

        ip = pkt[IP]
        udp = pkt[UDP]
        now = time.time()
        events: list[Event] = []

        src_ip = ip.src
        src_port = udp.sport
        dst_port = udp.dport
        chaddr = bootp.chaddr.hex() if isinstance(bootp.chaddr, bytes) else str(bootp.chaddr)
        siaddr = bootp.siaddr if bootp.siaddr else src_ip

        msg_type = None
        server_id = None
        for opt in bootp.options:
            if isinstance(opt, tuple) and len(opt) >= 2:
                if opt[0] == 'message-type':
                    msg_type = opt[1]
                elif opt[0] == 'server_id':
                    server_id = str(opt[1])

        if msg_type is None:
            return []

        self._total_dhcp += 1
        type_name = DHCP_MSG_TYPES.get(msg_type, f"UNKNOWN({msg_type})")
        learning = now < self._learn_until

        if msg_type in (2, 4, 5):
            server_ip = server_id or siaddr
            if learning:
                self._known_servers.add(server_ip)
            elif server_ip not in self._known_servers:
                self._known_servers.add(server_ip)
                self._total_anomaly += 1
                log.warning("Rogue DHCP server detected: %s (%s)", server_ip, type_name)
                events.append(Event(
                    type=EventType.DHCP_ANOMALY,
                    severity="critical",
                    source="dhcp_monitor",
                    timestamp=now,
                    data={
                        "anomaly": "rogue_server",
                        "server_ip": server_ip,
                        "server_mac": chaddr,
                        "message_type": type_name,
                        "description": f"Rogue DHCP server: {server_ip} ({chaddr}) sent {type_name}",
                    },
                ))

        if msg_type in (1, 3):
            key = chaddr or src_ip
            times = self._discover_counts.setdefault(key, [])
            times.append(now)
            cutoff = now - FLOOD_WINDOW
            self._discover_counts[key] = [t for t in times if t > cutoff]
            count = len(self._discover_counts[key])
            if count == FLOOD_THRESHOLD and not learning:
                self._total_anomaly += 1
                log.warning("DHCP flood from %s (%s): %d messages in %ds", src_ip, key, count, FLOOD_WINDOW)
                events.append(Event(
                    type=EventType.DHCP_ANOMALY,
                    severity="warning",
                    source="dhcp_monitor",
                    timestamp=now,
                    data={
                        "anomaly": "dhcp_flood",
                        "src_ip": src_ip,
                        "chaddr": chaddr,
                        "count": count,
                        "message_type": type_name,
                        "description": f"DHCP flood: {count} {type_name} from {src_ip} in {FLOOD_WINDOW}s",
                    },
                ))

        return events