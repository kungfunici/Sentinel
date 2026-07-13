import asyncio
import time
import logging
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.l2 import ARP
from scapy.sendrecv import AsyncSniffer

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.sniffer")

SYN_FLOOD_WINDOW    = 10
SYN_FLOOD_THRESHOLD = 50
LARGE_PACKET_BYTES  = 8192


class PacketSniffer:
    def __init__(
        self,
        bus: EventBus,
        iface: Optional[str] = None,
        bpf_filter: str = "ip or ip6 or arp",
        loop: Optional[asyncio.AbstractEventLoop] = None,
        own_ip: Optional[str] = None,
    ):
        self.bus    = bus
        self.iface  = iface
        self.filter = bpf_filter
        self.loop   = loop

        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False

        self.own_ip = own_ip
        self._seen_ips: set[str] = set()
        self._syn_times: dict[str, list[float]] = {}

    async def start(self) -> None:
        self.loop = self.loop or asyncio.get_running_loop()
        self._running = True
        log.info("Starting packet sniffer (iface=%s, filter=%r)", self.iface or "default", self.filter)

        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.filter,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()
        log.info("Sniffer active")

    async def stop(self) -> None:
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
            log.info("Sniffer stopped")

    def _on_packet(self, pkt) -> None:
        if not self._running:
            return
        try:
            event = self._parse(pkt)
            if event and self.loop:
                asyncio.run_coroutine_threadsafe(self.bus.publish(event), self.loop)
        except Exception as exc:
            log.debug("Packet parse error: %s", exc)

    def _parse(self, pkt) -> Optional[Event]:
        if ARP in pkt:
            self._maybe_new_device(pkt[ARP].psrc, mac=pkt[ARP].hwsrc)
            return None

        if IP in pkt:
            ip_layer = pkt[IP]
            is_v6 = False
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]
            is_v6 = True
        else:
            return None

        src  = ip_layer.src
        dst  = ip_layer.dst
        size = len(pkt)
        now  = time.time()
        proto = ip_layer.nh if is_v6 else ip_layer.proto

        self._maybe_new_device(src)

        data: dict = {
            "src_ip":    src,
            "dst_ip":    dst,
            "protocol":  self._proto_name(proto),
            "size":      size,
            "ip_version": 6 if is_v6 else 4,
        }
        severity = "info"

        if TCP in pkt:
            tcp = pkt[TCP]
            data["src_port"] = tcp.sport
            data["dst_port"] = tcp.dport
            data["flags"]    = str(tcp.flags)

            if "S" in str(tcp.flags) and "A" not in str(tcp.flags):
                if src != self.own_ip:
                    severity = self._check_syn_flood(src, now)

        elif UDP in pkt:
            udp = pkt[UDP]
            data["src_port"] = udp.sport
            data["dst_port"] = udp.dport

        elif ICMP in pkt and not is_v6:
            data["icmp_type"] = pkt[ICMP].type

        elif is_v6 and ICMPv6EchoRequest in pkt:
            data["icmp_type"] = 128

        if size > LARGE_PACKET_BYTES and severity != "critical":
            severity = "warning"
            data["anomaly"] = f"large_packet:{size}b"

        return Event(
            type      = EventType.PACKET_CAPTURED,
            data      = data,
            severity  = severity,
            source    = "sniffer",
            timestamp = now,
        )

    def _maybe_new_device(self, ip: str, mac: Optional[str] = None) -> None:
        if not ip or ip in self._seen_ips:
            return
        if ip.startswith("0.") or ip == "255.255.255.255" or ip == "ff02::1" or ip.startswith("fe80::"):
            return
        self._seen_ips.add(ip)
        log.info("New device seen: %s", ip)
        event = Event(
            type     = EventType.NEW_DEVICE,
            data     = {"ip": ip, "mac": mac},
            severity = "info",
            source   = "sniffer",
        )
        if self.loop:
            asyncio.run_coroutine_threadsafe(self.bus.publish(event), self.loop)

    def _check_syn_flood(self, src: str, now: float) -> str:
        times = self._syn_times.setdefault(src, [])
        times.append(now)
        cutoff = now - SYN_FLOOD_WINDOW
        self._syn_times[src] = [t for t in times if t > cutoff]
        count = len(self._syn_times[src])
        if count >= SYN_FLOOD_THRESHOLD:
            log.warning("SYN flood detected from %s (%d SYNs in %ds)", src, count, SYN_FLOOD_WINDOW)
            return "critical"
        if count >= SYN_FLOOD_THRESHOLD // 2:
            return "warning"
        return "info"

    @staticmethod
    def _proto_name(proto: int) -> str:
        return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))