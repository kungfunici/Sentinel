"""
sentinel/collectors/sniffer.py

Passive packet capture using Scapy.
Runs in a background thread (Scapy's sniff() is blocking).
Publishes PACKET_CAPTURED events onto the EventBus.

Detected and published:
    - Every IP packet (src/dst/proto/size)
    - TCP SYN floods (heuristic)
    - Large payload anomalies
    - New src IPs → NEW_DEVICE event
"""

import asyncio
import threading
import time
import logging
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import AsyncSniffer

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.sniffer")


# Heuristic thresholds
SYN_FLOOD_WINDOW    = 10       # seconds
SYN_FLOOD_THRESHOLD = 50       # SYNs from one IP in that window
LARGE_PACKET_BYTES  = 8192     # flag packets larger than this


class PacketSniffer:
    """
    Wraps Scapy's AsyncSniffer.

    Runs the capture in a background thread and dispatches
    parsed events to the asyncio EventBus.
    """

    def __init__(
        self,
        bus: EventBus,
        iface: Optional[str] = None,
        bpf_filter: str = "ip or arp",
        loop: Optional[asyncio.AbstractEventLoop] = None,
        own_ip: Optional[str] = None,
    ):
        self.bus    = bus
        self.iface  = iface        # None = Scapy picks the default
        self.filter = bpf_filter
        self.loop   = loop

        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False

        # Track seen IPs for NEW_DEVICE detection
        self.own_ip = own_ip
        self._seen_ips: set[str] = set()

        # SYN flood tracking: {src_ip: [timestamps]}
        self._syn_times: dict[str, list[float]] = {}

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

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

    # ------------------------------------------------------------------ #
    #  Packet handler (called from Scapy's capture thread)                #
    # ------------------------------------------------------------------ #

    def _on_packet(self, pkt) -> None:
        """
        Called by Scapy in its own thread.
        We schedule a coroutine on the asyncio event loop — safe cross-thread.
        """
        if not self._running:
            return
        try:
            event = self._parse(pkt)
            if event and self.loop:
                asyncio.run_coroutine_threadsafe(self.bus.publish(event), self.loop)
        except Exception as exc:
            log.debug("Packet parse error: %s", exc)

    def _parse(self, pkt) -> Optional[Event]:
        """Turn a Scapy packet into an Event. Returns None to drop silently."""

        # ---- ARP (hand off to ARP watcher, just track devices here) ----
        if ARP in pkt:
            self._maybe_new_device(pkt[ARP].psrc, mac=pkt[ARP].hwsrc)
            return None   # ARP watcher handles the detail

        if IP not in pkt:
            return None

        ip   = pkt[IP]
        src  = ip.src
        dst  = ip.dst
        size = len(pkt)
        now  = time.time()

        self._maybe_new_device(src)

        # Base packet data
        data: dict = {
            "src_ip":   src,
            "dst_ip":   dst,
            "protocol": self._proto_name(ip.proto),
            "size":     size,
        }
        severity = "info"

        # TCP layer
        if TCP in pkt:
            tcp = pkt[TCP]
            data["src_port"] = tcp.sport
            data["dst_port"] = tcp.dport
            data["flags"]    = str(tcp.flags)

            # SYN flood heuristic — skip own IP (port scanner causes false positives)
            if "S" in str(tcp.flags) and "A" not in str(tcp.flags):
                if src != self.own_ip:
                    severity = self._check_syn_flood(src, now)

        # UDP layer
        elif UDP in pkt:
            udp = pkt[UDP]
            data["src_port"] = udp.sport
            data["dst_port"] = udp.dport

        # ICMP
        elif ICMP in pkt:
            data["icmp_type"] = pkt[ICMP].type

        # Large packet anomaly (override if already critical)
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

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _maybe_new_device(self, ip: str, mac: Optional[str] = None) -> None:
        if not ip or ip in self._seen_ips or ip.startswith("0.") or ip == "255.255.255.255":
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
        # Prune old entries
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