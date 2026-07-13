import asyncio
import logging
import time
from typing import Optional

from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr
from scapy.layers.l2 import ARP
from scapy.sendrecv import AsyncSniffer

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.arp_watcher")

FLOOD_WINDOW    = 10
FLOOD_THRESHOLD = 20
LEARN_WINDOW    = 30
GARP_COOLDOWN   = 30


class ArpWatcher:
    def __init__(
        self,
        bus: EventBus,
        iface: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        learn_window: int = LEARN_WINDOW,
    ):
        self.bus         = bus
        self.iface       = iface
        self.gateway_ip  = gateway_ip
        self._learn_until = 0.0
        self._learn_window = learn_window

        self._table:      dict[str, set[str]]   = {}
        self._seen_pairs: set[tuple[str, str]]  = set()

        self._arp_times:  dict[str, list[float]] = {}
        self._garp_seen:  dict[str, float]       = {}

        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._loop:   Optional[asyncio.AbstractEventLoop] = None

        self._total_arp     = 0
        self._total_anomaly = 0

    async def start(self) -> None:
        self._loop       = asyncio.get_running_loop()
        self._running    = True
        self._learn_until = time.time() + self._learn_window

        log.info(
            "ARP watcher starting — learning mode for %ds (iface=%s)",
            self._learn_window, self.iface or "default",
        )

        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter="arp or (ip6 and icmp6)",
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

        asyncio.get_event_loop().call_later(
            self._learn_window,
            lambda: log.info(
                "ARP watcher — learning mode ended. Known hosts: %d (gateway: %s)",
                len(self._table), self.gateway_ip or "not detected",
            ),
        )

    async def stop(self) -> None:
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
        log.info(
            "ARP watcher stopped. total_arp=%d anomalies=%d known_hosts=%d",
            self._total_arp, self._total_anomaly, len(self._table),
        )

    def _on_packet(self, pkt) -> None:
        if not self._running:
            return
        try:
            events = self._analyze(pkt)
            for ev in events:
                asyncio.run_coroutine_threadsafe(self.bus.publish(ev), self._loop)
        except Exception as exc:
            log.debug("ARP parse error: %s", exc)

    def _analyze(self, pkt) -> list[Event]:
        now = time.time()
        learning = now < self._learn_until
        events: list[Event] = []

        if ARP in pkt:
            self._analyze_arp(pkt, now, learning, events)
        elif IPv6 in pkt and ICMPv6ND_NS in pkt:
            self._analyze_ndp(pkt, now, learning, events)
        elif IPv6 in pkt and ICMPv6ND_NA in pkt:
            self._analyze_ndp(pkt, now, learning, events)

        return events

    def _analyze_arp(self, pkt, now: float, learning: bool, events: list[Event]) -> None:
        arp = pkt[ARP]
        sender_ip = arp.psrc
        sender_mac = arp.hwsrc
        target_ip = arp.pdst
        op = arp.op

        if not sender_ip or sender_ip == "0.0.0.0":
            return

        self._total_arp += 1

        if not self.gateway_ip and sender_ip.endswith(".1"):
            self.gateway_ip = sender_ip
            log.info("Gateway auto-detected: %s (%s)", sender_ip, sender_mac)

        self._check_ip_mac(sender_ip, sender_mac, now, learning, events, "ARP")

        if op == 2 and sender_ip == target_ip and not learning:
            last = self._garp_seen.get(sender_mac, 0)
            if now - last > GARP_COOLDOWN:
                self._garp_seen[sender_mac] = now
                log.warning("Gratuitous ARP from %s (%s)", sender_ip, sender_mac)
                self._total_anomaly += 1
                events.append(Event(
                    type=EventType.ARP_ANOMALY,
                    severity="warning",
                    source="arp_watcher",
                    timestamp=now,
                    data={
                        "anomaly": "gratuitous_arp",
                        "src_ip": sender_ip,
                        "mac": sender_mac,
                        "description": f"Gratuitous ARP: {sender_ip} ({sender_mac}) — possible arpspoof",
                    },
                ))

        self._check_flood(sender_mac, now, learning, events, "ARP")

    def _analyze_ndp(self, pkt, now: float, learning: bool, events: list[Event]) -> None:
        ipv6 = pkt[IPv6]
        src_ip = ipv6.src
        src_mac = None

        if ICMPv6ND_NS in pkt and ICMPv6NDOptSrcLLAddr in pkt:
            src_mac = pkt[ICMPv6NDOptSrcLLAddr].lladdr
        elif ICMPv6ND_NA in pkt and ICMPv6NDOptDstLLAddr in pkt:
            src_mac = pkt[ICMPv6NDOptDstLLAddr].lladdr

        if not src_mac or not src_ip:
            return
        if src_ip.startswith("fe80::"):
            self._maybe_new_ndp_device(src_ip, src_mac, now, events)
        self._check_ip_mac(src_ip, src_mac, now, learning, events, "NDP")
        self._check_flood(src_mac, now, learning, events, "NDP")

    def _check_ip_mac(self, ip: str, mac: str, now: float, learning: bool, events: list[Event], proto: str) -> None:
        known_macs = self._table.setdefault(ip, set())

        if learning:
            known_macs.add(mac)
        else:
            if mac not in known_macs:
                if known_macs:
                    is_gateway = (ip == self.gateway_ip)
                    label = "Gateway spoofing" if is_gateway else f"{proto} spoofing"
                    log.warning(
                        "%s: %s known as %s, now claims %s",
                        label, ip, "/".join(known_macs), mac,
                    )
                    self._total_anomaly += 1
                    events.append(Event(
                        type=EventType.ARP_ANOMALY,
                        severity="critical",
                        source="arp_watcher",
                        timestamp=now,
                        data={
                            "anomaly": label.lower().replace(" ", "_"),
                            "src_ip": ip,
                            "mac": mac,
                            "known_macs": list(known_macs),
                            "is_gateway": is_gateway,
                            "description": (
                                f"{label}: {ip} known as "
                                f"{'/'.join(known_macs)}, now claims {mac}"
                            ),
                        },
                    ))
                known_macs.add(mac)

        pair = (ip, mac)
        if pair not in self._seen_pairs:
            self._seen_pairs.add(pair)
            events.append(Event(
                type=EventType.NEW_DEVICE,
                severity="info",
                source="arp_watcher",
                timestamp=now,
                data={"ip": ip, "mac": mac},
            ))

    def _check_flood(self, mac: str, now: float, learning: bool, events: list[Event], proto: str) -> None:
        times = self._arp_times.setdefault(mac, [])
        times.append(now)
        cutoff = now - FLOOD_WINDOW
        self._arp_times[mac] = [t for t in times if t > cutoff]
        count = len(self._arp_times[mac])

        if count == FLOOD_THRESHOLD and not learning:
            log.warning(
                "%s flood from %s: %d packets in %ds",
                proto, mac, count, FLOOD_WINDOW,
            )
            self._total_anomaly += 1
            events.append(Event(
                type=EventType.ARP_ANOMALY,
                severity="warning",
                source="arp_watcher",
                timestamp=now,
                data={
                    "anomaly": f"{proto.lower()}_flood",
                    "mac": mac,
                    "count": count,
                    "window_secs": FLOOD_WINDOW,
                    "description": f"{proto} flood: {count} packets in {FLOOD_WINDOW}s from {mac}",
                },
            ))

    def _maybe_new_ndp_device(self, ip: str, mac: str, now: float, events: list[Event]) -> None:
        pair = (ip, mac)
        if pair in self._seen_pairs:
            return
        self._seen_pairs.add(pair)

    @property
    def table(self) -> dict[str, list[str]]:
        return {ip: list(macs) for ip, macs in self._table.items()}

    @property
    def stats(self) -> dict:
        return {
            "total_arp":      self._total_arp,
            "total_anomaly":  self._total_anomaly,
            "known_hosts":    len(self._table),
            "gateway":        self.gateway_ip,
            "learning_mode":  time.time() < self._learn_until,
        }