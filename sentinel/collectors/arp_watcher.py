"""
sentinel/collectors/arp_watcher.py

ARP Watcher — detects ARP-based attacks:

    1. ARP Spoofing      — known IP appears with a different MAC
    2. Gateway Spoofing  — someone claims the router's IP
    3. Gratuitous ARP    — unsolicited ARP replies (arpspoof, ettercap)
    4. ARP Flood         — too many ARP packets from one MAC in short time

Learning mode (first LEARN_WINDOW seconds):
    All IP/MAC pairs are silently learned — no alerts fired.
    This prevents false positives from routers/APs with multiple MACs.
"""

import asyncio
import logging
import time
from typing import Optional

from scapy.layers.l2 import ARP
from scapy.sendrecv import AsyncSniffer

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.arp_watcher")

FLOOD_WINDOW    = 10    # seconds
FLOOD_THRESHOLD = 20    # ARP packets from one MAC in that window
LEARN_WINDOW    = 30    # seconds of silent learning at startup
GARP_COOLDOWN   = 30    # seconds between gratuitous ARP alerts per MAC


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
        self._learn_until = 0.0   # set on start()
        self._learn_window = learn_window

        # ip → set of known MACs (multiple allowed after learning)
        self._table:      dict[str, set[str]]   = {}
        self._seen_pairs: set[tuple[str, str]]  = set()

        self._arp_times:  dict[str, list[float]] = {}
        self._garp_seen:  dict[str, float]       = {}

        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._loop:   Optional[asyncio.AbstractEventLoop] = None

        self._total_arp     = 0
        self._total_anomaly = 0

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

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
            filter="arp",
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

        # Log when learning mode ends
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

    # ------------------------------------------------------------------ #
    #  Packet handler                                                      #
    # ------------------------------------------------------------------ #

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
        if ARP not in pkt:
            return []

        arp        = pkt[ARP]
        now        = time.time()
        learning   = now < self._learn_until
        events: list[Event] = []

        sender_ip  = arp.psrc
        sender_mac = arp.hwsrc
        target_ip  = arp.pdst
        op         = arp.op      # 1=request, 2=reply

        if not sender_ip or sender_ip == "0.0.0.0":
            return []

        self._total_arp += 1

        # Auto-detect gateway
        if not self.gateway_ip and sender_ip.endswith(".1"):
            self.gateway_ip = sender_ip
            log.info("Gateway auto-detected: %s (%s)", sender_ip, sender_mac)

        # ---- Learn or check IP→MAC mapping ----
        known_macs = self._table.setdefault(sender_ip, set())

        if learning:
            # Silent learning — just record, no alerts
            known_macs.add(sender_mac)
        else:
            if sender_mac not in known_macs:
                if known_macs:
                    # Known IP, new MAC — this is the spoofing signal
                    is_gateway = (sender_ip == self.gateway_ip)
                    label      = "Gateway spoofing" if is_gateway else "ARP spoofing"
                    log.warning(
                        "%s: %s known as %s, now claims %s",
                        label, sender_ip,
                        "/".join(known_macs), sender_mac,
                    )
                    self._total_anomaly += 1
                    events.append(Event(
                        type      = EventType.ARP_ANOMALY,
                        severity  = "critical",
                        source    = "arp_watcher",
                        timestamp = now,
                        data      = {
                            "anomaly":     label.lower().replace(" ", "_"),
                            "src_ip":      sender_ip,
                            "mac":         sender_mac,
                            "known_macs":  list(known_macs),
                            "target_ip":   target_ip,
                            "is_gateway":  is_gateway,
                            "description": (
                                f"{label}: {sender_ip} known as "
                                f"{'/'.join(known_macs)}, now claims {sender_mac}"
                            ),
                        },
                    ))
                # Add to known MACs either way (avoid repeat alerts)
                known_macs.add(sender_mac)

        # ---- New device (always, even during learning) ----
        pair = (sender_ip, sender_mac)
        if pair not in self._seen_pairs:
            self._seen_pairs.add(pair)
            events.append(Event(
                type      = EventType.NEW_DEVICE,
                severity  = "info",
                source    = "arp_watcher",
                timestamp = now,
                data      = {"ip": sender_ip, "mac": sender_mac},
            ))

        # ---- Gratuitous ARP (op=2, sender_ip == target_ip) ----
        if op == 2 and sender_ip == target_ip and not learning:
            last = self._garp_seen.get(sender_mac, 0)
            if now - last > GARP_COOLDOWN:
                self._garp_seen[sender_mac] = now
                log.warning("Gratuitous ARP from %s (%s)", sender_ip, sender_mac)
                self._total_anomaly += 1
                events.append(Event(
                    type      = EventType.ARP_ANOMALY,
                    severity  = "warning",
                    source    = "arp_watcher",
                    timestamp = now,
                    data      = {
                        "anomaly":     "gratuitous_arp",
                        "src_ip":      sender_ip,
                        "mac":         sender_mac,
                        "description": f"Gratuitous ARP: {sender_ip} ({sender_mac}) — possible arpspoof",
                    },
                ))

        # ---- ARP Flood ----
        times = self._arp_times.setdefault(sender_mac, [])
        times.append(now)
        cutoff = now - FLOOD_WINDOW
        self._arp_times[sender_mac] = [t for t in times if t > cutoff]
        count = len(self._arp_times[sender_mac])

        if count == FLOOD_THRESHOLD and not learning:
            log.warning(
                "ARP flood from %s (%s): %d packets in %ds",
                sender_ip, sender_mac, count, FLOOD_WINDOW,
            )
            self._total_anomaly += 1
            events.append(Event(
                type      = EventType.ARP_ANOMALY,
                severity  = "warning",
                source    = "arp_watcher",
                timestamp = now,
                data      = {
                    "anomaly":     "arp_flood",
                    "src_ip":      sender_ip,
                    "mac":         sender_mac,
                    "count":       count,
                    "window_secs": FLOOD_WINDOW,
                    "description": f"ARP flood: {count} packets in {FLOOD_WINDOW}s from {sender_mac}",
                },
            ))

        return events

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