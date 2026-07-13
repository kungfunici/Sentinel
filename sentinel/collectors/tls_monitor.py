import asyncio
import hashlib
import logging
import time
from typing import Optional

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import AsyncSniffer

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.tls")

SUSPICIOUS_JA3 = {
    "6734f37431670b3ab4292b8f60f29984": "Known malware C2",
    "51c64c77e60f3980eea90869b68c58a8": "Trickbot",
    "a0e9f5d64349fb13191bc781f81f42e1": "Mirai variant",
    "b0e9f5d64349fb13191bc781f81f42e1": "Emotet",
    "c25e4a8c5e7f2e4c5a6b7c8d9e0f1a2b": "可疑扫描工具",
}


class TlsMonitor:
    def __init__(self, bus: EventBus, iface: Optional[str] = None):
        self.bus = bus
        self.iface = iface
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._total_connections = 0
        self._total_suspicious = 0

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._running = True
        log.info("TLS monitor starting (iface=%s)", self.iface or "default")
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter="tcp port 443",
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()

    async def stop(self) -> None:
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
        log.info(
            "TLS monitor stopped. connections=%d suspicious=%d",
            self._total_connections, self._total_suspicious,
        )

    def _on_packet(self, pkt) -> None:
        if not self._running:
            return
        try:
            ev = self._parse_tls(pkt)
            if ev and self._loop:
                asyncio.run_coroutine_threadsafe(self.bus.publish(ev), self._loop)
        except Exception as exc:
            log.debug("TLS parse error: %s", exc)

    def _parse_tls(self, pkt) -> Optional[Event]:
        if IP not in pkt or TCP not in pkt:
            return None

        ip = pkt[IP]
        tcp = pkt[TCP]
        src_ip = ip.src
        dst_ip = ip.dst

        if not tcp.payload or len(tcp.payload) == 0:
            return None

        raw = bytes(tcp.payload)
        parsed = self._parse_client_hello(raw)
        if not parsed:
            return None

        self._total_connections += 1
        now = time.time()

        ja3_hash = parsed["ja3"]
        sni = parsed["sni"]
        tls_version = parsed["version"]

        is_suspicious = ja3_hash in SUSPICIOUS_JA3
        ja3_label = SUSPICIOUS_JA3.get(ja3_hash, "")

        if is_suspicious:
            self._total_suspicious += 1
            severity = "critical" if "Trickbot" in ja3_label or "Emotet" in ja3_label else "warning"
            log.warning(
                "TLS suspicious [%s] JA3=%s (%s) from %s to %s SNI=%s",
                severity, ja3_hash, ja3_label, src_ip, dst_ip, sni or "?",
            )
        else:
            severity = "info"
            log.info(
                "TLS %s -> %s SNI=%s JA3=%s", src_ip, dst_ip, sni or "?", ja3_hash,
            )

        description = (
            f"TLS {src_ip} -> {dst_ip} SNI={sni or '?'} v={tls_version} "
            f"JA3={ja3_hash}"
        )
        if ja3_label:
            description += f" [{ja3_label}]"

        return Event(
            type=EventType.HTTP_REQUEST,
            severity=severity,
            source="tls",
            timestamp=now,
            data={
                "description": description,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "sni": sni or "",
                "ja3": ja3_hash,
                "ja3_label": ja3_label,
                "tls_version": tls_version,
                "suspicious": is_suspicious,
            },
        )

    @staticmethod
    def _parse_client_hello(raw: bytes) -> Optional[dict]:
        if len(raw) < 5:
            return None
        if raw[0] != 0x16:
            return None

        record_version = (raw[1], raw[2])
        version_str = f"0x{record_version[0]:02x}{record_version[1]:02x}"

        record_length = (raw[3] << 8) | raw[4]
        if len(raw) < 5 + record_length:
            return None

        handshake = raw[5:]
        if len(handshake) < 1 or handshake[0] != 0x01:
            return None

        if len(handshake) < 4:
            return None
        hs_length = (handshake[1] << 16) | (handshake[2] << 8) | handshake[3]
        if len(handshake) < 4 + hs_length:
            return None

        body = handshake[4:4 + hs_length]
        if len(body) < 2:
            return None

        client_version = (body[0], body[1])
        version_str = f"0x{client_version[0]:02x}{client_version[1]:02x}"

        pos = 2 + 32
        if len(body) < pos + 1:
            return None

        sid_len = body[pos]
        pos += 1 + sid_len

        if len(body) < pos + 2:
            return None
        cs_len = (body[pos] << 8) | body[pos + 1]
        pos += 2
        if len(body) < pos + cs_len:
            return None
        cipher_suites = []
        for i in range(0, cs_len, 2):
            if pos + i + 2 <= len(body):
                c = (body[pos + i] << 8) | body[pos + i + 1]
                cipher_suites.append(f"0x{c:04x}")
        pos += cs_len

        if len(body) < pos + 1:
            return None
        comp_len = body[pos]
        pos += 1 + comp_len

        if len(body) < pos + 2:
            return None
        pos += 2

        extensions = []
        sni = None
        groups = []
        ec_formats = []

        while pos + 4 <= len(body):
            ext_type = (body[pos] << 8) | body[pos + 1]
            ext_data_len = (body[pos + 2] << 8) | body[pos + 3]
            pos += 4
            extensions.append(str(ext_type))

            if ext_type == 0x0000 and ext_data_len >= 5:
                name_type = body[pos + 2]
                name_len = (body[pos + 3] << 8) | body[pos + 4]
                if name_type == 0x00 and pos + 5 + name_len <= len(body):
                    sni = body[pos + 5:pos + 5 + name_len].decode("utf-8", errors="ignore")
            elif ext_type == 0x000a and ext_data_len >= 2:
                groups_len = (body[pos] << 8) | body[pos + 1]
                for i in range(0, groups_len, 2):
                    if pos + 2 + i + 2 <= len(body):
                        g = (body[pos + 2 + i] << 8) | body[pos + 2 + i + 1]
                        groups.append(str(g))
            elif ext_type == 0x000b and ext_data_len >= 1:
                fmt_len = body[pos]
                for i in range(fmt_len):
                    if pos + 1 + i < len(body):
                        ec_formats.append(str(body[pos + 1 + i]))

            pos += ext_data_len

        ja3_str = (
            f"{version_str},"
            f"{'-'.join(cipher_suites)},"
            f"{','.join(extensions)},"
            f"{'-'.join(groups)},"
            f"{'-'.join(ec_formats)}"
        )
        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

        return {
            "ja3": ja3_hash,
            "ja3_string": ja3_str,
            "sni": sni,
            "version": version_str,
            "cipher_suites": cipher_suites,
            "extensions": extensions,
            "groups": groups,
            "ec_formats": ec_formats,
        }
