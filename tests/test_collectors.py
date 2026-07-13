import time
import struct
import hashlib

import pytest
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr

from sentinel.core.event_bus import Event, EventBus, EventType
from sentinel.collectors.http_monitor import HttpMonitor
from sentinel.collectors.arp_watcher import ArpWatcher
from sentinel.collectors.dhcp_monitor import DhcpMonitor
from sentinel.collectors.icmp_monitor import IcmpMonitor
from sentinel.collectors.sniffer import PacketSniffer
from sentinel.collectors.dns_monitor import DnsMonitor
from sentinel.collectors.tls_monitor import TlsMonitor

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# HTTP Monitor
# ---------------------------------------------------------------------------

class TestHttpMonitorParse:
    def _make_http_pkt(self, method: str = b"GET", path: str = "/index.html",
                       host: str = "example.com", ua: str = "Mozilla/5.0",
                       referer: str = "", body: bytes = b"",
                       src: str = "192.168.1.10", dst: str = "93.184.216.34",
                       dport: int = 80) -> Ether:
        headers = f"Host: {host}\r\nUser-Agent: {ua}\r\n"
        if referer:
            headers += f"Referer: {referer}\r\n"
        raw = f"{method.decode()} {path} HTTP/1.1\r\n{headers}\r\n".encode() + body
        return Ether() / IP(src=src, dst=dst) / TCP(sport=40000, dport=dport) / Raw(raw)

    def _parse(self, pkt):
        bus = EventBus()
        mon = HttpMonitor(bus)
        return mon._parse(pkt)

    def test_normal_request_returns_event(self):
        pkt = self._make_http_pkt()
        ev = self._parse(pkt)
        assert ev is not None
        assert ev.type == EventType.HTTP_REQUEST
        assert ev.severity == "info"
        assert ev.data["method"] == "GET"
        assert ev.data["host"] == "example.com"
        assert ev.data["path"] == "/index.html"
        assert ev.data["flags"] == []

    def test_suspicious_keyword_in_path(self):
        pkt = self._make_http_pkt(path="/login.php")
        ev = self._parse(pkt)
        assert ev is not None
        assert ev.severity == "warning"
        assert "keyword:login" in ev.data["flags"]

    def test_multiple_keywords(self):
        pkt = self._make_http_pkt(path="/secure/account/verify")
        ev = self._parse(pkt)
        assert ev is not None
        assert ev.severity == "warning"
        flags = ev.data["flags"]
        assert "keyword:secure" in flags
        assert "keyword:account" in flags
        assert "keyword:verify" in flags

    def test_paypal_keyword_flags(self):
        pkt = self._make_http_pkt(path="/paypal/login")
        ev = self._parse(pkt)
        assert ev is not None
        assert ev.severity == "warning"
        assert "keyword:paypal" in ev.data["flags"]
        assert "keyword:login" in ev.data["flags"]

    def test_suspicious_user_agent_curl(self):
        pkt = self._make_http_pkt(ua="curl/7.68.0")
        ev = self._parse(pkt)
        assert ev is not None
        assert ev.severity == "warning"
        assert "suspicious_ua" in ev.data["flags"]

    def test_suspicious_user_agent_nmap(self):
        pkt = self._make_http_pkt(ua="nmap-script-engine")
        ev = self._parse(pkt)
        assert ev is not None
        assert ev.severity == "warning"
        assert "suspicious_ua" in ev.data["flags"]

    def test_suspicious_ua_wget(self):
        pkt = self._make_http_pkt(ua="Wget/1.21")
        ev = self._parse(pkt)
        assert ev is not None
        assert "suspicious_ua" in ev.data["flags"]

    def test_cross_origin_referer(self):
        pkt = self._make_http_pkt(host="mybank.com", referer="https://evil.com/")
        ev = self._parse(pkt)
        assert ev is not None
        assert "cross_origin_referer" in ev.data["flags"]

    def test_same_origin_referer_no_flag(self):
        pkt = self._make_http_pkt(host="example.com", referer="https://example.com/page")
        ev = self._parse(pkt)
        assert ev is not None
        assert "cross_origin_referer" not in ev.data["flags"]

    def test_post_request(self):
        pkt = self._make_http_pkt(method=b"POST", path="/login", body=b"user=admin&pass=1234")
        ev = self._parse(pkt)
        assert ev is not None
        assert ev.data["method"] == "POST"
        assert ev.severity == "warning"
        assert "keyword:login" in ev.data["flags"]

    def test_non_http_port_returns_none(self):
        pkt = self._make_http_pkt(dport=8080)
        ev = self._parse(pkt)
        assert ev is None

    def test_no_raw_layer_returns_none(self):
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=80, dport=40000)
        ev = self._parse(pkt)
        assert ev is None

    def test_no_tcp_returns_none(self):
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=80, dport=40000) / Raw(b"GET / HTTP/1.1\r\n")
        ev = self._parse(pkt)
        assert ev is None

    def test_invalid_http_line_returns_none(self):
        pkt = self._make_http_pkt()
        pkt[Raw].load = b"NOTHTTP\r\n\r\n"
        ev = self._parse(pkt)
        assert ev is None

    def test_empty_payload_returns_none(self):
        pkt = self._make_http_pkt()
        pkt[Raw].load = b""
        ev = self._parse(pkt)
        assert ev is None

    def test_combined_keyword_and_suspicious_ua(self):
        pkt = self._make_http_pkt(path="/password", ua="sqlmap/1.5")
        ev = self._parse(pkt)
        assert ev is not None
        flags = ev.data["flags"]
        assert "keyword:password" in flags
        assert "suspicious_ua" in flags

    def test_description_contains_flags(self):
        pkt = self._make_http_pkt(path="/login", ua="nikto/2.1")
        ev = self._parse(pkt)
        assert ev is not None
        desc = ev.data["description"]
        assert "keyword:login" in desc
        assert "suspicious_ua" in desc

    def test_counter_increments(self):
        bus = EventBus()
        mon = HttpMonitor(bus)
        assert mon._total_requests == 0
        pkt = self._make_http_pkt()
        mon._parse(pkt)
        assert mon._total_requests == 1
        mon._parse(pkt)
        assert mon._total_requests == 2

    def test_source_ip_in_data(self):
        pkt = self._make_http_pkt(src="10.0.0.42")
        ev = self._parse(pkt)
        assert ev.data["src_ip"] == "10.0.0.42"

    def test_custom_suspicious_keywords(self):
        bus = EventBus()
        mon = HttpMonitor(bus, suspicious_keywords=["admin", "config"])
        pkt = self._make_http_pkt(path="/admin/config")
        ev = mon._parse(pkt)
        assert ev is not None
        assert ev.severity == "warning"
        assert "keyword:admin" in ev.data["flags"]

    def test_path_decoded_correctly(self):
        pkt = self._make_http_pkt(path="/%2F%2F%2F%6C%6F%67%69%6E")
        ev = self._parse(pkt)
        assert ev is not None
        assert ev.data["path"] == "/%2F%2F%2F%6C%6F%67%69%6E"


# ---------------------------------------------------------------------------
# ARP Watcher
# ---------------------------------------------------------------------------

class TestArpWatcherAnalyze:
    def _make_arp(self, op: int = 1, psrc: str = "192.168.1.1",
                  pdst: str = "192.168.1.2", hwsrc: str = "aa:bb:cc:11:22:33",
                  hwdst: str = "00:00:00:00:00:00") -> Ether:
        return Ether(dst="ff:ff:ff:ff:ff:ff", src=hwsrc) / ARP(
            op=op, psrc=psrc, pdst=pdst, hwsrc=hwsrc, hwdst=hwdst
        )

    def _make_ndp_ns(self, src_ip: str = "fe80::1", src_mac: str = "aa:bb:cc:11:22:33",
                     target: str = "fe80::2") -> Ether:
        return (
            Ether(src=src_mac) /
            IPv6(src=src_ip, dst=target) /
            ICMPv6ND_NS(tgt=target) /
            ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
        )

    def _make_ndp_na(self, src_ip: str = "fe80::1", src_mac: str = "aa:bb:cc:11:22:33",
                     target: str = "fe80::2") -> Ether:
        return (
            Ether(src=src_mac) /
            IPv6(src=src_ip, dst=target) /
            ICMPv6ND_NA(tgt=target) /
            ICMPv6NDOptDstLLAddr(lladdr=src_mac)
        )

    def test_arp_request_emits_new_device(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=0)
        watcher._learn_until = 0
        pkt = self._make_arp(op=1, psrc="192.168.1.100")
        evs = watcher._analyze(pkt)
        assert any(e.type == EventType.NEW_DEVICE for e in evs)
        dev = next(e for e in evs if e.type == EventType.NEW_DEVICE)
        assert dev.data["ip"] == "192.168.1.100"

    def test_zero_ip_ignored(self):
        bus = EventBus()
        watcher = ArpWatcher(bus)
        watcher._learn_until = 0
        pkt = self._make_arp(psrc="0.0.0.0")
        evs = watcher._analyze(pkt)
        assert len(evs) == 0

    def test_spoofing_detected_after_learning(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=0)
        watcher._learn_until = 0
        # First ARP — learns IP-MAC
        pkt1 = self._make_arp(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:11:22:33", pdst="192.168.1.1")
        watcher._analyze(pkt1)
        assert watcher._table.get("192.168.1.1") == {"aa:bb:cc:11:22:33"}
        # Second ARP — same IP, different MAC → spoofing
        pkt2 = self._make_arp(op=2, psrc="192.168.1.1", hwsrc="dd:ee:ff:11:22:33", pdst="192.168.1.1")
        evs = watcher._analyze(pkt2)
        anom = [e for e in evs if e.type == EventType.ARP_ANOMALY]
        assert len(anom) >= 1
        assert "spoofing" in anom[0].data["anomaly"]

    def test_gateway_spoofing_is_critical(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, gateway_ip="192.168.1.1", learn_window=0)
        watcher._learn_until = 0
        pkt1 = self._make_arp(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:11:22:33", pdst="192.168.1.1")
        watcher._analyze(pkt1)
        pkt2 = self._make_arp(op=2, psrc="192.168.1.1", hwsrc="ee:ff:aa:bb:cc:dd", pdst="192.168.1.1")
        evs = watcher._analyze(pkt2)
        anom = [e for e in evs if e.type == EventType.ARP_ANOMALY]
        crit = [e for e in anom if e.data.get("is_gateway")]
        assert len(crit) >= 1
        assert crit[0].severity == "critical"
        assert "gateway_spoofing" in crit[0].data["anomaly"]

    def test_gratuitous_arp_detected(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=0)
        watcher._learn_until = 0
        pkt = self._make_arp(op=2, psrc="192.168.1.50", hwsrc="aa:bb:cc:11:22:33", pdst="192.168.1.50")
        evs = watcher._analyze(pkt)
        garp = [e for e in evs if e.data.get("anomaly") == "gratuitous_arp"]
        assert len(garp) >= 1
        assert garp[0].severity == "warning"

    def test_gratuitous_arp_cooldown(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=0)
        watcher._learn_until = 0
        pkt = self._make_arp(op=2, psrc="192.168.1.50", hwsrc="aa:bb:cc:11:22:33", pdst="192.168.1.50")
        watcher._analyze(pkt)
        watcher._analyze(pkt)
        watcher._analyze(pkt)
        garp_count = sum(1 for e in watcher._analyze(pkt) if e.data.get("anomaly") == "gratuitous_arp")
        assert garp_count == 0

    def test_learning_mode_suppresses_anomalies(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=100)
        watcher._learn_until = time.time() + 100
        pkt = self._make_arp(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:11:22:33", pdst="192.168.1.1")
        watcher._analyze(pkt)
        pkt2 = self._make_arp(op=2, psrc="192.168.1.1", hwsrc="dd:ee:ff:11:22:33", pdst="192.168.1.1")
        evs = watcher._analyze(pkt2)
        spoof = [e for e in evs if e.type == EventType.ARP_ANOMALY]
        assert len(spoof) == 0

    def test_ndp_neighbor_solicitation_new_device(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=0)
        watcher._learn_until = 0
        pkt = self._make_ndp_ns()
        evs = watcher._analyze(pkt)
        new = [e for e in evs if e.type == EventType.NEW_DEVICE]
        assert len(new) >= 1

    def test_ndp_neighbor_advertisement_new_device(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=0)
        watcher._learn_until = 0
        pkt = self._make_ndp_na()
        evs = watcher._analyze(pkt)
        new = [e for e in evs if e.type == EventType.NEW_DEVICE]
        assert len(new) >= 1

    def test_non_arp_ndp_packet_returns_empty(self):
        bus = EventBus()
        watcher = ArpWatcher(bus)
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=80, dport=443)
        evs = watcher._analyze(pkt)
        assert evs == []

    def test_flood_detection(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=0)
        watcher._learn_until = 0
        mac = "aa:bb:cc:11:22:33"
        flood_evs = []
        for i in range(25):
            pkt = self._make_arp(hwsrc=mac, hwdst=mac)
            evs = watcher._analyze(pkt)
            flood_evs.extend(evs)
        flood = [e for e in flood_evs if e.data.get("anomaly") == "arp_flood"]
        assert len(flood) >= 1

    def test_gateway_auto_detection(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=0)
        watcher._learn_until = 0
        assert watcher.gateway_ip is None
        pkt = self._make_arp(psrc="192.168.1.1")
        watcher._analyze(pkt)
        assert watcher.gateway_ip == "192.168.1.1"

    def test_total_arp_counter(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=0)
        watcher._learn_until = 0
        assert watcher._total_arp == 0
        pkt = self._make_arp()
        watcher._analyze(pkt)
        assert watcher._total_arp == 1

    def test_stats_property(self):
        bus = EventBus()
        watcher = ArpWatcher(bus, learn_window=0)
        watcher._learn_until = 0
        s = watcher.stats
        assert "total_arp" in s
        assert "total_anomaly" in s
        assert "known_hosts" in s
        assert "learning_mode" in s


# ---------------------------------------------------------------------------
# DHCP Monitor
# ---------------------------------------------------------------------------

class TestDhcpMonitorAnalyze:
    def _make_dhcp_pkt(self, msg_type: int = 1, chaddr: bytes = b'\xaa\xbb\xcc\x11\x22\x33',
                       src: str = "0.0.0.0", dst: str = "255.255.255.255",
                       siaddr: str = "0.0.0.0", server_id: str = "",
                       sport: int = 68, dport: int = 67) -> Ether:
        options = [("message-type", msg_type)]
        if server_id:
            options.append(("server_id", server_id))
        options.append("end")
        return (
            Ether() /
            IP(src=src, dst=dst) /
            UDP(sport=sport, dport=dport) /
            BOOTP(chaddr=chaddr, siaddr=siaddr) /
            DHCP(options=options)
        )

    def test_dhcp_discover_returns_empty(self):
        bus = EventBus()
        mon = DhcpMonitor(bus)
        mon._learn_until = 0
        pkt = self._make_dhcp_pkt(msg_type=1)
        evs = mon._analyze(pkt)
        assert evs is not None
        assert isinstance(evs, list)

    def test_dhcp_offer_from_unknown_server_flagged(self):
        bus = EventBus()
        mon = DhcpMonitor(bus)
        mon._learn_until = 0
        pkt = self._make_dhcp_pkt(msg_type=2, src="10.0.0.5", server_id="10.0.0.5")
        evs = mon._analyze(pkt)
        rogue = [e for e in evs if e.type == EventType.DHCP_ANOMALY]
        assert len(rogue) >= 1
        assert rogue[0].severity == "critical"
        assert "rogue_server" in rogue[0].data["anomaly"]
        assert rogue[0].data["server_ip"] == "10.0.0.5"

    def test_known_server_not_flagged(self):
        bus = EventBus()
        mon = DhcpMonitor(bus, known_servers={"192.168.1.1"})
        mon._learn_until = 0
        pkt = self._make_dhcp_pkt(msg_type=2, src="192.168.1.1", server_id="192.168.1.1")
        evs = mon._analyze(pkt)
        rogue = [e for e in evs if e.type == EventType.DHCP_ANOMALY]
        assert len(rogue) == 0

    def test_learning_mode_suppresses_rogue_detection(self):
        bus = EventBus()
        mon = DhcpMonitor(bus)
        mon._learn_until = time.time() + 100
        pkt = self._make_dhcp_pkt(msg_type=2, src="10.0.0.99", server_id="10.0.0.99")
        evs = mon._analyze(pkt)
        rogue = [e for e in evs if e.type == EventType.DHCP_ANOMALY]
        assert len(rogue) == 0
        assert "10.0.0.99" in mon._known_servers

    def test_dhcp_ack_from_rogue_flagged(self):
        bus = EventBus()
        mon = DhcpMonitor(bus)
        mon._learn_until = 0
        pkt = self._make_dhcp_pkt(msg_type=4, src="10.0.0.5", server_id="10.0.0.5")
        evs = mon._analyze(pkt)
        rogue = [e for e in evs if e.type == EventType.DHCP_ANOMALY]
        assert len(rogue) >= 1

    def test_no_message_type_returns_empty(self):
        bus = EventBus()
        mon = DhcpMonitor(bus)
        pkt = self._make_dhcp_pkt()
        pkt[DHCP].options = [("end")]
        evs = mon._analyze(pkt)
        assert evs == []

    def test_flood_detection(self):
        bus = EventBus()
        mon = DhcpMonitor(bus)
        mon._learn_until = 0
        flood_evs = []
        for i in range(35):
            pkt = self._make_dhcp_pkt(msg_type=1, chaddr=b'\xaa\xbb\xcc\x11\x22\x33')
            evs = mon._analyze(pkt)
            flood_evs.extend(evs)
        flood = [e for e in flood_evs if e.data.get("anomaly") == "dhcp_flood"]
        assert len(flood) >= 1

    def test_counter_stats(self):
        bus = EventBus()
        mon = DhcpMonitor(bus)
        mon._learn_until = 0
        pkt = self._make_dhcp_pkt(msg_type=1)
        mon._analyze(pkt)
        assert mon._total_dhcp >= 1
        assert mon._total_anomaly == 0


# ---------------------------------------------------------------------------
# ICMP Monitor
# ---------------------------------------------------------------------------

class TestIcmpMonitorAnalyze:
    def _make_icmp_echo(self, src: str = "10.0.0.5", dst: str = "192.168.1.1",
                        size: int = 64, broadcast: bool = False) -> Ether:
        ip = IP(src=src, dst="255.255.255.255" if broadcast else dst)
        return ip / ICMP(type=8, code=0) / Raw(b"x" * size)

    def test_normal_echo_no_events(self):
        bus = EventBus()
        mon = IcmpMonitor(bus)
        pkt = self._make_icmp_echo(size=64)
        evs = mon._analyze(pkt)
        assert len([e for e in evs if e.type == EventType.ICMP_ANOMALY]) == 0

    def test_ping_flood_detected(self):
        bus = EventBus()
        mon = IcmpMonitor(bus)
        flood_evs = []
        for i in range(25):
            pkt = self._make_icmp_echo(src="10.0.0.5")
            evs = mon._analyze(pkt)
            flood_evs.extend(evs)
        flood = [e for e in flood_evs if e.data.get("anomaly") == "ping_flood"]
        assert len(flood) >= 1
        assert flood[0].severity == "warning"

    def test_icmp_tunnel_detected(self):
        bus = EventBus()
        mon = IcmpMonitor(bus)
        pkt = self._make_icmp_echo(src="10.0.0.5", size=1500)
        evs = mon._analyze(pkt)
        tunnel = [e for e in evs if e.data.get("anomaly") == "icmp_tunnel"]
        assert len(tunnel) >= 1
        assert tunnel[0].severity == "critical"
        assert tunnel[0].data["size"] >= 1000

    def test_smurf_attack_detected(self):
        bus = EventBus()
        mon = IcmpMonitor(bus)
        smurf_evs = []
        for i in range(8):
            pkt = self._make_icmp_echo(src="10.0.0.5", broadcast=True)
            evs = mon._analyze(pkt)
            smurf_evs.extend(evs)
        smurf = [e for e in smurf_evs if e.data.get("anomaly") == "smurf_attack"]
        assert len(smurf) >= 1
        assert smurf[0].severity == "critical"

    def test_non_icmp_packet_returns_empty(self):
        bus = EventBus()
        mon = IcmpMonitor(bus)
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=80, dport=443)
        evs = mon._analyze(pkt)
        assert evs == []

    def test_icmp_reply_not_analyzed(self):
        bus = EventBus()
        mon = IcmpMonitor(bus)
        pkt = IP(src="1.2.3.4", dst="10.0.0.5") / ICMP(type=0, code=0)
        evs = mon._analyze(pkt)
        assert len(evs) == 0

    def test_counter_stats(self):
        bus = EventBus()
        mon = IcmpMonitor(bus)
        pkt = self._make_icmp_echo(size=64)
        mon._analyze(pkt)
        assert mon._total_icmp == 1


# ---------------------------------------------------------------------------
# Packet Sniffer
# ---------------------------------------------------------------------------

class TestPacketSnifferParse:
    def test_tcp_packet_parsed(self):
        bus = EventBus()
        sniffer = PacketSniffer(bus)
        pkt = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=80, flags="A")
        ev = sniffer._parse(pkt)
        assert ev is not None
        assert ev.type == EventType.PACKET_CAPTURED
        assert ev.data["src_ip"] == "192.168.1.10"
        assert ev.data["protocol"] == "TCP"
        assert ev.data["src_port"] == 40000
        assert ev.severity == "info"

    def test_syn_packet_no_flood(self):
        bus = EventBus()
        sniffer = PacketSniffer(bus)
        pkt = Ether() / IP(src="192.168.1.10", dst="1.2.3.4") / TCP(sport=40000, dport=80, flags="S")
        ev = sniffer._parse(pkt)
        assert ev is not None
        assert ev.severity == "info"

    def test_syn_flood_detected(self):
        bus = EventBus()
        sniffer = PacketSniffer(bus)
        pkt = Ether() / IP(src="10.0.0.5", dst="1.2.3.4") / TCP(sport=40000, dport=80, flags="S")
        critical = False
        for i in range(60):
            ev = sniffer._parse(pkt)
            if ev and ev.severity == "critical":
                critical = True
                break
        assert critical, "SYN flood should reach critical severity"

    def test_udp_packet_parsed(self):
        bus = EventBus()
        sniffer = PacketSniffer(bus)
        pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=40000, dport=53)
        ev = sniffer._parse(pkt)
        assert ev is not None
        assert ev.data["protocol"] == "UDP"
        assert ev.data["src_port"] == 40000
        assert ev.data["dst_port"] == 53

    def test_large_packet_flagged(self):
        bus = EventBus()
        sniffer = PacketSniffer(bus)
        raw = Raw(b"x" * 9000)
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=80, dport=40000, flags="A") / raw
        ev = sniffer._parse(pkt)
        assert ev is not None
        assert ev.severity == "warning"
        assert "large_packet" in ev.data.get("anomaly", "")

    def test_arp_packet_returns_none(self):
        bus = EventBus()
        sniffer = PacketSniffer(bus)
        pkt = Ether() / ARP(psrc="192.168.1.1", hwsrc="aa:bb:cc:11:22:33")
        ev = sniffer._parse(pkt)
        assert ev is None

    def test_new_device_discovered(self):
        bus = EventBus()
        sniffer = PacketSniffer(bus)
        assert "10.0.0.99" not in sniffer._seen_ips
        pkt = Ether() / IP(src="10.0.0.99", dst="8.8.8.8") / UDP(sport=40000, dport=53)
        sniffer._parse(pkt)
        assert "10.0.0.99" in sniffer._seen_ips

    def test_ipv6_packet_parsed(self):
        bus = EventBus()
        sniffer = PacketSniffer(bus)
        pkt = Ether() / IPv6(src="fe80::1", dst="ff02::1") / UDP(sport=40000, dport=53)
        ev = sniffer._parse(pkt)
        assert ev is not None
        assert ev.data["ip_version"] == 6

    def test_icmp_packet_included(self):
        bus = EventBus()
        sniffer = PacketSniffer(bus)
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / ICMP(type=8, code=0)
        ev = sniffer._parse(pkt)
        assert ev is not None
        assert ev.data["protocol"] == "ICMP"
        assert ev.data.get("icmp_type") == 8

    def test_own_ip_syn_not_counted(self):
        bus = EventBus()
        sniffer = PacketSniffer(bus, own_ip="192.168.1.10")
        pkt = Ether() / IP(src="192.168.1.10", dst="1.2.3.4") / TCP(sport=40000, dport=80, flags="S")
        for i in range(60):
            ev = sniffer._parse(pkt)
            assert ev is None or ev.severity != "critical"


# ---------------------------------------------------------------------------
# DNS Monitor
# ---------------------------------------------------------------------------

class TestDnsMonitorParse:
    def _make_dns_query(self, qname: str = "example.com", qtype: int = 1,
                        src: str = "192.168.1.10", dst: str = "8.8.8.8") -> Ether:
        return (
            Ether() /
            IP(src=src, dst=dst) /
            UDP(sport=40000, dport=53) /
            DNS(id=1, qr=0, qd=DNSQR(qname=qname, qtype=qtype))
        )

    def _make_dns_response(self, qname: str = "example.com", rcode: int = 0,
                           answers: list[str] = None,
                           src: str = "8.8.8.8", dst: str = "192.168.1.10") -> Ether:
        dns = DNS(id=1, qr=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=1))
        if answers:
            dns.an = DNSRR(rrname=qname, type=1, rdata=answers[0])
            for ip in answers[1:]:
                last = dns.an
                while last.payload:
                    last = last.payload
                last.payload = DNSRR(rrname=qname, type=1, rdata=ip)
            dns.ancount = len(answers)
        return (
            Ether() /
            IP(src=src, dst=dst) /
            UDP(sport=53, dport=40000) /
            dns
        )

    def test_dns_query_parsed(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        pkt = self._make_dns_query(qname="google.com")
        evs = mon._parse_dns(pkt)
        assert len(evs) == 1
        assert evs[0].type == EventType.DNS_QUERY
        assert evs[0].data["query_name"] == "google.com"
        assert evs[0].data["query_type"] == "A"
        assert evs[0].data["blocked"] is False

    def test_dns_query_aaaa_type(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        pkt = self._make_dns_query(qname="google.com", qtype=28)
        evs = mon._parse_dns(pkt)
        assert evs[0].data["query_type"] == "AAAA"

    def test_blocked_domain_returns_blocked_event(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        mon._blocklist.add("evil.com")
        pkt = self._make_dns_query(qname="evil.com")
        evs = mon._parse_dns(pkt)
        assert len(evs) == 1
        assert evs[0].type == EventType.DNS_BLOCKED
        assert evs[0].severity == "warning"
        assert evs[0].data["blocked"] is True

    def test_builtin_blocklist_blocks(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        pkt = self._make_dns_query(qname="doubleclick.net")
        evs = mon._parse_dns(pkt)
        assert evs[0].type == EventType.DNS_BLOCKED

    def test_wildcard_blocklist(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        mon._wildcards.append("malware.test")
        pkt = self._make_dns_query(qname="sub.malware.test")
        evs = mon._parse_dns(pkt)
        assert len(evs) == 1
        assert evs[0].type == EventType.DNS_BLOCKED

    def test_non_blocked_passes(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        pkt = self._make_dns_query(qname="safe-site.com")
        evs = mon._parse_dns(pkt)
        assert evs[0].type == EventType.DNS_QUERY

    def test_response_nxdomain_flood(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        mon._learn_until = 0
        flood_evs = []
        for i in range(25):
            pkt = self._make_dns_response(rcode=3, dst="192.168.1.10")
            evs = mon._parse_dns(pkt)
            flood_evs.extend(evs)
        nx = [e for e in flood_evs if e.data.get("anomaly") == "nxdomain_flood"]
        assert len(nx) >= 1

    def test_answer_change_detected(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        pkt1 = self._make_dns_response(qname="example.com", answers=["1.2.3.4"], dst="192.168.1.10")
        mon._parse_dns(pkt1)
        pkt2 = self._make_dns_response(qname="example.com", answers=["5.6.7.8"], dst="192.168.1.10")
        evs = mon._parse_dns(pkt2)
        change = [e for e in evs if e.data.get("anomaly") == "answer_change"]
        assert len(change) >= 1
        assert "5.6.7.8" in change[0].data["current_answers"]
        assert "1.2.3.4" in change[0].data["previous_answers"]

    def test_same_answer_not_anomaly(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        pkt1 = self._make_dns_response(qname="example.com", answers=["1.2.3.4"], dst="192.168.1.10")
        mon._parse_dns(pkt1)
        pkt2 = self._make_dns_response(qname="example.com", answers=["1.2.3.4"], dst="192.168.1.10")
        evs = mon._parse_dns(pkt2)
        change = [e for e in evs if e.data.get("anomaly") == "answer_change"]
        assert len(change) == 0

    def test_no_dns_layer_returns_empty(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / UDP(sport=53, dport=40000)
        evs = mon._parse_dns(pkt)
        assert evs == []

    def test_domain_case_insensitive_block(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        mon._blocklist.add("evil.com")
        pkt = self._make_dns_query(qname="EVIL.COM")
        evs = mon._parse_dns(pkt)
        assert evs[0].type == EventType.DNS_BLOCKED

    def test_query_type_name_mapping(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        for qtype, name in [(1, "A"), (28, "AAAA"), (15, "MX"), (12, "PTR")]:
            assert mon._qtype_name(qtype) == name
        assert mon._qtype_name(99) == "99"

    def test_stats_property(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        s = mon.stats
        assert "total_queries" in s
        assert "total_blocked" in s
        assert "blocklist_size" in s

    def test_add_domain(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        mon.add_domain("new-threat.com")
        assert "new-threat.com" in mon._blocklist

    def test_remove_domain(self):
        bus = EventBus()
        mon = DnsMonitor(bus)
        mon._blocklist.add("test.com")
        mon.remove_domain("test.com")
        assert "test.com" not in mon._blocklist

    def test_load_blocklist_file(self, tmp_path):
        bus = EventBus()
        bl = tmp_path / "blocklist.txt"
        bl.write_text("evil.com\n*.danger.test\n# comment\n\n")
        mon = DnsMonitor(bus, blocklist_path=bl)
        assert "evil.com" in mon._blocklist
        assert "danger.test" in mon._wildcards

    def test_blocklist_reload_skips_same_mtime(self):
        bus = EventBus()
        bl_file = tmp_path_factory = None
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("test.com\n")
            bl_path = f.name
        try:
            bus2 = EventBus()
            mon = DnsMonitor(bus2, blocklist_path=bl_path)
            original = set(mon._blocklist)
            mon._load_blocklist(bl_path)
            assert mon._blocklist == original
        finally:
            import os
            os.unlink(bl_path)


# ---------------------------------------------------------------------------
# TLS Monitor
# ---------------------------------------------------------------------------

class TestTlsMonitorParse:
    def _make_client_hello(self, sni: str = "example.com") -> bytes:
        sni_bytes = sni.encode() if sni else b""

        body = bytes([0x03, 0x03]) + b"\x00" * 32
        body += b"\x00"  # session_id length = 0
        cipher_suites = [0x1301, 0x1302, 0x1303]
        body += struct.pack(">H", len(cipher_suites) * 2)  # cipher_suites length
        for cs in cipher_suites:
            body += struct.pack(">H", cs)
        body += b"\x01\x00"

        ext_data = b""
        if sni_bytes:
            name_entry = b"\x00" + struct.pack(">H", len(sni_bytes)) + sni_bytes
            sni_list = struct.pack(">H", len(name_entry)) + name_entry
            ext_data += struct.pack(">HH", 0x0000, len(sni_list))
            ext_data += sni_list

        groups = struct.pack(">HH", 0x000a, 6)
        groups += b"\x00\x04\x00\x1d\x00\x17"
        ext_data += groups

        ec = struct.pack(">HH", 0x000b, 3)
        ec += b"\x02\x01\x02"
        ext_data += ec

        body += struct.pack(">H", len(ext_data))
        body += ext_data

        hs_len = len(body)
        record = b"\x16\x03\x01" + struct.pack(">H", hs_len + 4)
        record += b"\x01" + struct.pack(">I", hs_len)[1:]
        record += body
        return record

    def test_normal_tls_parsed(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        raw = self._make_client_hello(sni="example.com")
        pkt = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=443) / Raw(raw)
        ev = mon._parse_tls(pkt)
        assert ev is not None
        assert ev.data["sni"] == "example.com"
        assert ev.severity == "info"

    def test_no_sni_still_parsed(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        raw = self._make_client_hello(sni="")
        pkt = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=40000, dport=443) / Raw(raw)
        ev = mon._parse_tls(pkt)
        assert ev is not None
        assert ev.data["sni"] == ""

    def test_no_tcp_payload_returns_none(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=40000, dport=443)
        ev = mon._parse_tls(pkt)
        assert ev is None

    def test_no_ip_layer_returns_none(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        pkt = Ether() / TCP(sport=40000, dport=443) / Raw(b"test")
        ev = mon._parse_tls(pkt)
        assert ev is None

    def test_non_client_hello_returns_none(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        raw = b"\x16\x03\x04\x00\x05\x02\x00\x00\x01\x00"
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=40000, dport=443) / Raw(raw)
        ev = mon._parse_tls(pkt)
        assert ev is None

    def test_not_tls_record_returns_none(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        raw = b"\x15\x03\x04\x00\x02\x00\x00"
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=40000, dport=443) / Raw(raw)
        ev = mon._parse_tls(pkt)
        assert ev is None

    def test_truncated_record_returns_none(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        raw = b"\x16\x03\x04\xff\xff\x01"
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=40000, dport=443) / Raw(raw)
        ev = mon._parse_tls(pkt)
        assert ev is None

    def test_ja3_consistency(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        raw = self._make_client_hello(sni="test.com")
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=40000, dport=443) / Raw(raw)
        ev = mon._parse_tls(pkt)
        raw2 = self._make_client_hello(sni="test.com")
        pkt2 = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=40000, dport=443) / Raw(raw2)
        ev2 = mon._parse_tls(pkt2)
        assert ev.data["ja3"] == ev2.data["ja3"]

    def test_ja3_length_at_least_32(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        raw = self._make_client_hello(sni="test.com")
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=40000, dport=443) / Raw(raw)
        ev = mon._parse_tls(pkt)
        assert len(ev.data["ja3"]) == 32

    def test_tls_version_in_data(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        raw = self._make_client_hello(sni="test.com")
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=40000, dport=443) / Raw(raw)
        ev = mon._parse_tls(pkt)
        assert ev.data["tls_version"] is not None

    def test_counter_increments(self):
        bus = EventBus()
        mon = TlsMonitor(bus)
        raw = self._make_client_hello(sni="test.com")
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=40000, dport=443) / Raw(raw)
        assert mon._total_connections == 0
        mon._parse_tls(pkt)
        assert mon._total_connections == 1
