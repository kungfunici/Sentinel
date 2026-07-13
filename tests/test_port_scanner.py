import time
import asyncio
import pytest
from sentinel.collectors.port_scanner import PortScanner, is_private, HIGH_RISK_PORTS, DEFAULT_PORTS
from sentinel.core.event_bus import Event, EventBus, EventType

pytestmark = pytest.mark.asyncio


class TestIsPrivate:
    def test_private_10_dot(self):
        assert is_private("10.0.0.1") is True

    def test_private_192_168(self):
        assert is_private("192.168.1.1") is True

    def test_private_172_16(self):
        assert is_private("172.16.0.1") is True
        assert is_private("172.31.255.255") is True

    def test_public_ip(self):
        assert is_private("8.8.8.8") is False
        assert is_private("93.184.216.34") is False

    def test_invalid_ip(self):
        assert is_private("not.an.ip") is False
        assert is_private("") is False

    def test_link_local_not_private(self):
        assert is_private("169.254.1.1") is False

    def test_loopback_not_private(self):
        assert is_private("127.0.0.1") is False


class TestHighRiskPorts:
    def test_ssh_is_high_risk(self):
        assert 22 in HIGH_RISK_PORTS

    def test_telnet_is_high_risk(self):
        assert 23 in HIGH_RISK_PORTS

    def test_rdp_is_high_risk(self):
        assert 3389 in HIGH_RISK_PORTS

    def test_vnc_is_high_risk(self):
        assert 5900 in HIGH_RISK_PORTS

    def test_smb_is_high_risk(self):
        assert 445 in HIGH_RISK_PORTS

    def test_redis_is_high_risk(self):
        assert 6379 in HIGH_RISK_PORTS

    def test_mongodb_is_high_risk(self):
        assert 27017 in HIGH_RISK_PORTS

    def test_http_not_high_risk(self):
        assert 80 not in HIGH_RISK_PORTS

    def test_https_not_high_risk(self):
        assert 443 not in HIGH_RISK_PORTS


class TestDefaultPorts:
    def test_common_ports_present(self):
        for p in [21, 22, 23, 80, 443, 3306, 3389, 8080]:
            assert p in DEFAULT_PORTS

    def test_no_duplicates(self):
        assert len(DEFAULT_PORTS) == len(set(DEFAULT_PORTS))


class TestPortScannerProcessResults:
    async def test_first_scan_emits_info(self):
        bus = EventBus()
        scanner = PortScanner(bus)
        received = []

        async with bus.subscribe(min_severity="info") as sub:
            async def collect():
                async for e in sub:
                    received.append(e)
                    return
            task = asyncio.create_task(collect())
            await asyncio.sleep(0.05)
            await scanner._process_results("192.168.1.10", {22, 80}, time.time())
            await asyncio.wait_for(task, timeout=2)

        assert len(received) >= 1
        assert received[0].severity == "info"
        assert received[0].data["first_scan"] is True

    async def test_new_high_risk_port_emits_critical(self):
        bus = EventBus()
        scanner = PortScanner(bus)
        scanner._known_open["192.168.1.10"] = {80, 443}
        received = []

        async with bus.subscribe(min_severity="info") as sub:
            async def collect():
                async for e in sub:
                    received.append(e)
                    return
            task = asyncio.create_task(collect())
            await asyncio.sleep(0.05)
            await scanner._process_results("192.168.1.10", {22, 80, 443}, time.time())
            await asyncio.wait_for(task, timeout=2)

        assert len(received) >= 1
        assert received[0].severity == "critical"
        assert 22 in received[0].data["high_risk"]

    async def test_new_non_high_risk_port_emits_warning(self):
        bus = EventBus()
        scanner = PortScanner(bus)
        scanner._known_open["192.168.1.10"] = {80}
        received = []

        async with bus.subscribe(min_severity="info") as sub:
            async def collect():
                async for e in sub:
                    received.append(e)
                    return
            task = asyncio.create_task(collect())
            await asyncio.sleep(0.05)
            await scanner._process_results("192.168.1.10", {80, 8080}, time.time())
            await asyncio.wait_for(task, timeout=2)

        assert len(received) >= 1
        assert received[0].severity == "warning"
        assert received[0].data["high_risk"] == []

    async def test_port_closed_emits_info(self):
        bus = EventBus()
        scanner = PortScanner(bus)
        scanner._known_open["192.168.1.10"] = {22, 80, 443}
        received = []

        async with bus.subscribe(min_severity="info") as sub:
            async def collect():
                async for e in sub:
                    received.append(e)
                    return
            task = asyncio.create_task(collect())
            await asyncio.sleep(0.05)
            await scanner._process_results("192.168.1.10", {80, 443}, time.time())
            await asyncio.wait_for(task, timeout=2)

        assert len(received) >= 1
        assert received[0].severity == "info"
        assert 22 in received[0].data["closed_ports"]

    async def test_no_changes_no_event(self):
        bus = EventBus()
        scanner = PortScanner(bus)
        scanner._known_open["192.168.1.10"] = {80, 443}
        published = []

        original_publish = scanner.bus.publish
        scanner.bus.publish = lambda ev: published.append(ev)

        await scanner._process_results("192.168.1.10", {80, 443}, time.time())
        assert len(published) == 0

        scanner.bus.publish = original_publish

    def test_add_target_only_private(self):
        bus = EventBus()
        scanner = PortScanner(bus)
        scanner.add_target("8.8.8.8")
        assert "8.8.8.8" not in scanner._targets
        scanner.add_target("192.168.1.50")
        assert "192.168.1.50" in scanner._targets

    def test_own_ip_excluded_from_targets(self):
        bus = EventBus()
        scanner = PortScanner(bus, own_ip="192.168.1.10")
        scanner.add_target("192.168.1.10")
        assert "192.168.1.10" not in scanner._targets

    def test_open_ports_for_returns_sorted(self):
        bus = EventBus()
        scanner = PortScanner(bus)
        scanner._known_open["192.168.1.10"] = {443, 80, 22}
        assert scanner.open_ports_for("192.168.1.10") == [22, 80, 443]

    def test_open_ports_for_unknown_returns_empty(self):
        bus = EventBus()
        scanner = PortScanner(bus)
        assert scanner.open_ports_for("1.2.3.4") == []

    def test_stats_property(self):
        bus = EventBus()
        scanner = PortScanner(bus)
        s = scanner.stats
        assert "targets" in s
        assert "scanned_hosts" in s
        assert "total_open_ports" in s
        assert "interval" in s
