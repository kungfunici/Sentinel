import argparse
import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from sentinel.main import (
    load_json_config, setup_logging, _format_detail, _apply_config_defaults,
    LiveDisplay,
)
from sentinel.core.event_bus import Event, EventType


class TestLoadJsonConfig:
    def test_file_not_found_returns_empty(self):
        result = load_json_config("/nonexistent/path.json")
        assert result == {}

    def test_invalid_json_returns_empty(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not json")
            path = f.name
        try:
            result = load_json_config(path)
            assert result == {}
        finally:
            Path(path).unlink()

    def test_valid_json_returns_dict(self):
        data = {"key": "value", "num": 42}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            path = f.name
        try:
            result = load_json_config(path)
            assert result == data
        finally:
            Path(path).unlink()


class TestSetupLogging:
    def test_verbose_sets_debug(self):
        with patch("sentinel.main.logging.getLogger") as mock_get:
            setup_logging(verbose=True)

    def test_non_verbose_sets_info(self):
        with patch("sentinel.main.logging.getLogger") as mock_get:
            setup_logging(verbose=False)

    def test_scapy_logger_set_to_warning(self):
        with patch("sentinel.main.logging.getLogger") as mock_get:
            setup_logging(verbose=True)
            mock_get.assert_any_call("scapy")


class TestFormatDetail:
    def test_packet_captured(self):
        ev = Event(
            type=EventType.PACKET_CAPTURED, severity="info", source="sniffer",
            data={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80, "protocol": "TCP", "flags": "SYN"},
        )
        result = _format_detail(ev)
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result
        assert ":80" in result
        assert "SYN" in result

    def test_packet_captured_no_flags(self):
        ev = Event(
            type=EventType.PACKET_CAPTURED, severity="info", source="sniffer",
            data={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
        )
        result = _format_detail(ev)
        assert "10.0.0.1" in result

    def test_dns_query(self):
        ev = Event(
            type=EventType.DNS_QUERY, severity="info", source="dns",
            data={"src_ip": "10.0.0.1", "query_name": "example.com", "query_type": "A"},
        )
        result = _format_detail(ev)
        assert "example.com" in result
        assert "A" in result

    def test_dns_blocked(self):
        ev = Event(
            type=EventType.DNS_BLOCKED, severity="info", source="dns",
            data={"src_ip": "10.0.0.1", "query_name": "evil.com", "query_type": "A", "blocked": True},
        )
        result = _format_detail(ev)
        assert "BLOCKED" in result

    def test_new_device(self):
        ev = Event(
            type=EventType.NEW_DEVICE, severity="info", source="arp",
            data={"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"},
        )
        result = _format_detail(ev)
        assert "10.0.0.1" in result
        assert "aa:bb:cc:dd:ee:ff" in result

    def test_new_device_no_mac(self):
        ev = Event(
            type=EventType.NEW_DEVICE, severity="info", source="arp",
            data={"ip": "10.0.0.1"},
        )
        result = _format_detail(ev)
        assert "10.0.0.1" in result

    def test_arp_anomaly(self):
        ev = Event(
            type=EventType.ARP_ANOMALY, severity="warning", source="arp",
            data={"description": "ARP spoof detected"},
        )
        result = _format_detail(ev)
        assert "ARP spoof" in result

    def test_http_request(self):
        ev = Event(
            type=EventType.HTTP_REQUEST, severity="info", source="http",
            data={"description": "Suspicious HTTP request"},
        )
        result = _format_detail(ev)
        assert "Suspicious" in result

    def test_icmp_anomaly(self):
        ev = Event(
            type=EventType.ICMP_ANOMALY, severity="warning", source="icmp",
            data={"description": "Ping flood detected"},
        )
        result = _format_detail(ev)
        assert "Ping flood" in result

    def test_dhcp_anomaly(self):
        ev = Event(
            type=EventType.DHCP_ANOMALY, severity="warning", source="dhcp",
            data={"description": "Rogue DHCP server"},
        )
        result = _format_detail(ev)
        assert "Rogue" in result

    def test_dns_anomaly(self):
        ev = Event(
            type=EventType.DNS_ANOMALY, severity="warning", source="dns",
            data={"description": "NXDOMAIN flood"},
        )
        result = _format_detail(ev)
        assert "NXDOMAIN" in result

    def test_bandwidth_report(self):
        ev = Event(
            type=EventType.BANDWIDTH_REPORT, severity="info", source="bw",
            data={"description": "Bandwidth report"},
        )
        result = _format_detail(ev)
        assert "Bandwidth" in result

    def test_fallback_to_dict(self):
        ev = Event(
            type=EventType.SENTINEL_START, severity="info", source="main",
            data={"foo": "bar"},
        )
        result = _format_detail(ev)
        assert "foo" in result

    def test_unknown_type_with_no_data(self):
        ev = Event(
            type=EventType.SENTINEL_START, severity="info", source="main",
            data={},
        )
        result = _format_detail(ev)
        assert isinstance(result, str)


class TestApplyConfigDefaults:
    def test_apply_defaults_overrides_parser(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--iface", default=None)
        parser.add_argument("--db", default="sentinel.db")
        config = {"iface": "eth0", "db": "custom.db"}
        _apply_config_defaults(parser, config)
        assert parser.get_default("iface") == "eth0"
        assert parser.get_default("db") == "custom.db"

    def test_unknown_config_keys_ignored(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--iface", default=None)
        config = {"unknown_key": "value", "iface": "eth0"}
        _apply_config_defaults(parser, config)
        assert parser.get_default("iface") == "eth0"

    def test_none_values_ignored(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--iface", default="default")
        config = {"iface": None}
        _apply_config_defaults(parser, config)
        assert parser.get_default("iface") == "default"

    def test_empty_config_no_change(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--iface", default="default")
        _apply_config_defaults(parser, {})
        assert parser.get_default("iface") == "default"


class TestLiveDisplay:
    def test_add_event_increments_count(self):
        display = LiveDisplay(max_rows=5)
        ev = Event(type=EventType.HTTP_REQUEST, severity="info", source="http", data={})
        display.add(ev)
        assert display._counts["info"] == 1

    def test_add_max_rows_trims_oldest(self):
        display = LiveDisplay(max_rows=3)
        for i in range(5):
            ev = Event(type=EventType.HTTP_REQUEST, severity="info", source="test", data={"i": i})
            display.add(ev)
        assert len(display._events) == 3
        assert display._events[0].data["i"] == 2

    def test_add_multiple_severities(self):
        display = LiveDisplay()
        display.add(Event(type=EventType.HTTP_REQUEST, severity="warning", source="http", data={}))
        display.add(Event(type=EventType.ERROR, severity="critical", source="main", data={}))
        assert display._counts["warning"] == 1
        assert display._counts["critical"] == 1

    def test_build_table_returns_table(self):
        from rich.table import Table
        display = LiveDisplay()
        display.add(Event(type=EventType.HTTP_REQUEST, severity="info", source="http", data={}))
        table = display.build_table()
        assert isinstance(table, Table)
