import json
from rich.table import Table
from sentinel.cli.query import fmt_time, fmt_data, events_table, dns_table, devices_table, stats_table


class TestFmtTime:
    def test_returns_string(self):
        result = fmt_time(0)
        assert isinstance(result, str)

    def test_known_timestamp(self):
        result = fmt_time(1000000000)
        assert "2001" in result


class TestFmtData:
    def test_src_dst_ip(self):
        raw = json.dumps({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80, "protocol": "TCP"})
        result = fmt_data(raw)
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result
        assert "TCP" in result

    def test_port_and_flags(self):
        raw = json.dumps({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 443, "flags": "SYN"})
        result = fmt_data(raw)
        assert ":443" in result
        assert "SYN" in result

    def test_dns_query(self):
        raw = json.dumps({"src_ip": "10.0.0.1", "query_name": "example.com", "query_type": "A"})
        result = fmt_data(raw)
        assert "example.com" in result
        assert "A" in result

    def test_dns_blocked(self):
        raw = json.dumps({"src_ip": "10.0.0.1", "query_name": "evil.com", "query_type": "A", "blocked": True})
        result = fmt_data(raw)
        assert "BLOCKED" in result

    def test_ip_mac(self):
        raw = json.dumps({"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"})
        result = fmt_data(raw)
        assert "10.0.0.1" in result
        assert "aa:bb:cc:dd:ee:ff" in result

    def test_fallback_to_dict(self):
        raw = json.dumps({"foo": "bar"})
        result = fmt_data(raw)
        assert "foo" in result
        assert "bar" in result

    def test_invalid_json(self):
        result = fmt_data("not json")
        assert result == "not json"

    def test_truncated_long_data(self):
        raw = json.dumps({"x": "a" * 200})
        result = fmt_data(raw)
        assert len(result) <= 120


class TestEventsTable:
    def test_returns_table(self):
        rows = [
            {"id": 1, "timestamp": 1000000000, "severity": "info", "type": "dns.query", "source": "dns",
             "data": '{"description": "test"}'},
        ]
        table = events_table(rows)
        assert isinstance(table, Table)
        assert len(table.columns) == 6

    def test_empty_rows_returns_table(self):
        table = events_table([])
        assert isinstance(table, Table)


class TestDnsTable:
    def test_returns_table(self):
        rows = [
            {"id": 1, "timestamp": 1000000000, "src_ip": "10.0.0.1", "query_name": "example.com", "query_type": "A",
             "blocked": False},
        ]
        table = dns_table(rows)
        assert isinstance(table, Table)
        assert len(table.columns) == 6

    def test_blocked_shows_yes(self):
        rows = [
            {"id": 1, "timestamp": 1000000000, "src_ip": "10.0.0.1", "query_name": "evil.com", "query_type": "A",
             "blocked": True},
        ]
        table = dns_table(rows)
        assert isinstance(table, Table)

    def test_empty_rows(self):
        table = dns_table([])
        assert isinstance(table, Table)


class TestDevicesTable:
    def test_returns_table(self):
        rows = [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "test", "vendor": "Intel",
             "first_seen": 1000000000, "last_seen": 1000000000, "flagged": False},
        ]
        table = devices_table(rows)
        assert isinstance(table, Table)
        assert len(table.columns) == 7

    def test_flagged_shows_yes(self):
        rows = [
            {"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": None, "vendor": None,
             "first_seen": 1000000000, "last_seen": 1000000000, "flagged": True},
        ]
        table = devices_table(rows)
        assert isinstance(table, Table)

    def test_empty_rows(self):
        table = devices_table([])
        assert isinstance(table, Table)


class TestStatsTable:
    def test_returns_table(self):
        s = {"events": 100, "dns_queries": 50, "dns_blocked": 5, "packets": 200, "devices": 10}
        table = stats_table(s)
        assert isinstance(table, Table)
        assert len(table.columns) == 2

    def test_empty_stats(self):
        table = stats_table({})
        assert isinstance(table, Table)
