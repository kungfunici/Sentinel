import pytest
from unittest.mock import AsyncMock, MagicMock
from sentinel.cli.shell import SentinelShell, fmt_time, fmt_data
from sentinel.core.event_bus import EventBus


class FakeDb:
    def __init__(self):
        self.query_events = AsyncMock(return_value=[])
        self.query_dns = AsyncMock(return_value=[])
        self.query_devices = AsyncMock(return_value=[])
        self.stats = AsyncMock(return_value={})
        self.flag_device = AsyncMock()
        self.flag_device = AsyncMock()


@pytest.fixture
def shell():
    db = FakeDb()
    bus = EventBus()
    return SentinelShell(db, bus)


class TestFmtTime:
    def test_returns_string(self):
        result = fmt_time(0)
        assert isinstance(result, str)


class TestFmtData:
    def test_src_dst_ip(self):
        import json
        raw = json.dumps({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "dst_port": 80, "flags": "SYN", "protocol": "TCP"})
        result = fmt_data(raw)
        assert "10.0.0.1" in result

    def test_dns_query(self):
        import json
        raw = json.dumps({"src_ip": "10.0.0.1", "query_name": "example.com", "query_type": "A"})
        result = fmt_data(raw)
        assert "example.com" in result

    def test_device(self):
        import json
        raw = json.dumps({"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff"})
        result = fmt_data(raw)
        assert "10.0.0.1" in result

    def test_description(self):
        import json
        raw = json.dumps({"description": "custom event"})
        result = fmt_data(raw)
        assert result == "custom event"

    def test_invalid_json(self):
        result = fmt_data("not json")
        assert result == "not json"


class TestGetHandler:
    def test_help_command(self, shell):
        assert shell._get_handler("help") == shell._help

    def test_question_mark(self, shell):
        assert shell._get_handler("?") == shell._help

    def test_events_command(self, shell):
        assert shell._get_handler("events") == shell._events

    def test_dns_command(self, shell):
        assert shell._get_handler("dns") == shell._dns

    def test_devices_command(self, shell):
        assert shell._get_handler("devices") == shell._devices

    def test_stats_command(self, shell):
        assert shell._get_handler("stats") == shell._stats

    def test_tail_command(self, shell):
        assert shell._get_handler("tail") == shell._tail

    def test_flag_command(self, shell):
        assert shell._get_handler("flag") == shell._flag

    def test_unflag_command(self, shell):
        assert shell._get_handler("unflag") == shell._unflag

    def test_block_command(self, shell):
        assert shell._get_handler("block") == shell._block

    def test_clear_command(self, shell):
        assert shell._get_handler("clear") == shell._clear

    def test_history_command(self, shell):
        assert shell._get_handler("history") == shell._history_cmd

    def test_exit_command(self, shell):
        assert shell._get_handler("exit") == shell._exit

    def test_quit_command(self, shell):
        assert shell._get_handler("quit") == shell._exit

    def test_unknown_command(self, shell):
        assert shell._get_handler("unknown") is None


class TestShellCommands:
    async def test_events_empty(self, shell):
        await shell._events([])
        shell.db.query_events.assert_awaited_once()

    async def test_events_with_severity(self, shell):
        await shell._events(["warning"])
        shell.db.query_events.assert_awaited_once()

    async def test_events_with_limit(self, shell):
        await shell._events(["limit=10"])
        shell.db.query_events.assert_awaited_once_with(severity=None, limit=10)

    async def test_dns_default(self, shell):
        await shell._dns([])
        shell.db.query_dns.assert_awaited_once_with(blocked_only=False, limit=50)

    async def test_dns_blocked(self, shell):
        await shell._dns(["--blocked"])
        shell.db.query_dns.assert_awaited_once_with(blocked_only=True, limit=50)

    async def test_devices_default(self, shell):
        await shell._devices([])
        shell.db.query_devices.assert_awaited_once_with(flagged_only=False)

    async def test_devices_flagged(self, shell):
        await shell._devices(["--flagged"])
        shell.db.query_devices.assert_awaited_once_with(flagged_only=True)

    async def test_stats(self, shell):
        await shell._stats([])
        shell.db.stats.assert_awaited_once()

    async def test_flag(self, shell):
        await shell._flag(["10.0.0.1"])
        shell.db.flag_device.assert_awaited_once_with("10.0.0.1", flagged=True)

    async def test_unflag(self, shell):
        await shell._unflag(["10.0.0.1"])
        shell.db.flag_device.assert_awaited_once_with("10.0.0.1", flagged=False)

    async def test_flag_no_args_prints_usage(self, shell):
        await shell._flag([])
        shell.db.flag_device.assert_not_awaited()

    async def test_exit_sets_running_false(self, shell):
        assert shell._running is True
        await shell._exit([])
        assert shell._running is False

    async def test_events_invalid_limit(self, shell):
        await shell._events(["limit=abc"])
        shell.db.query_events.assert_not_awaited()

    async def test_events_unknown_arg(self, shell):
        await shell._events(["bogus"])
        shell.db.query_events.assert_not_awaited()

    async def test_dns_invalid_limit(self, shell):
        await shell._dns(["limit=abc"])
        shell.db.query_dns.assert_not_awaited()

    async def test_dns_unknown_arg(self, shell):
        await shell._dns(["bogus"])
        shell.db.query_dns.assert_not_awaited()
