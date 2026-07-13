import time
import pytest
from sentinel.core.database import Database
from sentinel.core.event_bus import Event, EventType


@pytest.fixture
async def db(tmp_path):
    path = tmp_path / "test.db"
    async with Database(path) as d:
        yield d


@pytest.mark.asyncio
class TestDatabase:
    async def test_setup_creates_tables(self, db):
        rows = await db._conn.execute_fetchall(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [r["name"] for r in rows]
        assert "events" in tables
        assert "dns_queries" in tables
        assert "packets" in tables
        assert "devices" in tables

    async def test_write_and_query_event(self, db):
        event = Event(
            type=EventType.NEW_DEVICE,
            data={"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:ff"},
            severity="info",
            source="test",
        )
        event_id = await db.write_event(event)
        assert event_id > 0

        rows = await db.query_events(limit=10)
        assert len(rows) == 1
        assert rows[0]["type"] == "device.new"
        assert rows[0]["severity"] == "info"

    async def test_write_dns_query(self, db):
        event = Event(
            type=EventType.DNS_QUERY,
            data={"src_ip": "192.168.1.5", "query_name": "example.com", "query_type": "A"},
            severity="info",
            source="dns",
        )
        await db.write_event(event)

        rows = await db.query_dns(limit=10)
        assert len(rows) == 1
        assert rows[0]["query_name"] == "example.com"
        assert rows[0]["blocked"] == 0

    async def test_write_blocked_dns(self, db):
        event = Event(
            type=EventType.DNS_BLOCKED,
            data={"src_ip": "192.168.1.5", "query_name": "bad.example.com", "query_type": "A"},
            severity="warning",
            source="dns",
        )
        await db.write_event(event)

        rows = await db.query_dns(blocked_only=True, limit=10)
        assert len(rows) == 1
        assert rows[0]["blocked"] == 1

    async def test_write_device_upsert(self, db):
        event1 = Event(
            type=EventType.NEW_DEVICE,
            data={"ip": "192.168.1.1", "mac": "aa:bb:cc:11:22:33"},
            severity="info",
            source="sniffer",
        )
        await db.write_event(event1)

        devices = await db.query_devices()
        assert len(devices) == 1
        assert devices[0]["mac"] == "aa:bb:cc:11:22:33"

        event2 = Event(
            type=EventType.NEW_DEVICE,
            data={"ip": "192.168.1.1", "hostname": "router.local"},
            severity="info",
            source="enricher",
        )
        await db.write_event(event2)

        devices = await db.query_devices()
        assert len(devices) == 1
        assert devices[0]["hostname"] == "router.local"
        assert devices[0]["mac"] == "aa:bb:cc:11:22:33"

    async def test_flag_device(self, db):
        event = Event(
            type=EventType.NEW_DEVICE,
            data={"ip": "10.0.0.5", "mac": "11:22:33:44:55:66"},
            severity="info",
            source="test",
        )
        await db.write_event(event)

        await db.flag_device("10.0.0.5", flagged=True)
        flagged = await db.query_devices(flagged_only=True)
        assert len(flagged) == 1

        await db.flag_device("10.0.0.5", flagged=False)
        flagged = await db.query_devices(flagged_only=True)
        assert len(flagged) == 0

    async def test_severity_filter(self, db):
        for sev in ("info", "warning", "critical"):
            await db.write_event(Event(
                type=EventType.SENTINEL_START,
                data={"test": sev},
                severity=sev,
                source="test",
            ))

        all_rows = await db.query_events(limit=10)
        assert len(all_rows) == 3

        crit_rows = await db.query_events(severity="critical", limit=10)
        assert len(crit_rows) == 1
        assert crit_rows[0]["severity"] == "critical"

    async def test_stats(self, db):
        s = await db.stats()
        assert s["events"] == 0
        assert s["dns_queries"] == 0
        assert s["devices"] == 0

        await db.write_event(Event(
            type=EventType.DNS_QUERY,
            data={"src_ip": "1.2.3.4", "query_name": "test.com", "query_type": "A"},
            severity="info",
            source="test",
        ))
        s = await db.stats()
        assert s["dns_queries"] == 1

    async def test_cleanup_old_events(self, db):
        old_event = Event(
            type=EventType.SENTINEL_START,
            data={"test": "old"},
            severity="info",
            source="test",
            timestamp=time.time() - (100 * 86400),
        )
        await db.write_event(old_event)

        new_event = Event(
            type=EventType.NEW_DEVICE,
            data={"ip": "1.2.3.4"},
            severity="info",
            source="test",
        )
        await db.write_event(new_event)

        deleted = await db.cleanup_old_events(retention_days=30)
        assert deleted.get("events", 0) >= 1

        remaining = await db.query_events(limit=10)
        assert all(r["type"] != "sentinel.start" for r in remaining)
