import asyncio

import pytest
from sentinel.core.event_bus import Event, EventBus, EventType


class TestEvent:
    def test_create_info_event(self):
        e = Event(type=EventType.NEW_DEVICE, data={"ip": "192.168.1.1"}, severity="info", source="test")
        assert e.type == EventType.NEW_DEVICE
        assert e.data == {"ip": "192.168.1.1"}
        assert e.severity == "info"
        assert e.source == "test"
        assert e.timestamp > 0

    def test_create_critical_event(self):
        e = Event(type=EventType.ARP_ANOMALY, data={"anomaly": "spoofing"}, severity="critical", source="test")
        assert e.severity == "critical"

    def test_invalid_severity(self):
        with pytest.raises(ValueError):
            Event(type=EventType.ERROR, data={}, severity="invalid")

    def test_as_dict(self):
        e = Event(type=EventType.DNS_BLOCKED, data={"query_name": "bad.com"}, severity="warning", source="dns")
        d = e.as_dict()
        assert d["type"] == "dns.blocked"
        assert d["severity"] == "warning"
        assert d["source"] == "dns"
        assert d["data"]["query_name"] == "bad.com"


@pytest.mark.asyncio
class TestEventBus:
    async def test_publish_subscribe(self):
        bus = EventBus()
        received = []

        async with bus.subscribe(min_severity="info") as sub:
            async def collect():
                async for event in sub:
                    received.append(event)
                    break

            task = asyncio.create_task(collect())
            await asyncio.sleep(0.05)

            await bus.publish(Event(type=EventType.NEW_DEVICE, data={"ip": "1.2.3.4"}, severity="info", source="test"))
            await asyncio.wait_for(task, timeout=2)

        assert len(received) == 1
        assert received[0].data["ip"] == "1.2.3.4"

    async def test_severity_filter(self):
        bus = EventBus()
        received = []

        async with bus.subscribe(min_severity="warning") as sub:
            async def collect():
                async for event in sub:
                    received.append(event.severity)
                    if len(received) >= 2:
                        break

            task = asyncio.create_task(collect())
            await asyncio.sleep(0.05)

            await bus.publish(Event(type=EventType.NEW_DEVICE, data={}, severity="info", source="test"))
            await bus.publish(Event(type=EventType.ARP_ANOMALY, data={}, severity="warning", source="test"))
            await bus.publish(Event(type=EventType.ARP_ANOMALY, data={}, severity="critical", source="test"))
            await asyncio.wait_for(task, timeout=2)

        assert "info" not in received
        assert "warning" in received
        assert "critical" in received

    async def test_multiple_subscribers(self):
        bus = EventBus()
        received_a = []
        received_b = []

        async with bus.subscribe(min_severity="info") as sub_a:
            async with bus.subscribe(min_severity="info") as sub_b:
                async def collect_a():
                    async for e in sub_a:
                        received_a.append(e)
                        break
                async def collect_b():
                    async for e in sub_b:
                        received_b.append(e)
                        break

                task_a = asyncio.create_task(collect_a())
                task_b = asyncio.create_task(collect_b())
                await asyncio.sleep(0.05)

                await bus.publish(Event(type=EventType.SENTINEL_START, data={}, severity="info", source="test"))
                await asyncio.wait_for(asyncio.gather(task_a, task_b), timeout=2)

        assert len(received_a) == 1
        assert len(received_b) == 1

    async def test_bus_stats(self):
        bus = EventBus()
        assert bus.stats["published"] == 0
        assert bus.stats["subscribers"] == 0

        async with bus.subscribe(min_severity="info"):
            await bus.publish(Event(type=EventType.ERROR, data={}, severity="info", source="test"))
            await asyncio.sleep(0.05)

        assert bus.stats["published"] == 1
        assert bus.stats["subscribers"] == 0  # subscription ended

    async def test_auto_cleanup_on_exit(self):
        bus = EventBus()
        async with bus.subscribe(min_severity="info"):
            pass
        assert bus.stats["subscribers"] == 0
