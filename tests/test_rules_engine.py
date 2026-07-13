import asyncio
import time

import pytest

from sentinel.core.event_bus import Event, EventBus, EventType
from sentinel.core.rules_engine import RulesEngine, Rule, rule_from_dict


class TestRuleFromDict:
    def test_minimal_rule(self):
        d = {"name": "test", "match": {"type": "arp.anomaly"}}
        r = rule_from_dict(d)
        assert r.name == "test"
        assert r.match == {"type": "arp.anomaly"}
        assert r.threshold == 5
        assert r.window == 300
        assert r.escalate_to is None

    def test_full_rule(self):
        d = {
            "name": "full",
            "match": {"type": "dns.blocked", "severity": "warning"},
            "threshold": 3,
            "window": 60,
            "action": {"escalate_to": "critical"},
            "cooldown": 120,
        }
        r = rule_from_dict(d)
        assert r.name == "full"
        assert r.threshold == 3
        assert r.window == 60
        assert r.escalate_to == "critical"
        assert r.cooldown == 120

    def test_rule_with_data_match(self):
        d = {
            "name": "data match",
            "match": {"type": "arp.anomaly", "data": {"anomaly": "arp_spoofing"}},
            "threshold": 2,
            "window": 30,
        }
        r = rule_from_dict(d)
        assert r.match["data"]["anomaly"] == "arp_spoofing"


class TestRule:
    def test_defaults(self):
        r = Rule(name="test", match={"type": "device.new"})
        assert r.threshold == 5
        assert r.window == 300
        assert r.cooldown == 600
        assert r.escalate_to is None


@pytest.mark.asyncio
class TestRulesEngine:
    async def test_no_rules_no_crash(self):
        bus = EventBus()
        engine = RulesEngine(bus, [])
        task = asyncio.create_task(engine.start())
        await asyncio.sleep(0.05)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def test_rule_does_not_match(self):
        bus = EventBus()
        rule = Rule(name="no match", match={"type": "arp.anomaly"}, threshold=2, window=10, cooldown=1)
        engine = RulesEngine(bus, [rule])
        task = asyncio.create_task(engine.start())
        await asyncio.sleep(0.05)

        # Publish a non-matching event
        await bus.publish(Event(type=EventType.DNS_QUERY, data={}, severity="info", source="test"))
        await asyncio.sleep(0.1)

        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def test_rule_fires(self):
        bus = EventBus()
        fired = []
        rule = Rule(name="fire test", match={"type": "arp.anomaly"}, threshold=2, window=10, cooldown=1)
        engine = RulesEngine(bus, [rule])

        # Override _fire to capture
        async def fake_fire(r, trigger, count):
            fired.append((r.name, count))
        engine._fire = fake_fire

        task = asyncio.create_task(engine.start())
        await asyncio.sleep(0.05)

        for _ in range(3):
            await bus.publish(Event(
                type=EventType.ARP_ANOMALY,
                data={"anomaly": "spoofing"},
                severity="warning",
                source="arp_watcher",
            ))
        await asyncio.sleep(0.2)

        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

        assert len(fired) >= 1
        assert fired[0][0] == "fire test"

    async def test_cooldown(self):
        bus = EventBus()
        fired = []
        rule = Rule(name="cooldown", match={"type": "arp.anomaly"}, threshold=2, window=10, cooldown=60)
        engine = RulesEngine(bus, [rule])

        async def fake_fire(r, trigger, count):
            fired.append((r.name, count, time.time()))
        engine._fire = fake_fire

        task = asyncio.create_task(engine.start())
        await asyncio.sleep(0.05)

        # Fire 1st batch
        for _ in range(3):
            await bus.publish(Event(type=EventType.ARP_ANOMALY, data={}, severity="info", source="test"))
        await asyncio.sleep(0.1)

        # Fire 2nd batch (cooldown should block)
        for _ in range(3):
            await bus.publish(Event(type=EventType.ARP_ANOMALY, data={}, severity="info", source="test"))
        await asyncio.sleep(0.1)

        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

        # Should have fired at least once, but cooldown should limit total firings
        assert 1 <= len(fired) <= 2

    async def test_multiple_rules(self):
        bus = EventBus()
        fired = []
        rule_a = Rule(name="rule_a", match={"type": "dns.blocked"}, threshold=2, window=10, cooldown=1)
        rule_b = Rule(name="rule_b", match={"type": "device.new"}, threshold=2, window=10, cooldown=1)
        engine = RulesEngine(bus, [rule_a, rule_b])

        async def fake_fire(r, trigger, count):
            fired.append(r.name)
        engine._fire = fake_fire

        task = asyncio.create_task(engine.start())
        await asyncio.sleep(0.05)

        for _ in range(3):
            await bus.publish(Event(type=EventType.DNS_BLOCKED, data={}, severity="warning", source="dns"))
            await bus.publish(Event(type=EventType.NEW_DEVICE, data={}, severity="info", source="sniffer"))
        await asyncio.sleep(0.2)

        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

        assert "rule_a" in fired
        assert "rule_b" in fired
