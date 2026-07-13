import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.rules")


@dataclass
class Rule:
    name: str
    match: dict
    threshold: int = 5
    window: float = 300.0
    escalate_to: Optional[str] = None
    cooldown: float = 600.0


@dataclass
class _Counter:
    times: list[float] = field(default_factory=list)
    last_fired: float = 0


def rule_from_dict(d: dict) -> Rule:
    return Rule(
        name=d.get("name", "Unnamed rule"),
        match=d.get("match", {}),
        threshold=d.get("threshold", 5),
        window=d.get("window", 300),
        escalate_to=d.get("action", {}).get("escalate_to") if isinstance(d.get("action"), dict) else None,
        cooldown=d.get("cooldown", 600),
    )


def _matches(event: Event, match: dict) -> bool:
    for key, expected in match.items():
        if key == "type":
            if event.type.value != expected:
                return False
        elif key == "severity":
            if event.severity != expected:
                return False
        elif key == "source":
            if event.source != expected:
                return False
        elif key == "data":
            for dk, dv in expected.items():
                if event.data.get(dk) != dv:
                    return False
    return True


class RulesEngine:
    def __init__(self, bus: EventBus, rules: Optional[list[Rule]] = None):
        self.bus = bus
        self.rules: list[Rule] = rules or []
        self._counters: dict[str, _Counter] = {}

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)

    async def start(self) -> None:
        if not self.rules:
            return
        log.info("Rules engine active (%d rules)", len(self.rules))
        async with self.bus.subscribe(min_severity="info") as sub:
            async for event in sub:
                await self._evaluate(event)

    async def _evaluate(self, event: Event) -> None:
        now = time.time()
        for rule in self.rules:
            if not _matches(event, rule.match):
                continue

            key = rule.name
            counter = self._counters.setdefault(key, _Counter())
            counter.times.append(now)
            cutoff = now - rule.window
            counter.times = [t for t in counter.times if t > cutoff]

            count = len(counter.times)
            if count >= rule.threshold and now - counter.last_fired > rule.cooldown:
                counter.last_fired = now
                log.warning(
                    "Rule fired: %s (%d events in %.0fs)",
                    rule.name, count, rule.window,
                )
                await self._fire(rule, event, count)

    async def _fire(self, rule: Rule, trigger: Event, count: int) -> None:
        data = {
            "rule": rule.name,
            "match": rule.match,
            "threshold": rule.threshold,
            "window_secs": rule.window,
            "actual_count": count,
            "trigger_event": {
                "type": trigger.type.value,
                "severity": trigger.severity,
                "source": trigger.source,
                "data": trigger.data,
            },
            "description": (
                f"Rule [{rule.name}] fired: {count} matching events "
                f"in {rule.window:.0f}s (threshold: {rule.threshold})"
            ),
        }

        await self.bus.publish(Event(
            type=EventType.ARP_ANOMALY,
            data=data,
            severity=rule.escalate_to or "warning",
            source="rules_engine",
        ))
