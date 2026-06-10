"""
sentinel/core/event_bus.py

Central async event bus. Every collector puts Events here.
Every consumer (DB writer, CLI, Jarvis, future WebSocket) gets from here.

Usage:
    bus = EventBus()
    await bus.publish(Event(...))
    async for event in bus.subscribe():
        ...
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator


class EventType(str, Enum):
    # Passive collectors
    PACKET_CAPTURED  = "packet.captured"
    DNS_QUERY        = "dns.query"
    DNS_BLOCKED      = "dns.blocked"

    # Active collectors (stubs for Phase 2)
    PORT_SCAN_RESULT = "port.scan_result"
    ARP_ANOMALY      = "arp.anomaly"
    NEW_DEVICE       = "device.new"

    # System
    SENTINEL_START   = "sentinel.start"
    SENTINEL_STOP    = "sentinel.stop"
    ERROR            = "system.error"


SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


@dataclass
class Event:
    type: EventType
    data: dict
    severity: str = "info"          # "info" | "warning" | "critical"
    source: str   = "unknown"       # which collector produced this
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"Invalid severity: {self.severity!r}")

    def as_dict(self) -> dict:
        return {
            "type":      self.type.value,
            "data":      self.data,
            "severity":  self.severity,
            "source":    self.source,
            "timestamp": self.timestamp,
        }


class EventBus:
    """
    Fan-out async event bus.

    - Multiple collectors can publish concurrently.
    - Multiple consumers each get their own queue via subscribe().
    - max_queue_size guards against a slow consumer blocking everything.
    """

    def __init__(self, max_queue_size: int = 2000):
        self._subscribers: list[asyncio.Queue] = []
        self._max_size = max_queue_size
        self._published = 0
        self._dropped   = 0

    def subscribe(self, min_severity: str = "info") -> "Subscription":
        q: asyncio.Queue = asyncio.Queue(maxsize=self._max_size)
        self._subscribers.append(q)
        return Subscription(q, min_severity, self._subscribers)

    async def publish(self, event: Event) -> None:
        self._published += 1
        for q in self._subscribers:
            if q.full():
                self._dropped += 1
                continue
            await q.put(event)

    @property
    def stats(self) -> dict:
        return {
            "published":   self._published,
            "dropped":     self._dropped,
            "subscribers": len(self._subscribers),
        }


class Subscription:
    """
    Returned by EventBus.subscribe(). Use as an async context manager
    or call .events() directly.

        async with bus.subscribe() as sub:
            async for event in sub:
                handle(event)
    """

    def __init__(
        self,
        queue: asyncio.Queue,
        min_severity: str,
        all_subscribers: list,
    ):
        self._q    = queue
        self._min  = SEVERITY_ORDER[min_severity]
        self._all  = all_subscribers

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        self._all.remove(self._q)

    def __aiter__(self) -> AsyncIterator[Event]:
        return self._iter()

    async def _iter(self) -> AsyncIterator[Event]:
        while True:
            event: Event = await self._q.get()
            if SEVERITY_ORDER.get(event.severity, 0) >= self._min:
                yield event