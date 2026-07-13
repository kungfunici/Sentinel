import asyncio
import logging
import time
from typing import Optional

from sentinel.core.event_bus import Event, EventBus, EventType

log = logging.getLogger("sentinel.bandwidth")

REPORT_INTERVAL = 60
TOP_TALKERS     = 10


class BandwidthTracker:
    def __init__(
        self,
        bus: EventBus,
        interval: int = REPORT_INTERVAL,
        top_n: int = TOP_TALKERS,
    ):
        self.bus = bus
        self._interval = interval
        self._top_n = top_n
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._tx: dict[str, int] = {}
        self._rx: dict[str, int] = {}
        self._sessions: dict[tuple[str, str, int], int] = {}

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._run(), name="bandwidth-tracker")
        log.info("Bandwidth tracker started (interval=%ds)", self._interval)

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        log.info("Bandwidth tracker stopped")

    async def _run(self) -> None:
        async with self.bus.subscribe(min_severity="info") as sub:
            async for event in sub:
                if not self._running:
                    break
                if event.type == EventType.PACKET_CAPTURED:
                    self._track(event)
                elif event.type == EventType.BANDWIDTH_REPORT:
                    await self._publish_report()

    def _track(self, event: Event) -> None:
        d = event.data
        src = d.get("src_ip")
        dst = d.get("dst_ip")
        size = d.get("size", 0)
        dport = d.get("dst_port", 0)

        if src:
            self._tx[src] = self._tx.get(src, 0) + size
        if dst:
            self._rx[dst] = self._rx.get(dst, 0) + size
        if src and dst and dport:
            key = (src, dst, dport)
            self._sessions[key] = self._sessions.get(key, 0) + size

    async def _publish_report(self) -> None:
        if not self._tx and not self._rx:
            return

        now = time.time()

        tx_sorted = sorted(self._tx.items(), key=lambda x: -x[1])[:self._top_n]
        rx_sorted = sorted(self._rx.items(), key=lambda x: -x[1])[:self._top_n]
        sessions_sorted = sorted(self._sessions.items(), key=lambda x: -x[1])[:self._top_n]

        top_talkers = [
            {"ip": ip, "tx_bytes": self._tx.get(ip, 0), "rx_bytes": self._rx.get(ip, 0), "total": self._tx.get(ip, 0) + self._rx.get(ip, 0)}
            for ip, _ in tx_sorted
        ]

        top_sessions = [
            {"src_ip": s[0], "dst_ip": s[1], "dst_port": s[2], "bytes": b}
            for s, b in sessions_sorted
        ]

        self._tx.clear()
        self._rx.clear()
        self._sessions.clear()

        event = Event(
            type=EventType.BANDWIDTH_REPORT,
            severity="info",
            source="bandwidth_tracker",
            timestamp=now,
            data={
                "top_talkers": top_talkers,
                "top_sessions": top_sessions,
                "interval_secs": self._interval,
                "description": f"Bandwidth report: {len(top_talkers)} top talkers, {len(top_sessions)} top sessions",
            },
        )
        await self.bus.publish(event)