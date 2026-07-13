import pytest
from sentinel.core.event_bus import EventBus, Event, EventType
from sentinel.collectors.bandwidth_tracker import BandwidthTracker


class TestTrackMethod:
    def test_track_adds_tx_bytes(self):
        bus = EventBus()
        bw = BandwidthTracker(bus)
        ev = Event(
            type=EventType.PACKET_CAPTURED, severity="info", source="test",
            data={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "size": 100, "dst_port": 80},
        )
        bw._track(ev)
        assert bw._tx == {"10.0.0.1": 100}
        assert bw._rx == {"10.0.0.2": 100}

    def test_track_adds_session(self):
        bus = EventBus()
        bw = BandwidthTracker(bus)
        ev = Event(
            type=EventType.PACKET_CAPTURED, severity="info", source="test",
            data={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "size": 100, "dst_port": 443},
        )
        bw._track(ev)
        assert bw._sessions == {("10.0.0.1", "10.0.0.2", 443): 100}

    def test_track_accumulates_bytes(self):
        bus = EventBus()
        bw = BandwidthTracker(bus)
        for _ in range(5):
            ev = Event(
                type=EventType.PACKET_CAPTURED, severity="info", source="test",
                data={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "size": 50, "dst_port": 80},
            )
            bw._track(ev)
        assert bw._tx["10.0.0.1"] == 250
        assert bw._rx["10.0.0.2"] == 250
        assert bw._sessions[("10.0.0.1", "10.0.0.2", 80)] == 250

    def test_track_no_src_or_dst_skipped(self):
        bus = EventBus()
        bw = BandwidthTracker(bus)
        ev = Event(
            type=EventType.PACKET_CAPTURED, severity="info", source="test",
            data={"size": 100},
        )
        bw._track(ev)
        assert bw._tx == {}
        assert bw._rx == {}
        assert bw._sessions == {}

    def test_track_no_dport_skips_session(self):
        bus = EventBus()
        bw = BandwidthTracker(bus)
        ev = Event(
            type=EventType.PACKET_CAPTURED, severity="info", source="test",
            data={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "size": 100},
        )
        bw._track(ev)
        assert bw._tx == {"10.0.0.1": 100}
        assert bw._rx == {"10.0.0.2": 100}
        assert bw._sessions == {}


class TestPublishReport:
    async def test_no_data_skips_report(self):
        bus = EventBus()
        bw = BandwidthTracker(bus)
        await bw._publish_report()

    async def test_report_contains_top_talkers(self):
        bus = EventBus()
        bw = BandwidthTracker(bus)
        ev = Event(
            type=EventType.PACKET_CAPTURED, severity="info", source="test",
            data={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "size": 200, "dst_port": 80},
        )
        bw._track(ev)
        received = []
        async with bus.subscribe("info") as sub:
            await bw._publish_report()
            async for e in sub:
                received.append(e)
                break
        assert len(received) == 1
        report = received[0]
        assert report.type == EventType.BANDWIDTH_REPORT
        assert len(report.data["top_talkers"]) == 1
        assert report.data["top_talkers"][0]["ip"] == "10.0.0.1"

    async def test_report_clears_counters(self):
        bus = EventBus()
        bw = BandwidthTracker(bus)
        ev = Event(
            type=EventType.PACKET_CAPTURED, severity="info", source="test",
            data={"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "size": 200, "dst_port": 80},
        )
        bw._track(ev)
        async with bus.subscribe("info") as sub:
            await bw._publish_report()
            async for _ in sub:
                break
        assert bw._tx == {}
        assert bw._rx == {}
        assert bw._sessions == {}

    async def test_top_n_limits_results(self):
        bus = EventBus()
        bw = BandwidthTracker(bus, top_n=2)
        for i in range(5):
            ev = Event(
                type=EventType.PACKET_CAPTURED, severity="info", source="test",
                data={"src_ip": f"10.0.0.{i}", "dst_ip": "10.0.0.99", "size": 100, "dst_port": 80},
            )
            bw._track(ev)
        received = []
        async with bus.subscribe("info") as sub:
            await bw._publish_report()
            async for e in sub:
                received.append(e)
                break
        assert len(received[0].data["top_talkers"]) == 2


class TestLifecycle:
    async def test_start_stop_no_crash(self):
        bus = EventBus()
        bw = BandwidthTracker(bus)
        await bw.start()
        assert bw._running is True
        assert bw._task is not None
        await bw.stop()
        assert bw._running is False

    async def test_double_stop_no_crash(self):
        bus = EventBus()
        bw = BandwidthTracker(bus)
        await bw.start()
        await bw.stop()
        await bw.stop()
