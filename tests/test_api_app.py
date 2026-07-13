import pytest
from unittest.mock import AsyncMock, MagicMock
import sentinel.api.app
from sentinel.api.app import ConnectionManager, _datetimeformat, manager
from sentinel.core.event_bus import EventBus
from sentinel.core.database import Database


class TestDateTimeFormat:
    def test_local_format(self):
        result = _datetimeformat(1000000000, utc=False)
        assert isinstance(result, str)

    def test_utc_format(self):
        result = _datetimeformat(1000000000, utc=True)
        assert isinstance(result, str)
        assert "2001" in result

    def test_default_is_local(self):
        result = _datetimeformat(0)
        assert isinstance(result, str)


class TestConnectionManager:
    @pytest.fixture
    def cm(self):
        return ConnectionManager()

    @pytest.fixture
    def mock_ws(self):
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_json = AsyncMock()
        return ws

    async def test_connect_adds_client(self, cm, mock_ws):
        await cm.connect(mock_ws)
        assert len(cm._clients) == 1
        mock_ws.accept.assert_awaited_once()

    async def test_disconnect_removes_client(self, cm, mock_ws):
        await cm.connect(mock_ws)
        cm.disconnect(mock_ws)
        assert len(cm._clients) == 0

    async def test_broadcast_sends_to_all(self, cm, mock_ws):
        ws2 = AsyncMock()
        ws2.send_json = AsyncMock()
        await cm.connect(mock_ws)
        await cm.connect(ws2)
        await cm.broadcast({"msg": "test"})
        mock_ws.send_json.assert_awaited_once_with({"msg": "test"})
        ws2.send_json.assert_awaited_once_with({"msg": "test"})

    async def test_broadcast_removes_dead_clients(self, cm, mock_ws):
        dead_ws = AsyncMock()
        dead_ws.send_json = AsyncMock(side_effect=Exception("dead"))
        await cm.connect(mock_ws)
        await cm.connect(dead_ws)
        await cm.broadcast({"msg": "test"})
        assert len(cm._clients) == 1

    async def test_count_property(self, cm, mock_ws):
        assert cm.count == 0
        await cm.connect(mock_ws)
        assert cm.count == 1

    async def test_disconnect_not_in_list_raises(self, cm):
        ws = AsyncMock()
        with pytest.raises(ValueError):
            cm.disconnect(ws)


class TestInit:
    def test_init_sets_globals(self):
        orig_db = sentinel.api.app._db
        orig_bus = sentinel.api.app._bus
        db = MagicMock(spec=Database)
        bus = EventBus()
        sentinel.api.app.init(db, bus)
        assert sentinel.api.app._db is db
        assert sentinel.api.app._bus is bus
        sentinel.api.app.init(orig_db, orig_bus if orig_bus else bus)
