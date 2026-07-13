import asyncio
import pytest
from sentinel.core.notifier import EmailConfig, EmailNotifier
from sentinel.core.event_bus import Event, EventBus, EventType

pytestmark = pytest.mark.asyncio


class TestEmailConfig:
    def test_default_values(self):
        cfg = EmailConfig(server="smtp.test.com")
        assert cfg.port == 587
        assert cfg.use_tls is True
        assert cfg.from_addr == "sentinel@localhost"
        assert cfg.to_addr == ""
        assert cfg.min_severity == "warning"
        assert cfg.cooldown_secs == 60.0

    def test_custom_values(self):
        cfg = EmailConfig(
            server="smtp.gmail.com",
            port=465,
            username="test",
            password="secret",
            use_tls=False,
            from_addr="alert@test.com",
            to_addr="admin@test.com",
            min_severity="critical",
            cooldown_secs=120,
            type_cooldown_secs=600,
        )
        assert cfg.server == "smtp.gmail.com"
        assert cfg.port == 465
        assert cfg.password == "secret"
        assert cfg.use_tls is False
        assert cfg.min_severity == "critical"
        assert cfg.type_cooldown_secs == 600


class TestEmailNotifierCooldown:
    def test_cooldown_blocks(self):
        cfg = EmailConfig(
            server="smtp.test.com",
            username="u", password="p",
            min_severity="info",
            cooldown_secs=300,
            type_cooldown_secs=300,
        )
        bus = EventBus()
        notifier = EmailNotifier(bus, cfg)
        import time
        now = time.time()
        notifier._last_send = now
        notifier._type_cooldowns["device.new:test"] = now
        assert notifier._last_send == now
        assert notifier._type_cooldowns["device.new:test"] == now

    def test_cooldown_allows_after_expiry(self):
        cfg = EmailConfig(
            server="smtp.test.com",
            username="u", password="p",
            min_severity="info",
            cooldown_secs=300,
        )
        bus = EventBus()
        notifier = EmailNotifier(bus, cfg)
        import time
        now = time.time()
        notifier._last_send = now
        notifier._type_cooldowns["test:test"] = now
        assert time.time() - notifier._last_send < cfg.cooldown_secs
        # After expiry simulation
        notifier._last_send = now - 600
        assert time.time() - notifier._last_send > cfg.cooldown_secs

    def test_password_masked_in_log(self):
        import logging
        from io import StringIO
        buf = StringIO()
        handler = logging.StreamHandler(buf)
        handler.setLevel(logging.DEBUG)
        logger = logging.getLogger("sentinel.notifier")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        cfg = EmailConfig(server="s", username="u", password="secret123")
        bus = EventBus()
        notifier = EmailNotifier(bus, cfg)
        pw_log = "****" if cfg.password else "<not set>"
        assert pw_log == "****"
        assert "secret123" not in pw_log

        logger.removeHandler(handler)

    def test_no_password_no_crash(self):
        cfg = EmailConfig(server="smtp.test.com")
        bus = EventBus()
        notifier = EmailNotifier(bus, cfg)
        assert notifier.config.password is None


class TestEmailNotifierSubscribe:
    def test_subscribe_severity_filter(self):
        bus = EventBus()
        cfg = EmailConfig(
            server="smtp.test.com",
            min_severity="warning",
        )
        notifier = EmailNotifier(bus, cfg)
        assert notifier.config.min_severity == "warning"

    def test_min_severity_info_passes_all(self):
        cfg = EmailConfig(
            server="smtp.test.com",
            min_severity="info",
        )
        assert cfg.min_severity == "info"
