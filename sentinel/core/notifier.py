import asyncio
import json
import logging
import smtplib
import time
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Optional

from sentinel.core.event_bus import Event, EventBus

log = logging.getLogger("sentinel.notifier")


@dataclass
class EmailConfig:
    server: str
    port: int = 587
    username: Optional[str] = None
    password: Optional[str] = None
    use_tls: bool = True
    from_addr: str = "sentinel@localhost"
    to_addr: str = ""
    min_severity: str = "warning"
    cooldown_secs: float = 60.0
    type_cooldown_secs: float = 300.0


class EmailNotifier:
    def __init__(self, bus: EventBus, config: EmailConfig):
        self.bus = bus
        self.config = config
        self._last_send: float = 0
        self._type_cooldowns: dict[str, float] = {}

    async def start(self) -> None:
        pw_log = "****" if self.config.password else "<not set>"
        log.info(
            "Email notifier active (%s -> %s, server=%s:%d, user=%s, password=%s)",
            self.config.from_addr,
            self.config.to_addr,
            self.config.server,
            self.config.port,
            self.config.username or "<not set>",
            pw_log,
        )
        async with self.bus.subscribe(min_severity=self.config.min_severity) as sub:
            async for event in sub:
                await self._handle_event(event)

    async def _handle_event(self, event: Event) -> None:
        now = time.time()

        if now - self._last_send < self.config.cooldown_secs:
            return

        type_key = f"{event.type.value}:{event.source}"
        last_type = self._type_cooldowns.get(type_key, 0)
        if now - last_type < self.config.type_cooldown_secs:
            self._type_cooldowns[type_key] = now
            return

        self._last_send = now
        self._type_cooldowns[type_key] = now

        try:
            await asyncio.to_thread(self._send_sync, event)
            log.debug("Email sent for %s from %s", event.type.value, event.source)
        except Exception as e:
            log.error("Failed to send email notification: %s", e)

    def _send_sync(self, event: Event) -> None:
        subject = (
            f"[Sentinel] {event.severity.upper()}: "
            f"{event.type.value} from {event.source}"
        )

        body_parts = [
            f"Event:       {event.type.value}",
            f"Severity:    {event.severity}",
            f"Source:      {event.source}",
            f"Timestamp:   {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event.timestamp))}",
            "",
            "Details:",
            json.dumps(event.data, indent=2, default=str),
        ]

        body = "\n".join(body_parts)

        msg = MIMEText(body, _charset="utf-8")
        msg["Subject"] = subject
        msg["From"] = self.config.from_addr
        msg["To"] = self.config.to_addr

        self._send_smtp(msg)

    def _send_smtp(self, msg: MIMEText) -> None:
        cfg = self.config

        if cfg.use_tls:
            server = smtplib.SMTP(cfg.server, cfg.port, timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP_SSL(cfg.server, cfg.port, timeout=15)

        try:
            if cfg.username and cfg.password:
                server.login(cfg.username, cfg.password)
            server.send_message(msg)
        finally:
            server.quit()
