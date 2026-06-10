"""
sentinel/main.py

Entry point. Wires up:
    EventBus → DB writer
    PacketSniffer → EventBus
    DnsMonitor → EventBus
    Enricher → auto-enriches NEW_DEVICE events in background
    CLI display loop

Run as Admin (required for raw packet capture):
    .venv\Scripts\python.exe -m sentinel.main         (Windows, Admin PowerShell)
    sudo python -m sentinel.main                      (Linux)
"""

import asyncio
import argparse
import logging
import signal
import sys
import time
from pathlib import Path

import rich.logging
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich import box
from rich.text import Text

from sentinel.core.event_bus import Event, EventBus, EventType
from sentinel.core.database import Database
from sentinel.core.enrichment import Enricher
from sentinel.collectors.sniffer import PacketSniffer
from sentinel.collectors.dns_monitor import DnsMonitor

console = Console()


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[rich.logging.RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )
    logging.getLogger("scapy").setLevel(logging.WARNING)
    if not verbose:
        logging.getLogger("asyncio").setLevel(logging.WARNING)


log = logging.getLogger("sentinel")


# ------------------------------------------------------------------ #
#  DB writer                                                           #
# ------------------------------------------------------------------ #

async def db_writer(bus: EventBus, db: Database) -> None:
    async with bus.subscribe(min_severity="info") as sub:
        async for event in sub:
            try:
                await db.write_event(event)
            except Exception as exc:
                log.error("DB write failed: %s", exc)


# ------------------------------------------------------------------ #
#  Enrichment background task                                          #
# ------------------------------------------------------------------ #

async def enrichment_loop(bus: EventBus, db: Database, enricher: Enricher) -> None:
    """
    Listens for NEW_DEVICE events and enriches them in the background.
    Also runs a full enrichment pass on startup for existing devices.
    """
    # Enrich existing devices on startup
    await asyncio.sleep(3)   # let DB writer settle first
    await enricher.enrich_all_devices(db)

    # Then enrich new devices as they appear
    async with bus.subscribe(min_severity="info") as sub:
        async for event in sub:
            if event.type != EventType.NEW_DEVICE:
                continue
            ip  = event.data.get("ip", "")
            mac = event.data.get("mac")
            if not ip:
                continue
            result = await enricher.enrich(ip, mac)
            if result.get("hostname") or result.get("vendor"):
                log.info(
                    "Enriched %s → %s (%s)",
                    ip,
                    result.get("hostname") or "?",
                    result.get("vendor") or "unknown vendor",
                )


# ------------------------------------------------------------------ #
#  Live CLI display                                                    #
# ------------------------------------------------------------------ #

SEVERITY_STYLE = {"info": "dim", "warning": "yellow", "critical": "bold red"}
EVENT_ICON = {
    EventType.PACKET_CAPTURED:  "PKT",
    EventType.DNS_QUERY:        "DNS",
    EventType.DNS_BLOCKED:      "BLK",
    EventType.NEW_DEVICE:       "NEW",
    EventType.ARP_ANOMALY:      "ARP",
    EventType.PORT_SCAN_RESULT: "SCN",
    EventType.ERROR:            "ERR",
}


class LiveDisplay:
    def __init__(self, max_rows: int = 25):
        self.max_rows = max_rows
        self._events: list[Event] = []
        self._counts  = {s: 0 for s in ("info", "warning", "critical")}
        self._start   = time.time()

    def add(self, event: Event) -> None:
        self._events.append(event)
        if len(self._events) > self.max_rows:
            self._events.pop(0)
        self._counts[event.severity] = self._counts.get(event.severity, 0) + 1

    def build_table(self) -> Table:
        elapsed = int(time.time() - self._start)
        title = (
            f"[bold]Sentinel[/] · "
            f"[green]{self._counts['info']} info[/]  "
            f"[yellow]{self._counts['warning']} warn[/]  "
            f"[red]{self._counts['critical']} crit[/]  "
            f"[dim]uptime {elapsed}s[/]"
        )
        table = Table(title=title, box=box.MINIMAL_DOUBLE_HEAD, expand=True, header_style="bold")
        table.add_column("Time",   style="dim", width=10, no_wrap=True)
        table.add_column("Sev",    width=8,  no_wrap=True)
        table.add_column("Type",   width=6,  no_wrap=True)
        table.add_column("Source", width=10, no_wrap=True)
        table.add_column("Detail", ratio=1)

        for ev in reversed(self._events):
            t      = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
            sev    = Text(ev.severity, style=SEVERITY_STYLE.get(ev.severity, ""))
            icon   = EVENT_ICON.get(ev.type, "·")
            detail = _format_detail(ev)
            table.add_row(t, sev, icon, ev.source, detail)
        return table


def _format_detail(ev: Event) -> str:
    d = ev.data
    if ev.type == EventType.PACKET_CAPTURED:
        flags = f" [{d['flags']}]" if d.get("flags") else ""
        port  = f":{d['dst_port']}" if d.get("dst_port") else ""
        return f"{d.get('src_ip','?')} -> {d.get('dst_ip','?')}{port} {d.get('protocol','')}{flags}"
    if ev.type in (EventType.DNS_QUERY, EventType.DNS_BLOCKED):
        blocked = " [BLOCKED]" if d.get("blocked") else ""
        return f"{d.get('src_ip','?')} queried {d.get('query_name','?')} ({d.get('query_type','')}){blocked}"
    if ev.type == EventType.NEW_DEVICE:
        mac = f" mac={d['mac']}" if d.get("mac") else ""
        return f"New host: {d.get('ip','?')}{mac}"
    return str(d)[:120]


async def display_loop(bus: EventBus, display: LiveDisplay) -> None:
    with Live(display.build_table(), console=console, refresh_per_second=4) as live:
        async with bus.subscribe(min_severity="info") as sub:
            async for event in sub:
                if event.type == EventType.PACKET_CAPTURED and event.severity == "info":
                    display.add(event)
                    if int(time.time()) % 2 == 0:
                        live.update(display.build_table())
                    continue
                display.add(event)
                live.update(display.build_table())


# ------------------------------------------------------------------ #
#  Main                                                                #
# ------------------------------------------------------------------ #

async def run(args: argparse.Namespace, stop_event: asyncio.Event) -> None:
    bus      = EventBus()
    display  = LiveDisplay()
    enricher = Enricher()

    async with Database(args.db) as db:
        enricher._db = db

        await bus.publish(Event(
            type=EventType.SENTINEL_START,
            data={"iface": args.iface, "db": args.db},
            severity="info", source="main",
        ))

        # Setup enricher (load/download OUI db)
        console.print("[dim]Loading OUI database...[/]")
        await enricher.setup()

        sniffer = PacketSniffer(bus, iface=args.iface)
        dns     = DnsMonitor(
            bus, iface=args.iface, mode="active",
            blocklist_path=Path(args.blocklist) if args.blocklist else None,
        )

        tasks = [
            asyncio.create_task(db_writer(bus, db),                          name="db-writer"),
            asyncio.create_task(display_loop(bus, display),                   name="cli-display"),
            asyncio.create_task(enrichment_loop(bus, db, enricher),           name="enricher"),
        ]

        await sniffer.start()
        await dns.start()

        if sys.platform != "win32":
            loop = asyncio.get_running_loop()
            def _shutdown(*_):
                console.print("\n[yellow]Shutting down Sentinel...[/]")
                stop_event.set()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, _shutdown)

        try:
            await stop_event.wait()
        except asyncio.CancelledError:
            pass

        await sniffer.stop()
        await dns.stop()

        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        stats = await db.stats()
        console.print("\n[bold]Session stats:[/]", stats)
        console.print("[bold]Bus stats:[/]", bus.stats)


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel — local network security monitor")
    parser.add_argument("--iface",     default=None,          help="Network interface (default: auto)")
    parser.add_argument("--db",        default="sentinel.db", help="SQLite database path")
    parser.add_argument("--blocklist", default=None,          help="Path to DNS blocklist file")
    parser.add_argument("--verbose",   action="store_true",   help="Debug logging")
    args = parser.parse_args()

    setup_logging(args.verbose)
    console.print("[bold green]Sentinel starting...[/] (Ctrl+C to stop)")

    stop_event = asyncio.Event()

    try:
        asyncio.run(run(args, stop_event))
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/]")


if __name__ == "__main__":
    main()