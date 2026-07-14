import asyncio
import argparse
import json
import logging
import uvicorn
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Optional

import rich.logging
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich import box
from rich.text import Text

from sentinel.core.event_bus import Event, EventBus, EventType
from sentinel.core.database import Database
from sentinel.core.enrichment import Enricher
from sentinel.core.notifier import EmailConfig, EmailNotifier
from sentinel.collectors.sniffer import PacketSniffer
from sentinel.collectors.dns_monitor import DnsMonitor
from sentinel.collectors.arp_watcher import ArpWatcher
from sentinel.collectors.port_scanner import PortScanner
from sentinel.collectors.dhcp_monitor import DhcpMonitor
from sentinel.collectors.http_monitor import HttpMonitor
from sentinel.collectors.icmp_monitor import IcmpMonitor
from sentinel.collectors.tls_monitor import TlsMonitor
from sentinel.collectors.bandwidth_tracker import BandwidthTracker
from sentinel.api.app import app as fastapi_app, init as api_init, event_broadcaster
from sentinel.cli.shell import SentinelShell
from sentinel.core.threat_feeds import update_blocklist, DEFAULT_FEEDS

_SENTINEL_DIR = Path(__file__).parent
from sentinel.core.rules_engine import RulesEngine, rule_from_dict

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

CONFIG_FILE = "sentinel.json"


def load_json_config(path: str = CONFIG_FILE) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
        log.info("Loaded config from %s", path)
        return cfg
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        log.warning("Invalid config file %s: %s", path, e)
        return {}


async def db_writer(bus: EventBus, db: Database) -> None:
    async with bus.subscribe(min_severity="info") as sub:
        async for event in sub:
            try:
                await db.write_event(event)
            except Exception as exc:
                log.error("DB write failed: %s", exc)
                for attempt in range(3):
                    try:
                        await asyncio.sleep(1 << attempt)
                        await db.write_event(event)
                        break
                    except Exception as retry_exc:
                        log.warning(f"Retry {attempt + 1} failed: {retry_exc}")
                else:
                    log.critical("Failed to write event after retries")

async def enrichment_loop(bus: EventBus, db: Database, enricher: Enricher) -> None:
    await asyncio.sleep(3)
    try:
        await enricher.enrich_all_devices(db)
    except Exception as exc:
        log.error("Enrichment failed: %s", exc)

    async with bus.subscribe(min_severity="info") as sub:
        async for event in sub:
            if event.type != EventType.NEW_DEVICE:
                continue
            ip = event.data.get("ip", "")
            mac = event.data.get("mac")
            if not ip:
                continue
            try:
                result = await enricher.enrich(ip, mac)
                if result.get("hostname") or result.get("vendor"):
                    log.info(
                        "Enriched %s → %s (%s)",
                        ip,
                        result.get("hostname") or "?",
                        result.get("vendor") or "unknown vendor",
                    )
            except Exception as exc:
                log.error(f"Failed to enrich {ip}: {exc}")


SEVERITY_STYLE = {"info": "dim", "warning": "yellow", "critical": "bold red"}
EVENT_ICON = {
    EventType.PACKET_CAPTURED:  "PKT",
    EventType.DNS_QUERY:        "DNS",
    EventType.DNS_BLOCKED:      "BLK",
    EventType.NEW_DEVICE:       "NEW",
    EventType.ARP_ANOMALY:      "ARP",
    EventType.PORT_SCAN_RESULT: "SCN",
    EventType.ERROR:            "ERR",
    EventType.DHCP_ANOMALY:     "DHP",
    EventType.DNS_ANOMALY:      "DNS",
    EventType.HTTP_REQUEST:     "HTTP",
    EventType.ICMP_ANOMALY:     "ICM",
    EventType.BANDWIDTH_REPORT: "BND",
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
        table.add_column("Source", width=12, no_wrap=True)
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
    if ev.type == EventType.ARP_ANOMALY:
        return d.get("description", str(d)[:120])
    if ev.type == EventType.DNS_ANOMALY:
        return d.get("description", str(d)[:120])
    if ev.type == EventType.DHCP_ANOMALY:
        return d.get("description", str(d)[:120])
    if ev.type == EventType.HTTP_REQUEST:
        return d.get("description", str(d)[:120])
    if ev.type == EventType.ICMP_ANOMALY:
        return d.get("description", str(d)[:120])
    if ev.type == EventType.BANDWIDTH_REPORT:
        return d.get("description", str(d)[:120])
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


async def _run_uvicorn(host: str, port: int) -> None:
    config = uvicorn.Config(fastapi_app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    try:
        await server.serve()
    except asyncio.CancelledError:
        server.should_exit = True


async def _target_feeder(bus: EventBus, scanner: PortScanner) -> None:
    async with bus.subscribe(min_severity="info") as sub:
        async for event in sub:
            if event.type == EventType.NEW_DEVICE:
                ip = event.data.get("ip", "")
                if ip:
                    scanner.add_target(ip)


async def cleanup_loop(db: Database, retention_days: int, interval: int = 3600) -> None:
    while True:
        try:
            deleted = await db.cleanup_old_events(retention_days)
            total = sum(deleted.values())
            if total:
                log.info("Cleanup: removed %d old rows (retention=%dd)", total, retention_days)
        except Exception as exc:
            log.warning("Cleanup failed: %s", exc)
        await asyncio.sleep(interval)


async def feeds_update_loop(
    blocklist_path: Optional[Path],
    feeds: Optional[list[dict]],
    interval: int = 86400,
) -> None:
    while True:
        try:
            added = await update_blocklist(blocklist_path, feeds)
            if added:
                log.info("Threat feeds: %d new domains added", added)
        except Exception as exc:
            log.warning("Threat feed update failed: %s", exc)
        await asyncio.sleep(interval)


async def run(args: argparse.Namespace, stop_event: asyncio.Event) -> None:
    bus      = EventBus()
    display  = LiveDisplay()
    enricher = Enricher(oui_path=args.oui_path)

    own_ip = None
    gateway_ip = args.gateway
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            own_ip = s.getsockname()[0]
        log.info("Own IP detected: %s", own_ip)
    except Exception:
        try:
            own_ip = socket.gethostbyname(socket.gethostname())
            log.info("Own IP detected (fallback): %s", own_ip)
        except Exception:
            log.warning("Could not detect own IP — SYN flood self-alerts may occur")

    if not gateway_ip:
        try:
            import subprocess
            import re
            if sys.platform == "win32":
                out = subprocess.check_output("ipconfig", text=True, encoding="utf-8", errors="ignore")
                match = re.search(r"Standardgateway[^:]*:[^\d]*(\d+\.\d+\.\d+\.\d+)", out)
            else:
                out = subprocess.check_output(["ip", "route"], text=True)
                match = re.search(r"default via ([\d.]+)", out)
            if match:
                gateway_ip = match.group(1)
                log.info("Default gateway auto-detected: %s", gateway_ip)
        except Exception as exc:
            log.warning("Could not auto-detect gateway: %s", exc)

    async with Database(args.db) as db:
        enricher._db = db

        await bus.publish(Event(
            type=EventType.SENTINEL_START,
            data={"iface": args.iface, "db": args.db},
            severity="info", source="main",
        ))

        api_init(
            db, bus,
            blocklist_path=Path(args.blocklist),
            whitelist_path=Path(args.whitelist),
        )

        console.print("[dim]Loading OUI database...[/]")
        await enricher.setup()

        sniffer = PacketSniffer(bus, iface=args.iface, own_ip=own_ip)
        dns     = DnsMonitor(
            bus, iface=args.iface, mode="active",
            blocklist_path=Path(args.blocklist),
        )
        arp     = ArpWatcher(bus, iface=args.iface, gateway_ip=gateway_ip)
        scanner = PortScanner(bus, interval=args.scan_interval, own_ip=own_ip)
        dhcp    = DhcpMonitor(bus, iface=args.iface)
        http    = HttpMonitor(bus, iface=args.iface, whitelist_path=Path(args.whitelist))
        icmp    = IcmpMonitor(bus, iface=args.iface)
        tls     = TlsMonitor(bus, iface=args.iface)
        bw      = BandwidthTracker(bus)

        email_notifier = None
        if args.smtp_server:
            email_cfg = EmailConfig(
                server=args.smtp_server,
                port=args.smtp_port,
                username=args.smtp_user,
                password=args.smtp_password,
                use_tls=not args.smtp_ssl,
                from_addr=args.email_from,
                to_addr=args.email_to,
            )
            email_notifier = EmailNotifier(bus, email_cfg)

        rules_engine = None
        raw_rules = load_json_config().get("rules", [])
        if raw_rules:
            parsed = [rule_from_dict(r) for r in raw_rules]
            rules_engine = RulesEngine(bus, parsed)

        tasks = [
            asyncio.create_task(cleanup_loop(db, args.retention_days), name="cleanup"),
            asyncio.create_task(db_writer(bus, db),                name="db-writer"),
            asyncio.create_task(enrichment_loop(bus, db, enricher), name="enricher"),
            asyncio.create_task(_target_feeder(bus, scanner),       name="target-feeder"),
            asyncio.create_task(event_broadcaster(),                name="ws-broadcaster"),
            asyncio.create_task(
                _run_uvicorn(args.host, args.port),
                name="api-server",
            ),
        ]

        if email_notifier:
            tasks.insert(0, asyncio.create_task(email_notifier.start(), name="email-notifier"))
        if rules_engine:
            tasks.insert(0, asyncio.create_task(rules_engine.start(), name="rules-engine"))

        if args.threat_feeds:
            tasks.insert(0, asyncio.create_task(
                feeds_update_loop(Path(args.blocklist), DEFAULT_FEEDS),
                name="threat-feeds",
            ))

        if args.daemon:
            tasks.insert(0, asyncio.create_task(display_loop(bus, display), name="cli-display"))
            console.print("[dim]Dashboard: http://localhost:{0}[/]".format(args.port))
        else:
            shell = SentinelShell(db, bus, blocklist_path=args.blocklist, stop_event=stop_event)
            tasks.insert(0, asyncio.create_task(shell.run(), name="shell"))

        await sniffer.start()
        await dns.start()
        await arp.start()
        await scanner.start()
        await dhcp.start()
        await http.start()
        await icmp.start()
        await tls.start()
        await bw.start()

        if sys.platform != "win32":
            loop = asyncio.get_running_loop()
            def _shutdown(*_):
                console.print("\n[yellow]Shutting down Sentinel...[/]")
                stop_event.set()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, _shutdown)
        else:
            def _win_shutdown(sig, frame):
                console.print("\n[yellow]Shutting down Sentinel...[/]")
                stop_event.set()
            signal.signal(signal.SIGINT, _win_shutdown)

        try:
            await stop_event.wait()
        except asyncio.CancelledError:
            pass

        await sniffer.stop()
        await dns.stop()
        await arp.stop()
        await scanner.stop()
        await dhcp.stop()
        await http.stop()
        await icmp.stop()
        await tls.stop()
        await bw.stop()

        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        stats = await db.stats()
        console.print("\n[bold]Session stats:[/]", stats)
        console.print("[bold]Bus stats:[/]", bus.stats)
        console.print("[bold]ARP stats:[/]", arp.stats)


def _apply_config_defaults(parser: argparse.ArgumentParser, config: dict) -> None:
    mapping = {
        "iface": "iface", "db": "db",         "blocklist": "blocklist",
        "whitelist": "whitelist",
        "gateway": "gateway", "host": "host", "port": "port",
        "scan_interval": "scan_interval", "oui_path": "oui_path",
        "verbose": "verbose", "daemon": "daemon",
        "retention_days": "retention_days",
        "smtp_server": "smtp_server", "smtp_port": "smtp_port",
        "smtp_user": "smtp_user", "smtp_password": "smtp_password",
        "smtp_ssl": "smtp_ssl",
        "email_from": "email_from", "email_to": "email_to",
        "threat_feeds": "threat_feeds",
    }
    overrides = {}
    for cfg_key, arg_key in mapping.items():
        val = config.get(cfg_key)
        if val is not None:
            overrides[arg_key] = val
    if overrides:
        parser.set_defaults(**overrides)


def main() -> None:
    config = load_json_config()

    parser = argparse.ArgumentParser(description="Sentinel — local network security monitor")
    parser.add_argument("--iface",       default=None,             help="Network interface (default: auto)")
    parser.add_argument("--db",          default="sentinel.db",    help="SQLite database path")
    parser.add_argument("--blocklist",   default=str(_SENTINEL_DIR / "blocklist.txt"),  help="Path to DNS blocklist file")
    parser.add_argument("--whitelist",   default=str(_SENTINEL_DIR / "whitelist.txt"),  help="Path to HTTP whitelist patterns file")
    parser.add_argument("--gateway",     default=None,             help="Gateway IP for spoofing detection (default: auto)")
    parser.add_argument("--host",        default="0.0.0.0",        help="API host (default: 0.0.0.0)")
    parser.add_argument("--port",        type=int, default=8888,   help="API port (default: 8888)")
    parser.add_argument("--scan-interval", type=int, default=60,   help="Port scan interval in seconds (default: 60)")
    parser.add_argument("--oui-path",    default="oui.csv",        help="Path to OUI vendor database (default: oui.csv)")
    parser.add_argument("--verbose",     action="store_true",      help="Debug logging")
    parser.add_argument("--retention-days", type=int, default=30, help="Delete events older than N days (default: 30)")
    parser.add_argument("--threat-feeds", action="store_true",      help="Enable automatic blocklist updates from threat intelligence feeds")

    parser.add_argument("--daemon",      action="store_true",      help="Run headless (no interactive shell, just dashboard + live TUI)")

    email_group = parser.add_argument_group("Email notifications")
    email_group.add_argument("--smtp-server",   default=None,      help="SMTP server hostname")
    email_group.add_argument("--smtp-port",     type=int, default=587, help="SMTP server port (default: 587)")
    email_group.add_argument("--smtp-user",     default=None,      help="SMTP username")
    email_group.add_argument("--smtp-password", default=None,      help="SMTP password")
    email_group.add_argument("--smtp-ssl",      action="store_true", help="Use SMTP over SSL (port 465) instead of STARTTLS")
    email_group.add_argument("--email-from",    default="sentinel@localhost", help="From address for email alerts")
    email_group.add_argument("--email-to",      default="",        help="Recipient address for email alerts")

    _apply_config_defaults(parser, config)
    args = parser.parse_args()

    setup_logging(args.verbose)

    if args.daemon:
        console.print("[bold green]Sentinel starting (daemon mode)...[/] (Ctrl+C to stop)")
    else:
        console.print("[bold green]Sentinel starting...[/] (Ctrl+C to stop)")
        console.print("[dim]Interactive shell available — type 'help' for commands.[/]")

    stop_event = asyncio.Event()

    try:
        asyncio.run(run(args, stop_event))
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/]")


if __name__ == "__main__":
    main()