import argparse
import asyncio
import json
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich import box
from rich.text import Text

from sentinel.core.database import Database

console = Console()

SEVERITY_STYLE = {
    "info":     "dim",
    "warning":  "yellow",
    "critical": "bold red",
}


def fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def fmt_data(raw: str) -> str:
    try:
        d = json.loads(raw)
        if "src_ip" in d and "dst_ip" in d:
            port  = f":{d['dst_port']}" if d.get("dst_port") else ""
            flags = f" [{d['flags']}]" if d.get("flags") else ""
            return f"{d['src_ip']} -> {d['dst_ip']}{port} {d.get('protocol','')}{flags}"
        if "query_name" in d:
            blocked = " [BLOCKED]" if d.get("blocked") else ""
            return f"{d.get('src_ip','?')} queried {d['query_name']} ({d.get('query_type','')}){blocked}"
        if "ip" in d and "mac" in d:
            return f"ip={d['ip']} mac={d.get('mac','?')}"
        return str(d)[:100]
    except Exception:
        return raw[:100]


def events_table(rows: list[dict], title: str = "Events") -> Table:
    t = Table(title=title, box=box.MINIMAL_DOUBLE_HEAD, expand=True, header_style="bold")
    t.add_column("ID",       width=6,  no_wrap=True, style="dim")
    t.add_column("Time",     width=20, no_wrap=True)
    t.add_column("Severity", width=10, no_wrap=True)
    t.add_column("Type",     width=20, no_wrap=True)
    t.add_column("Source",   width=12, no_wrap=True)
    t.add_column("Detail",   ratio=1)

    for r in rows:
        sev = Text(r["severity"], style=SEVERITY_STYLE.get(r["severity"], ""))
        t.add_row(
            str(r["id"]),
            fmt_time(r["timestamp"]),
            sev,
            r["type"],
            r["source"],
            fmt_data(r["data"]),
        )
    return t


def dns_table(rows: list[dict], title: str = "DNS queries") -> Table:
    t = Table(title=title, box=box.MINIMAL_DOUBLE_HEAD, expand=True, header_style="bold")
    t.add_column("ID",      width=6,  no_wrap=True, style="dim")
    t.add_column("Time",    width=20, no_wrap=True)
    t.add_column("Src IP",  width=18, no_wrap=True)
    t.add_column("Query",   ratio=1)
    t.add_column("Type",    width=7,  no_wrap=True)
    t.add_column("Blocked", width=8,  no_wrap=True)

    for r in rows:
        blocked = Text("YES", style="bold red") if r["blocked"] else Text("no", style="dim")
        t.add_row(
            str(r["id"]),
            fmt_time(r["timestamp"]),
            r["src_ip"],
            r["query_name"],
            r["query_type"],
            blocked,
        )
    return t


def devices_table(rows: list[dict], title: str = "Devices") -> Table:
    t = Table(title=title, box=box.MINIMAL_DOUBLE_HEAD, expand=True, header_style="bold")
    t.add_column("IP",         width=18, no_wrap=True)
    t.add_column("MAC",        width=20, no_wrap=True)
    t.add_column("Hostname",   width=20, no_wrap=True)
    t.add_column("Vendor",     width=16, no_wrap=True)
    t.add_column("First seen", width=20, no_wrap=True)
    t.add_column("Last seen",  width=20, no_wrap=True)
    t.add_column("Flagged",    width=8,  no_wrap=True)

    for r in rows:
        flagged = Text("YES", style="bold red") if r["flagged"] else Text("no", style="dim")
        t.add_row(
            r["ip"],
            r.get("mac") or "-",
            r.get("hostname") or "-",
            r.get("vendor") or "-",
            fmt_time(r["first_seen"]),
            fmt_time(r["last_seen"]),
            flagged,
        )
    return t


def stats_table(stats: dict) -> Table:
    t = Table(title="Sentinel DB stats", box=box.MINIMAL_DOUBLE_HEAD, header_style="bold")
    t.add_column("Table",  width=20)
    t.add_column("Count",  width=10, justify="right")

    labels = {
        "events":      "Total events",
        "dns_queries": "DNS queries",
        "dns_blocked": "DNS blocked",
        "packets":     "Packets",
        "devices":     "Devices seen",
    }
    for key, label in labels.items():
        val = stats.get(key, 0)
        style = "bold red" if key == "dns_blocked" and val > 0 else ""
        t.add_row(label, Text(str(val), style=style))
    return t


async def tail_mode(db: Database, severity: str, interval: float = 1.5) -> None:
    """Poll DB every interval seconds and show new events live."""
    console.print("[dim]Tail mode — Ctrl+C to stop[/]")
    seen_ids: set[int] = set()
    since = time.time() - 60

    try:
        while True:
            rows = await db.query_events(severity=severity if severity != "info" else None, since=since, limit=50)
            new  = [r for r in rows if r["id"] not in seen_ids]
            for r in reversed(new):
                seen_ids.add(r["id"])
                sev    = Text(f"[{r['severity']:8}]", style=SEVERITY_STYLE.get(r["severity"], ""))
                detail = fmt_data(r["data"])
                console.print(
                    f"[dim]{fmt_time(r['timestamp'])}[/]  ",
                    sev,
                    f"[dim]{r['type']:20}[/]  ",
                    detail,
                    sep="",
                )
            await asyncio.sleep(interval)
    except KeyboardInterrupt:
        pass


async def run(args: argparse.Namespace) -> None:
    db_path = Path(args.db)
    if not db_path.exists():
        console.print(f"[red]Database not found:[/] {db_path}")
        console.print("[dim]Start sentinel first to create it.[/]")
        return

    async with Database(db_path) as db:

        if args.stats:
            s = await db.stats()
            console.print(stats_table(s))
            return

        if args.tail:
            await tail_mode(db, severity=args.severity or "info")
            return

        if args.dns:
            rows = await db.query_dns(
                blocked_only=args.blocked,
                limit=args.limit,
            )
            title = "Blocked DNS queries" if args.blocked else "DNS queries"
            if not rows:
                console.print(f"[dim]No {title.lower()} found.[/]")
                return
            console.print(dns_table(rows, title=f"{title} (last {len(rows)})"))
            return

        if args.devices:
            rows = await db.query_devices(flagged_only=args.flagged)
            title = "Flagged devices" if args.flagged else "All devices"
            if not rows:
                console.print(f"[dim]No {title.lower()} found.[/]")
                return
            console.print(devices_table(rows, title=f"{title} ({len(rows)})"))
            return

        rows = await db.query_events(
            severity=args.severity,
            event_type=args.type,
            limit=args.limit,
        )
        title = "Events"
        if args.severity:
            title += f" [{args.severity}]"
        if args.type:
            title += f" [{args.type}]"
        if not rows:
            console.print(f"[dim]No events found.[/]")
            return
        console.print(events_table(rows, title=f"{title} (last {len(rows)})"))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel query tool — inspect the local DB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  sentinel-query --stats
  sentinel-query --events
  sentinel-query --events --severity warning
  sentinel-query --events --severity critical
  sentinel-query --events --type dns.blocked
  sentinel-query --dns
  sentinel-query --dns --blocked
  sentinel-query --devices
  sentinel-query --devices --flagged
  sentinel-query --tail
  sentinel-query --tail --severity warning
        """,
    )

    parser.add_argument("--db",       default="sentinel.db", help="Path to sentinel.db")
    parser.add_argument("--limit",    type=int, default=50,  help="Max rows to return (default: 50)")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--events",  action="store_true", help="Query events table (default)")
    mode.add_argument("--dns",     action="store_true", help="Query DNS queries table")
    mode.add_argument("--devices", action="store_true", help="Query devices table")
    mode.add_argument("--stats",   action="store_true", help="Show DB statistics")
    mode.add_argument("--tail",    action="store_true", help="Live follow new events (like tail -f)")

    parser.add_argument("--severity", choices=["info", "warning", "critical"], help="Filter by severity")
    parser.add_argument("--type",     help="Filter by event type (e.g. dns.blocked, packet.captured)")
    parser.add_argument("--blocked",  action="store_true", help="DNS: show blocked only")
    parser.add_argument("--flagged",  action="store_true", help="Devices: show flagged only")

    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()