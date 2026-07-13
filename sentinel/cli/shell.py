import asyncio
import shlex
import time
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

console = Console()

SEVERITY_STYLE = {
    "info":     "dim",
    "warning":  "yellow",
    "critical": "bold red",
}

EVENT_TYPE_STYLE = {
    "packet.captured":  "dim",
    "dns.query":        "cyan",
    "dns.blocked":      "bold red",
    "device.new":       "green",
    "arp.anomaly":      "yellow",
    "port.scan_result": "magenta",
    "dhcp.anomaly":     "yellow",
    "dns.anomaly":      "yellow",
    "http.request":     "cyan",
    "icmp.anomaly":     "yellow",
    "bandwidth.report": "dim",
    "system.error":     "bold red",
}


def fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def fmt_data(raw: str) -> str:
    import json
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
        if "description" in d:
            return d["description"]
        return str(d)[:120]
    except Exception:
        return raw[:120]


class SentinelShell:
    def __init__(self, db, bus, blocklist_path: str | None = None, stop_event=None):
        self.db = db
        self.bus = bus
        self.blocklist_path = Path(blocklist_path) if blocklist_path else None
        self.stop_event = stop_event
        self._running = True
        self._history: list[str] = []

    async def run(self) -> None:
        console.print("[bold green]Sentinel Interactive Shell[/]")
        console.print("[dim]Monitors are running in the background.[/]")
        console.print("[dim]Type 'help' for commands, 'exit' to quit.[/]")
        console.print()
        await self._repl()

    async def _repl(self) -> None:
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                line = await loop.run_in_executor(None, lambda: input("sentinel> "))
            except (EOFError, KeyboardInterrupt):
                console.print()
                continue

            if not line.strip():
                continue

            self._history.append(line.strip())

            try:
                parts = shlex.split(line)
            except ValueError as e:
                console.print(f"[red]Invalid syntax:[/] {e}")
                continue

            cmd = parts[0].lower()
            args = parts[1:]

            handler = self._get_handler(cmd)
            if handler:
                try:
                    await handler(args)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    console.print(f"[red]Error:[/] {e}")
            else:
                console.print(f"[red]Unknown command:[/] {cmd}")
                console.print("[dim]Type 'help' for available commands.[/]")

        if self.stop_event:
            self.stop_event.set()

    def _get_handler(self, cmd: str):
        handlers = {
            "help": self._help,
            "?": self._help,
            "events": self._events,
            "dns": self._dns,
            "devices": self._devices,
            "stats": self._stats,
            "tail": self._tail,
            "flag": self._flag,
            "unflag": self._unflag,
            "block": self._block,
            "clear": self._clear,
            "history": self._history_cmd,
            "exit": self._exit,
            "quit": self._exit,
        }
        return handlers.get(cmd)

    async def _help(self, _args: list[str]) -> None:
        console.print()
        console.print("[bold]Available commands:[/]")
        console.print("  [green]help[/]                       Show this help message")
        console.print("  [green]events[/] [severity] [limit=N]  Show recent events")
        console.print("  [green]dns[/] [--blocked] [limit=N]    Show DNS queries")
        console.print("  [green]devices[/] [--flagged]          Show discovered devices")
        console.print("  [green]stats[/]                       Show database statistics")
        console.print("  [green]tail[/] [severity]              Live-tail new events (Ctrl+C to stop)")
        console.print("  [green]flag[/] <ip>                    Mark a device as flagged")
        console.print("  [green]unflag[/] <ip>                  Remove flag from a device")
        console.print("  [green]block[/] <domain>               Add domain to DNS blocklist")
        console.print("  [green]history[/]                      Show command history")
        console.print("  [green]clear[/]                        Clear the screen")
        console.print("  [green]exit[/] / [green]quit[/]                 Exit the shell")
        console.print()

    async def _events(self, args: list[str]) -> None:
        severity = "info"
        limit = 50
        for a in args:
            if a in ("info", "warning", "critical"):
                severity = a
            elif a.startswith("limit="):
                try:
                    limit = int(a.split("=", 1)[1])
                except ValueError:
                    console.print("[red]Invalid limit value[/]")
                    return
            else:
                console.print(f"[red]Unknown argument:[/] {a}")
                return

        rows = await self.db.query_events(
            severity=severity if severity != "info" else None,
            limit=limit,
        )
        if not rows:
            console.print("[dim]No events found.[/]")
            return

        table = Table(
            title=f"Events (last {len(rows)}) [{severity}]",
            box=box.MINIMAL_DOUBLE_HEAD,
            expand=True,
            header_style="bold",
        )
        table.add_column("ID",       width=6,  no_wrap=True, style="dim")
        table.add_column("Time",     width=20, no_wrap=True)
        table.add_column("Severity", width=10, no_wrap=True)
        table.add_column("Type",     width=20, no_wrap=True)
        table.add_column("Source",   width=12, no_wrap=True)
        table.add_column("Detail",   ratio=1)

        for r in rows:
            sev = Text(r["severity"], style=SEVERITY_STYLE.get(r["severity"], ""))
            t_style = EVENT_TYPE_STYLE.get(r["type"], "")
            table.add_row(
                str(r["id"]),
                fmt_time(r["timestamp"]),
                sev,
                Text(r["type"], style=t_style),
                r["source"],
                fmt_data(r["data"]),
            )

        console.print(table)

    async def _dns(self, args: list[str]) -> None:
        blocked_only = False
        limit = 50
        for a in args:
            if a == "--blocked":
                blocked_only = True
            elif a.startswith("limit="):
                try:
                    limit = int(a.split("=", 1)[1])
                except ValueError:
                    console.print("[red]Invalid limit value[/]")
                    return
            else:
                console.print(f"[red]Unknown argument:[/] {a}")
                return

        rows = await self.db.query_dns(blocked_only=blocked_only, limit=limit)
        if not rows:
            console.print("[dim]No DNS queries found.[/]")
            return

        title = "DNS queries"
        if blocked_only:
            title = "Blocked DNS queries"

        table = Table(
            title=f"{title} (last {len(rows)})",
            box=box.MINIMAL_DOUBLE_HEAD,
            expand=True,
            header_style="bold",
        )
        table.add_column("ID",      width=6,  no_wrap=True, style="dim")
        table.add_column("Time",    width=20, no_wrap=True)
        table.add_column("Src IP",  width=18, no_wrap=True)
        table.add_column("Query",   ratio=1)
        table.add_column("Type",    width=7,  no_wrap=True)
        table.add_column("Blocked", width=8,  no_wrap=True)

        for r in rows:
            blocked = Text("YES", style="bold red") if r["blocked"] else Text("no", style="dim")
            table.add_row(
                str(r["id"]),
                fmt_time(r["timestamp"]),
                r["src_ip"],
                r["query_name"],
                r["query_type"],
                blocked,
            )

        console.print(table)

    async def _devices(self, args: list[str]) -> None:
        flagged_only = "--flagged" in args
        rows = await self.db.query_devices(flagged_only=flagged_only)
        if not rows:
            console.print("[dim]No devices found.[/]")
            return

        title = "Flagged devices" if flagged_only else "All devices"

        table = Table(
            title=f"{title} ({len(rows)})",
            box=box.MINIMAL_DOUBLE_HEAD,
            expand=True,
            header_style="bold",
        )
        table.add_column("IP",         width=18, no_wrap=True)
        table.add_column("MAC",        width=20, no_wrap=True)
        table.add_column("Hostname",   width=20, no_wrap=True)
        table.add_column("Vendor",     width=16, no_wrap=True)
        table.add_column("First seen", width=20, no_wrap=True)
        table.add_column("Last seen",  width=20, no_wrap=True)
        table.add_column("Flagged",    width=8,  no_wrap=True)

        for r in rows:
            flagged = Text("YES", style="bold red") if r["flagged"] else Text("no", style="dim")
            table.add_row(
                r["ip"],
                r.get("mac") or "-",
                r.get("hostname") or "-",
                r.get("vendor") or "-",
                fmt_time(r["first_seen"]),
                fmt_time(r["last_seen"]),
                flagged,
            )

        console.print(table)

    async def _stats(self, _args: list[str]) -> None:
        s = await self.db.stats()

        table = Table(
            title="Database Statistics",
            box=box.MINIMAL_DOUBLE_HEAD,
            header_style="bold",
        )
        table.add_column("Metric",          width=20)
        table.add_column("Count",           width=10, justify="right")

        labels = {
            "events":      "Total events",
            "dns_queries": "DNS queries",
            "dns_blocked": "DNS blocked",
            "packets":     "Packets captured",
            "devices":     "Devices seen",
        }
        for key, label in labels.items():
            val = s.get(key, 0)
            style = "bold red" if key == "dns_blocked" and val > 0 else ""
            table.add_row(label, Text(str(val), style=style))

        console.print(table)

    async def _tail(self, args: list[str]) -> None:
        severity = "info"
        for a in args:
            if a in ("info", "warning", "critical"):
                severity = a
            else:
                console.print(f"[red]Unknown argument:[/] {a}")
                console.print("[dim]Usage: tail [severity][/]")
                return

        sev_param = severity if severity != "info" else None

        console.print("[dim]Tail mode — new events will appear below.[/]")
        console.print("[dim]Press Ctrl+C to stop and return to the shell.[/]")
        console.print()

        seen_ids: set[int] = set()
        since = time.time() - 60

        try:
            while True:
                rows = await self.db.query_events(severity=sev_param, since=since, limit=50)
                for r in reversed(rows):
                    if r["id"] not in seen_ids:
                        seen_ids.add(r["id"])
                        sev = Text(f"[{r['severity']:8}]", style=SEVERITY_STYLE.get(r["severity"], ""))
                        detail = fmt_data(r["data"])
                        console.print(
                            f"[dim]{fmt_time(r['timestamp'])}[/]  ",
                            sev,
                            f"[dim]{r['type']:20}[/]  ",
                            detail,
                            sep="",
                        )
                await asyncio.sleep(1.5)
        except (KeyboardInterrupt, asyncio.CancelledError):
            console.print()
            console.print("[dim]Tail stopped.[/]")

    async def _flag(self, args: list[str]) -> None:
        if not args:
            console.print("[red]Usage: flag <ip>[/]")
            return
        ip = args[0]
        await self.db.flag_device(ip, flagged=True)
        console.print(f"[green]Flagged[/] {ip}")

    async def _unflag(self, args: list[str]) -> None:
        if not args:
            console.print("[red]Usage: unflag <ip>[/]")
            return
        ip = args[0]
        await self.db.flag_device(ip, flagged=False)
        console.print(f"[green]Unflagged[/] {ip}")

    async def _block(self, args: list[str]) -> None:
        if not args:
            console.print("[red]Usage: block <domain>[/]")
            return
        domain = args[0]

        if not self.blocklist_path:
            console.print("[yellow]No blocklist file configured.[/]")
            return

        if domain in (".", "*"):
            console.print("[red]Invalid domain.[/]")
            return

        try:
            with open(self.blocklist_path, "a", encoding="utf-8") as f:
                f.write(domain.strip().lower() + "\n")
            console.print(f"[green]Added[/] {domain} to blocklist")
            console.print("[dim]DNS monitor will pick up the change within 60s.[/]")
        except OSError as e:
            console.print(f"[red]Failed to write blocklist:[/] {e}")

    async def _clear(self, _args: list[str]) -> None:
        console.clear()

    async def _history_cmd(self, _args: list[str]) -> None:
        if not self._history:
            console.print("[dim]No commands in history.[/]")
            return
        for i, cmd in enumerate(self._history, 1):
            console.print(f"  {i:3d}  {cmd}")

    async def _exit(self, _args: list[str]) -> None:
        self._running = False


def main() -> None:
    import argparse
    from sentinel.core.database import Database
    from sentinel.core.event_bus import EventBus

    parser = argparse.ArgumentParser(
        description="Sentinel interactive shell — query a Sentinel database",
    )
    parser.add_argument("--db", default="sentinel.db", help="Path to sentinel.db")
    parser.add_argument("--blocklist", default=None, help="Path to DNS blocklist file")
    args = parser.parse_args()

    async def _run():
        db_path = Path(args.db)
        if not db_path.exists():
            console.print(f"[red]Database not found:[/] {db_path}")
            console.print("[dim]Start 'sentinel' first to create the database.[/]")
            return
        async with Database(db_path) as db:
            bus = EventBus()
            shell = SentinelShell(db, bus, blocklist_path=args.blocklist)
            await shell.run()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print()
        console.print("[yellow]Exiting.[/]")


if __name__ == "__main__":
    main()
