# Sentinel

Local network security monitoring suite. Passively sniffs traffic with Scapy to detect ARP spoofing, DNS threats, unknown devices, and port scans on your LAN.

## Features

- **Packet sniffing** — captures and analyzes live traffic
- **ARP monitoring** — detects spoofing, flooding, gratuitous ARP, and MITM attacks
- **DNS monitoring** — sniffs DNS queries and blocks malicious domains against a customizable blocklist (supports wildcards)
- **HTTP monitoring** — inspects HTTP requests for suspicious keywords, user agents, and cross-origin referers
- **DHCP monitoring** — detects DHCP starvation, rogue servers, and anomalies
- **ICMP monitoring** — detects ping floods, smurf attacks, and ICMP redirects
- **TLS monitoring** — captures TLS handshake metadata (JA3, SNI, certificate info)
- **Device discovery** — automatically finds new hosts on the LAN via ARP and IP traffic
- **Port scanning** — periodically scans discovered hosts for open ports; alerts on new or high-risk ports (SSH, RDP, Telnet)
- **Bandwidth tracking** — per-device bandwidth usage over time
- **Device enrichment** — reverse DNS lookups and MAC OUI vendor identification
- **Alert rules engine** — threshold-based rules (e.g., escalate after N critical events in a time window)
- **Email notifications** — SMTP alerts for warning/critical events with cooldown
- **Threat feeds** — automatic blocklist updates from external intelligence feeds
- **Interactive shell** — real-time CLI with commands for events, devices, DNS, flagging
- **Web dashboard** — FastAPI + Tailwind + HTMX with real-time WebSocket live feed
- **Network topology** — visualize discovered devices and connections
- **Data retention** — automatic cleanup of old events (configurable)

## Quick start

```bash
pip install sentinel
sentinel
```

Open http://localhost:8888 for the dashboard.

### Options

```
sentinel --iface eth0 --blocklist blocklist.txt --gateway 192.168.1.1 --daemon
```

| Flag | Default | Description |
|------|---------|-------------|
| `--iface` | auto | Network interface |
| `--db` | sentinel.db | SQLite database path |
| `--blocklist` | — | DNS blocklist file |
| `--gateway` | auto | Gateway IP for spoofing detection |
| `--host` | 0.0.0.0 | API bind address |
| `--port` | 8888 | API port |
| `--scan-interval` | 60 | Port scan interval in seconds |
| `--retention-days` | 30 | Delete events older than N days |
| `--oui-path` | oui.csv | Path to OUI vendor database |
| `--threat-feeds` | — | Enable automatic blocklist updates |
| `--daemon` | — | Run headless (no shell, live TUI + dashboard) |
| `--smtp-server` | — | SMTP server for email alerts |
| `--smtp-port` | 587 | SMTP port |
| `--smtp-user` | — | SMTP username |
| `--smtp-password` | — | SMTP password |
| `--smtp-ssl` | — | Use SMTP over SSL (port 465) |
| `--email-from` | sentinel@localhost | From address |
| `--email-to` | — | Recipient address |
| `--verbose` | — | Debug logging |

### Config file

Copy `sentinel.example.json` to `sentinel.json` (gitignored) to persist settings and define alert rules:

```json
{
    "smtp_server": "smtp.gmail.com",
    "smtp_user": "you@gmail.com",
    "smtp_password": "your-app-password",
    "email_to": "you@gmail.com",
    "iface": "eth0",
    "gateway": "192.168.1.1",
    "rules": [
        {
            "name": "ARP spoofing burst",
            "match": {"type": "arp.anomaly", "severity": "critical"},
            "threshold": 3,
            "window": 120,
            "action": {"escalate_to": "critical"}
        }
    ]
}
```

### Interactive shell

Without `--daemon`, Sentinel starts an interactive shell:

```
╭─ Sentinel ──────────────────────────╮
│                                     │
│  events    — show recent events     │
│  devices   — list discovered hosts  │
│  dns       — show DNS queries       │
│  flag/unflag — mark devices         │
│  stats     — session statistics     │
│  help      — show all commands      │
│  exit      — stop                   │
╰─────────────────────────────────────╯
```

## Blocklist format

One domain per line. Wildcards (`*.`) are supported:

```
example.com
*.malware.test
ads.tracking.net
```

## Architecture

Collectors publish events to a central `EventBus`. Consumers write to SQLite, run enrichment, evaluate alert rules, and stream to the dashboard via WebSocket.

```
PacketSniffer ─┐
DnsMonitor    ─┤
ArpWatcher    ─┤
PortScanner   ─┤
HttpMonitor   ─┼─→ EventBus ─→ Database (SQLite)
DhcpMonitor   ─┤       │
IcmpMonitor   ─┤       ├─→ WebSocket → Dashboard
TlsMonitor    ─┘       ├─→ Rules Engine → Email Notifier
BandwidthTracker ──────┘
```

## Requirements

- Python ≥ 3.11
- [Npcap](https://npcap.com) (Windows) or libpcap (Linux/macOS) for packet capture
- Administrator/root privileges may be required for raw socket access
