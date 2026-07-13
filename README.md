# Sentinel

Local network security monitoring suite. Passively sniffs traffic with Scapy to detect ARP spoofing, DNS threats, unknown devices, and port scans on your LAN.

## Features

- **ARP monitoring** — detects spoofing, flooding, gratuitous ARP, and MITM attacks
- **DNS monitoring** — sniffs DNS queries and blocks malicious domains against a customizable blocklist (supports wildcards)
- **Device discovery** — automatically finds new hosts on the LAN via ARP and IP traffic
- **Port scanning** — periodically scans discovered hosts for open ports; alerts on new or high-risk ports (SSH, RDP, Telnet)
- **Device enrichment** — reverse DNS lookups and MAC OUI vendor identification
- **Web dashboard** — FastAPI + Tailwind + HTMX with real-time WebSocket live feed
- **CLI query tool** — inspect the database from the terminal

## Quick start

```bash
pip install sentinel
sentinel
```

Open http://localhost:8888 for the dashboard.

### Options

```
sentinel --iface eth0 --blocklist blocklist.txt --gateway 192.168.1.1
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
| `--verbose` | — | Debug logging |

### Query tool

```bash
sentinel-query events --severity critical
sentinel-query dns --blocked
sentinel-query devices
sentinel-query tail
```

## Blocklist format

One domain per line. Wildcards (`*.`) are supported:

```
example.com
*.malware.test
ads.tracking.net
```

## Architecture

Collectors (sniffer, DNS monitor, ARP watcher, port scanner) publish events to a central `EventBus`. A database consumer writes them to SQLite, and the web dashboard displays them in real time via WebSocket.

```
PacketSniffer ─┐
DnsMonitor    ─┤
ArpWatcher    ─┼─→ EventBus ─→ Database (SQLite)
PortScanner   ─┘       │
                        └─→ WebSocket → Dashboard
```

## Requirements

- Python ≥ 3.11
- [Npcap](https://npcap.com) (Windows) or libpcap (Linux/macOS) for packet capture
- Administrator/root privileges may be required for raw socket access
