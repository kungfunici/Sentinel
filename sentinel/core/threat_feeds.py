import asyncio
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.threat_feeds")

DEFAULT_FEEDS = [
    {
        "name": "StevenBlack hosts",
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "parser": "hosts",
        "enabled": True,
    },
    {
        "name": "OISD big",
        "url": "https://big.oisd.nl/",
        "parser": "domain",
        "enabled": True,
    },
]


def _parse_hosts_format(text: str) -> set[str]:
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::"):
            domain = parts[1].strip().lower()
            if domain.endswith(".localdomain") or domain == "localhost":
                continue
            domains.add(domain)
    return domains


def _parse_domain_per_line(text: str) -> set[str]:
    domains = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        domains.add(line)
    return domains


PARSERS = {
    "hosts": _parse_hosts_format,
    "domain": _parse_domain_per_line,
}


async def fetch_feed(url: str, parser_name: str) -> set[str]:
    import urllib.request
    loop = asyncio.get_running_loop()
    def _fetch():
        req = urllib.request.Request(url, headers={"User-Agent": "Sentinel/0.1"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", errors="ignore")
    try:
        text = await loop.run_in_executor(None, _fetch)
    except Exception as exc:
        log.warning("Feed download failed (%s): %s", url, exc)
        return set()

    parser = PARSERS.get(parser_name)
    if not parser:
        log.warning("Unknown parser: %s", parser_name)
        return set()

    domains = parser(text)
    log.info("Feed %s: %d domains", url, len(domains))
    return domains


async def update_blocklist(
    blocklist_path: Optional[Path],
    feeds: Optional[list[dict]] = None,
) -> int:
    if not blocklist_path:
        return 0

    feeds = DEFAULT_FEEDS if feeds is None else feeds
    enabled = [f for f in feeds if f.get("enabled", True)]
    if not enabled:
        return 0

    all_domains: set[str] = set()

    if blocklist_path.exists():
        existing = blocklist_path.read_text(encoding="utf-8").splitlines()
        for line in existing:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                all_domains.add(line)

    tasks = [fetch_feed(f["url"], f["parser"]) for f in enabled]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    added = 0
    for result in results:
        if isinstance(result, Exception):
            continue
        for domain in result:
            if domain not in all_domains:
                all_domains.add(domain)
                added += 1

    if added > 0:
        sorted_domains = sorted(all_domains)
        blocklist_path.write_text("\n".join(sorted_domains) + "\n", encoding="utf-8")
        log.info("Blocklist updated: %d total, %d new from feeds", len(sorted_domains), added)

    return added
