"""
sentinel/core/enrichment.py

Async enrichment for discovered devices:
    - Reverse DNS lookup  (socket.getnameinfo)
    - MAC vendor lookup   (local IEEE OUI database, auto-downloaded)

Usage:
    enricher = Enricher(db)
    await enricher.setup()           # downloads OUI db if missing
    info = await enricher.enrich("192.168.178.1", "0c:72:74:8e:ab:ad")
    # -> {"hostname": "fritz.box", "vendor": "AVM GmbH"}

The enricher is also wired into the main event loop — it listens for
NEW_DEVICE events and auto-enriches them in the background.
"""

import asyncio
import csv
import io
import logging
import socket
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("sentinel.enrichment")

OUI_URL      = "https://standards-oui.ieee.org/oui/oui.csv"
OUI_FALLBACK = "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
OUI_PATH     = Path("oui.csv")
OUI_MAX_AGE  = 60 * 60 * 24 * 30   # refresh monthly


# ------------------------------------------------------------------ #
#  OUI database                                                        #
# ------------------------------------------------------------------ #

def _parse_oui_csv(text: str) -> dict[str, str]:
    """Parse IEEE OUI CSV → {prefix_upper: vendor_name}"""
    result: dict[str, str] = {}
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        try:
            # CSV columns: Registry,Assignment,Organization Name,Organization Address
            prefix = row.get("Assignment", "").upper().strip()
            vendor = row.get("Organization Name", "").strip()
            if prefix and vendor:
                result[prefix] = vendor
        except Exception:
            continue
    return result


def _parse_wireshark_manuf(text: str) -> dict[str, str]:
    """
    Fallback: parse Wireshark manuf file format:
        00:00:00\tXerox\t# Xerox Corporation
    """
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        prefix = parts[0].replace(":", "").replace("-", "").upper()[:6]
        vendor = parts[1].strip()
        if prefix and vendor:
            result[prefix] = vendor
    return result


async def _download_oui() -> dict[str, str]:
    """Download OUI database. Tries IEEE CSV first, falls back to Wireshark manuf."""
    import urllib.request

    log.info("Downloading OUI database from IEEE...")
    try:
        req = urllib.request.Request(
            OUI_URL,
            headers={"User-Agent": "Sentinel/0.1 network-monitor"},
        )
        loop = asyncio.get_running_loop()
        def _fetch():
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", errors="ignore")

        text = await loop.run_in_executor(None, _fetch)
        db   = _parse_oui_csv(text)
        if db:
            OUI_PATH.write_text(text, encoding="utf-8")
            log.info("OUI database saved: %d vendors (%s)", len(db), OUI_PATH)
            return db
    except Exception as exc:
        log.warning("IEEE OUI download failed: %s — trying Wireshark fallback", exc)

    # Wireshark fallback
    try:
        req2 = urllib.request.Request(
            OUI_FALLBACK,
            headers={"User-Agent": "Sentinel/0.1"},
        )
        loop = asyncio.get_running_loop()
        def _fetch2():
            with urllib.request.urlopen(req2, timeout=30) as r:
                return r.read().decode("utf-8", errors="ignore")

        text2 = await loop.run_in_executor(None, _fetch2)
        db2   = _parse_wireshark_manuf(text2)
        if db2:
            log.info("OUI database loaded from Wireshark manuf: %d vendors", len(db2))
            return db2
    except Exception as exc2:
        log.warning("Wireshark OUI fallback also failed: %s", exc2)

    log.warning("Could not download OUI database — vendor lookup disabled")
    return {}


def _load_oui_from_disk() -> dict[str, str]:
    if not OUI_PATH.exists():
        return {}
    try:
        text = OUI_PATH.read_text(encoding="utf-8")
        # Detect format
        if "Assignment" in text[:200]:
            db = _parse_oui_csv(text)
        else:
            db = _parse_wireshark_manuf(text)
        log.info("OUI database loaded from disk: %d vendors", len(db))
        return db
    except Exception as exc:
        log.warning("Failed to load OUI from disk: %s", exc)
        return {}


# ------------------------------------------------------------------ #
#  Enricher                                                            #
# ------------------------------------------------------------------ #

class Enricher:
    """
    Enriches IP/MAC pairs with hostname and vendor info.
    Results are cached in memory to avoid repeat lookups.
    """

    def __init__(self, db=None, dns_timeout: float = 2.0):
        self._db          = db          # sentinel Database instance (optional)
        self._oui:  dict[str, str] = {}
        self._cache: dict[str, dict] = {}   # ip -> {hostname, vendor}
        self._dns_timeout = dns_timeout
        self._dns_sem     = asyncio.Semaphore(10)   # max 10 concurrent DNS lookups

    async def setup(self) -> None:
        """Load or download OUI database."""
        # Try disk first
        self._oui = _load_oui_from_disk()

        # Download if missing or stale
        needs_download = not self._oui
        if OUI_PATH.exists():
            age = time.time() - OUI_PATH.stat().st_mtime
            if age > OUI_MAX_AGE:
                log.info("OUI database is %.0f days old, refreshing...", age / 86400)
                needs_download = True

        if needs_download:
            self._oui = await _download_oui()

    def vendor_for_mac(self, mac: Optional[str]) -> Optional[str]:
        """Look up vendor for a MAC address string like 'aa:bb:cc:dd:ee:ff'."""
        if not mac:
            return None
        try:
            prefix = mac.replace(":", "").replace("-", "").upper()[:6]
            return self._oui.get(prefix)
        except Exception:
            return None

    async def reverse_dns(self, ip: str) -> Optional[str]:
        """Non-blocking reverse DNS lookup with timeout."""
        if ip in self._cache and "hostname" in self._cache[ip]:
            return self._cache[ip]["hostname"]

        async with self._dns_sem:
            try:
                loop = asyncio.get_running_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)[0]
                    ),
                    timeout=self._dns_timeout,
                )
                # Don't store if result is just the IP back
                hostname = result if result != ip else None
                self._cache.setdefault(ip, {})["hostname"] = hostname
                return hostname
            except Exception:
                self._cache.setdefault(ip, {})["hostname"] = None
                return None

    async def enrich(self, ip: str, mac: Optional[str] = None) -> dict:
        """
        Full enrichment for an IP+MAC pair.
        Returns dict with hostname and vendor (both can be None).
        """
        if ip in self._cache:
            cached = self._cache[ip]
            if "hostname" in cached and "vendor" in cached:
                return cached

        hostname = await self.reverse_dns(ip)
        vendor   = self.vendor_for_mac(mac)

        result = {"hostname": hostname, "vendor": vendor}
        self._cache[ip] = result

        # Persist to DB if available
        if self._db and (hostname or vendor):
            try:
                await self._db._conn.execute(
                    """
                    UPDATE devices SET
                        hostname = COALESCE(?, hostname),
                        vendor   = COALESCE(?, vendor)
                    WHERE ip = ?
                    """,
                    (hostname, vendor, ip),
                )
                await self._db._conn.commit()
            except Exception as exc:
                log.debug("DB enrichment update failed: %s", exc)

        return result

    async def enrich_all_devices(self, db) -> int:
        """
        Enrich all devices in DB that are missing hostname or vendor.
        Returns count of devices updated.
        """
        devices = await db.query_devices()
        tasks   = []
        count   = 0

        for d in devices:
            if d.get("hostname") and d.get("vendor"):
                continue
            tasks.append(self.enrich(d["ip"], d.get("mac")))

        if not tasks:
            log.info("All devices already enriched")
            return 0

        log.info("Enriching %d devices...", len(tasks))
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for d, result in zip(
            [x for x in devices if not (x.get("hostname") and x.get("vendor"))],
            results
        ):
            if isinstance(result, Exception):
                continue
            if result.get("hostname") or result.get("vendor"):
                count += 1
                log.debug(
                    "  %s → hostname=%s vendor=%s",
                    d["ip"], result.get("hostname"), result.get("vendor"),
                )

        log.info("Enriched %d/%d devices", count, len(tasks))
        return count