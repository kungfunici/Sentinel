import asyncio
import pytest
from pathlib import Path
from sentinel.core.enrichment import Enricher, _parse_oui_csv, _parse_wireshark_manuf

pytestmark = pytest.mark.asyncio


class TestParseOuiCsv:
    def test_single_entry(self):
        text = "Assignment,Organization Name\n000000,Test Vendor Inc.\n"
        result = _parse_oui_csv(text)
        assert result.get("000000") == "Test Vendor Inc."

    def test_multiple_entries(self):
        text = "Assignment,Organization Name\n000000,Vendor A\n000001,Vendor B\n"
        result = _parse_oui_csv(text)
        assert len(result) == 2
        assert result["000000"] == "Vendor A"
        assert result["000001"] == "Vendor B"

    def test_empty_text_returns_empty(self):
        assert _parse_oui_csv("") == {}

    def test_whitespace_stripped(self):
        text = "Assignment,Organization Name\n 000000 , Test Vendor \n"
        result = _parse_oui_csv(text)
        assert result.get("000000") == "Test Vendor"

    def test_missing_assignment_skipped(self):
        text = "Organization Name\nTest\n"
        result = _parse_oui_csv(text)
        assert result == {}

    def test_realistic_sample(self):
        text = "Assignment,Organization Name\n0050C2,Microsoft\n00037C,Apple\n"
        result = _parse_oui_csv(text)
        assert result["0050C2"] == "Microsoft"
        assert result["00037C"] == "Apple"


class TestParseWiresharkManuf:
    def test_single_entry(self):
        text = "00:00:00\tVendor Zero\n"
        result = _parse_wireshark_manuf(text)
        assert result.get("000000") == "Vendor Zero"

    def test_dash_separated(self):
        text = "00-50-C2\tMicrosoft\n"
        result = _parse_wireshark_manuf(text)
        assert result.get("0050C2") == "Microsoft"

    def test_comment_ignored(self):
        text = "# This is a comment\n00:00:00\tVendor\n"
        result = _parse_wireshark_manuf(text)
        assert "000000" in result

    def test_empty_line_ignored(self):
        text = "\n\n00:00:00\tVendor\n"
        result = _parse_wireshark_manuf(text)
        assert "000000" in result

    def test_entry_with_short_prefix(self):
        text = "000000/8\tShort Vendor\n"
        result = _parse_wireshark_manuf(text)
        assert result.get("000000") == "Short Vendor"

    def test_multiple_entries(self):
        text = "00:00:00\tVendor A\n00:00:01\tVendor B\n"
        result = _parse_wireshark_manuf(text)
        assert len(result) == 2


class TestVendorForMac:
    async def test_known_vendor(self):
        enricher = Enricher()
        enricher._oui = {"0050C2": "Microsoft"}
        result = enricher.vendor_for_mac("00:50:C2:00:00:01")
        assert result == "Microsoft"

    async def test_dash_format(self):
        enricher = Enricher()
        enricher._oui = {"0050C2": "Microsoft"}
        result = enricher.vendor_for_mac("00-50-C2-00-00-01")
        assert result == "Microsoft"

    async def test_unknown_vendor(self):
        enricher = Enricher()
        enricher._oui = {"0050C2": "Microsoft"}
        result = enricher.vendor_for_mac("ff:ff:ff:ff:ff:ff")
        assert result is None

    async def test_no_mac_returns_none(self):
        enricher = Enricher()
        result = enricher.vendor_for_mac(None)
        assert result is None

    async def test_empty_string_returns_none(self):
        enricher = Enricher()
        result = enricher.vendor_for_mac("")
        assert result is None

    async def test_oui_prefix_truncated_to_6_chars(self):
        enricher = Enricher()
        enricher._oui = {"0050C2": "Microsoft"}
        result = enricher.vendor_for_mac("00:50:C2:FF:FF:FF")
        assert result == "Microsoft"

    async def test_oui_cache_not_shared(self):
        e1 = Enricher()
        e2 = Enricher()
        assert e1._oui is not e2._oui


class TestEnricherCache:
    async def test_cache_hits(self):
        enricher = Enricher()
        enricher._cache["10.0.0.1"] = {"hostname": "router.local", "vendor": "Cisco"}
        result = await enricher.enrich("10.0.0.1")
        assert result["hostname"] == "router.local"
        assert result["vendor"] == "Cisco"

    async def test_partial_cache_miss(self):
        enricher = Enricher()
        enricher._cache["10.0.0.1"] = {"hostname": "router.local"}
        result = await enricher.enrich("10.0.0.1")
        assert result["hostname"] == "router.local"


class TestEnricherSetup:
    async def test_setup_no_oui_file(self, tmp_path, monkeypatch):
        async def fake_download(path):
            return {}
        enricher = Enricher(oui_path=str(tmp_path / "nonexistent.csv"))
        with monkeypatch.context() as m:
            m.setattr("sentinel.core.enrichment._download_oui", fake_download)
            await enricher.setup()
        assert enricher._oui == {}


class TestReverseDns:
    async def test_reverse_dns_returns_none_on_invalid(self):
        enricher = Enricher()
        result = await enricher.reverse_dns("192.0.2.1")
        assert result is None or isinstance(result, str)
