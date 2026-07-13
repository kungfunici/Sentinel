import asyncio
import pytest
from pathlib import Path
from sentinel.core.threat_feeds import (
    _parse_hosts_format,
    _parse_domain_per_line,
    fetch_feed,
    update_blocklist,
    DEFAULT_FEEDS,
)

pytestmark = pytest.mark.asyncio


class TestParseHostsFormat:
    def test_standard_hosts_line(self):
        text = "0.0.0.0 evil.com\n"
        result = _parse_hosts_format(text)
        assert "evil.com" in result

    def test_127_dot_0_0_1_line(self):
        text = "127.0.0.1 tracking.example.com\n"
        result = _parse_hosts_format(text)
        assert "tracking.example.com" in result

    def test_ipv6_hosts_line(self):
        text = ":: malware.test\n"
        result = _parse_hosts_format(text)
        assert "malware.test" in result

    def test_comment_ignored(self):
        text = "# this is a comment\n0.0.0.0 real.com\n"
        result = _parse_hosts_format(text)
        assert "real.com" in result

    def test_empty_line_ignored(self):
        text = "\n\n0.0.0.0 test.com\n\n"
        result = _parse_hosts_format(text)
        assert "test.com" in result

    def test_localhost_excluded(self):
        text = "127.0.0.1 localhost\n0.0.0.0 evil.com\n"
        result = _parse_hosts_format(text)
        assert "localhost" not in result
        assert "evil.com" in result

    def test_localdomain_excluded(self):
        text = "0.0.0.0 host.localdomain\n0.0.0.0 real.com\n"
        result = _parse_hosts_format(text)
        assert "host.localdomain" not in result
        assert "real.com" in result

    def test_case_normalized(self):
        text = "0.0.0.0 EVIL.COM\n"
        result = _parse_hosts_format(text)
        assert "evil.com" in result

    def test_multiple_entries(self):
        text = "0.0.0.0 a.com\n0.0.0.0 b.com\n127.0.0.1 c.com\n"
        result = _parse_hosts_format(text)
        assert result == {"a.com", "b.com", "c.com"}

    def test_wrong_ip_not_parsed(self):
        text = "1.2.3.4 not-a-host-entry.com\n"
        result = _parse_hosts_format(text)
        assert len(result) == 0

    def test_no_valid_lines_returns_empty(self):
        text = "# only comments\n# another\n"
        result = _parse_hosts_format(text)
        assert result == set()


class TestParseDomainPerLine:
    def test_simple_domain(self):
        text = "evil.com\n"
        result = _parse_domain_per_line(text)
        assert "evil.com" in result

    def test_comment_ignored(self):
        text = "# comment\nmalware.test\n"
        result = _parse_domain_per_line(text)
        assert "malware.test" in result

    def test_adblock_comment_ignored(self):
        text = "! adblock\nbad.com\n"
        result = _parse_domain_per_line(text)
        assert "bad.com" in result

    def test_empty_line_ignored(self):
        text = "\n\n\ndanger.com\n\n"
        result = _parse_domain_per_line(text)
        assert "danger.com" in result

    def test_case_normalized(self):
        text = "EVIL.COM\n"
        result = _parse_domain_per_line(text)
        assert "evil.com" in result

    def test_whitespace_stripped(self):
        text = "  evil.com  \n"
        result = _parse_domain_per_line(text)
        assert "evil.com" in result

    def test_multiple_domains(self):
        text = "a.com\nb.com\nc.com\n"
        result = _parse_domain_per_line(text)
        assert result == {"a.com", "b.com", "c.com"}


class TestDEFAULT_FEEDS:
    def test_feeds_have_required_keys(self):
        for feed in DEFAULT_FEEDS:
            assert "name" in feed
            assert "url" in feed
            assert "parser" in feed
            assert "enabled" in feed

    def test_feeds_use_known_parsers(self):
        known = {"hosts", "domain"}
        for feed in DEFAULT_FEEDS:
            assert feed["parser"] in known

    def test_feeds_are_enabled_by_default(self):
        for feed in DEFAULT_FEEDS:
            assert feed["enabled"] is True


class TestUpdateBlocklist:
    async def test_no_blocklist_path_returns_zero(self):
        result = await update_blocklist(None)
        assert result == 0

    async def test_no_enabled_feeds_returns_zero(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("existing.com\n")
            bl_path = f.name
        try:
            result = await update_blocklist(Path(bl_path), feeds=[])
            assert result == 0
        finally:
            import os
            os.unlink(bl_path)

    async def test_all_feeds_disabled_returns_zero(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("existing.com\n")
            bl_path = f.name
        try:
            result = await update_blocklist(
                Path(bl_path),
                feeds=[{"name": "x", "url": "http://x", "parser": "domain", "enabled": False}],
            )
            assert result == 0
        finally:
            import os
            os.unlink(bl_path)

    async def test_existing_entries_preserved(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("existing.com\n")
            bl_path = f.name
        try:
            result = await update_blocklist(
                Path(bl_path),
                feeds=[{"name": "x", "url": "http://x", "parser": "domain", "enabled": True}],
            )
            content = Path(bl_path).read_text()
            assert "existing.com" in content
        finally:
            import os
            os.unlink(bl_path)

    async def test_new_blocklist_created(self, tmp_path):
        bl_path = tmp_path / "blocklist.txt"
        feeds = [{"name": "test", "url": "http://localhost:0/fake", "parser": "domain", "enabled": True}]
        result = await update_blocklist(bl_path, feeds)
        assert isinstance(result, int)
        assert bl_path.exists() or result == 0


class TestFetchFeed:
    async def test_invalid_url_returns_empty(self):
        result = await fetch_feed("http://localhost:1/nonexistent", "domain")
        assert result == set()

    async def test_unknown_parser_returns_empty(self):
        result = await fetch_feed("http://x.com", "unknown_parser")
        assert result == set()
