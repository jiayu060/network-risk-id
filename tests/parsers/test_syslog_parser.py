"""Tests for SyslogParser."""

import os
import pytest
from src.parsers.syslog_parser import SyslogParser
from src.parsers.parser_registry import ParserRegistry

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")


class TestSyslogParser:
    def setup_method(self):
        self.parser = SyslogParser(sensor_id="test-sensor")

    def test_parse_rfc5424_deny(self):
        line = '<134>1 2024-06-15T10:30:00.000Z firewall01 kernel - - - Denied TCP connection from 10.1.2.3:54321 to 192.168.1.100:443'
        record = self.parser.parse_line(line)
        assert record["source_type"] == "syslog"
        assert record["sensor_id"] == "firewall01"
        assert record["src_ip"] == "10.1.2.3"
        assert record["dst_ip"] == "192.168.1.100"
        assert record["src_port"] == 54321
        assert record["event_type"] == "suspicious_traffic"
        assert record["severity"] <= 5  # informational
        assert record["event_id"] is not None

    def test_parse_rfc3164_auth_success(self):
        line = '<13>Jun 15 10:30:15 webserver sshd[12345]: Accepted publickey for admin from 10.1.0.5 port 51234 ssh2'
        record = self.parser.parse_line(line)
        assert record["sensor_id"] == "webserver"
        assert record["src_ip"] == "10.1.0.5"
        assert record["src_port"] == 51234
        assert record["event_type"] == "auth_success"
        assert record["process_name"] == "sshd"
        assert record["process_id"] == 12345

    def test_parse_dns_query(self):
        line = '<14>Jun 15 10:30:20 dns-server named[6789]: client 192.168.1.50#51472: query: evil.xyz (A)'
        record = self.parser.parse_line(line)
        assert record["event_type"] == "dns_query"
        assert record["src_ip"] == "192.168.1.50"
        assert "evil.xyz" in record["raw_message"]

    def test_parse_auth_failure(self):
        line = '<134>1 2024-06-15T10:31:00.000Z authserver sshd - - - Failed password for invalid user root from 192.168.100.5 port 44567 ssh2'
        record = self.parser.parse_line(line)
        assert record["event_type"] == "auth_failure"
        assert record["src_ip"] == "192.168.100.5"

    def test_skip_comment_line(self):
        line = "# This is a comment line"
        record = self.parser.parse_line(line)
        assert record == {}

    def test_skip_empty_line(self):
        record = self.parser.parse_line("   ")
        assert record == {}

    def test_parse_batch(self):
        lines = [
            '<134>1 2024-06-15T10:30:00.000Z fw01 kernel - - - Denied TCP from 10.1.0.1 to 10.2.0.1',
            '<13>Jun 15 11:00:00 web01 sshd[1]: Accepted for user1 from 10.1.0.2',
        ]
        table = self.parser.parse_batch(iter(lines))
        assert len(table) == 2
        assert table.column("source_type")[0].as_py() == "syslog"

    def test_registry_get_parser(self):
        parser = ParserRegistry.get_parser("syslog")
        assert isinstance(parser, SyslogParser)

    def test_registry_unknown_source(self):
        with pytest.raises(ValueError, match="No parser registered"):
            ParserRegistry.get_parser("unknown_format")

    def test_parse_sample_file(self):
        filepath = os.path.join(FIXTURES_DIR, "sample_syslog.txt")
        assert os.path.exists(filepath), f"Fixture not found: {filepath}"

        records = []
        with open(filepath, "r") as f:
            for line in f:
                record = self.parser.parse_line(line)
                if record:
                    records.append(record)

        # 8 valid records, 1 comment skipped
        assert len(records) == 8, f"Expected 8 records, got {len(records)}"
        event_types = [r["event_type"] for r in records]
        assert "auth_success" in event_types
        assert "auth_failure" in event_types
        assert "suspicious_traffic" in event_types
        assert "dns_query" in event_types
