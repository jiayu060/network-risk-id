"""DNS log parser: BIND query logs, Unbound logs, Windows DNS debug logs."""

import hashlib
import uuid
import re
from datetime import datetime, timezone
from typing import Optional

from src.parsers.base import LogParser
from src.utils.text_utils import shannon_entropy, consonant_vowel_ratio

# BIND query log: DD-Mon-YYYY HH:MM:SS.mmm queries: client IP#port (domain): query: domain IN A +...
_BIND_QUERY_RE = re.compile(
    r"(\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+"
    r"queries:\s+info:\s+client\s+(@\S+)?\s*(\S+)#(\d+)\s+"
    r"\((\S+)\):\s+query:\s+(\S+)\s+IN\s+(\S+)"
)

# Simpler BIND pattern
_BIND_SIMPLE_RE = re.compile(
    r"client\s+(\S+?)(?:#(\d+))?[\s:]+(?:query|view).*?[:]\s*(\S+)\s"
)

# Unbound: [timestamp] unbound[pid:0] info: query response nxdomain . . .
_UNBOUND_RE = re.compile(
    r"\[\d+\]\s+unbound\[\d+:\d+\]\s+\w+:\s+(\S+)\s+(\S+)\s+(\S+)\s+"
    r"([\d.]+)\s+(\S+)\s+(\S+)"
)

# Windows DNS debug log (tab-separated)
# Fields: DateTime, ClientIP, QueryName, QueryType, ResponseCode, ...

# TLD extraction
_TLD_RE = re.compile(r"\.([a-z]{2,63})$", re.IGNORECASE)

# DNS response codes
_RCODE_MAP = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}


class DNSParser(LogParser):
    """Parser for DNS query logs (BIND, Unbound, Windows DNS debug)."""

    def __init__(self, sensor_id: str = "unknown"):
        self.sensor_id = sensor_id
        self.source_type = "dns"

    def parse_line(self, line: str) -> dict:
        line = line.strip()
        if not line or line.startswith("#"):
            return {}

        # Try BIND format first
        record = self._parse_bind(line)
        if record:
            return record

        # Try Unbound
        record = self._parse_unbound(line)
        if record:
            return record

        # Try Windows DNS debug (tab-separated)
        record = self._parse_windows_dns(line)
        if record:
            return record

        return self._parse_fallback(line)

    def _parse_bind(self, line: str) -> Optional[dict]:
        m = _BIND_QUERY_RE.match(line)
        if not m:
            m = _BIND_SIMPLE_RE.search(line)
        if not m:
            return None

        groups = m.groups()
        ts = int(datetime.now(timezone.utc).timestamp() * 1000)
        client_ip = groups[-5] if len(groups) >= 5 else None
        client_port = int(groups[-4]) if len(groups) >= 4 and groups[-4] and groups[-4].isdigit() else None
        domain = groups[-2] if len(groups) >= 2 else None
        qtype = groups[-1] if len(groups) >= 1 else None

        return self._build_record(line, ts, client_ip, client_port, domain, qtype, None)

    def _parse_unbound(self, line: str) -> Optional[dict]:
        m = _UNBOUND_RE.search(line)
        if not m:
            return None
        ts = int(datetime.now(timezone.utc).timestamp() * 1000)
        # Unbound fields: thread, level, rcode, elapsed_us, ip, qtype, domain
        rcode_str = m.group(1)
        domain = m.group(6)
        qtype = m.group(5)
        client_ip = m.group(4)

        rcode = None
        if rcode_str.lower() in ("nxdomain", "servfail", "noerror", "refused"):
            rcode = rcode_str.upper()

        return self._build_record(line, ts, client_ip, None, domain, qtype, rcode)

    def _parse_windows_dns(self, line: str) -> Optional[dict]:
        """Parse Windows DNS debug log (tab-separated with header)."""
        if "\t" not in line:
            return None
        parts = line.split("\t")
        if len(parts) < 8:
            return None
        # Typical order: DateTime, ClientIP, QueryName, QueryType, ResponseCode, ...
        try:
            # Try to detect schema by checking first field format
            ts_str = parts[0]
            try:
                ts = int(datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp() * 1000)
            except ValueError:
                ts = int(datetime.now(timezone.utc).timestamp() * 1000)

            client_ip = parts[1] if len(parts) > 1 else None
            domain = parts[2] if len(parts) > 2 else None
            qtype = parts[3] if len(parts) > 3 else None
            rcode = parts[4] if len(parts) > 4 else None

            # Convert numeric rcode
            if rcode and rcode.isdigit():
                rcode = _RCODE_MAP.get(int(rcode), rcode)

            return self._build_record(line, ts, client_ip, None, domain, qtype, rcode)
        except Exception:
            return None

    def _parse_fallback(self, line: str) -> dict:
        """Best-effort DNS log parsing."""
        ts = int(datetime.now(timezone.utc).timestamp() * 1000)
        # Try to find a domain-like pattern
        domain_matches = re.findall(r'\b([a-z0-9][-a-z0-9]*\.)+[a-z]{2,}\b', line, re.IGNORECASE)
        domain = domain_matches[0] if domain_matches else None

        ip_matches = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", line)
        client_ip = ip_matches[0] if ip_matches else None

        rcode = None
        if "NXDOMAIN" in line.upper():
            rcode = "NXDOMAIN"
        elif "SERVFAIL" in line.upper():
            rcode = "SERVFAIL"

        return self._build_record(line, ts, client_ip, None, domain, None, rcode)

    def _build_record(self, raw: str, ts: int, client_ip: Optional[str],
                      client_port: Optional[int], domain: Optional[str],
                      qtype: Optional[str], rcode: Optional[str]) -> dict:
        tags = []
        if rcode == "NXDOMAIN":
            tags.append("nxdomain")

        return {
            "event_id": self._gen_id(raw),
            "timestamp": ts,
            "ingest_time": int(datetime.now(timezone.utc).timestamp() * 1000),
            "source_type": "dns",
            "sensor_id": self.sensor_id,
            "src_ip": client_ip,
            "src_port": client_port,
            "dst_ip": None,
            "dst_port": None,
            "proto": "DNS",
            "event_type": "dns_query",
            "severity": 3,
            "user": None,
            "process_name": None,
            "process_id": None,
            "domain": domain,
            "url": None,
            "http_method": None,
            "http_status": None,
            "bytes_in": None,
            "bytes_out": None,
            "duration_ms": None,
            "dns_rcode": rcode,
            "dns_rdata": None,
            "waf_action": None,
            "waf_rule_id": None,
            "raw_message": raw,
            "tags": tags,
        }

    def _gen_id(self, raw: str) -> str:
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        return str(uuid.UUID(hex=h))
