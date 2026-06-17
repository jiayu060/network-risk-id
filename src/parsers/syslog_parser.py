"""Syslog parser: RFC 3164 (BSD) and RFC 5424 (IETF)."""

import re
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from src.parsers.base import LogParser

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
_RFC5424_RE = re.compile(
    r"^<(\d{1,3})>"            # PRI
    r"(\d)"                     # VERSION
    r"\s+(\S+)"                 # TIMESTAMP (ISO8601, possibly with TZ)
    r"\s+(\S+)"                 # HOSTNAME
    r"\s+(\S+)"                 # APP-NAME
    r"\s+(\S+)"                 # PROCID
    r"\s+(\S+)"                 # MSGID
    r"\s+(\[[^\]]*\])?"        # STRUCTURED-DATA (optional)
    r"\s*(.*)"                  # MSG
)

# RFC 3164: <PRI>TIMESTAMP HOSTNAME MSG (simpler, legacy)
_RFC3164_RE = re.compile(
    r"^<(\d{1,3})>"            # PRI
    r"(\S{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"  # TIMESTAMP (MMM DD HH:MM:SS)
    r"\s+(\S+)"                # HOSTNAME
    r"\s+(.*)"                 # MSG (may include TAG + CONTENT)
)

# IP extraction regexes
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_IPV6_RE = re.compile(r"\b([0-9a-fA-F:]+:+[0-9a-fA-F:]+\b)")

# Port extraction: matches "port 1234" and "IP:PORT" notation
_PORT_RE = re.compile(r"\b(?:port|dport|sport)[=:\s]+(\d{1,5})\b", re.IGNORECASE)
_IPPORT_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d{1,5})\b")

# Common syslog tag for network devices
_TAG_RE = re.compile(r"^(\S+?)(?:\[(\d+)\])?:\s*(.*)")

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class SyslogParser(LogParser):
    """Parser for Syslog RFC 3164 and RFC 5424 formats."""

    def __init__(self, sensor_id: str = "unknown"):
        self.sensor_id = sensor_id
        self.source_type = "syslog"
        self.nxdomain_count: dict = {}

    def parse_line(self, line: str) -> dict:
        line = line.strip()
        if not line or line.startswith("#"):
            return {}

        record = self._parse_with_format(line)
        if record is None:
            return {}
        return record

    def _parse_with_format(self, line: str) -> Optional[dict]:
        """Try RFC 5424 first, fall back to RFC 3164."""
        m = _RFC5424_RE.match(line)
        if m and m.group(2) == "1":  # version must be 1
            return self._parse_rfc5424(m, line)
        m = _RFC3164_RE.match(line)
        if m:
            return self._parse_rfc3164(m, line)
        return self._parse_fallback(line)

    def _parse_rfc5424(self, m: re.Match, raw: str) -> dict:
        pri = int(m.group(1))
        ts_str = m.group(3)
        hostname = m.group(4)
        app_name = m.group(5)
        procid = m.group(6)
        msgid = m.group(7)
        structured_data = m.group(8) or ""
        msg = m.group(9) or ""

        facility = pri >> 3
        severity = pri & 0x07

        timestamp = self._parse_iso_timestamp(ts_str)
        event_type = self._classify_syslog_event(facility, severity, app_name, msg)
        src_ip, dst_ip = self._extract_ips(msg, hostname)

        return {
            "event_id": self._generate_event_id(raw),
            "timestamp": timestamp,
            "ingest_time": int(datetime.now(timezone.utc).timestamp() * 1000),
            "source_type": "syslog",
            "sensor_id": hostname or self.sensor_id,
            "src_ip": src_ip,
            "src_port": self._extract_port(msg),
            "dst_ip": dst_ip,
            "dst_port": None,
            "proto": self._guess_proto(msg),
            "event_type": event_type,
            "severity": self._normalize_severity(severity),
            "user": None,
            "process_name": app_name if app_name != "-" else None,
            "process_id": int(procid) if procid.isdigit() else None,
            "domain": None,
            "url": None,
            "http_method": None,
            "http_status": None,
            "bytes_in": None,
            "bytes_out": None,
            "duration_ms": None,
            "dns_rcode": None,
            "dns_rdata": None,
            "waf_action": None,
            "waf_rule_id": None,
            "raw_message": raw,
            "tags": [],
        }

    def _parse_rfc3164(self, m: re.Match, raw: str) -> dict:
        pri = int(m.group(1))
        ts_str = m.group(2)
        hostname = m.group(3)
        msg = m.group(4)

        facility = pri >> 3
        severity = pri & 0x07

        # Extract app[pid]: tag from RFC 3164 message body
        proc_name = None
        proc_id = None
        tag_match = _TAG_RE.match(msg)
        if tag_match:
            proc_name = tag_match.group(1) or None
            if tag_match.group(2):
                proc_id = int(tag_match.group(2))
            msg_body = tag_match.group(3) or ""
        else:
            msg_body = msg

        timestamp = self._parse_3164_timestamp(ts_str)
        event_type = self._classify_syslog_event(facility, severity, hostname, msg_body)
        src_ip, dst_ip = self._extract_ips(msg_body, hostname)

        return {
            "event_id": self._generate_event_id(raw),
            "timestamp": timestamp,
            "ingest_time": int(datetime.now(timezone.utc).timestamp() * 1000),
            "source_type": "syslog",
            "sensor_id": hostname or self.sensor_id,
            "src_ip": src_ip,
            "src_port": self._extract_port(msg_body),
            "dst_ip": dst_ip,
            "dst_port": None,
            "proto": self._guess_proto(msg_body),
            "event_type": event_type,
            "severity": self._normalize_severity(severity),
            "user": None,
            "process_name": proc_name,
            "process_id": proc_id,
            "domain": None,
            "url": None,
            "http_method": None,
            "http_status": None,
            "bytes_in": None,
            "bytes_out": None,
            "duration_ms": None,
            "dns_rcode": None,
            "dns_rdata": None,
            "waf_action": None,
            "waf_rule_id": None,
            "raw_message": raw,
            "tags": [],
        }

    def _parse_fallback(self, line: str) -> Optional[dict]:
        """Best-effort parse for non-standard syslog-like lines."""
        m = re.match(r"^<(\d{1,3})>", line)
        pri = int(m.group(1)) if m else 13  # default: user.notice
        severity = pri & 0x07

        ts = int(datetime.now(timezone.utc).timestamp() * 1000)
        src_ip, dst_ip = self._extract_ips(line)
        return {
            "event_id": self._generate_event_id(line),
            "timestamp": ts,
            "ingest_time": ts,
            "source_type": "syslog",
            "sensor_id": self.sensor_id,
            "src_ip": src_ip,
            "src_port": self._extract_port(line),
            "dst_ip": dst_ip,
            "dst_port": None,
            "proto": self._guess_proto(line),
            "event_type": "suspicious_traffic" if "deny" in line.lower() or "block" in line.lower() else "network_connect",
            "severity": self._normalize_severity(severity),
            "user": None,
            "process_name": None,
            "process_id": None,
            "domain": None,
            "url": None,
            "http_method": None,
            "http_status": None,
            "bytes_in": None,
            "bytes_out": None,
            "duration_ms": None,
            "dns_rcode": None,
            "dns_rdata": None,
            "waf_action": None,
            "waf_rule_id": None,
            "raw_message": line,
            "tags": [],
        }

    # ---- helpers ----

    def _generate_event_id(self, raw: str) -> str:
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        return str(uuid.UUID(hex=h))

    def _parse_iso_timestamp(self, ts_str: str) -> int:
        """Parse ISO8601 timestamp (with or without timezone)."""
        ts_str = ts_str.replace("T", " ").replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            return int(datetime.now(timezone.utc).timestamp() * 1000)

    def _parse_3164_timestamp(self, ts_str: str) -> int:
        """Parse RFC 3164 timestamp: MMM DD HH:MM:SS."""
        now = datetime.now(timezone.utc)
        try:
            parts = ts_str.split()
            if len(parts) < 3:
                raise ValueError
            month = _MONTH_MAP.get(parts[0][:3], now.month)
            day = int(parts[1])
            time_parts = parts[2].split(":")
            h, m, s = int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
            dt = datetime(now.year, month, day, h, m, s, tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except (ValueError, IndexError):
            return int(now.timestamp() * 1000)

    def _classify_syslog_event(self, facility: int, severity: int, app: str, msg: str) -> str:
        msg_lower = msg.lower()

        # Check auth before network — "Accepted" is auth, not network
        if any(kw in msg_lower for kw in ("accepted",)):
            if any(kw in msg_lower for kw in ("password", "publickey", "keyboard", "ssh", "login")):
                return "auth_success"
        if any(kw in msg_lower for kw in ("failed password", "invalid user", "authentication failure",
                                            "incorrect password", "login incorrect")):
            return "auth_failure"
        if any(kw in msg_lower for kw in ("login", "authentication", "session opened")):
            return "auth_success" if "success" in msg_lower else "auth_failure"
        if any(kw in msg_lower for kw in ("failed", "failure")):
            if "ssh" in msg_lower or "auth" in msg_lower or "login" in msg_lower:
                return "auth_failure"

        # Check DNS before generic network
        if any(kw in msg_lower.split() for kw in ("dns", "named", "nxdomain", "soa", "cname")):
            return "dns_query"
        # "query:" (note colon) is common in BIND DNS logs but rare in firewall logs
        if re.search(r'\bquery\s*:', msg_lower):
            return "dns_query"

        # Firewall / network device messages
        if any(kw in msg_lower for kw in ("denied", "blocked", "drop", "reject")):
            return "suspicious_traffic"
        if any(kw in msg_lower for kw in ("allowed", "permit", "established", "connected")):
            return "network_connect"
        if "accept" in msg_lower:
            return "network_connect"

        if "http" in msg_lower:
            return "http_request"
        if any(kw in msg_lower for kw in ("alert", "exploit", "overflow", "scan", "malware")):
            return "suspicious_traffic"
        if severity <= 2:
            return "suspicious_traffic"
        return "network_connect"

    def _normalize_severity(self, syslog_severity: int) -> int:
        """Map syslog severity (0-7, 0=emerg) to our 0-10 scale."""
        mapping = {0: 10, 1: 9, 2: 8, 3: 7, 4: 5, 5: 3, 6: 2, 7: 1}
        return mapping.get(syslog_severity, 3)

    def _extract_ips(self, text: str, hostname: str = "") -> tuple:
        """Extract (src_ip, dst_ip) heuristically."""
        ipv4s = _IPV4_RE.findall(text)
        # Filter out non-routable-looking patterns
        ips = [ip for ip in ipv4s if not ip.startswith("0.") and not ip.startswith("127.")]
        if len(ips) >= 2:
            return ips[0], ips[1]
        if len(ips) == 1:
            return ips[0], None
        # Try hostname as IP
        if hostname and _IPV4_RE.match(hostname):
            return hostname, None
        return None, None

    def _extract_port(self, text: str) -> Optional[int]:
        # Try IP:PORT format first (common in network logs)
        for m in _IPPORT_RE.finditer(text):
            p = int(m.group(1))
            if 0 < p < 65536:
                return p
        # Fall back to "port NNNN" style
        m = _PORT_RE.search(text)
        if m:
            p = int(m.group(1))
            if 0 < p < 65536:
                return p
        return None

    def _guess_proto(self, text: str) -> Optional[str]:
        text_upper = text.upper()
        for proto in ["TCP", "UDP", "ICMP", "HTTP", "DNS", "TLS", "SSH"]:
            if proto in text_upper:
                return proto
        return None
