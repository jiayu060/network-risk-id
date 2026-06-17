"""WAF log parser: Cloudflare, ModSecurity, AWS WAF, generic JSON/KV formats."""

import hashlib
import json
import uuid
import re
from datetime import datetime, timezone
from typing import Optional

from src.parsers.base import LogParser

# Common WAF fields across vendors
# Cloudflare: JSON with "action", "clientIP", "clientRequestHTTPHost", etc.
# ModSecurity: "ModSecurity: ..." prefix with key-value pairs
# AWS WAF: JSON with "httpRequest", "action", etc.

_MODSEC_RE = re.compile(
    r"ModSecurity:\s*(.*?)(?:\s*\[[^\]]+\])+\s*$"
)

_KV_RE = re.compile(r'(\w+)\s*[:=]\s*"([^"]*)"|(\w+)\s*[:=]\s*(\S+)')

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


class WAFParser(LogParser):
    """Parser for WAF logs (Cloudflare, ModSecurity, AWS WAF, generic)."""

    def __init__(self, sensor_id: str = "unknown"):
        self.sensor_id = sensor_id
        self.source_type = "waf"

    def parse_line(self, line: str) -> dict:
        line = line.strip()
        if not line:
            return {}

        # Try JSON first (Cloudflare, AWS WAF)
        record = self._parse_json(line)
        if record:
            return record

        # Try ModSecurity key-value format
        record = self._parse_modsecurity(line)
        if record:
            return record

        # Try generic key-value
        return self._parse_generic(line)

    def _parse_json(self, line: str) -> Optional[dict]:
        """Parse JSON-formatted WAF logs (Cloudflare, AWS WAF)."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        ts = self._extract_timestamp(data)
        src_ip = (
            data.get("clientIP") or
            data.get("client_ip") or
            data.get("sourceIP") or
            (data.get("httpRequest", {}).get("clientIp"))
        )
        dst_ip = data.get("destinationIP") or data.get("serverIP")
        domain = data.get("clientRequestHTTPHost") or data.get("host")
        url = data.get("clientRequestPath") or data.get("uri") or data.get("path")
        http_method = data.get("clientRequestHTTPMethodName") or data.get("httpMethod") or data.get("method")
        http_status = data.get("edgeResponseStatus") or data.get("status")
        action = data.get("action") or data.get("terminatingAction")
        rule_id = data.get("ruleId") or data.get("WAFRuleId")

        return self._build_record(line, ts, src_ip, dst_ip, domain, url,
                                  http_method, http_status, action, rule_id)

    def _parse_modsecurity(self, line: str) -> Optional[dict]:
        """Parse ModSecurity audit log lines."""
        if "ModSecurity" not in line:
            return None

        ts = int(datetime.now(timezone.utc).timestamp() * 1000)
        src_ip = None
        dst_ip = None
        action = None
        rule_id = None

        # Extract IPs
        ips = _IP_RE.findall(line)
        if len(ips) >= 2:
            src_ip, dst_ip = ips[0], ips[1]
        elif len(ips) == 1:
            src_ip = ips[0]

        # Extract action
        if "Access denied" in line or "denied" in line.lower():
            action = "block"
        elif "Warning" in line:
            action = "log"

        # Extract rule ID
        rid_match = re.search(r'id\s*[:"\'](\d+)', line)
        if rid_match:
            rule_id = rid_match.group(1)

        return self._build_record(line, ts, src_ip, dst_ip, None, None, None, None, action, rule_id)

    def _parse_generic(self, line: str) -> dict:
        """Best-effort parsing for generic WAF key-value log."""
        ts = int(datetime.now(timezone.utc).timestamp() * 1000)
        src_ip = None
        dst_ip = None
        action = None
        rule_id = None

        # Try to extract key-value pairs
        kvs = dict(_KV_RE.findall(line))
        src_ip = kvs.get("src_ip") or kvs.get("clientip") or kvs.get("source_ip")
        dst_ip = kvs.get("dst_ip") or kvs.get("server_ip") or kvs.get("host")
        action = kvs.get("action") or kvs.get("waf_action")
        rule_id = kvs.get("rule_id") or kvs.get("ruleid")

        # Fallback IP extraction
        if not src_ip:
            ips = _IP_RE.findall(line)
            if ips:
                src_ip = ips[0]
                if len(ips) > 1:
                    dst_ip = ips[1]

        # Detect action from message keywords
        if not action:
            line_lower = line.lower()
            if any(kw in line_lower for kw in ("block", "deny", "reject", "drop")):
                action = "block"
            elif any(kw in line_lower for kw in ("allow", "pass", "accept")):
                action = "allow"
            elif any(kw in line_lower for kw in ("challenge", "captcha")):
                action = "challenge"
            else:
                action = "log"

        return self._build_record(line, ts, src_ip, dst_ip, None, None, None, None, action, rule_id)

    def _extract_timestamp(self, data: dict) -> int:
        """Extract timestamp from various JSON formats."""
        ts_str = data.get("timestamp") or data.get("dateTime") or data.get("@timestamp") or ""
        if ts_str:
            try:
                # ISO format
                ts_str = ts_str.replace("T", " ").replace("Z", "+00:00")
                dt = datetime.fromisoformat(ts_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return int(dt.timestamp() * 1000)
            except (ValueError, TypeError):
                pass
            try:
                # Unix timestamp (seconds or milliseconds)
                ts_val = float(ts_str)
                if ts_val < 1e12:
                    ts_val *= 1000
                return int(ts_val)
            except (ValueError, TypeError):
                pass
        return int(datetime.now(timezone.utc).timestamp() * 1000)

    def _build_record(self, raw: str, ts: int, src_ip: Optional[str],
                      dst_ip: Optional[str], domain: Optional[str],
                      url: Optional[str], http_method: Optional[str],
                      http_status: Optional[int], action: Optional[str],
                      rule_id: Optional[str]) -> dict:
        # Determine severity based on action
        severity = 3  # default: informational
        if action == "block":
            severity = 6
        elif action == "challenge":
            severity = 5

        tags = []
        if rule_id:
            tags.append(f"waf_rule:{rule_id}")

        return {
            "event_id": self._gen_id(raw),
            "timestamp": ts,
            "ingest_time": int(datetime.now(timezone.utc).timestamp() * 1000),
            "source_type": "waf",
            "sensor_id": self.sensor_id,
            "src_ip": src_ip,
            "src_port": None,
            "dst_ip": dst_ip,
            "dst_port": None,
            "proto": "HTTP",
            "event_type": "waf_alert",
            "severity": severity,
            "user": None,
            "process_name": None,
            "process_id": None,
            "domain": domain,
            "url": url,
            "http_method": http_method,
            "http_status": http_status if isinstance(http_status, int) else (int(http_status) if http_status and str(http_status).isdigit() else None),
            "bytes_in": None,
            "bytes_out": None,
            "duration_ms": None,
            "dns_rcode": None,
            "dns_rdata": None,
            "waf_action": action,
            "waf_rule_id": rule_id,
            "raw_message": raw,
            "tags": tags,
        }

    def _gen_id(self, raw: str) -> str:
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        return str(uuid.UUID(hex=h))
