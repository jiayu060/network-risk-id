"""General security log parser for semi-structured / annotated log lines.

Handles formats like:
  2026-06-17T08:12:34.221Z 10.2.15.88 -> 192.168.1.105:443 TLS handshake ...
  2026-06-17T09:15:08.443Z 10.2.15.200 -> 10.2.0.0/16: ICMP echo request ...
"""

import math
import re
import time
import uuid
from datetime import datetime, timezone

from src.parsers.base import LogParser
from src.utils.ip_utils import is_internal_ip


class GeneralSecurityLogParser(LogParser):
    """Parses semi-structured security log lines with annotated attack labels."""

    source_type = "general"

    def __init__(self):
        self._ts_re = re.compile(
            r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)"
        )
        # src_ip -> dst_ip:port pattern
        self._conn_re = re.compile(
            r"(\d+\.\d+\.\d+\.\d+)\)?\s*->\s*(\d+\.\d+\.\d+\.\d+):(\d+)"
        )
        self._conn_subnet_re = re.compile(
            r"(\d+\.\d+\.\d+\.\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+/\d+)"
        )
        # IP only (no port)
        self._ip_pair_re = re.compile(
            r"(\d+\.\d+\.\d+\.\d+)\s*->\s*(\d+\.\d+\.\d+\.\d+)"
        )
        # "from X to Y" pattern (alternative format)
        self._from_to_re = re.compile(
            r"from\s+(\d+\.\d+\.\d+\.\d+)\s+to\s+(\d+\.\d+\.\d+\.\d+)",
            re.IGNORECASE,
        )
        self._to_from_re = re.compile(
            r"to\s+(\d+\.\d+\.\d+\.\d+):?(\d*)\s+from\s+(?:[\w-]+\s*\(\s*)?(\d+\.\d+\.\d+\.\d+)",
            re.IGNORECASE,
        )
        self._from_to_subnet_re = re.compile(
            r"from\s+(\d+\.\d+\.\d+\.\d+)\s+to\s+(\d+\.\d+\.\d+\.\d+/\d+)",
            re.IGNORECASE,
        )
        # "exported/uploaded/transferred from X to Y:port" (reverse of standard)
        self._export_from_to_re = re.compile(
            r"(?:exported|uploaded|transferred|dumped)\s+from\s+[\w-]+\s*\(?(\d+\.\d+\.\d+\.\d+)\)?\s+to\s+(\S+)",
            re.IGNORECASE,
        )
        # "Domain X from IP" (DGA domain reported)
        self._domain_from_ip_re = re.compile(
            r"(?:domain|host)\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\s+(?:\w+\s+)?from\s+(\d+\.\d+\.\d+\.\d+)",
            re.IGNORECASE,
        )
        # "from IP to DOMAIN" (destination is domain, not IP)
        self._from_ip_to_domain_re = re.compile(
            r"from\s+(\d+\.\d+\.\d+\.\d+)\s+to\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})",
            re.IGNORECASE,
        )
        # "DNS query for DOMAIN from IP" (DNS-specific format)
        self._query_for_from_re = re.compile(
            r"query\s+for\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\s+from\s+(\d+\.\d+\.\d+\.\d+)",
            re.IGNORECASE,
        )
        # "on DST from SRC" (reverse with "on" instead of "to")
        self._on_from_re = re.compile(
            r"on\s+(\d+\.\d+\.\d+\.\d+)\s+from\s+(\d+\.\d+\.\d+\.\d+)",
            re.IGNORECASE,
        )
        # "sent X to Y" data transfer
        self._sent_to_re = re.compile(
            r"sent\s+(\d+(?:\.\d+)?)\s*(GB|MB|KB|TB)\s+(?:attachment\s+)?to\s+(\d+\.\d+\.\d+\.\d+)",
            re.IGNORECASE,
        )
        # Severity level [WARNING], [ALERT], [CRITICAL]
        self._level_re = re.compile(r"\[(WARNING|ALERT|CRITICAL|INFO|ERROR)\]")
        # CIDR range
        self._cidr_re = re.compile(r"(\d+\.\d+\.\d+\.\d+/\d+)")
        # Port mentions
        self._port_re = re.compile(r":(\d{1,5})\b")
        self._multi_port_re = re.compile(r"port(?:s?\s*(?:sweep|scan|probe)?\s*)(\d+)[-–](\d+)", re.IGNORECASE)
        # Bytes/Size
        self._bytes_re = re.compile(
            r"(?:bytes_out|bytes_in|bytes|size|total)\s*[=:]*\s*(\d+(?:\.\d+)?)\s*(GB|MB|KB|bytes|b)?",
            re.IGNORECASE,
        )
        # Domain
        self._domain_re = re.compile(
            r'(?:DNS\s+query\s+for\s+|domain\s+)"?([a-z0-9][a-z0-9.-]*\.[a-z]{2,})"?',
            re.IGNORECASE,
        )
        self._domain_simple_re = re.compile(
            r'"([a-z0-9][a-z0-9.-]*\.[a-z]{2,})"'
        )
        # User
        self._user_re = re.compile(
            r'(?:user\s*[:=]?\s*"?|User(?:Name)?\s*[:=]?\s*"?)([a-zA-Z_][a-zA-Z0-9_-]*)',
            re.IGNORECASE,
        )
        self._user_re2 = re.compile(r'user\s+"([^"]+)"', re.IGNORECASE)
        self._user_re3 = re.compile(r"user:\s*([a-zA-Z_][a-zA-Z0-9_-]*)", re.IGNORECASE)
        # Protocol
        self._proto_map = [
            ("TLS", "TLS"), ("HTTPS", "HTTPS"), ("HTTP", "HTTP"),
            ("SMB2", "SMB"), ("SMB", "SMB"), ("DNS", "DNS"),
            ("SSH", "SSH"), ("RDP", "RDP"), ("ICMP", "ICMP"),
            ("DCE/RPC", "TCP"), ("FTP", "FTP"), ("SMTP", "SMTP"),
            ("SNMP", "SNMP"), ("SMB2", "SMB"),
        ]

    def parse_line(self, line: str) -> dict:
        ts = self._extract_timestamp(line)
        src_ip = None
        dst_ip = None
        dst_port = None
        proto = None
        domain = None
        user = None
        bytes_out = None
        bytes_in = None
        event_type = "network_connect"
        raw = line.strip()

        # ---- Severity from [LEVEL] ----
        sev_match = self._level_re.search(line)
        severity_label = sev_match.group(1) if sev_match else None

        # ---- IP extraction ----
        # Try "src -> dst:port" pattern first
        m = self._conn_re.search(line)
        if m:
            src_ip = m.group(1)
            dst_ip = m.group(2)
            dst_port = int(m.group(3))
        else:
            # Try CIDR notation with ->
            m = self._conn_subnet_re.search(line)
            if m:
                src_ip = m.group(1)
                dst_ip = m.group(2)
                dst_port = None
            else:
                # Simple IP pair with ->
                m = self._ip_pair_re.search(line)
                if m:
                    src_ip = m.group(1)
                    dst_ip = m.group(2)
                else:
                    # "to DST:PORT from SRC" (reverse order)
                    m = self._to_from_re.search(line)
                    if m:
                        dst_ip = m.group(1)
                        src_ip = m.group(3)
                        if m.group(2):
                            dst_port = int(m.group(2))
                    else:
                        # "exported/uploaded/transferred from HOST (IP) to DST"
                        m = self._export_from_to_re.search(line)
                        if m:
                            src_ip = m.group(1)
                            dst_str = m.group(2)
                            # Split port from IP:port if present
                            port_m = re.match(r"^(\d+\.\d+\.\d+\.\d+):(\d{1,5})$", dst_str)
                            if port_m:
                                dst_ip = port_m.group(1)
                                dst_port = int(port_m.group(2))
                            elif re.match(r"^\d+\.\d+\.\d+\.\d+", dst_str):
                                dst_ip = dst_str
                            else:
                                domain = dst_str
                                dst_ip = dst_str  # Use domain as destination for edge creation
                        else:
                            # "Domain X from IP" (DGA/reputation domain report)
                            m = self._domain_from_ip_re.search(line)
                            if m:
                                domain = m.group(1)
                                src_ip = m.group(2)
                                dst_ip = domain
                            # "DNS query for DOMAIN from IP"
                            elif self._query_for_from_re.search(line):
                                m = self._query_for_from_re.search(line)
                                domain = m.group(1)
                                src_ip = m.group(2)
                                dst_ip = domain
                            # "from IP to DOMAIN" (destination is domain name)
                            elif self._from_ip_to_domain_re.search(line):
                                m = self._from_ip_to_domain_re.search(line)
                                src_ip = m.group(1)
                                domain = m.group(2)
                                dst_ip = domain  # Use domain as edge destination
                            else:
                                # "on DST from SRC" (reverse with "on" keyword)
                                m = self._on_from_re.search(line)
                                if m:
                                    dst_ip = m.group(1)
                                    src_ip = m.group(2)
                                else:
                                    # "sent X MB/GB to DST" data transfer
                                    m = self._sent_to_re.search(line)
                                    if m:
                                        dst_ip = m.group(3)
                                    # "from X to Y:port" pattern (only if not already matched)
                                    if not (src_ip and dst_ip):
                                        m = self._from_to_re.search(line)
                                        if m:
                                            src_ip = m.group(1)
                                            dst_ip = m.group(2)
                                        else:
                                            # "from X to Y/subnet" pattern
                                            m = self._from_to_subnet_re.search(line)
                                            if m:
                                                src_ip = m.group(1)
                                                dst_ip = m.group(2)
                                            else:
                                                # Try to extract any IPs
                                                ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
                                                if len(ips) >= 2:
                                                    src_ip = ips[0]
                                                    dst_ip = ips[1]
                                                elif len(ips) == 1:
                                                    src_ip = ips[0]

        # Port extraction from broader context if not already found
        if dst_port is None:
            # CIDR notations have no port
            if dst_ip and "/" in dst_ip:
                dst_port = None
            # Try port after colon pattern after dst_ip
            elif dst_ip:
                m2 = re.search(rf"{re.escape(dst_ip)}:(\d{{1,5}})", line)
                if m2:
                    dst_port = int(m2.group(1))
            # Fallback: find port-like numbers NOT in timestamps
            if dst_port is None and dst_ip:
                # Only search after '->' or 'to' pattern to avoid timestamp ports
                idx = max(line.find("->"), line.find(" to "))
                if idx > 0:
                    m2 = self._port_re.search(line[idx:])
                    if m2:
                        p = int(m2.group(1))
                        if 1 <= p <= 65535:
                            dst_port = p
            if dst_port is None:
                m2 = self._multi_port_re.search(line)
                if m2:
                    dst_port = int(m2.group(1))  # start of range

        # If multiple IPs, try to identify src vs dst
        if src_ip and not dst_ip:
            all_ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", line)
            all_ips = [ip for ip in all_ips if ip != src_ip]
            if all_ips:
                dst_ip = all_ips[0]

        # ---- Protocol detection ----
        for keyword, proto_name in self._proto_map:
            if keyword.lower() in line.lower():
                proto = proto_name
                break

        # ---- Domain ----
        m = self._domain_re.search(line)
        if m:
            domain = m.group(1)
        else:
            # Fallback: find domain-like strings in quotes
            m = self._domain_simple_re.search(line)
            if m:
                cand = m.group(1)
                if "." in cand and not re.match(r"^\d+\.\d+\.\d+\.\d+$", cand):
                    domain = cand
        # Domain as destination: keep dst_ip as domain so edges can be created
        if not domain and dst_ip and not re.match(r"^\d+\.\d+\.\d+\.\d+", dst_ip):
            if "." in dst_ip and re.search(r"[a-zA-Z]", dst_ip):
                domain = dst_ip
                # Keep dst_ip as the domain — edges need a non-unknown destination
        # Domains mentioned inline: "domain xxx.com", "queried xxx.com", "matches xxx DGA"
        if not domain:
            m = re.search(r"(?:domain\s+|queried\s+|matches\s+|to\s+)([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", line, re.IGNORECASE)
            if m:
                domain = m.group(1)
        # TLS SNI: sync537.xyz, SNI=xxx.com
        if not domain:
            m = re.search(r"(?:SNI|sni)\s*[:=]\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", line)
            if m:
                domain = m.group(1)
        # "information gathering on domain.com", "gathering on domain.com"
        if not domain:
            m = re.search(r"(?:gathering|information|intel)\s+on\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", line, re.IGNORECASE)
            if m:
                domain = m.group(1)
        # Generic domain pattern: high-entropy-looking .xyz/.club/.space/.biz/.info/.top domains
        if not domain:
            m = re.search(r"([a-z0-9]{10,30}\.(?:xyz|club|space|biz|info|top|com|org|net))\b", line, re.IGNORECASE)
            if m:
                domain = m.group(1)
        # "to domain.com" where to is followed by a domain (not IP)
        if not domain:
            m = re.search(r"\bto\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})(?:\s|$)", line, re.IGNORECASE)
            if m and not re.match(r"^\d+\.\d+\.\d+\.\d+", m.group(1)):
                domain = m.group(1)

        # Port extraction: "to IP:port" in from-to format
        if dst_port is None and dst_ip:
            m2 = re.search(r"to\s+" + re.escape(dst_ip) + r":(\d{1,5})", line)
            if m2:
                dst_port = int(m2.group(1))

        # ---- User ----
        for ure in [self._user_re, self._user_re2, self._user_re3]:
            m = ure.search(line)
            if m:
                user = m.group(1)
                break

        # ---- Event type ----
        text_lower = line.lower()
        if "dns query" in text_lower or ("dns" in text_lower and "query" in text_lower) or "dns tunnel" in text_lower:
            event_type = "dns_query"
        elif "dns zone transfer" in text_lower:
            event_type = "dns_query"
        elif "dns txt" in text_lower or ("dns" in text_lower and "txt record" in text_lower):
            event_type = "dns_query"
        elif "dga" in text_lower or "domain generation" in text_lower:
            event_type = "dns_query"
        elif "low reputation" in text_lower and "domain" in text_lower:
            event_type = "dns_query"
        elif "auth_success" in text_lower or "logon success" in text_lower or "login success" in text_lower:
            event_type = "auth_success"
        elif "pass-the-hash" in text_lower or "ntlm hash" in text_lower:
            event_type = "auth_success"
        elif "kerberos" in text_lower or "kerberoasting" in text_lower or "tgs-req" in text_lower:
            event_type = "auth_success"
        elif "ldap" in text_lower and ("bind" in text_lower or "enum" in text_lower):
            event_type = "auth_success"
        elif "auth_failure" in text_lower or "logon failure" in text_lower or "login fail" in text_lower or "failed password" in text_lower:
            event_type = "auth_failure"
        elif "brute force" in text_lower or "password spray" in text_lower or "password guessing" in text_lower:
            event_type = "auth_failure"
        elif "rdp logon" in text_lower or ("rdp" in text_lower and ("logon" in text_lower or "login" in text_lower)):
            if "failure" in text_lower or "fail" in text_lower:
                event_type = "auth_failure"
            elif "success" in text_lower:
                event_type = "auth_success"
            else:
                event_type = "auth_success" if "4624" in line else "auth_failure"
        elif "ssh" in text_lower:
            if "failure" in text_lower or "fail" in text_lower:
                event_type = "auth_failure"
            elif "success" in text_lower or "established" in text_lower or "key-based login" in text_lower or "public key" in text_lower:
                event_type = "auth_success"
            elif "login" in text_lower:
                event_type = "auth_success"
            else:
                event_type = "network_connect"
        elif "shadow copy" in text_lower or "vssadmin" in text_lower:
            event_type = "file_delete"
        elif "file created" in text_lower or "file_create" in text_lower:
            event_type = "file_create"
        elif "file deleted" in text_lower or "file_delete" in text_lower:
            event_type = "file_delete"
        elif "database dump" in text_lower or "sql exfil" in text_lower:
            event_type = "file_create"
        elif "registry" in text_lower and ("modified" in text_lower or "run key" in text_lower):
            event_type = "file_create"
        elif "persistence" in text_lower:
            event_type = "file_create"
        elif "process creat" in text_lower or "process_start" in text_lower:
            event_type = "process_create"
        elif "masquerading" in text_lower or "renamed as" in text_lower:
            event_type = "process_create"
        elif "uac bypass" in text_lower or "privilege escalation" in text_lower or "privilege elevation" in text_lower:
            event_type = "process_create"
        elif "amsi bypass" in text_lower or "amsi" in text_lower:
            event_type = "process_create"
        elif "memory-resident" in text_lower or "fileless" in text_lower or "fileless attack" in text_lower:
            event_type = "process_create"
        elif "dcom" in text_lower and ("lateral" in text_lower or "triggered" in text_lower):
            event_type = "process_create"
        elif "waf" in text_lower and "alert" in text_lower:
            event_type = "waf_alert"
        elif "scheduled task" in text_lower or "schtasks" in text_lower:
            event_type = "process_create"
        elif "wmi process" in text_lower or ("wmi" in text_lower and "creation" in text_lower):
            event_type = "process_create"
        elif "lsass" in text_lower or "credential dump" in text_lower or "procdump" in text_lower:
            event_type = "process_create"
        elif "smb enumeration" in text_lower or "port scan" in text_lower:
            event_type = "network_connect"
        elif "c2 beacon" in text_lower or "cobalt strike" in text_lower or "beacon interval" in text_lower:
            event_type = "network_connect"
        elif "persistent connection" in text_lower:
            event_type = "network_connect"
        elif "icmp" in text_lower:
            event_type = "network_connect"
        elif "ftp" in text_lower:
            event_type = "network_connect"
        elif "http" in text_lower and ("post" in text_lower or "get " in text_lower):
            event_type = "http_request"

        # ---- Bytes ----
        # Pattern: "8.3GB exported", "28.7GB uploaded", "sent 15.2MB attachment"
        m = re.search(r"(\d+(?:\.\d+)?)\s*(GB|MB|KB|TB)\s*(?:exported|uploaded|transferred|dumped|detected|sent|in\s)", line, re.IGNORECASE)
        if not m:
            m = re.search(r"sent\s+(\d+(?:\.\d+)?)\s*(GB|MB|KB|TB)", line, re.IGNORECASE)
        if not m:
            m = re.search(r"(?:size|total|amount)\s*[=:]*\s*(\d+(?:\.\d+)?)\s*(GB|MB|KB|bytes|b)?", line, re.IGNORECASE)
        if not m:
            m = self._bytes_re.search(line)
        if m:
            val = float(m.group(1))
            unit = (m.group(2) or "bytes").upper().strip() if m.lastindex and m.lastindex >= 2 else "bytes"
            if unit == "TB":
                bytes_out = int(val * 1024 * 1024 * 1024 * 1024)
            elif unit == "GB":
                bytes_out = int(val * 1024 * 1024 * 1024)
            elif unit == "MB":
                bytes_out = int(val * 1024 * 1024)
            elif unit == "KB":
                bytes_out = int(val * 1024)
            else:
                bytes_out = int(val)
            # For "bytes_in", apply to bytes_in
            if "bytes_in" in text_lower:
                bytes_in = bytes_out
                bytes_out = None

        # ---- CIDR scan target ----
        if not dst_ip:
            m = self._cidr_re.search(line)
            if m:
                dst_ip = m.group(1)

        # Build record - use parsed severity label if available
        severity = self._infer_severity(line)
        if severity_label:
            sev_map = {"CRITICAL": 10, "ALERT": 9, "WARNING": 7, "ERROR": 8, "INFO": 4}
            severity = sev_map.get(severity_label, severity)
        record = {
            "event_id": str(uuid.uuid4())[:16],
            "timestamp": ts,
            "ingest_time": int(time.time() * 1000),
            "source_type": "general",
            "sensor_id": "manual-input",
            "src_ip": src_ip or "unknown",
            "src_port": None,
            "dst_ip": dst_ip or "unknown",
            "dst_port": dst_port,
            "proto": proto or "TCP",
            "event_type": event_type,
            "severity": severity,
            "user": user,
            "process_name": None,
            "process_id": None,
            "domain": domain,
            "url": None,
            "http_method": "POST" if "post" in text_lower else ("GET" if "get " in text_lower else None),
            "http_status": None,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "duration_ms": None,
            "dns_rcode": None,
            "dns_rdata": None,
            "waf_action": None,
            "waf_rule_id": None,
            "raw_message": raw,
            "tags": [],
        }

        return record

    def _extract_timestamp(self, line: str) -> int:
        """Extract ISO 8601 timestamp and convert to millisecond epoch.
        Handles both 'T' and space separators: 2026-06-17T19:30:01.234Z or 2026-06-17 14:09:24
        """
        m = self._ts_re.search(line)
        if m:
            ts_str = m.group(1).rstrip("Z")
            # Normalize space to T for parsing
            ts_str = ts_str.replace(" ", "T")
            try:
                if "." in ts_str:
                    dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f")
                else:
                    dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
                return int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)
            except ValueError:
                pass
        return int(time.time() * 1000)

    def _infer_severity(self, line: str) -> int:
        """Infer severity 1-10 from log content."""
        score = 3
        text = line.lower()
        if any(kw in text for kw in ("c2", "beacon", "exfil", "ransomware", "reverse shell")):
            score = 9
        elif any(kw in text for kw in ("scan", "sweep", "enumeration", "brute", "dga")):
            score = 7
        elif any(kw in text for kw in ("lateral", "ward movement", "wmi", "psexec", "smb exec")):
            score = 8
        elif any(kw in text for kw in ("credential", "cred dump", "mimikatz", "lsass")):
            score = 9
        elif any(kw in text for kw in ("data exfil", "外泄", "upload")):
            score = 8
        elif any(kw in text for kw in ("privilege", "escalation", "admin")):
            score = 7
        elif any(kw in text for kw in ("persistence", "持久化", "tunnel")):
            score = 7
        return score
