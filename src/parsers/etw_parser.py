"""ETW/EVTX log parser: Windows Event Tracing XML logs."""

import hashlib
import uuid
import re
from datetime import datetime, timezone
from typing import Optional
from xml.etree import ElementTree as ET

from src.parsers.base import LogParser

# EventID -> (event_type, description) mapping
EVENTID_MAP = {
    4624: ("auth_success", "Successful logon"),
    4625: ("auth_failure", "Failed logon"),
    4634: ("auth_success", "Logoff"),
    4648: ("auth_success", "Logon using explicit credentials"),
    4672: ("auth_success", "Special privileges assigned"),
    4688: ("process_create", "New process created"),
    4689: ("process_create", "Process terminated"),
    4697: ("process_create", "Service installed"),
    4720: ("auth_success", "User account created"),
    4722: ("auth_success", "User account enabled"),
    4725: ("auth_success", "User account disabled"),
    4728: ("auth_success", "Member added to security-enabled group"),
    4732: ("auth_success", "Member added to security-enabled local group"),
    4740: ("auth_success", "User account locked out"),
    4768: ("auth_success", "Kerberos TGT requested"),
    4769: ("auth_success", "Kerberos service ticket requested"),
    4771: ("auth_failure", "Kerberos pre-authentication failed"),
    4776: ("auth_failure", "NTLM authentication attempted"),
    4778: ("auth_success", "Session reconnected"),
    4779: ("auth_success", "Session disconnected"),
    4964: ("auth_success", "Special groups assigned"),
    5136: ("registry_modify", "Directory service object modified"),
    5137: ("file_create", "Directory service object created"),
    5140: ("file_delete", "Network share object accessed"),
    5142: ("file_create", "Network share object added"),
    5145: ("file_create", "Network share object checked"),
    5156: ("network_connect", "Windows Filtering Platform connection allowed"),
    5157: ("network_connect", "Windows Filtering Platform connection blocked"),
    5158: ("network_connect", "Windows Filtering Platform bind"),
    7045: ("process_create", "New service installed"),
    8003: ("dns_query", "DNS query"),
    8018: ("dns_query", "DNS query response"),

    # Sysmon events
    1: ("process_create", "Sysmon: Process creation"),
    2: ("file_create", "Sysmon: File creation time changed"),
    3: ("network_connect", "Sysmon: Network connection"),
    4: ("process_create", "Sysmon: Service state changed"),
    5: ("process_create", "Sysmon: Process terminated"),
    6: ("file_create", "Sysmon: Driver loaded"),
    7: ("file_create", "Sysmon: Image loaded"),
    8: ("process_create", "Sysmon: CreateRemoteThread"),
    9: ("file_create", "Sysmon: RawAccessRead"),
    10: ("process_create", "Sysmon: ProcessAccess"),
    11: ("file_create", "Sysmon: FileCreate"),
    12: ("registry_modify", "Sysmon: RegistryEvent"),
    13: ("registry_modify", "Sysmon: RegistryEvent"),
    14: ("registry_modify", "Sysmon: RegistryEvent"),
    17: ("process_create", "Sysmon: PipeEvent"),
    18: ("network_connect", "Sysmon: PipeEvent"),
    22: ("dns_query", "Sysmon: DNS query"),
}

# Namespace for Windows Event XML
_NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event",
}

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


class ETWParser(LogParser):
    """Parser for Windows ETW / EVTX XML log data."""

    def __init__(self, sensor_id: str = "unknown"):
        self.sensor_id = sensor_id
        self.source_type = "etw"

    def parse_line(self, line: str) -> dict:
        line = line.strip()
        if not line:
            return {}

        # ETW logs are typically XML events (one per line or multi-line)
        if line.startswith("<Event") or "<Event " in line:
            return self._parse_event_xml(line)
        if "<Events>" in line or "</Events>" in line:
            return {}  # skip wrapper element

        # Try extracting Event from within wrapping XML by finding <Event ... </Event>
        evt_match = re.search(r'<Event\b[^>]*>.*?</Event>', line, re.DOTALL)
        if evt_match:
            return self._parse_event_xml(evt_match.group(0))

        return {}

    def _parse_event_xml(self, xml_str: str) -> dict:
        """Parse a single <Event> XML element."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return {}

        system = root.find("e:System", _NS)
        if system is None:
            system = root.find("System")

        if system is None:
            return {}

        event_id_el = system.find("e:EventID", _NS) or system.find("EventID")
        event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0

        ts_el = system.find("e:TimeCreated", _NS) or system.find("TimeCreated")
        ts_str = ts_el.get("SystemTime") if ts_el is not None else None
        timestamp = self._parse_win_timestamp(ts_str) if ts_str else int(datetime.now(timezone.utc).timestamp() * 1000)

        computer = system.find("e:Computer", _NS) or system.find("Computer")
        sensor = computer.text if computer is not None else self.sensor_id

        severity = 3
        level_el = system.find("e:Level", _NS) or system.find("Level")
        if level_el is not None and level_el.text:
            level = int(level_el.text)
            severity = self._win_level_to_severity(level)

        event_type, _ = EVENTID_MAP.get(event_id, ("network_connect", "Unknown"))

        # Extract data fields
        event_data = root.find("e:EventData", _NS) or root.find("EventData")
        data_fields = {}
        if event_data is not None:
            for data_el in event_data.findall("e:Data", _NS) or event_data.findall("Data"):
                name = data_el.get("Name")
                value = data_el.text
                if name and value:
                    data_fields[name] = value

        src_ip = data_fields.get("IpAddress") or data_fields.get("SourceAddress") or data_fields.get("ClientAddress")
        dst_ip = data_fields.get("DestinationAddress") or data_fields.get("DestAddress")
        src_port = self._parse_int(data_fields.get("SourcePort") or data_fields.get("SrcPort"))
        dst_port = self._parse_int(data_fields.get("DestinationPort") or data_fields.get("DestPort"))
        user = data_fields.get("TargetUserName") or data_fields.get("SubjectUserName")
        process_name = data_fields.get("Image") or data_fields.get("NewProcessName")
        process_id = self._parse_int(data_fields.get("ProcessId") or data_fields.get("NewProcessId"))
        domain = data_fields.get("QueryName")

        # Try to extract info from raw data text if fields are empty
        raw_data = ""
        if event_data is not None:
            for data_el in event_data.findall("e:Data", _NS) or event_data.findall("Data"):
                if data_el.text and not data_el.get("Name"):
                    raw_data += data_el.text + " "
        raw_data = raw_data.strip()

        if not src_ip:
            ips = _IP_RE.findall(raw_data)
            if ips:
                src_ip = ips[0]
                if len(ips) > 1:
                    dst_ip = dst_ip or ips[1]

        return {
            "event_id": self._gen_id(xml_str),
            "timestamp": timestamp,
            "ingest_time": int(datetime.now(timezone.utc).timestamp() * 1000),
            "source_type": "etw",
            "sensor_id": sensor,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "proto": self._guess_proto_from_data(data_fields, raw_data),
            "event_type": event_type,
            "severity": severity,
            "user": user,
            "process_name": process_name or ("Sysmon" if event_id <= 22 else None),
            "process_id": process_id,
            "domain": domain,
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
            "raw_message": xml_str,
            "tags": [f"eventid:{event_id}"],
        }

    def _parse_batch_file(self, xml_content: str) -> list[dict]:
        """Parse a full ETW log file containing multiple <Event> elements."""
        # Find all <Event...>...</Event> blocks
        events = re.findall(r'<Event\b[^>]*>.*?</Event>', xml_content, re.DOTALL)
        records = []
        for evt_str in events:
            record = self._parse_event_xml(evt_str)
            if record:
                records.append(record)
        return records

    def parse_batch(self, lines) -> "pa.Table":
        """Override: handles both line-by-line and batch XML parsing."""
        import pyarrow as pa
        from src.core.schema import UNIFIED_LOG_SCHEMA

        all_lines = "".join(lines)
        if "<Events>" in all_lines or all_lines.startswith("<Event"):
            records = self._parse_batch_file(all_lines)
            if records:
                return pa.Table.from_pylist(records, schema=UNIFIED_LOG_SCHEMA)

        return super().parse_batch(iter(all_lines.split("\n")))

    def _parse_win_timestamp(self, ts_str: str) -> int:
        """Parse Windows timestamp: 2024-06-15T10:30:00.1234567Z"""
        try:
            ts_str = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except (ValueError, TypeError):
            return int(datetime.now(timezone.utc).timestamp() * 1000)

    def _win_level_to_severity(self, level: int) -> int:
        """Map Windows event level to our 0-10 severity."""
        # Win: 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose
        return {1: 10, 2: 8, 3: 5, 4: 3, 5: 1}.get(level, 3)

    def _guess_proto_from_data(self, data: dict, raw: str) -> Optional[str]:
        proto = data.get("Protocol")
        if proto:
            return proto
        combined = raw + " " + " ".join(data.values())
        combined_upper = combined.upper()
        for p in ["TCP", "UDP", "ICMP", "HTTP", "DNS", "TLS", "SMB", "RDP"]:
            if p in combined_upper:
                return p
        return None

    def _parse_int(self, val: Optional[str]) -> Optional[int]:
        if val is None:
            return None
        try:
            return int(val)
        except (ValueError, TypeError):
            return None

    def _gen_id(self, raw: str) -> str:
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]
        return str(uuid.UUID(hex=h))
