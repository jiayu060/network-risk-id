"""Unified PyArrow schema for all normalized log data."""

import pyarrow as pa

UNIFIED_LOG_SCHEMA = pa.schema([
    pa.field("event_id", pa.string(), nullable=False),
    pa.field("timestamp", pa.timestamp("ms"), nullable=False),
    pa.field("ingest_time", pa.timestamp("ms"), nullable=False),
    pa.field("source_type", pa.dictionary(pa.int8(), pa.string()), nullable=False),
    pa.field("sensor_id", pa.string(), nullable=False),
    pa.field("src_ip", pa.string(), nullable=True),
    pa.field("src_port", pa.int32(), nullable=True),
    pa.field("dst_ip", pa.string(), nullable=True),
    pa.field("dst_port", pa.int32(), nullable=True),
    pa.field("proto", pa.dictionary(pa.int8(), pa.string()), nullable=True),
    pa.field("event_type", pa.dictionary(pa.int8(), pa.string()), nullable=False),
    pa.field("severity", pa.int8(), nullable=True),
    pa.field("user", pa.string(), nullable=True),
    pa.field("process_name", pa.string(), nullable=True),
    pa.field("process_id", pa.int32(), nullable=True),
    pa.field("domain", pa.string(), nullable=True),
    pa.field("url", pa.string(), nullable=True),
    pa.field("http_method", pa.dictionary(pa.int8(), pa.string()), nullable=True),
    pa.field("http_status", pa.int16(), nullable=True),
    pa.field("bytes_in", pa.int64(), nullable=True),
    pa.field("bytes_out", pa.int64(), nullable=True),
    pa.field("duration_ms", pa.int32(), nullable=True),
    pa.field("dns_rcode", pa.dictionary(pa.int8(), pa.string()), nullable=True),
    pa.field("dns_rdata", pa.string(), nullable=True),
    pa.field("waf_action", pa.dictionary(pa.int8(), pa.string()), nullable=True),
    pa.field("waf_rule_id", pa.string(), nullable=True),
    pa.field("raw_message", pa.string(), nullable=True),
    pa.field("tags", pa.list_(pa.string()), nullable=True),
])

EVENT_TYPE_TAXONOMY = {
    "auth_success": "Successful authentication",
    "auth_failure": "Failed authentication",
    "process_create": "New process started",
    "network_connect": "Outbound network connection",
    "network_listen": "Service started listening",
    "dns_query": "DNS lookup performed",
    "http_request": "HTTP request observed",
    "file_create": "File created on disk",
    "file_delete": "File deleted",
    "registry_modify": "Registry key modified",
    "waf_alert": "WAF rule triggered",
    "suspicious_traffic": "Generic suspicious traffic",
}

SOURCE_TYPES = ["syslog", "etw", "waf", "dns", "general"]

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "TLS", "SMB", "RDP", "SSH", "FTP", "SMTP"]
