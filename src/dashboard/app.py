"""Streamlit dashboard — interactive network risk identification engine."""

import sys, io, json, random, re, time, hashlib, uuid
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime, timezone

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

st.set_page_config(page_title="网络风险识别", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")

__version__ = "0.3.2"  # deterministic seed + raw-message edge fallback + debug panel

# ============================================================
# Chinese Labels
# ============================================================
EVENT_LABELS = {
    "network_connect": "网络连接", "auth_success": "登录成功", "auth_failure": "登录失败",
    "dns_query": "DNS查询", "http_request": "HTTP请求", "waf_alert": "WAF告警",
    "file_create": "文件创建", "file_delete": "文件删除", "process_create": "进程创建",
    "suspicious_traffic": "可疑流量", "network": "网络通信", "auth": "认证",
    "dns": "DNS", "file": "文件操作", "process": "进程", "http": "HTTP",
}
CHAIN_LABELS = {
    "c2_beacon": "C2信标", "lateral_movement": "横向移动", "data_exfil": "数据外泄",
    "dga_activity": "DGA活动", "recon_scan": "侦察扫描", "ransomware_pattern": "勒索软件",
    "credential_theft": "凭据窃取", "privilege_escalation": "权限提升",
    "supply_chain": "供应链攻击", "suspicious_activity": "可疑活动",
    "anti_forensics": "反取证活动", "persistence": "持久化",
    "mitm_attack": "中间人攻击", "tool_download": "工具下载",
    "internal_recon": "内部侦察",
    "brute_force": "暴力破解",
}
ROLE_LABELS = {"source": "攻击源", "pivot": "跳板节点", "target": "攻击目标", "C2_infra": "C2基础设施"}

MITRE_INFO = {
    "T1071": ("C2应用层协议", "攻击者使用标准应用层协议进行C2通信"), "T1071.001": ("Web协议", "通过HTTP/HTTPS进行C2通信"),
    "T1573": ("加密通道", "C2通信使用TLS/SSL加密"), "T1021": ("远程服务", "利用RDP/SSH/SMB进行横向移动"),
    "T1078": ("有效账户", "使用合法凭据横向移动"), "T1041": ("通过C2通道外泄", "利用C2通道传输窃取数据"),
    "T1048": ("替代协议外泄", "使用非标准协议进行数据外泄"), "T1568": ("动态解析", "DGA域名绕过黑名单"),
    "T1046": ("网络服务扫描", "扫描目标网络开放端口"), "T1486": ("数据加密勒索", "加密受害主机索要赎金"),
    "T1003": ("OS凭据转储", "从内存提取密码哈希"), "T1110": ("暴力破解", "反复尝试密码爆破"),
    "T1550": ("备用认证材料", "利用令牌/Hash横向移动"), "T1485": ("数据销毁", "删除破坏数据"),
    "T1070": ("痕迹清除", "删除日志隐藏踪迹"), "T1068": ("漏洞利用提权", "利用系统漏洞获取高权限"),
    "T1134": ("访问令牌操纵", "窃取伪造访问令牌"), "T1548": ("滥用提权控制", "绕过UAC/SUDO"),
    "T1195": ("供应链攻陷", "通过第三方软件入侵"),
    "T1053": ("计划任务/作业", "利用计划任务实现持久化"), "T1543": ("创建修改系统进程", "安装系统服务持久化"),
    "T1547": ("启动/登录脚本", "利用启动文件夹持久化"), "T1557": ("中间人攻击", "ARP/DNS欺骗拦截通信"),
    "T1105": ("文件传输工具", "下载/上传工具到受害主机"), "T1083": ("文件目录发现", "枚举文件目录获取信息"),
    "T1082": ("系统信息发现", "收集系统信息"), "T1016": ("网络配置发现", "枚举网络配置信息"),
    "T1562": ("日志篡改清除", "清除或篡改审计日志"), "T1055": ("进程注入", "将代码注入进程维持访问"),
    "T1567": ("通过Web服务外泄", "利用Web SSL/TLS外泄数据"),
}

# ============================================================
# Sample Log Data (predefined for each format)
# ============================================================
SAMPLE_LOGS = {
    "syslog": [
        '<134>1 2024-06-15T07:30:15.000Z fw-1 kernel - - - ACCEPT IN=eth0 OUT=eth1 SRC=10.1.1.50 DST=203.0.113.10 PROTO=TCP SPT=45678 DPT=443',
        '<134>1 2024-06-15T07:31:00.000Z fw-1 kernel - - - ACCEPT IN=eth0 OUT=eth1 SRC=10.1.2.20 DST=198.51.100.5 PROTO=TCP SPT=34567 DPT=22',
        '<134>1 2024-06-15T08:30:15.000Z gateway-1 sshd 1234 - - Failed password for root from 203.0.113.99 port 22 ssh2',
        '<134>1 2024-06-15T08:30:20.000Z gateway-1 sshd 1235 - - Failed password for admin from 203.0.113.99 port 22 ssh2',
        '<134>1 2024-06-15T08:30:25.000Z gateway-1 sshd 1236 - - Failed password for admin from 203.0.113.99 port 22 ssh2',
        '<134>1 2024-06-15T08:30:28.000Z gateway-1 sshd 1237 - - Failed password for admin from 203.0.113.99 port 22 ssh2',
        '<134>1 2024-06-15T08:30:30.000Z gateway-1 sshd 1238 - - Accepted password for admin from 10.1.0.5 port 22 ssh2',
        '<134>1 2024-06-15T08:30:32.000Z gateway-1 sshd 1239 - - Accepted password for root from 10.1.0.5 port 22 ssh2',
        '<134>1 2024-06-15T08:30:35.000Z app-1 sshd 1240 - - Accepted password for oracle from 10.1.2.15 port 22 ssh2',
        '<134>1 2024-06-15T08:31:00.000Z app-1 sshd 1241 - - session opened for user oracle by (uid=0)',
        '<134>1 2024-06-15T08:31:10.000Z app-1 su 1242 - - Successful su for root by oracle',
        '<133>1 2024-06-15T08:35:00.000Z fw-1 kernel - - - DROP IN=eth0 OUT= MAC=xx SRC=10.1.2.15 DST=192.168.1.50 PROTO=TCP SPT=445 DPT=3389',
        '<133>1 2024-06-15T08:45:00.000Z fw-1 kernel - - - ACCEPT IN=eth0 OUT=eth1 SRC=10.1.2.15 DST=203.0.113.50 PROTO=TCP SPT=50000 DPT=443',
        '<133>1 2024-06-15T09:00:00.000Z fw-1 kernel - - - ACCEPT IN=eth0 OUT=eth1 SRC=10.1.2.15 DST=203.0.113.50 PROTO=TCP SPT=50001 DPT=443',
        '<133>1 2024-06-15T09:15:00.000Z fw-1 kernel - - - ACCEPT IN=eth0 OUT=eth1 SRC=10.1.2.15 DST=203.0.113.50 PROTO=TCP SPT=50002 DPT=443',
        '<134>1 2024-06-15T09:20:00.000Z web-1 httpd 5678 - - GET /admin/config HTTP/1.1 403 512 src=10.1.0.5 dst=10.1.1.50',
        '<134>1 2024-06-15T09:21:00.000Z web-1 httpd 5679 - - POST /upload HTTP/1.1 200 52428800 src=10.1.2.15 dst=198.51.100.20',
        '<134>1 2024-06-15T09:25:00.000Z dc-1 named 8901 - - client @0x7f 10.1.4.12#53123 (xfgioklwq.net): query: xfgioklwq.net IN A +',
        '<134>1 2024-06-15T09:25:10.000Z dc-1 named 8902 - - client @0x7f 10.1.4.12#53124 (rhwkqpmz.net): query: rhwkqpmz.net IN A +',
        '<134>1 2024-06-15T09:25:20.000Z dc-1 named 8903 - - client @0x7f 10.1.4.12#53125 (ztkvmqcb.net): query: ztkvmqcb.net IN A +',
        '<134>1 2024-06-15T09:25:30.000Z dc-1 named 8904 - - client @0x7f 10.1.4.12#53126 (bnlwqsjf.net): query: bnlwqsjf.net IN A +',
        '<134>1 2024-06-15T09:26:00.000Z dc-1 named 8905 - - client @0x7f 10.1.4.12#53127 (cdmktghy.net): query: cdmktghy.net IN A +',
        '<134>1 2024-06-15T09:26:10.000Z dc-1 named 8906 - - client @0x7f 10.1.4.12#53128 (wqplfgnh.net): query: wqplfgnh.net IN A +',
        '<134>1 2024-06-15T09:30:00.000Z db-1 sshd 2345 - - Failed password for root from 10.1.1.99 port 22 ssh2',
        '<134>1 2024-06-15T09:30:05.000Z db-1 sshd 2346 - - Failed password for root from 10.1.1.99 port 2222 ssh2',
        '<134>1 2024-06-15T09:30:10.000Z db-1 sshd 2347 - - Failed password for root from 10.1.1.99 port 8080 ssh2',
        '<134>1 2024-06-15T09:30:15.000Z db-1 sshd 2348 - - Failed password for root from 10.1.1.99 port 3389 ssh2',
        '<134>1 2024-06-15T09:30:20.000Z db-1 sshd 2349 - - Failed password for root from 10.1.1.99 port 53 ssh2',
    ],
    "dns": [
        '15-Jun-2024 08:00:00.123 queries: info: client @0x7f8a1c00 10.1.1.50#53123 (www.google.com): query: www.google.com IN A + (10.1.0.1)',
        '15-Jun-2024 08:01:00.456 queries: info: client @0x7f8a1c01 10.1.2.20#53124 (api.github.com): query: api.github.com IN A + (10.1.0.1)',
        '15-Jun-2024 08:30:00.789 queries: info: client @0x7f8a1c02 10.1.4.12#53125 (xfgioklwq.net): query: xfgioklwq.net IN A + (10.1.0.1)',
        '15-Jun-2024 08:30:10.012 queries: info: client @0x7f8a1c03 10.1.4.12#53126 (rhwkqpmz.net): query: rhwkqpmz.net IN A + (10.1.0.1)',
        '15-Jun-2024 09:00:00.345 queries: info: client @0x7f8a1c04 10.1.4.12#53127 (ztkvmqcb.net): query: ztkvmqcb.net IN A + (10.1.0.1)',
        '15-Jun-2024 09:00:10.678 queries: info: client @0x7f8a1c05 10.1.4.12#53128 (bnlwqsjf.net): query: bnlwqsjf.net IN A + (10.1.0.1)',
        '15-Jun-2024 09:00:20.901 queries: info: client @0x7f8a1c06 10.1.4.12#53129 (cdmktghy.net): query: cdmktghy.net IN A + (10.1.0.1)',
        '15-Jun-2024 09:00:30.234 queries: info: client @0x7f8a1c07 10.1.4.12#53130 (wqplfgnh.net): query: wqplfgnh.net IN A + (10.1.0.1)',
        '15-Jun-2024 09:00:40.567 queries: info: client @0x7f8a1c08 10.1.4.12#53131 (kmjnhbgv.net): query: kmjnhbgv.net IN A + (10.1.0.1)',
        '15-Jun-2024 09:15:00.890 queries: info: client @0x7f8a1c09 10.1.2.15#53132 (evil-c2.ddns.net): query: evil-c2.ddns.net IN A + (10.1.0.1)',
        '15-Jun-2024 09:20:00.123 queries: info: client @0x7f8a1c10 10.1.2.15#53133 (203.0.113.50.in-addr.arpa): query: 203.0.113.50.in-addr.arpa IN PTR + (10.1.0.1)',
        '15-Jun-2024 10:00:00.456 queries: info: client @0x7f8a1c11 10.1.3.8#53134 (exfil-storage.xyz): query: exfil-storage.xyz IN A + (10.1.0.1)',
    ],
    "waf": [
        '{"action":"log","clientIP":"10.1.1.50","clientRequestHTTPHost":"app.internal","clientRequestPath":"/api/data","clientRequestHTTPMethod":"GET","clientRequestHTTPVersion":"HTTP/1.1","timestamp":"2024-06-15T08:00:00Z","ruleId":"200001","ruleMessage":"Normal request","source":"cloudflare"}',
        '{"action":"block","clientIP":"203.0.113.99","clientRequestHTTPHost":"app.internal","clientRequestPath":"/admin/config.php","clientRequestHTTPMethod":"GET","clientRequestHTTPVersion":"HTTP/1.1","timestamp":"2024-06-15T08:30:30Z","ruleId":"100001","ruleMessage":"SQL injection attempt in URI","source":"cloudflare"}',
        '{"action":"block","clientIP":"203.0.113.99","clientRequestHTTPHost":"app.internal","clientRequestPath":"/login","clientRequestHTTPMethod":"POST","clientRequestHTTPVersion":"HTTP/1.1","timestamp":"2024-06-15T08:30:35Z","ruleId":"942100","ruleMessage":"SQL injection in POST body","source":"cloudflare"}',
        '{"action":"log","clientIP":"10.1.0.5","clientRequestHTTPHost":"app.internal","clientRequestPath":"/search?q=SELECT+*+FROM+users","clientRequestHTTPMethod":"GET","clientRequestHTTPVersion":"HTTP/1.1","timestamp":"2024-06-15T08:31:00Z","ruleId":"942100","ruleMessage":"Possible SQL injection","source":"modsecurity"}',
        '{"action":"block","clientIP":"10.1.2.15","clientRequestHTTPHost":"db.internal","clientRequestPath":"/exec/cmd.exe","clientRequestHTTPMethod":"POST","clientRequestHTTPVersion":"HTTP/1.1","timestamp":"2024-06-15T08:35:00Z","ruleId":"932110","ruleMessage":"Remote command execution","source":"cloudflare"}',
        '{"action":"log","clientIP":"10.1.3.8","clientRequestHTTPHost":"storage.internal","clientRequestPath":"/upload","clientRequestHTTPMethod":"POST","clientRequestHTTPVersion":"HTTP/1.1","timestamp":"2024-06-15T09:21:00Z","ruleId":"200002","ruleMessage":"Large file upload","source":"cloudflare","requestSize":52428800}',
    ],
    "etw": [
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2024-06-15T08:00:00.000Z"/></System><EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">10.1.1.50</Data></EventData></Event>',
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2024-06-15T08:30:15.000Z"/></System><EventData><Data Name="TargetUserName">administrator</Data><Data Name="IpAddress">203.0.113.99</Data></EventData></Event>',
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2024-06-15T08:30:20.000Z"/></System><EventData><Data Name="TargetUserName">administrator</Data><Data Name="IpAddress">203.0.113.99</Data></EventData></Event>',
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2024-06-15T08:30:30.000Z"/></System><EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">10.1.0.5</Data></EventData></Event>',
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4672</EventID><TimeCreated SystemTime="2024-06-15T08:30:32.000Z"/></System><EventData><Data Name="TargetUserName">admin</Data></EventData></Event>',
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2024-06-15T08:45:00.000Z"/></System><EventData><Data Name="SourceIp">10.1.2.15</Data><Data Name="DestinationIp">203.0.113.50</Data><Data Name="DestinationPort">443</Data></EventData></Event>',
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2024-06-15T09:00:00.000Z"/></System><EventData><Data Name="SourceIp">10.1.2.15</Data><Data Name="DestinationIp">203.0.113.50</Data><Data Name="DestinationPort">443</Data></EventData></Event>',
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2024-06-15T09:15:00.000Z"/></System><EventData><Data Name="SourceIp">10.1.2.15</Data><Data Name="DestinationIp">203.0.113.50</Data><Data Name="DestinationPort">443</Data></EventData></Event>',
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2024-06-15T08:35:05.000Z"/></System><EventData><Data Name="Image">C:\\Windows\\Temp\\payload.exe</Data><Data Name="CommandLine">cmd.exe /c whoami</Data></EventData></Event>',
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>22</EventID><TimeCreated SystemTime="2024-06-15T09:25:00.000Z"/></System><EventData><Data Name="QueryName">xfgioklwq.net</Data></EventData></Event>',
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>22</EventID><TimeCreated SystemTime="2024-06-15T09:25:10.000Z"/></System><EventData><Data Name="QueryName">rhwkqpmz.net</Data></EventData></Event>',
    ],
    "general": [
        '2026-06-17T08:12:34.221Z 10.2.15.88 -> 192.168.1.105:443 TLS handshake completed, JA3S=3b5074b1b5d032e5620f69f9f700ff4e, URI=/update/check?uid=7F3A2C, beacon interval=62s',
        '2026-06-17T08:23:11.047Z 10.2.15.88 -> 192.168.1.105:443 POST /collect, data size 2847 bytes, beacon interval=65s',
        '2026-06-17T08:45:22.198Z 10.2.15.100 -> 10.3.20.5:445 SMB2 TreeConnect \\\\10.3.20.5\\IPC$, user: Administrator, status=SUCCESS, EventID 4624 logon type 3',
        '2026-06-17T08:49:30.112Z 10.2.15.100 -> 10.3.20.5:445 SMB2 Exec, service=RemoteRegistry, command=sc start WinUpdate, remote process creation Event 4688',
        '2026-06-17T09:02:14.776Z 10.2.15.88 -> 193.42.187.34:53 DNS query for "d3f4ult-upd4te.xyz", response NXDOMAIN, qtype=A',
        '2026-06-17T09:04:22.991Z 10.2.15.88 -> 193.42.187.34:53 DNS query for "a7k2m9p4q1r8.space", response 193.42.187.99, TTL=300',
        '2026-06-17T09:06:45.112Z 10.2.15.88 -> 193.42.187.34:53 DNS query for "x9z8w7v6u5t4.top", response 193.42.187.100, high entropy domain',
        '2026-06-17T09:15:08.443Z 10.2.15.200 -> 10.2.0.0/16: ICMP echo request ping sweep, 256 hosts scanned in 12s, response rate 23%',
        '2026-06-17T09:17:33.821Z 10.2.15.200 -> 10.2.20.15:22 SSH banner grab, multiple SYN probes to port 22 across /24',
        '2026-06-17T09:20:15.669Z 10.2.15.200 -> 10.2.30.5:445 SMB null session enumeration, port sweep 135-445, 2000+ packets/min',
        '2026-06-17T09:35:42.502Z 10.2.15.88 -> 10.2.15.100:3389 RDP logon failure user "backup_admin", Event 4625, 5 attempts in 2 min',
        '2026-06-17T09:38:19.886Z 10.2.15.88 -> 10.2.15.100:3389 RDP logon success user "backup_admin", Event 4624, unusual time weekend',
        '2026-06-17T09:40:01.234Z 10.2.15.100 -> 193.42.187.99:443 HTTPS POST /exfil, bytes_out=1.2GB over 15 min, outbound traffic spike 450%',
        '2026-06-17T09:50:22.113Z 10.2.15.100 -> 10.2.15.200:22 SSH reverse tunnel established, local port 2222 -> remote 192.168.1.105:443',
        '2026-06-17T09:55:10.557Z 10.2.15.100 -> 10.2.15.200:135 DCE/RPC call, IFS interface, remote WMI execution Event 4698',
        '2026-06-17T10:01:45.882Z 10.2.15.88 -> 8.8.8.8:53 DNS query for "windows-update-service.cf", response 193.42.187.101, beacon interval=4s, domain age 2 days',
    ],
}

# ============================================================
# Session State Init
# ============================================================
def init_session():
    defaults = {
        "imported_records": None,
        "source_type": None,
        "analysis_results": None,
        "data_source_name": "演示数据 (内置攻击注入)",
        "use_demo_data": True,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_session()

# ============================================================
# Data Loading
# ============================================================
@st.cache_data(ttl=3600, show_spinner="正在生成演示数据并运行风险分析...")
def load_demo_data():
    """Generate rich demo data with diverse attack patterns and sparse baseline."""
    random.seed(42)
    from src.evaluation.attack_injector import AttackInjector
    from src.evaluation.metrics import DetectionMetrics
    from src.pipeline.orchestrator import PipelineOrchestrator

    injector = AttackInjector()
    internal = [f"10.1.{i}.{j}" for i in range(5) for j in range(1, 15)]
    external = [f"203.0.113.{i}" for i in range(1, 30)]
    ports_normal = [80, 443, 53]

    # Small baseline — just enough to establish normal communication patterns
    base_records = []
    for _ in range(500):
        src = random.choice(internal)
        dst = random.choice(internal + external)
        etype = random.choices(
            ["network_connect", "auth_success", "dns_query"],
            weights=[0.65, 0.10, 0.25]
        )[0]
        rec = {
            "src_ip": src, "dst_ip": dst,
            "dst_port": random.choice(ports_normal),
            "proto": "TCP", "event_type": etype,
            "timestamp": injector.base_ts + random.randint(0, 86400000),
            "bytes_out": random.randint(10, 5000),
        }
        if etype == "dns_query":
            rec["domain"] = random.choice([
                "www.google.com", "api.github.com", "cdn.cloudflare.com",
                "login.microsoft.com", "update.ubuntu.com", "registry.npmjs.org",
            ])
        if etype == "auth_success":
            rec["user"] = random.choice(["svc-backup", "monitor", "deploy"])
        base_records.append(rec)

    # ---- Rich attack injection ----
    # C2 Beacon: two different victims + C2 servers
    c2_recs = injector.inject_c2_beacon("10.1.2.15", "203.0.113.50", interval_sec=300, duration_hours=6)
    c2_recs2 = injector.inject_c2_beacon("10.1.0.8", "198.51.100.77", interval_sec=600, duration_hours=3)

    # Lateral Movement: two scenarios
    lm_recs = injector.inject_lateral_movement("10.1.0.5", "192.168.1.50", ["10.1.2.15"])
    lm_recs2 = injector.inject_lateral_movement("10.1.3.4", "10.1.4.8", ["10.1.1.12"])

    # Data Exfiltration: two scenarios
    exfil_recs = injector.inject_data_exfil("10.1.3.8", "198.51.100.20", num_connections=50)
    exfil_recs2 = injector.inject_data_exfil("10.1.0.7", "203.0.113.88", num_connections=30)

    # DGA: multiple hosts
    dga_recs = injector.inject_dga("10.1.4.12", num_domains=200)
    dga_recs2 = injector.inject_dga("10.1.2.6", num_domains=100)

    # Port Scan
    scan_recs = injector.inject_port_scan("10.1.1.99", "192.168.0.0/16", num_targets=100)

    all_records = (base_records + c2_recs + c2_recs2 + lm_recs + lm_recs2 +
                   exfil_recs + exfil_recs2 + dga_recs + dga_recs2 + scan_recs)

    orch = PipelineOrchestrator()
    results = orch.run(all_records)

    edge_summary = defaultdict(list)
    for r in all_records:
        if r.get("src_ip") and r.get("dst_ip"):
            edge_summary[(r["src_ip"], r["dst_ip"])].append(r)

    metrics = DetectionMetrics(match_threshold=0.6)
    eval_results = metrics.evaluate(injector.injected_attacks, results["chains"])

    total_injected = (len(c2_recs) + len(c2_recs2) + len(lm_recs) + len(lm_recs2) +
                      len(exfil_recs) + len(exfil_recs2) + len(dga_recs) + len(dga_recs2) + len(scan_recs))

    return {
        "records": all_records,
        "total_events": len(all_records),
        "total_injected": total_injected,
        "ip_scores": results["ip_scores"],
        "chains": results["chains"],
        "top_entities": results["top_entities"],
        "eval_results": eval_results,
        "graph_data": results["graph_data"],
        "dga_results": results["dga_results"],
        "injected_attacks": injector.injected_attacks,
        "entity_count": results["entity_count"],
        "edge_summary": dict(edge_summary),
        "source": "demo",
    }

def run_pipeline_on_records(records: list[dict]):
    """Run the full pipeline on parsed records."""
    from src.evaluation.metrics import DetectionMetrics
    from src.pipeline.orchestrator import PipelineOrchestrator

    orch = PipelineOrchestrator()
    results = orch.run(records)

    edge_summary = defaultdict(list)
    for r in records:
        if r.get("src_ip") and r.get("dst_ip"):
            edge_summary[(r["src_ip"], r["dst_ip"])].append(r)

    # Extract ground truth from user's annotated labels [攻击类型]
    ground_truth = _extract_ground_truth(records)

    metrics = DetectionMetrics(match_threshold=0.6)
    eval_results = metrics.evaluate(ground_truth, results["chains"])

    return {
        "records": records,
        "total_events": len(records),
        "total_injected": len(ground_truth),
        "ip_scores": results["ip_scores"],
        "chains": results["chains"],
        "top_entities": results["top_entities"],
        "eval_results": eval_results,
        "graph_data": results["graph_data"],
        "dga_results": results["dga_results"],
        "injected_attacks": ground_truth,
        "entity_count": results["entity_count"],
        "edge_summary": dict(edge_summary),
        "source": "imported",
    }


# Mapping from Chinese attack labels in brackets to chain_type
_LABEL_TO_CHAIN_TYPE = {
    "C2信标": "c2_beacon", "C2通信": "c2_beacon",
    "横向移动": "lateral_movement",
    "数据外泄": "data_exfil",
    "DGA活动": "dga_activity",
    "侦察扫描": "recon_scan",
    "暴力破解": "brute_force",
    "凭据访问": "credential_theft", "凭据窃取": "credential_theft",
    "持久化": "persistence",
    "反取证活动": "anti_forensics", "反取证": "anti_forensics",
    "中间人攻击": "mitm_attack",
    "内部侦察": "internal_recon",
    "工具下载": "tool_download",
    "防御规避": "anti_forensics",
    "勒索软件": "ransomware_pattern",
    "权限提升": "privilege_escalation",
}


def _extract_ground_truth(records: list[dict]) -> list:
    """Extract annotated attack labels from log lines as InjectedAttack ground truth."""
    from src.core.types import InjectedAttack

    attacks = []
    label_re = re.compile(r"\[([^\]]+)\]")  # extract [攻击类型]
    for r in records:
        raw = r.get("raw_message", "")
        labels = label_re.findall(raw)
        for label in labels:
            chain_type = _LABEL_TO_CHAIN_TYPE.get(label)
            if chain_type:
                entities = []
                if r.get("src_ip") and r["src_ip"] != "unknown":
                    entities.append(r["src_ip"])
                if r.get("dst_ip") and r["dst_ip"] != "unknown":
                    entities.append(r["dst_ip"])
                attacks.append(InjectedAttack(
                    attack_id=r.get("event_id", str(uuid.uuid4())[:8]),
                    attack_type=chain_type,
                    entities=entities,
                    start_time=r.get("timestamp", 0),
                    end_time=r.get("timestamp", 0),
                ))
    return attacks

def parse_log_text(log_text: str, source_type: str) -> list[dict]:
    """Parse a log text string into structured records. Auto-fallback to general parser."""
    from src.parsers.parser_registry import ParserRegistry
    parser = ParserRegistry.get_parser(source_type)
    records = []
    for line in log_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = parser.parse_line(line)
            if r and r.get("src_ip") and r["src_ip"] != "unknown":
                records.append(r)
        except Exception:
            pass

    # If the specific parser failed to extract useful records, auto-fallback to general
    if len(records) == 0 and source_type != "general":
        try:
            general = ParserRegistry.get_parser("general")
            for line in log_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r = general.parse_line(line)
                    if r and r.get("src_ip") and r["src_ip"] != "unknown":
                        records.append(r)
                except Exception:
                    pass
        except Exception:
            pass

    return records

# ============================================================
# UI Helpers
# ============================================================
def risk_badge(score):
    if score > 0.8: return "🔴"
    if score > 0.6: return "🟠"
    if score > 0.4: return "🟡"
    return "🟢"

def risk_color(score):
    if score > 0.7: return "#ff4444"
    if score > 0.4: return "#ffaa00"
    return "#44aa44"

def show_connection_detail(recs, src, dst):
    event_types = defaultdict(list)
    for r in recs:
        et = EVENT_LABELS.get(r.get("event_type", "?"), r.get("event_type", "?"))
        event_types[et].append(r)
    for et, et_recs in event_types.items():
        ports = sorted(set(r.get("dst_port") for r in et_recs if r.get("dst_port")))
        bytes_out = sum(r.get("bytes_out") or 0 for r in et_recs)
        tags = set()
        for r in et_recs:
            tags.update(r.get("tags", []))
        inject_note = ""
        if tags and any("injected" in t for t in tags):
            atk_tags = [t.replace("injected:", "") for t in tags if "injected" in t]
            inject_note = f"  ⚠️ [注入: {', '.join(atk_tags)}]"
        st.markdown(
            f"- **{et}** × {len(et_recs)}次 | "
            f"端口: {', '.join(map(str, ports[:5])) if ports else '无'} | "
            f"出站流量: {bytes_out:,} bytes{inject_note}"
        )


def _generate_pdf_report(data: dict, chains: list, ip_scores: dict,
                         high_risk: int, critical: int, eval_r: dict,
                         per_type: dict) -> bytes:
    """Generate a PDF security analysis report using fpdf2."""
    from fpdf import FPDF

    class PDF(FPDF):
        def header(self):
            if self.page_no() > 1:
                self.set_font("SimHei", "", 8)
                self.set_text_color(128, 128, 128)
                self.cell(0, 5, "网络风险识别分析报告", align="C")
                self.ln(8)

        def footer(self):
            self.set_y(-15)
            self.set_font("SimHei", "", 8)
            self.set_text_color(128, 128, 128)
            self.cell(0, 10, f"第 {self.page_no()} 页", align="C")

    pdf = PDF()
    pdf.set_auto_page_break(True, 20)

    # Add Chinese font — try platform-specific paths, download as last resort
    font_paths = [
        "C:/Windows/Fonts/simhei.ttf",
        "C:/Windows/Fonts/msyh.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    ]
    font_loaded = False
    for fp in font_paths:
        if Path(fp).exists():
            pdf.add_font("SimHei", "", fp, uni=True)
            font_loaded = True
            break
    if not font_loaded:
        # Download Noto Sans SC font on the fly
        import urllib.request, io as _io
        font_url = "https://github.com/googlefonts/noto-cjk/releases/download/Sans2.004/03_NotoSansCJKsc.zip"
        try:
            req = urllib.request.urlopen(font_url, timeout=10)
            data = _io.BytesIO(req.read())
            import zipfile
            with zipfile.ZipFile(data) as zf:
                for name in zf.namelist():
                    if name.endswith("Regular.otf"):
                        font_data = _io.BytesIO(zf.read(name))
                        pdf.add_font("SimHei", "", font_data, uni=True)
                        font_loaded = True
                        break
        except Exception:
            raise RuntimeError("无法加载中文字体，请使用JSON下载")

    pdf.add_page()

    # ---- Title ----
    pdf.set_font("SimHei", "", 22)
    pdf.set_text_color(180, 30, 30)
    pdf.cell(0, 15, "网络风险识别分析报告", align="C")
    pdf.ln(12)

    pdf.set_font("SimHei", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C")
    pdf.ln(6)
    pdf.cell(0, 8, f"数据源: {st.session_state.get('data_source_name', '未知')}", align="C")
    pdf.ln(12)

    # ---- Executive Summary ----
    pdf.set_fill_color(220, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("SimHei", "", 14)
    pdf.cell(0, 10, "  执行摘要", fill=True)
    pdf.ln(14)

    pdf.set_text_color(50, 50, 50)
    pdf.set_font("SimHei", "", 11)
    summary_items = [
        ("处理事件总数", f"{data['total_events']:,}"),
        ("检测攻击链", str(len(chains))),
        ("高风险IP (>0.7)", str(high_risk)),
        ("严重风险IP (>0.9)", str(critical)),
        ("识别实体数", str(data.get('entity_count', 0))),
        ("精确率 (Precision)", f"{eval_r.get('precision', 0):.1%}"),
        ("召回率 (Recall)", f"{eval_r.get('recall', 0):.1%}"),
        ("F1 分数", f"{eval_r.get('f1', 0):.1%}"),
    ]
    for label, value in summary_items:
        pdf.cell(90, 8, f"  {label}:")
        pdf.set_font("SimHei", "", 11)
        pdf.cell(0, 8, value)
        pdf.ln(7)

    pdf.ln(6)

    # ---- Attack Chain Details ----
    pdf.set_fill_color(220, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("SimHei", "", 14)
    pdf.cell(0, 10, "  攻击链详情", fill=True)
    pdf.ln(14)

    type_names = {
        "c2_beacon": "C2信标", "lateral_movement": "横向移动",
        "data_exfil": "数据外泄", "dga_activity": "DGA活动",
        "recon_scan": "侦察扫描", "suspicious_activity": "可疑活动",
    }

    top_chains = sorted(chains, key=lambda x: x.total_risk_score, reverse=True)[:15]
    if top_chains:
        pdf.set_text_color(50, 50, 50)
        for i, c in enumerate(top_chains):
            pdf.set_font("SimHei", "", 10)
            ctype = type_names.get(c.chain_type, c.chain_type)
            pdf.cell(0, 7, f"#{i+1} [{ctype}] Risk: {c.total_risk_score:.2f}  Confidence: {c.confidence:.0%}")
            pdf.ln(6)
            nodes_str = " -> ".join(n.entity for n in c.nodes[:5])
            pdf.set_font("SimHei", "", 9)
            pdf.set_text_color(80, 80, 80)
            pdf.cell(0, 6, f"  路径: {nodes_str}")
            pdf.ln(5)
            if c.mitre_techniques:
                pdf.cell(0, 6, f"  MITRE: {', '.join(c.mitre_techniques[:5])}")
                pdf.ln(5)
            pdf.set_text_color(50, 50, 50)
            # Check page space
            if pdf.get_y() > 240:
                pdf.add_page()
    else:
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("SimHei", "", 10)
        pdf.cell(0, 8, "  未发现攻击链")
        pdf.ln(8)

    pdf.ln(4)

    # ---- Per-Type Metrics ----
    if pdf.get_y() > 200:
        pdf.add_page()
    pdf.set_fill_color(220, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("SimHei", "", 14)
    pdf.cell(0, 10, "  各攻击类型检测指标", fill=True)
    pdf.ln(14)

    if per_type:
        pdf.set_text_color(50, 50, 50)
        pdf.set_font("SimHei", "", 10)
        # Header row
        col_w = [55, 35, 35, 35]
        headers = ["攻击类型", "精确率", "召回率", "F1分数"]
        for h, w in zip(headers, col_w):
            pdf.set_fill_color(240, 240, 240)
            pdf.cell(w, 8, h, border=1, fill=True)
        pdf.ln()

        for atype, m in per_type.items():
            p = m.get("precision", 0)
            r = m.get("recall", 0)
            f1 = 2 * p * r / max(p + r, 1e-10)
            tname = type_names.get(atype, atype)
            pdf.set_font("SimHei", "", 9)
            pdf.cell(col_w[0], 7, f" {tname}", border=1)
            pdf.cell(col_w[1], 7, f" {p:.1%}", border=1)
            pdf.cell(col_w[2], 7, f" {r:.1%}", border=1)
            pdf.cell(col_w[3], 7, f" {f1:.1%}", border=1)
            pdf.ln()

    pdf.ln(6)

    # ---- Risk Aggregation ----
    if pdf.get_y() > 200:
        pdf.add_page()
    pdf.set_fill_color(220, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("SimHei", "", 14)
    pdf.cell(0, 10, "  风险聚合与溯源线索", fill=True)
    pdf.ln(14)

    top_ips = sorted(ip_scores.items(), key=lambda x: x[1], reverse=True)[:20]
    if top_ips:
        pdf.set_text_color(50, 50, 50)
        for ip, score in top_ips:
            tier = "严重" if score > 0.9 else ("高风险" if score > 0.7 else ("中风险" if score > 0.4 else "低风险"))
            pdf.set_font("SimHei", "", 10)
            pdf.cell(0, 7, f"  {ip}  |  风险: {score:.3f}  |  等级: {tier}")
            pdf.ln(6)

    pdf.ln(6)

    # ---- Recommendations ----
    if pdf.get_y() > 200:
        pdf.add_page()
    pdf.set_fill_color(220, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("SimHei", "", 14)
    pdf.cell(0, 10, "  处置建议", fill=True)
    pdf.ln(14)

    pdf.set_text_color(50, 50, 50)
    recommendations = []
    if critical > 0:
        recommendations.append(f"发现 {critical} 个严重风险IP，建议立即隔离并启动应急响应")
    if high_risk > 0:
        recommendations.append(f"发现 {high_risk} 个高风险IP，建议在24小时内进行调查")
    found_types = set(c.chain_type for c in chains)
    action_map = {
        "c2_beacon": "阻断C2信标IP的出站流量，检查受害主机是否存在恶意软件",
        "lateral_movement": "隔离跳板主机，重置相关凭据，审查认证日志",
        "data_exfil": "阻断出站大流量传输，审查目标外部IP的历史通信",
        "dga_activity": "封禁DGA域名，扫描源主机排查恶意软件感染",
        "recon_scan": "确认扫描来源，加强目标网络防火墙规则",
    }
    for atype in found_types:
        if atype in action_map:
            recommendations.append(f"[{type_names.get(atype, atype)}] {action_map[atype]}")
    if not recommendations:
        recommendations.append("当前未发现明显攻击活动，建议保持现有监控策略")

    for i, rec in enumerate(recommendations[:10]):
        pdf.set_font("SimHei", "", 10)
        pdf.cell(8, 7, f"{i+1}.")
        pdf.cell(0, 7, rec)
        pdf.ln(7)

    pdf.ln(6)
    pdf.set_font("SimHei", "", 8)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 10, "本报告由网络风险识别分析引擎自动生成 | 仅供安全分析参考", align="C")

    return bytes(pdf.output())


# ============================================================
# Determine active DATA
# ============================================================
def get_data():
    if st.session_state.get("analysis_results"):
        return st.session_state.analysis_results
    return load_demo_data()

DATA = get_data()

# ============================================================
# Sidebar
# ============================================================
st.sidebar.title("🛡️ 网络风险识别")

# Data source indicator
current_source = st.session_state.get("data_source_name", "演示数据")
data_badge = "📦" if st.session_state.get("use_demo_data", True) else "📁"
st.sidebar.markdown(f"**当前数据源**: {data_badge} {current_source}")

st.sidebar.markdown("---")
st.sidebar.caption(f"🔧 引擎版本: {__version__}")

# Navigation — placed directly below data source
page = st.sidebar.radio(
    "📋 功能导航",
    ["📁 日志导入与分析", "📊 系统概览", "🔗 攻击链详情", "👤 实体风险",
     "🕸️ 溯源追踪", "📈 检测评估", "📋 综合分析报告"],
)

st.sidebar.markdown("---")
st.sidebar.metric("处理事件总数", f"{DATA['total_events']:,}")
st.sidebar.metric("发现攻击链", len(DATA["chains"]))
st.sidebar.metric("识别实体数", DATA.get("entity_count", 0))
high_risk = sum(1 for s in DATA["ip_scores"].values() if s > 0.7)
watch_ips = sum(1 for s in DATA["ip_scores"].values() if s > 0.5)
st.sidebar.metric("异常IP (>0.7)", high_risk)
st.sidebar.metric("需关注IP (>0.5)", watch_ips)

st.sidebar.markdown("---")
st.sidebar.caption(f"v2.0 — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
st.sidebar.info("""
**关于此引擎**
基于无监督异常检测与稀有路径挖掘，
自动从安全日志中识别攻击链模式。
支持 Syslog / DNS / WAF / ETW 格式。
""")

# ============================================================
# Page: 日志导入与分析 (FIRST page = default)
# ============================================================
if page == "📁 日志导入与分析":
    st.header("📁 日志导入与分析")
    st.markdown("支持 Syslog、DNS、WAF、ETW 等日志格式。导入后自动进行六阶段风险分析。")

    # ---- Mode selector ----
    mode_tab1, mode_tab2, mode_tab3 = st.tabs(
        ["📤 上传日志文件", "📝 粘贴/编辑日志", "👁️ 查看当前示例日志"]
    )

    # ===== Tab 1: File Upload =====
    with mode_tab1:
        c1, c2 = st.columns([2, 1])
        with c1:
            uploaded_files = st.file_uploader(
                "选择日志文件 (支持多选)",
                type=["log", "txt", "json", "csv", "xml", "evtx"],
                accept_multiple_files=True,
                help="支持 Syslog (RFC 3164/5424)、DNS (BIND/Unbound)、WAF (Cloudflare/ModSecurity)、ETW/EVTX 格式"
            )
        with c2:
            source_type = st.selectbox(
                "日志格式",
                ["syslog", "dns", "waf", "etw", "general"],
                format_func=lambda x: {
                    "syslog": "Syslog (RFC 3164/5424)",
                    "dns": "DNS (BIND/Unbound)",
                    "waf": "WAF (Cloudflare/ModSecurity)",
                    "etw": "ETW/EVTX (Windows事件)"
                }.get(x, x),
                key="upload_source_type"
            )

        if uploaded_files:
            st.info(f"已选择 **{len(uploaded_files)}** 个文件: {', '.join(f'`{f.name}`' for f in uploaded_files)}")

            if st.button("👁️ 预览前20行", key="preview_upload"):
                content = ""
                for uf in uploaded_files[:2]:
                    uf.seek(0)
                    text = uf.read().decode("utf-8", errors="replace")
                    content += text[:3000] + "\n"
                st.text_area("日志预览", content[:5000], height=250, disabled=True)

            if st.button("🚀 导入并运行分析", type="primary", key="run_upload"):
                all_records = []
                for uf in uploaded_files:
                    uf.seek(0)
                    content = uf.read().decode("utf-8", errors="replace")
                    records = parse_log_text(content, source_type)
                    all_records.extend(records)

                if all_records:
                    with st.spinner(f"解析完成 {len(all_records)} 条记录，运行全流水线分析..."):
                        data = run_pipeline_on_records(all_records)
                        st.session_state.analysis_results = data
                        st.session_state.imported_records = all_records
                        st.session_state.source_type = source_type
                        st.session_state.data_source_name = f"导入: {', '.join(f.name for f in uploaded_files)}"
                        st.session_state.use_demo_data = False
                    st.success(f"✅ 分析完成！**{len(data['chains'])}** 条攻击链，**{sum(1 for s in data['ip_scores'].values() if s > 0.7)}** 个异常IP")
                    st.rerun()
                else:
                    st.error("未能解析出有效记录，请检查日志格式是否匹配。")

    # ===== Tab 2: Paste/Edit Logs =====
    with mode_tab2:
        paste_source = st.selectbox(
            "日志格式",
            ["syslog", "dns", "waf", "etw", "general"],
            format_func=lambda x: x.upper(),
            key="paste_source_type"
        )

        default_sample = "\n".join(SAMPLE_LOGS.get(paste_source, SAMPLE_LOGS["syslog"]))
        pasted_text = st.text_area(
            "粘贴或编辑日志内容 (每行一条日志)",
            value="",
            height=300,
            placeholder=default_sample[:500],
            key="paste_area"
        )

        c1, c2 = st.columns(2)
        with c1:
            if st.button("🧪 加载示例日志", key="load_sample"):
                st.session_state["sample_log_cache"] = default_sample
                st.rerun()

        with c2:
            btn_text = "🔬 分析日志"
            run_disabled = not pasted_text.strip()
            if st.button(btn_text, type="primary", disabled=run_disabled, key="run_paste"):
                records = parse_log_text(pasted_text, paste_source)
                if records:
                    with st.spinner(f"解析 {len(records)} 条记录，运行全流水线分析..."):
                        data = run_pipeline_on_records(records)
                        st.session_state.analysis_results = data
                        st.session_state.imported_records = records
                        st.session_state.source_type = paste_source
                        st.session_state.data_source_name = f"自定义 {paste_source.upper()} 日志 ({len(records)}条)"
                        st.session_state.use_demo_data = False
                    st.success(f"✅ 分析完成！**{len(data['chains'])}** 条攻击链")
                    st.rerun()
                else:
                    st.error("未能解析出有效记录，请检查日志格式。")

        # Show loaded sample
        if st.session_state.get("sample_log_cache"):
            st.text_area("示例日志 (可编辑)", st.session_state.sample_log_cache, height=300, key="sample_view")

    # ===== Tab 3: View Current Data Sample =====
    with mode_tab3:
        st.subheader("👁️ 当前数据源中的示例记录")
        st.caption(f"数据来源: **{st.session_state.get('data_source_name', '演示数据')}**")

        if DATA and DATA.get("records"):
            records = DATA["records"]
            st.write(f"共 **{len(records)}** 条记录")

            # Summary stats
            event_types = Counter(r.get("event_type", "?") for r in records)
            src_ips = Counter(r.get("src_ip", "?") for r in records)
            dst_ips = Counter(r.get("dst_ip", "?") for r in records)

            c1, c2, c3 = st.columns(3)
            with c1:
                st.metric("事件类型数", len(event_types))
                st.caption("事件类型分布")
                for et, cnt in event_types.most_common(10):
                    st.write(f"- {EVENT_LABELS.get(et, et)}: {cnt}")
            with c2:
                st.metric("源IP数", len(src_ips))
                st.caption("TOP 源IP")
                for ip, cnt in src_ips.most_common(10):
                    injected = any("injected" in (r.get("tags") or []) for r in records if r.get("src_ip") == ip)
                    mark = " ⚠️" if injected else ""
                    st.write(f"- {ip}: {cnt}{mark}")
            with c3:
                st.metric("目标IP数", len(dst_ips))
                st.caption("TOP 目标IP")
                for ip, cnt in dst_ips.most_common(10):
                    st.write(f"- {ip}: {cnt}")

            # Show raw log lines (reconstructed)
            st.markdown("---")
            st.subheader("📝 记录详情")
            show_injected = st.checkbox("仅显示注入的攻击记录", value=False, key="show_injected_only")

            display_records = records
            if show_injected:
                display_records = [r for r in records if r.get("tags") and any("injected" in t for t in r["tags"])]
                st.caption(f"共 {len(display_records)} 条注入攻击记录")

            if display_records:
                # Build table
                rows = []
                for r in display_records[:200]:
                    tags = r.get("tags", [])
                    has_inject = any("injected" in t for t in tags)
                    rows.append({
                        "时间": pd.to_datetime(r.get("timestamp", 0), unit="ms").strftime("%m-%d %H:%M:%S") if r.get("timestamp") else "-",
                        "源IP": r.get("src_ip", "-"),
                        "目标IP": r.get("dst_ip", "-"),
                        "端口": r.get("dst_port", "-"),
                        "事件类型": EVENT_LABELS.get(r.get("event_type", ""), r.get("event_type", "-")),
                        "标签": ", ".join(t.replace("injected:", "") for t in tags) if has_inject else "",
                        "注入": "⚠️" if has_inject else "",
                    })
                df = pd.DataFrame(rows)
                st.dataframe(df, use_container_width=True, hide_index=True, height=400)
        else:
            st.info("暂无数据。请导入日志或使用演示数据。")

    # ---- Current analysis status ----
    st.markdown("---")
    st.subheader("📊 当前分析结果摘要")
    res = DATA
    cols = st.columns(5)
    cols[0].metric("数据来源", st.session_state.get("data_source_name", "?"))
    cols[1].metric("总记录", f"{res['total_events']:,}")
    cols[2].metric("攻击链", len(res["chains"]))
    cols[3].metric("异常IP", sum(1 for s in res["ip_scores"].values() if s > 0.7))
    cols[4].metric("实体数", res.get("entity_count", 0))

    chain_types = Counter(c.chain_type for c in res["chains"])
    if chain_types:
        st.write("**检测到的攻击类型**:")
        badges = " | ".join(f"`{CHAIN_LABELS.get(ct, ct)}` ×{cnt}" for ct, cnt in chain_types.most_common())
        st.write(badges if badges else "无明确攻击类型")

    # Debug panel: show parsed records and graph edge types
    with st.expander("🔧 调试信息 — 解析记录与图边类型", expanded=False):
        records = res.get("records", [])
        if records:
            st.markdown("**解析记录 (event_type / src → dst / domain / bytes):**")
            debug_rows = []
            for i, r in enumerate(records):
                debug_rows.append({
                    "#": i+1,
                    "事件类型": r.get("event_type", "?"),
                    "源IP": str(r.get("src_ip", ""))[:18],
                    "目标IP": str(r.get("dst_ip", ""))[:22],
                    "端口": r.get("dst_port", ""),
                    "域名": str(r.get("domain", "") or "")[:25],
                    "流量": f"{r.get('bytes_out', 0) or 0 / 1e6:.1f}MB" if r.get("bytes_out") else "",
                })
            st.dataframe(pd.DataFrame(debug_rows), use_container_width=True, hide_index=True)

        gdata = res.get("graph_data", {})
        edges = gdata.get("edges", [])
        if edges:
            st.markdown(f"**图边类型分布 (共 {len(edges)} 条边):**")
            edge_type_counts = Counter(e.get("edge_type", e.get("key", "?")) for e in edges)
            et_rows = [{"边类型": et, "数量": cnt} for et, cnt in edge_type_counts.most_common()]
            st.dataframe(pd.DataFrame(et_rows), use_container_width=True, hide_index=True)

        scores = res.get("ip_scores", {})
        if scores:
            st.markdown("**IP 评分:**")
            score_rows = [{"IP": ip, "评分": f"{s:.3f}"} for ip, s in sorted(scores.items(), key=lambda x: x[1], reverse=True)]
            st.dataframe(pd.DataFrame(score_rows), use_container_width=True, hide_index=True)

    if st.button("🔄 恢复使用演示数据", key="reset_demo"):
        st.session_state.analysis_results = None
        st.session_state.data_source_name = "演示数据 (内置攻击注入)"
        st.session_state.use_demo_data = True
        st.rerun()


# ============================================================
# Page: 系统概览
# ============================================================
elif page == "📊 系统概览":
    st.header("📊 系统概览")

    # System introduction
    with st.expander("ℹ️ 关于此系统 — 点击展开", expanded=False):
        st.markdown("""
        ### 🛡️ 网络风险识别分析引擎 v2.0

        这是一个**基于无监督异常检测与稀有路径挖掘**的安全日志分析系统。

        **核心能力：**
        - 📥 **多格式日志解析** — 支持 Syslog (RFC 3164/5424)、DNS (BIND/Unbound)、WAF (Cloudflare/ModSecurity)、ETW/EVTX (Windows事件日志)
        - 🔍 **五检测器集成** — IsolationForest、ECOD、HDBSCAN、Autoencoder、GraphRarePath 五种算法并行检测异常
        - 🔗 **攻击链自动挖掘** — 从通信图中发现 C2信标、横向移动、数据外泄、DGA域名、侦察扫描等攻击模式
        - 📊 **风险评分与聚合** — 基于时间衰减的实体风险评分 + 日报聚合
        - 🕸️ **攻击溯源** — 跨窗口持久化溯源图，支持路径查询和邻域扩展
        - 🎯 **MITRE ATT&CK 映射** — 每条攻击链自动映射到 MITRE ATT&CK 战术技术

        **分析流程**：原始日志 → 解析归一化 → 31维特征提取 → 5模型异常检测 → 通信图构建 → 稀有路径挖掘 → 攻击链分类 → 风险评分 → 报告生成

        **当前页面**展示的是系统的实时运行状态和检测结果概览。
        """)

    chains, scores = DATA["chains"], list(DATA["ip_scores"].values())
    high_risk = sum(1 for s in scores if s > 0.7)

    cols = st.columns(6)
    cols[0].metric("处理事件", f"{DATA['total_events']:,}")
    cols[1].metric("异常IP (>0.7)", high_risk)
    cols[2].metric("攻击链", len(chains))
    cols[3].metric("识别实体", DATA.get("entity_count", 0))
    drift = "⚠️ 上升" if high_risk > len(scores) * 0.3 else "→ 稳定"
    cols[4].metric("风险趋势", drift)
    f1_val = DATA['eval_results'].get('f1', 0)
    cols[5].metric("F1分数", f"{f1_val:.2%}" if f1_val > 0 else "N/A")

    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("攻击链类型分布")
        ct = {}
        for c in chains:
            t = CHAIN_LABELS.get(c.chain_type, c.chain_type)
            ct[t] = ct.get(t, 0) + 1
        if ct:
            fig = px.bar(x=list(ct.keys()), y=list(ct.values()),
                         labels={"x": "攻击类型", "y": "数量"},
                         color=list(ct.values()), color_continuous_scale="Reds")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("未发现攻击链")

    with c2:
        st.subheader("IP 风险评分分布")
        if scores:
            df = pd.DataFrame({"风险评分": scores})
            fig = px.histogram(df, x="风险评分", nbins=30)
            fig.add_vline(x=0.5, line_dash="dash", line_color="orange", annotation_text="调查阈值")
            fig.add_vline(x=0.7, line_dash="dash", line_color="red", annotation_text="告警阈值")
            fig.update_layout(xaxis_range=[0, 1])
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    st.subheader("🔝 TOP 高风险攻击链")
    for c in sorted(chains, key=lambda x: x.total_risk_score, reverse=True)[:10]:
        emoji = risk_badge(c.total_risk_score)
        ctype = CHAIN_LABELS.get(c.chain_type, c.chain_type)
        with st.expander(f"{emoji} {ctype} — Risk:{c.total_risk_score:.2f} | {c.description[:60]}...",
                         expanded=(c.total_risk_score > 0.8)):
            ca, cb = st.columns(2)
            ca.write(f"**类型**: {ctype}  |  **优先级**: {c.investigation_priority}  |  **置信度**: {c.confidence:.0%}")
            ca.write(f"**Kill-Chain**: {' → '.join(c.kill_chain_phases)}")
            cb.write(f"**MITRE**: {', '.join(c.mitre_techniques[:5])}")
            cb.write("**受影响**: " + ", ".join(c.affected_assets[:8]))
            st.write("**攻击路径**: " + " → ".join(
                f"{n.entity}({ROLE_LABELS.get(n.role, n.role)})" for n in c.nodes))


# ============================================================
# Page: 攻击链详情
# ============================================================
elif page == "🔗 攻击链详情":
    st.header("🔗 攻击链详情")
    st.markdown("""
    **攻击链 (Attack Chain)** 是将孤立的异常事件串联起来形成的完整攻击路径。
    每条链展示攻击者如何从一个入口节点，通过多个跳板，最终到达攻击目标的完整过程。
    链中每个节点和边都带有**风险评分**，帮助安全分析师聚焦最危险的攻击模式。
    """)

    with st.expander("📖 攻击类型说明 — 点击展开", expanded=False):
        st.markdown("""
        | 攻击类型 | 英文名 | 说明 | 典型特征 | MITRE ATT&CK |
        |---------|--------|------|---------|-------------|
        | **C2信标** | C2 Beacon | 受害主机与C2服务器建立周期性通信信道，通过HTTP/HTTPS/DNS/ICMP等协议远程控制 | 周期性外联(55-67s间隔)、心跳包、JA3指纹、TLS加密 | T1071, T1573 |
        | **横向移动** | Lateral Movement | 攻击者通过已攻陷主机向内部网络扩散，利用跳板机访问更多目标 | SMB/RDP/WMI/DCOM/计划任务、Admin$共享、PsExec | T1021, T1078 |
        | **数据外泄** | Data Exfiltration | 敏感数据秘密传输到外部服务器，通常发生在攻击末期 | 大流量出站(GB级)、FTP/SFTP/SMTP/HTTP上传、加密传输 | T1041, T1048 |
        | **DGA活动** | DGA Activity | 恶意软件通过算法自动生成大量随机域名，用于定位C2服务器并绕过黑名单 | 高熵域名(>3.5)、大量NXDOMAIN、短域名生命周期(<3天) | T1568 |
        | **侦察扫描** | Recon Scan | 对目标网络进行大规模端口/服务扫描，收集存活主机与服务信息 | ICMP/SYN/ARP/UDP扫描、多子网探测、SNMP/LDAP枚举 | T1046, T1595 |
        | **凭据窃取** | Credential Theft | 窃取系统凭据、密码哈希、访问令牌，为横向移动和权限提升做准备 | SAM/SYSTEM/NTDS读取、LSASS内存转储、KDBX文件访问 | T1003, T1110 |
        | **暴力破解** | Brute Force | 反复尝试登录凭据，针对RDP/SSH/SMB等远程服务进行密码爆破 | 短时间多次登录失败(3+)、多用户名尝试、RDP/3389 | T1110 |
        | **反取证活动** | Anti-Forensics | 清除或篡改安全审计日志、事件日志，隐藏攻击痕迹 | 读取/删除evtx日志、audit.log访问、安全日志清除 | T1070, T1562 |
        | **持久化** | Persistence | 在受害主机上设置持久化机制，确保重启后仍能维持访问 | 启动文件夹写入、计划任务创建(schtasks)、WMI持久化 | T1053, T1547 |
        | **中间人攻击** | MITM Attack | 通过ARP欺骗、DNS投毒等手段拦截/篡改网络通信 | 免费ARP包、ARP缓存投毒、DNS响应伪造 | T1557 |
        | **工具下载** | Tool Download | 从外部下载攻击工具、后门、凭证转储器等恶意文件 | FTP/SFTP下载、wget/curl下载、BITSAdmin传输 | T1105 |
        | **内部侦察** | Internal Recon | 在已攻陷主机上收集内网信息，为横向扩散做准备 | hosts文件读取、systeminfo/whoami、net view枚举 | T1083, T1016 |
        | **可疑活动** | Suspicious Activity | 不符合已知攻击模式但风险评分较高的异常行为 | 通信模式罕见、路径稀有度高 | 待确认 |
        """)
        st.caption("每条攻击链都会自动映射到 MITRE ATT&CK 框架的战术技术编号，便于与威胁情报和合规要求对齐。覆盖 12 种攻击类型。")
    chains = DATA["chains"]
    if not chains:
        st.warning("未发现攻击链 — 当前日志数据中未检测到攻击模式。这可能意味着网络状态正常，或需要调整检测灵敏度。"); st.stop()

    c1, c2, c3 = st.columns(3)
    with c1:
        chain_types = sorted(set(c.chain_type for c in chains))
        type_filter = st.multiselect(
            "攻击类型筛选", chain_types, default=list(chain_types),
            format_func=lambda x: CHAIN_LABELS.get(x, x)
        )
    with c2:
        min_risk = st.slider("最低风险评分", 0.0, 1.0, 0.5, 0.05)
    with c3:
        sort_by = st.selectbox("排序", ["风险评分↓", "置信度↓", "事件数↓"])

    filtered = [c for c in chains if c.chain_type in type_filter and c.total_risk_score >= min_risk]
    if sort_by == "置信度↓":
        filtered.sort(key=lambda c: c.confidence, reverse=True)
    elif sort_by == "事件数↓":
        filtered.sort(key=lambda c: sum(e.event_count for e in c.edges), reverse=True)
    else:
        filtered.sort(key=lambda c: c.total_risk_score, reverse=True)

    st.caption(f"显示 {len(filtered)} / {len(chains)} 条攻击链")

    chain_map = {}
    for c in filtered[:50]:
        label = f"[{CHAIN_LABELS.get(c.chain_type, c.chain_type)}] {c.chain_id} — Risk={c.total_risk_score:.2f} — {c.description[:50]}"
        chain_map[label] = c

    if not chain_map:
        st.info("无匹配链"); st.stop()

    selected = st.selectbox("选择攻击链", list(chain_map.keys()))
    chain = chain_map[selected]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("风险评分", f"{chain.total_risk_score:.3f}")
    c2.metric("置信度", f"{chain.confidence:.0%}")
    pri = {1: "🔴 CRITICAL", 2: "🟠 HIGH", 3: "🟡 MEDIUM", 4: "🔵 LOW", 5: "⚪ INFO"}
    c3.metric("优先级", pri.get(chain.investigation_priority, "?"))
    c4.metric("类型", CHAIN_LABELS.get(chain.chain_type, chain.chain_type))

    st.markdown("---")
    st.subheader("🔫 攻击路径图")
    nodes = chain.nodes
    edges = chain.edges

    if nodes and edges:
        steps = [nodes[0]]
        for e in edges:
            dst_node = next((n for n in nodes if n.entity == e.dst), None)
            if dst_node:
                steps.append(dst_node)

        for i, step in enumerate(steps):
            n_cols = st.columns([1, 2, 3, 2, 1])
            with n_cols[1]:
                color = risk_color(step.risk_score)
                st.markdown(f"""<div style="border:2px solid {color};border-radius:10px;padding:10px;text-align:center;">
                    <div style="font-size:11px;color:#888;">{ROLE_LABELS.get(step.role, step.role)}</div>
                    <div style="font-weight:bold;font-size:16px;">{step.entity}</div>
                    <div style="font-size:12px;color:{color};">风险: {step.risk_score:.3f}</div></div>""",
                    unsafe_allow_html=True)

            if i < len(edges):
                with n_cols[2]:
                    e = edges[i]
                    etype = EVENT_LABELS.get(e.edge_type, e.edge_type)
                    ac = "#ff6666" if e.anomalous_score > 0.5 else "#888888"
                    st.markdown(f"""<div style="text-align:center;padding-top:20px;">
                        <span style="font-size:28px;color:{ac};">→</span><br>
                        <span style="background:#333;color:white;padding:2px 8px;border-radius:4px;font-size:11px;">{etype}</span><br>
                        <span style="font-size:10px;color:#888;">{e.event_count}次</span></div>""",
                        unsafe_allow_html=True)

    st.markdown("---")
    tab_a, tab_b, tab_c = st.tabs(["📋 详细数据", "🎯 MITRE ATT&CK", "📝 攻击叙事"])

    with tab_a:
        ndf = pd.DataFrame([{
            "角色": ROLE_LABELS.get(n.role, n.role), "实体": n.entity,
            "类型": n.entity_type, "风险": f"{n.risk_score:.3f}",
        } for n in nodes])
        st.dataframe(ndf, use_container_width=True, hide_index=True)

        edf = pd.DataFrame([{
            "源": e.src, "目标": e.dst, "事件类型": EVENT_LABELS.get(e.edge_type, e.edge_type),
            "次数": e.event_count, "异常评分": f"{e.anomalous_score:.3f}",
        } for e in edges])
        st.dataframe(edf, use_container_width=True, hide_index=True)

    with tab_b:
        for tech in chain.mitre_techniques[:10]:
            name, desc = MITRE_INFO.get(tech, ("", ""))
            st.markdown(f"#### {tech} — {name}")
            st.caption(desc)

    with tab_c:
        ctype = CHAIN_LABELS.get(chain.chain_type, chain.chain_type)
        if nodes and edges:
            story = []
            for i, n in enumerate(nodes):
                role = ROLE_LABELS.get(n.role, n.role)
                if n.role == "source":
                    story.append(f"攻击者从 **{n.entity}** 开始活动")
                elif n.role == "pivot" and i > 0:
                    e = edges[i-1]
                    story.append(f"通过 **{EVENT_LABELS.get(e.edge_type, e.edge_type)}** 连接到跳板机 **{n.entity}**")
                elif n.role == "target" and i > 0:
                    e = edges[i-1]
                    story.append(f"通过 **{EVENT_LABELS.get(e.edge_type, e.edge_type)}** 到达目标 **{n.entity}**")
            st.markdown(f"> {'，随后'.join(story)}。")
            st.markdown(f"**类型**: {ctype} | **风险**: {chain.total_risk_score:.2f} | **置信度**: {chain.confidence:.0%}")


# ============================================================
# Page: 实体风险
# ============================================================
elif page == "👤 实体风险":
    st.header("👤 实体风险评估")

    with st.expander("📖 风险评分说明 — 点击展开", expanded=False):
        st.markdown("""
        ### 风险评分是如何计算的？
        每个实体（IP地址）的风险评分 **综合了多个维度的异常信号**：

        1. **异常检测器输出** (权重最高) — 5个检测器（IsolationForest、ECOD、HDBSCAN、Autoencoder、GraphRarePath）并行分析31维特征向量，通过Rank Aggregation聚合各检测器的排序结果
        2. **关联攻击链** — 如果该实体出现在攻击链中（作为攻击源、跳板或目标），风险评分会相应提升。关联链越多、角色越关键，风险越高
        3. **通信模式稀有度** — 与该实体相关的通信路径在全局中的稀有程度，稀有路径通常意味着异常行为
        4. **时间衰减** — 最近的异常事件权重更高，旧事件的影响随时间指数衰减（半衰期24小时）

        **评分阈值：**
        - 🔴 **> 0.7 高风险** — 需要立即调查，该实体极可能参与攻击活动
        - 🟠 **0.4-0.7 中风险** — 需要持续关注，存在可疑行为但不确认为恶意
        - 🟢 **< 0.4 低风险** — 可以暂时忽略，属于正常通信范围

        **关联攻击链** 表示该实体出现在哪些攻击链中。一个实体可能同时出现在多条攻击链中（例如既是C2信标的受害者，又是横向移动的跳板），这表示该实体的安全威胁更加严重。
        """)
    entities = DATA["top_entities"]
    search = st.text_input("🔍 搜索实体", placeholder="输入IP地址...")
    min_score = st.slider("最低风险评分", 0.0, 1.0, 0.0, 0.05)

    filtered = [e for e in entities if e["risk_score"] >= min_score]
    if search:
        filtered = [e for e in filtered if search.lower() in e.get("entity_id", "").lower()]

    if not filtered:
        st.warning("无匹配实体"); st.stop()

    st.subheader(f"风险排名 (共 {len(filtered)} 个)")
    for i, e in enumerate(filtered[:50]):
        emoji = risk_badge(e["risk_score"])
        risk_text = "高风险" if e["risk_score"] > 0.7 else ("中风险" if e["risk_score"] > 0.4 else "低风险")
        with st.expander(f"{emoji} #{i+1} {e['entity_id']} | {risk_text} | {e['risk_score']:.3f}", expanded=(i < 5)):
            ca, cb, cc, cd = st.columns(4)
            ca.metric("风险评分", f"{e['risk_score']:.3f}")
            cb.metric("趋势", e.get("risk_trend", "?"))
            cc.metric("证据数", e.get("evidence_count", 0))
            cd.metric("关联链数", len(e.get("chains", [])))

            rc = risk_color(e["risk_score"])
            st.markdown(f'<progress value="{e["risk_score"]}" max="1" style="width:100%;height:16px;accent-color:{rc};"></progress>',
                        unsafe_allow_html=True)
            if e.get("tags"):
                tag_labels = {
                    "c2_beacon": "C2信标", "lateral_movement": "横向移动", "data_exfil": "数据外泄",
                    "dga_activity": "DGA活动", "recon_scan": "侦察扫描",
                }
                tag_display = [f"`{tag_labels.get(t, t)}`" for t in e["tags"]]
                st.write("**🏷️ 标签**:", ", ".join(tag_display))
            if e.get("chains"):
                chain_display = []
                for cid in e["chains"][:8]:
                    matching = [c for c in DATA["chains"] if c.chain_id == cid]
                    if matching:
                        c = matching[0]
                        ctype = CHAIN_LABELS.get(c.chain_type, c.chain_type)
                        chain_display.append(f"[{cid}] {ctype} (Risk:{c.total_risk_score:.2f})")
                    else:
                        chain_display.append(cid)
                st.write("**🔗 关联攻击链** (该实体参与的攻击路径):")
                for cd_item in chain_display:
                    st.markdown(f"- {cd_item}")
                st.caption("关联攻击链说明: 实体作为「攻击源」表示它发起了攻击，作为「跳板」表示攻击者利用它横向移动，作为「目标」表示它是攻击的最终受害者。")

            if st.button(f"🔍 查看通信关系", key=f"trace_{i}"):
                ip = e["entity_id"]
                edge_summary = DATA.get("edge_summary", {})
                ip_conns = []
                for (src, dst), recs in edge_summary.items():
                    if src == ip or dst == ip:
                        direction = "出站→" if src == ip else "入站←"
                        peer = dst if src == ip else src
                        event_types = defaultdict(int)
                        for r in recs:
                            event_types[EVENT_LABELS.get(r.get("event_type", "?"), r.get("event_type", "?"))] += 1
                        ip_conns.append({"direction": direction, "peer": peer, "events": dict(event_types), "total": len(recs)})
                if ip_conns:
                    for conn in sorted(ip_conns, key=lambda x: x["total"], reverse=True)[:20]:
                        d = "📤" if "出站" in conn["direction"] else "📥"
                        ev = "、".join(f"{k}×{v}" for k, v in conn["events"].items())
                        st.markdown(f"{d} {conn['direction']} **{conn['peer']}** ({conn['total']}次) <small>{ev}</small>", unsafe_allow_html=True)
                else:
                    st.info("无通信记录")

    if len(filtered) > 1:
        st.markdown("---")
        st.subheader("实体风险排名")
        df = pd.DataFrame([{"实体": e["entity_id"], "风险评分": e["risk_score"]} for e in filtered[:20]])
        fig = px.bar(df, x="实体", y="风险评分", color="风险评分", color_continuous_scale="RdYlGn_r")
        st.plotly_chart(fig, use_container_width=True)


# ============================================================
# Page: 溯源追踪
# ============================================================
elif page == "🕸️ 溯源追踪":
    st.header("🕸️ 溯源追踪 — 攻击路径回放")
    st.markdown("""
    **溯源追踪** 帮助你理解攻击是如何发生的。通过**通信网络图**可以直观看到哪些IP之间存在异常通信，
    通过**攻击链路径**可以追踪攻击者从入口到目标的每一步。
    还可以自定义查询任意两个 IP 之间的连接路径，用于手动溯源分析。
    - **节点大小** = 风险评分 (越大越危险)
    - **边颜色** = 关联风险 (越红越可疑)
    - **边粗细** = 通信频次 (越粗通信越多)
    """)
    chains = DATA["chains"]
    edge_summary = DATA.get("edge_summary", {})

    trace_tab1, trace_tab2 = st.tabs(["🔗 攻击链路径", "🕸️ 网络图分析"])

    with trace_tab1:
        if not chains:
            st.info("未发现攻击链")
        else:
            for c in sorted(chains, key=lambda x: x.total_risk_score, reverse=True)[:15]:
                ctype = CHAIN_LABELS.get(c.chain_type, c.chain_type)
                cn = c.nodes
                ce = c.edges
                if cn:
                    with st.expander(f"{risk_badge(c.total_risk_score)} {ctype} — {' → '.join(n.entity for n in cn[:5])} — Risk:{c.total_risk_score:.2f}",
                                     expanded=(c.total_risk_score > 0.8)):
                        for i, n in enumerate(cn):
                            cols = st.columns([3, 1, 3])
                            with cols[0]:
                                bg = f"{risk_color(n.risk_score)}20"
                                st.markdown(f"""<div style="border:2px solid #888;border-radius:8px;padding:8px;background:{bg};">
                                    <strong>{n.entity}</strong><br><small>{ROLE_LABELS.get(n.role, n.role)} | 风险: {n.risk_score:.3f}</small></div>""",
                                    unsafe_allow_html=True)
                            if i < len(ce):
                                with cols[1]:
                                    e = ce[i]
                                    etype = EVENT_LABELS.get(e.edge_type, e.edge_type)
                                    st.markdown(f"""<div style="text-align:center;font-size:24px;padding-top:12px;">→</div>
                                        <div style="text-align:center;background:#444;color:white;border-radius:4px;padding:2px 6px;font-size:11px;">{etype}</div>
                                        <div style="text-align:center;font-size:9px;color:#888;">{e.event_count}次</div>""",
                                        unsafe_allow_html=True)
                                with cols[2]:
                                    if i + 1 < len(cn):
                                        nn = cn[i+1]
                                        st.markdown(f"""<div style="border:2px solid #888;border-radius:8px;padding:8px;background:{risk_color(nn.risk_score)}20;">
                                            <strong>{nn.entity}</strong><br><small>{ROLE_LABELS.get(nn.role, nn.role)} | 风险: {nn.risk_score:.3f}</small></div>""",
                                            unsafe_allow_html=True)
                        st.markdown("---")

    with trace_tab2:
        st.subheader("通信网络图")
        high_risk_ips = {ip for ip, s in DATA["ip_scores"].items() if s > 0.3}
        if len(high_risk_ips) < 2:
            high_risk_ips = set(list(DATA["ip_scores"].keys())[:30])

        G_plot = nx.DiGraph()
        for (src, dst), recs in edge_summary.items():
            if src in high_risk_ips or dst in high_risk_ips:
                risk = DATA["ip_scores"].get(src, 0) + DATA["ip_scores"].get(dst, 0)
                event_types = set(r.get("event_type", "?") for r in recs)
                G_plot.add_edge(src, dst, weight=len(recs), risk=risk, etypes=", ".join(event_types))

        if G_plot.number_of_nodes() > 0:
            pos = nx.spring_layout(G_plot, k=2, iterations=50, seed=42)
            edge_traces = []
            for u, v, d in G_plot.edges(data=True):
                x0, y0 = pos[u]; x1, y1 = pos[v]
                r = d.get("risk", 0.5)
                red = max(0, min(255, 150 + int(r * 105)))
                green = max(0, min(255, 100 - int(r * 100)))
                edge_traces.append(go.Scatter(
                    x=[x0, x1, None], y=[y0, y1, None], mode="lines",
                    line=dict(width=max(0.5, np.log1p(d.get("weight", 1))),
                              color=f"rgba({red},{green},100,0.6)"),
                    hoverinfo="text",
                    text=f"{u} → {v}<br>事件: {d.get('etypes', '?')}<br>次数: {d.get('weight', 0)}<br>风险: {d.get('risk', 0):.2f}",
                    showlegend=False,
                ))

            node_x, node_y, node_text, node_size, node_color = [], [], [], [], []
            for node in G_plot.nodes():
                x, y = pos[node]
                node_x.append(x); node_y.append(y)
                risk = DATA["ip_scores"].get(node, 0)
                node_text.append(f"{node}<br>风险: {risk:.3f}")
                node_size.append(8 + risk * 40)
                node_color.append(risk)

            node_trace = go.Scatter(
                x=node_x, y=node_y, mode="markers+text",
                text=list(G_plot.nodes()), textposition="top center", textfont=dict(size=9),
                marker=dict(size=node_size, color=node_color, colorscale="RdYlGn_r",
                            showscale=True, colorbar=dict(title="风险评分"), line=dict(width=1, color="#888")),
                hovertext=node_text, hoverinfo="text", showlegend=False,
            )
            fig = go.Figure(data=edge_traces + [node_trace])
            fig.update_layout(title=f"通信网络 ({G_plot.number_of_nodes()}节点, {G_plot.number_of_edges()}边)",
                              hovermode="closest", margin=dict(b=20, l=20, r=20, t=40),
                              xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                              yaxis=dict(showgrid=False, zeroline=False, showticklabels=False), height=600)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("数据不足以构建网络图")

    # Query tool
    st.markdown("---")
    st.subheader("🔍 自定义溯源查询")
    all_ips = sorted(set(DATA["ip_scores"].keys()))
    if len(all_ips) >= 2:
        c1, c2, c3 = st.columns([2, 2, 1])
        with c1: src_ip = st.selectbox("源 IP", all_ips, key="q_src")
        with c2: dst_ip = st.selectbox("目标 IP", [ip for ip in all_ips if ip != src_ip], key="q_dst")
        with c3:
            st.write(""); st.write("")
            if st.button("🔍 查询", type="primary"):
                st.markdown(f"### {src_ip} ↔ {dst_ip}")
                G = nx.MultiDiGraph()
                for (s, d), recs in edge_summary.items():
                    G.add_edge(s, d, records=recs)
                found = False
                for key in [(src_ip, dst_ip), (dst_ip, src_ip)]:
                    if key in edge_summary:
                        recs = edge_summary[key]
                        direction = f"{key[0]} → {key[1]}"
                        st.success(f"✅ 直接连接: {direction} ({len(recs)}次)")
                        show_connection_detail(recs, key[0], key[1])
                        found = True
                if not found:
                    try:
                        path = nx.shortest_path(G, source=src_ip, target=dst_ip)
                        st.success(f"🔗 多跳路径 ({len(path)-1}跳): {' → '.join(path)}")
                        for i in range(len(path)-1):
                            pair = (path[i], path[i+1])
                            if pair in edge_summary:
                                st.markdown(f"**第{i+1}跳**: {path[i]} → {path[i+1]}")
                                show_connection_detail(edge_summary[pair], path[i], path[i+1])
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        st.warning("未找到连接路径")


# ============================================================
# Page: 检测评估
# ============================================================
elif page == "📈 检测评估":
    st.header("📈 检测性能评估")
    st.markdown("""
    **检测评估** 用于衡量系统的检测效果。通过向日志中注入已知的模拟攻击（作为"标准答案"），
    对比系统输出的攻击链，计算以下核心指标：
    - **精确率 (Precision)**: 检测到的攻击链中，真正是攻击的比例。越高说明误报越少。
    - **召回率 (Recall)**: 所有真实攻击中，被系统检测到的比例。越高说明漏报越少。
    - **F1分数**: 精确率与召回率的调和平均，综合衡量检测效果。
    - **TP/FP/FN**: 真阳性（正确检测）/ 假阳性（误报）/ 假阴性（漏报）。
    """)
    eval_r = DATA["eval_results"]

    cols = st.columns(4)
    cols[0].metric("Precision", f"{eval_r['precision']:.2%}")
    cols[1].metric("Recall", f"{eval_r['recall']:.2%}")
    cols[2].metric("F1 Score", f"{eval_r['f1']:.2%}" if eval_r['f1'] > 0 else "N/A")
    cols[3].metric("注入攻击", eval_r.get("total_injected", 0))
    c2 = st.columns(3)
    c2[0].metric("TP", eval_r["true_positives"])
    c2[1].metric("FP", eval_r["false_positives"])
    c2[2].metric("FN", eval_r["false_negatives"])

    st.markdown("---")
    st.subheader("按攻击类型指标")
    per_type = eval_r.get("per_type", {})
    if per_type:
        rows = []
        for atype, m in sorted(per_type.items()):
            p = m.get("precision", 0); r = m.get("recall", 0)
            rows.append({
                "类型": CHAIN_LABELS.get(atype, atype),
                "Precision": f"{p:.2%}", "Recall": f"{r:.2%}",
                "F1": f"{2*p*r/max(p+r,1e-10):.2%}",
                "注入": m.get("injected", 0), "检测": m.get("detected", 0), "匹配": m.get("matched", 0),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        fig = go.Figure()
        types_list = [r["类型"] for r in rows]
        fig.add_trace(go.Bar(name="Precision", x=types_list, y=[float(r["Precision"].strip("%"))/100 for r in rows]))
        fig.add_trace(go.Bar(name="Recall", x=types_list, y=[float(r["Recall"].strip("%"))/100 for r in rows]))
        fig.update_layout(barmode="group", yaxis_tickformat=".0%", title="各类型 Precision / Recall")
        st.plotly_chart(fig, use_container_width=True)

    # DGA
    dga_hits = [r for r in DATA.get("dga_results", []) if r.get("is_dga")]
    if dga_hits:
        st.markdown("---")
        st.subheader(f"🦠 DGA检测 ({len(dga_hits)}个疑似域名)")
        st.dataframe(pd.DataFrame(sorted(dga_hits, key=lambda x: x["score"], reverse=True)[:20]),
                     use_container_width=True, hide_index=True)

    # FP/FN analysis
    injected = DATA.get("injected_attacks", [])
    if injected and eval_r["total_detected"] > 0:
        st.markdown("---")
        st.subheader("📊 误报与漏报分析")

        # Debug: show entity overlap for each injected attack
        with st.expander("🔍 攻击匹配详情", expanded=True):
            for atk in injected:
                gt_entities = set(atk.entities)
                best_chains = []
                for dc in DATA["chains"]:
                    dc_entities = {n.entity for n in dc.nodes}
                    overlap = len(gt_entities & dc_entities) / max(len(gt_entities), 1)
                    if overlap > 0:
                        best_chains.append((overlap, dc))
                best_chains.sort(key=lambda x: -x[0])
                cname = CHAIN_LABELS.get(atk.attack_type, atk.attack_type)
                if best_chains:
                    best_overlap, best_chain = best_chains[0]
                    chain_entities = sorted({n.entity for n in best_chain.nodes})
                    match_ok = "✅" if best_overlap >= 0.6 else ("⚠️" if best_overlap > 0 else "❌")
                    st.markdown(
                        f"{match_ok} **{cname}**: {', '.join(atk.entities)} | "
                        f"最佳: [{CHAIN_LABELS.get(best_chain.chain_type, best_chain.chain_type)}] "
                        f"overlap={best_overlap:.2f} | "
                        f"entities={chain_entities}"
                    )
                else:
                    st.markdown(f"❌ **{cname}**: {', '.join(atk.entities)} | 无任何链包含这些实体")

        matched_types = set()
        for atype, m in per_type.items():
            if m.get("matched", 0) > 0:
                matched_types.add(atype)
        missed = [atk for atk in injected if atk.attack_type not in matched_types]
        if missed:
            st.warning(f"**漏报**: {len(missed)}个攻击未被检测")
            for m in missed:
                st.markdown(f"- {CHAIN_LABELS.get(m.attack_type, m.attack_type)}: {', '.join(m.entities[:5])}")
        else:
            st.success("✅ 所有注入攻击类型均被检测")
        fp_types = [(t, m) for t, m in per_type.items() if m.get("detected", 0) > m.get("matched", 0)]
        if fp_types:
            st.info("**误报分析**:")
            for t, m in fp_types:
                st.markdown(f"- **{CHAIN_LABELS.get(t, t)}**: {m.get('detected', 0) - m.get('matched', 0)}条假阳性 "
                           f"(Precision={m.get('precision', 0):.1%})")


# ============================================================
# Page: 综合分析报告
# ============================================================
elif page == "📋 综合分析报告":
    st.header("📋 综合安全分析报告")
    st.caption(f"生成: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 数据源: {st.session_state.get('data_source_name', '?')}")

    chains = DATA["chains"]
    ip_scores = DATA["ip_scores"]
    high_risk = sum(1 for s in ip_scores.values() if s > 0.7)
    critical = sum(1 for s in ip_scores.values() if s > 0.9)

    # Executive Summary
    st.markdown("---")
    st.subheader("📌 执行摘要")
    cols = st.columns(4)
    cols[0].metric("处理事件", f"{DATA['total_events']:,}")
    cols[1].metric("攻击链", len(chains))
    cols[2].metric("高风险IP", high_risk)
    cols[3].metric("严重风险IP", critical)

    chain_types = Counter(c.chain_type for c in chains)
    if chain_types:
        st.write("**攻击类型分布**:")
        tc = st.columns(min(len(chain_types), 5))
        for i, (ct, cnt) in enumerate(chain_types.most_common(5)):
            with tc[i]:
                st.metric(CHAIN_LABELS.get(ct, ct), cnt)

    # Risk Aggregation
    st.markdown("---")
    st.subheader("📊 风险聚合")
    rtab1, rtab2 = st.tabs(["评分趋势", "溯源线索"])

    with rtab1:
        if ip_scores:
            scores_sorted = sorted(ip_scores.values(), reverse=True)
            fig = go.Figure()
            fig.add_trace(go.Scatter(y=scores_sorted, mode="lines+markers", name="风险评分", line=dict(color="red")))
            fig.add_hline(y=0.7, line_dash="dash", line_color="orange", annotation_text="告警 0.7")
            fig.add_hline(y=0.9, line_dash="dash", line_color="red", annotation_text="严重 0.9")
            fig.update_layout(title="IP风险评分排名", xaxis_title="IP排名", yaxis_title="风险评分", yaxis=dict(range=[0, 1]))
            st.plotly_chart(fig, use_container_width=True)

        internal = [ip for ip in ip_scores if ip.startswith(("10.", "192.168.", "172.16."))]
        external = [ip for ip in ip_scores if not ip.startswith(("10.", "192.168.", "172.16."))]
        ic1, ic2 = st.columns(2)
        ic1.metric("内网IP (高风险)", f"{len(internal)} ({sum(1 for ip in internal if ip_scores[ip] > 0.5)})")
        ic2.metric("外网IP (高风险)", f"{len(external)} ({sum(1 for ip in external if ip_scores[ip] > 0.5)})")

    with rtab2:
        for i, c in enumerate(sorted(chains, key=lambda x: x.total_risk_score, reverse=True)[:10]):
            with st.expander(f"线索#{i+1}: {CHAIN_LABELS.get(c.chain_type, c.chain_type)} — Risk:{c.total_risk_score:.2f}"):
                for n in c.nodes:
                    st.markdown(f"🔹 **{n.entity}** ({ROLE_LABELS.get(n.role, n.role)}): 异常 {n.risk_score:.3f}")
                for e in c.edges:
                    st.markdown(f"🔸 {e.src} → {e.dst}: **{EVENT_LABELS.get(e.edge_type, e.edge_type)}** "
                               f"({e.event_count}次, 异常{e.anomalous_score:.3f})")
                if c.mitre_techniques:
                    st.markdown("**🎯 MITRE**: " + ", ".join(f"{t}({MITRE_INFO.get(t, ('',''))[0]})" for t in c.mitre_techniques[:5]))
                actions = {
                    "c2_beacon": "阻断源IP出站流量，检查定期信标模式",
                    "lateral_movement": "隔离跳板主机，检查认证日志并重置凭据",
                    "data_exfil": "阻断出站大流量传输，审查目标IP历史",
                    "dga_activity": "封禁DGA域名，扫描源主机排查恶意软件",
                    "suspicious_activity": "人工审查相关实体通信模式",
                }
                st.info(f"**建议**: {actions.get(c.chain_type, '调查所有涉及实体')}")
                st.write(f"**受影响**: {', '.join(c.affected_assets[:10])}")

    # Attack Scenario Analysis
    st.markdown("---")
    st.subheader("🎯 典型攻击场景识别分析")

    scenarios = {
        "c2_beacon": {
            "name": "C2 信标检测", "method": "时间自相关 + 稀有外部连接",
            "desc": "受害主机与C2服务器建立周期性通信信道。检测方法：通信间隔规律性 + 目标IP稀有度 + DNS查询模式。常见误报：定期API调用、CDN回源。"
        },
        "lateral_movement": {
            "name": "横向移动检测", "method": "认证图模式匹配 (Auth→Pivot→Connect)",
            "desc": "攻击者通过已攻陷主机向内部扩散。检测方法：认证来源异常 + 跳板主机通信模式。常见误报：运维脚本、监控探针。"
        },
        "data_exfil": {
            "name": "数据外泄检测", "method": "出站流量异常 + 稀有目标IP",
            "desc": "敏感数据被传输到外部。检测方法：出站流量突变 + 罕见外部目标 + 非标准端口。常见误报：云备份、合法API调用。"
        },
        "dga_activity": {
            "name": "DGA 域名检测", "method": "域名熵值 + N-gram统计",
            "desc": "恶意软件通过算法生成域名用于C2通信。检测方法：高熵域名 + NXDOMAIN率 + 域名长度异常。常见误报：CDN子域名。"
        },
        "recon_scan": {
            "name": "侦察扫描检测", "method": "目标多样性 + 端口扫描模式",
            "desc": "攻击者扫描目标网络发现开放端口。检测方法：短时大量不同目标 + 非标准端口 + SYN包特征。常见误报：资产扫描、P2P。"
        },
    }

    per_type = DATA["eval_results"].get("per_type", {})
    for atype, info in scenarios.items():
        m = per_type.get(atype, {"precision": 0, "recall": 0, "detected": 0, "matched": 0})
        matched = m.get("matched", 0)
        with st.expander(f"{'✅' if matched > 0 else '❌'} {info['name']} — "
                         f"P={m.get('precision', 0):.1%} R={m.get('recall', 0):.1%} "
                         f"检出:{m.get('detected', 0)} 匹配:{matched}",
                         expanded=(matched > 0)):
            st.markdown(f"**检测方法**: {info['method']}")
            st.markdown(info['desc'])
            c1, c2, c3 = st.columns(3)
            p = m.get("precision", 0); r = m.get("recall", 0)
            c1.metric("精确率", f"{p:.1%}"); c2.metric("召回率", f"{r:.1%}")
            c3.metric("F1", f"{2*p*r/max(p+r,1e-10):.1%}")
            related = [c for c in chains if c.chain_type == atype][:3]
            if related:
                st.write("**关联链**:")
                for rc in related:
                    st.markdown(f"- [{rc.chain_id}] {' → '.join(n.entity for n in rc.nodes[:4])} (Risk:{rc.total_risk_score:.2f})")

    # Summary
    st.markdown("---")
    st.subheader("📝 总结与建议")
    eval_r = DATA["eval_results"]
    points = []
    if len(chains) == 0:
        points.append("🔵 未发现攻击链")
    else:
        points.append(f"🔴 发现 **{len(chains)}** 条疑似攻击链，涉及 {len(ip_scores)} 个IP")
        if critical > 0:
            points.append(f"🚨 **{critical}** 个IP严重风险 (>0.9)，需立即处置")
        for atype, m in sorted(per_type.items()):
            if m.get("matched", 0) > 0:
                points.append(f"✅ **{CHAIN_LABELS.get(atype, atype)}**: {m.get('matched', 0)}/{m.get('injected', 1)} (P={m.get('precision', 0):.0%})")
    if eval_r.get("precision", 0) < 0.5 and eval_r.get("total_injected", 0) > 0:
        points.append(f"⚠️ 精确率偏低 ({eval_r['precision']:.0%})，建议调整检测阈值或增加上下文特征")
    for pt in points:
        st.markdown(f"- {pt}")

    # Export
    st.markdown("---")
    st.subheader("📥 下载报告")

    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {"events": DATA["total_events"], "chains": len(chains), "high_risk": high_risk, "critical": critical},
        "evaluation": {"precision": eval_r.get("precision"), "recall": eval_r.get("recall"), "f1": eval_r.get("f1")},
        "chains": [{
            "id": c.chain_id, "type": c.chain_type, "risk": c.total_risk_score,
            "nodes": [{"entity": n.entity, "role": n.role, "risk": n.risk_score} for n in c.nodes],
            "edges": [{"src": e.src, "dst": e.dst, "type": e.edge_type} for e in c.edges],
            "mitre": c.mitre_techniques,
        } for c in sorted(chains, key=lambda x: x.total_risk_score, reverse=True)[:20]],
    }

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        # PDF Report
        try:
            pdf_bytes = _generate_pdf_report(DATA, chains, ip_scores, high_risk, critical, eval_r, per_type)
            st.download_button(
                "📄 下载报告 (PDF)",
                pdf_bytes,
                f"风险分析报告_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                "application/pdf",
                key="pdf_download",
            )
        except Exception as pdf_err:
            st.warning(f"PDF生成失败: {pdf_err}。请使用JSON格式下载。")
    with col_btn2:
        st.download_button(
            "📋 下载报告 (JSON)",
            json.dumps(report, indent=2, ensure_ascii=False, default=str),
            f"risk_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "application/json",
            key="json_download",
        )
