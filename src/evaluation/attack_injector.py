"""Synthetic attack injection for evaluation.

Injects known attack patterns into clean log data to create ground truth
for measuring detection recall and precision.
"""

import math
import random
import uuid
from datetime import datetime, timezone, timedelta

from src.core.types import InjectedAttack


class AttackInjector:
    """Injects synthetic attack traces into normalized log records."""

    def __init__(self, base_timestamp: int = None):
        if base_timestamp is None:
            base_timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)
        self.base_ts = base_timestamp
        self.injected_attacks: list[InjectedAttack] = []

    def inject_c2_beacon(self, victim_ip: str, c2_ip: str, interval_sec: int = 300,
                          duration_hours: int = 24, jitter: float = 0.1) -> list[dict]:
        """Generate periodic HTTP GET requests to C2 server with jitter."""
        records = []
        attack_id = str(uuid.uuid4())[:8]
        start_time = self.base_ts
        end_time = start_time + duration_hours * 3600000

        num_beacons = (duration_hours * 3600) // interval_sec
        for i in range(int(num_beacons)):
            ts = start_time + i * interval_sec * 1000
            # Add jitter
            if jitter > 0:
                ts += int(random.uniform(-jitter, jitter) * interval_sec * 1000)

            records.append({
                "src_ip": victim_ip,
                "dst_ip": c2_ip,
                "dst_port": 443,
                "proto": "TCP",
                "event_type": "network_connect",
                "timestamp": ts,
                "bytes_out": random.randint(100, 5000),
                "bytes_in": random.randint(50, 2000),
                "tags": ["injected:c2_beacon"],
            })

        self.injected_attacks.append(InjectedAttack(
            attack_id=attack_id, attack_type="c2_beacon",
            entities=[victim_ip, c2_ip],
            start_time=start_time, end_time=end_time,
            params={"interval_sec": interval_sec, "jitter": jitter},
        ))
        return records

    def inject_lateral_movement(self, entry_host: str, target_host: str,
                                 pivot_hosts: list[str]) -> list[dict]:
        """Generate lateral movement: entry -> pivot(s) -> target."""
        records = []
        attack_id = str(uuid.uuid4())[:8]
        start_time = self.base_ts

        all_hosts = [entry_host] + pivot_hosts + [target_host]
        ts = start_time

        for i in range(len(all_hosts) - 1):
            src = all_hosts[i]
            dst = all_hosts[i + 1]

            # Unusual auth (off-hours, new user)
            records.append({
                "src_ip": src,
                "dst_ip": dst,
                "src_port": random.randint(40000, 60000),
                "dst_port": 445,
                "proto": "TCP",
                "event_type": "auth_success",
                "timestamp": ts,
                "user": "admin",
                "tags": ["injected:lateral_movement"],
            })

            ts += random.randint(10000, 60000)

            # Suspicious network connection
            records.append({
                "src_ip": src,
                "dst_ip": dst,
                "dst_port": random.choice([445, 3389, 5985, 22]),
                "proto": "TCP",
                "event_type": "network_connect",
                "timestamp": ts,
                "bytes_out": random.randint(1000, 10000),
                "tags": ["injected:lateral_movement"],
            })

            ts += random.randint(60000, 300000)

        end_time = ts
        self.injected_attacks.append(InjectedAttack(
            attack_id=attack_id, attack_type="lateral_movement",
            entities=all_hosts,
            start_time=start_time, end_time=end_time,
            params={"hops": len(pivot_hosts) + 1},
        ))
        return records

    def inject_data_exfil(self, victim_ip: str, exfil_ip: str,
                           num_connections: int = 50, volume_total: int = 10_000_000) -> list[dict]:
        """Generate large outbound transfers to a rare external IP."""
        records = []
        attack_id = str(uuid.uuid4())[:8]
        start_time = self.base_ts

        ts = start_time
        for i in range(num_connections):
            ts += random.randint(1000, 5000)
            volume_per_conn = volume_total // num_connections + random.randint(-1000, 1000)
            records.append({
                "src_ip": victim_ip,
                "dst_ip": exfil_ip,
                "dst_port": random.choice([443, 8443, 8080]),
                "proto": "TCP",
                "event_type": "network_connect",
                "timestamp": ts,
                "bytes_out": max(volume_per_conn, 100),
                "bytes_in": random.randint(10, 100),
                "tags": ["injected:data_exfil"],
            })

        end_time = ts
        self.injected_attacks.append(InjectedAttack(
            attack_id=attack_id, attack_type="data_exfil",
            entities=[victim_ip, exfil_ip],
            start_time=start_time, end_time=end_time,
            params={"connections": num_connections, "total_bytes": volume_total},
        ))
        return records

    def inject_dga(self, victim_ip: str, num_domains: int = 200) -> list[dict]:
        """Generate DNS queries for algorithmically generated domains."""
        records = []
        attack_id = str(uuid.uuid4())[:8]
        start_time = self.base_ts
        ts = start_time

        tlds = [".com", ".xyz", ".top", ".info", ".net", ".biz"]
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels = "aeiou"

        for i in range(num_domains):
            # Generate DGA-like domain
            length = random.randint(8, 16)
            domain_chars = []
            for j in range(length):
                if j % 3 == 0:
                    domain_chars.append(random.choice(consonants))
                else:
                    domain_chars.append(random.choice(vowels))
            domain = "".join(domain_chars) + random.choice(tlds)

            ts += random.randint(100, 3000)
            records.append({
                "src_ip": victim_ip,
                "dst_ip": "8.8.8.8",
                "dst_port": 53,
                "proto": "DNS",
                "event_type": "dns_query",
                "timestamp": ts,
                "domain": domain,
                "dns_rcode": "NXDOMAIN" if random.random() < 0.6 else "NOERROR",
                "tags": ["injected:dga"],
            })

        end_time = ts
        self.injected_attacks.append(InjectedAttack(
            attack_id=attack_id, attack_type="dga_activity",
            entities=[victim_ip],
            start_time=start_time, end_time=end_time,
            params={"num_domains": num_domains},
        ))
        return records

    def inject_port_scan(self, scanner_ip: str, target_subnet: str,
                          num_targets: int = 100) -> list[dict]:
        """Generate port scan traffic."""
        records = []
        attack_id = str(uuid.uuid4())[:8]
        start_time = self.base_ts
        ts = start_time

        # Parse subnet base
        base_ip_parts = target_subnet.split("/")[0].split(".")
        base = ".".join(base_ip_parts[:3]) + "."

        common_ports = [22, 80, 443, 445, 3389, 8080, 8443, 3306, 5432, 6379]

        for i in range(num_targets):
            target = f"{base}{random.randint(1, 254)}"
            for port in random.sample(common_ports, min(5, len(common_ports))):
                ts += random.randint(10, 500)
                records.append({
                    "src_ip": scanner_ip,
                    "dst_ip": target,
                    "dst_port": port,
                    "proto": "TCP",
                    "event_type": "network_connect",
                    "timestamp": ts,
                    "bytes_out": 0,
                    "tags": ["injected:port_scan"],
                })

        end_time = ts
        self.injected_attacks.append(InjectedAttack(
            attack_id=attack_id, attack_type="recon_scan",
            entities=[scanner_ip],
            start_time=start_time, end_time=end_time,
            params={"targets": num_targets, "subnet": target_subnet},
        ))
        return records

    def inject_ransomware(self, victim_ip: str, c2_ip: str,
                           num_files: int = 1000) -> list[dict]:
        """Generate ransomware-like: mass file writes + deletion + beaconing."""
        records = []
        attack_id = str(uuid.uuid4())[:8]
        start_time = self.base_ts
        ts = start_time

        # Mass file writes
        for i in range(num_files):
            ts += random.randint(10, 100)
            ext = random.choice([".encrypted", ".locked", ".crypt", ".aaa"])
            records.append({
                "src_ip": victim_ip,
                "dst_ip": victim_ip,
                "event_type": "file_create",
                "process_name": f"C:\\temp\\file_{i}{ext}",
                "timestamp": ts,
                "tags": ["injected:ransomware"],
            })

        # Deletion of originals
        for i in range(num_files):
            ts += random.randint(10, 100)
            records.append({
                "src_ip": victim_ip,
                "dst_ip": victim_ip,
                "event_type": "file_delete",
                "timestamp": ts,
                "tags": ["injected:ransomware"],
            })

        # C2 beacon after encryption
        for _ in range(10):
            ts += 60 * 1000
            records.append({
                "src_ip": victim_ip,
                "dst_ip": c2_ip,
                "dst_port": 443,
                "proto": "TCP",
                "event_type": "network_connect",
                "timestamp": ts,
                "bytes_out": 1500,
                "tags": ["injected:ransomware"],
            })

        end_time = ts
        self.injected_attacks.append(InjectedAttack(
            attack_id=attack_id, attack_type="ransomware_pattern",
            entities=[victim_ip, c2_ip],
            start_time=start_time, end_time=end_time,
            params={"files": num_files},
        ))
        return records

    def get_all_records(self) -> list[dict]:
        """Get all injected records with normalized fields filled."""
        all_records = []
        for method in [self.inject_c2_beacon, self.inject_lateral_movement,
                        self.inject_data_exfil, self.inject_dga,
                        self.inject_port_scan, self.inject_ransomware]:
            pass  # Called individually by user

        return all_records
