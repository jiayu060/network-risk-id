"""Feature extractor: computes 31-dim feature vectors per entity per time window."""

import math
from collections import Counter
from datetime import datetime, timezone

import pyarrow as pa
import pyarrow.parquet as pq
from src.utils.text_utils import shannon_entropy, consonant_vowel_ratio

FEATURE_NAMES = [
    # Group A: Volume & Rate (8)
    "event_count", "events_per_sec", "unique_dst_ips", "unique_dst_ports",
    "unique_domains", "bytes_out_total", "bytes_in_total", "byte_ratio",
    # Group B: Temporal Patterns (6)
    "mean_iat", "std_iat", "burstiness", "iat_entropy",
    "business_hour_fraction", "beacon_score",
    # Group C: Target Diversity (5)
    "dst_ip_entropy", "dst_port_entropy", "rare_ip_fraction",
    "new_ip_fraction", "geo_diversity",
    # Group D: DNS-specific (5)
    "mean_domain_len", "mean_domain_entropy", "nxdomain_fraction",
    "high_cv_domain_fraction", "mean_dns_ttl",
    # Group E: Auth & Access (4)
    "auth_failure_ratio", "unique_users_attempted",
    "off_hours_auth_fraction", "new_user_auth",
    # Group F: WAF-specific (3)
    "waf_alert_density", "unique_waf_rules", "max_waf_severity",
]


class FeatureExtractor:
    """Computes per-entity-window feature vectors from normalized logs."""

    def __init__(self, window_size_ms: int = 3600000, baseline_days: int = 7):
        self.window_size_ms = window_size_ms
        self.baseline_days = baseline_days
        # Baseline tracking for "new IP" and "rare IP" features
        self.global_ip_counts: dict[str, int] = {}
        self.historical_ips: set = set()

    def load_baseline(self, baseline_dir: str):
        """Load baseline IP statistics from historical Parquet files."""
        import os
        from pathlib import Path
        for f in Path(baseline_dir).rglob("*.parquet"):
            try:
                table = pq.read_table(str(f), columns=["src_ip", "dst_ip"])
                for batch in table.to_batches(max_chunksize=100000):
                    df = pa.Table.from_batches([batch]).to_pandas()
                    for _, row in df.iterrows():
                        if row["src_ip"]:
                            self.global_ip_counts[row["src_ip"]] = self.global_ip_counts.get(row["src_ip"], 0) + 1
                            self.historical_ips.add(row["src_ip"])
                        if row["dst_ip"]:
                            self.global_ip_counts[row["dst_ip"]] = self.global_ip_counts.get(row["dst_ip"], 0) + 1
                            self.historical_ips.add(row["dst_ip"])
            except Exception:
                pass

    def extract_window(self, table: pa.Table) -> dict[str, list[float]]:
        """Extract features from a single window of normalized logs.

        Returns dict mapping entity_id -> feature_vector
        """
        df = table.to_pandas()
        if df.empty:
            return {}

        t_min = df["timestamp"].min()
        t_max = df["timestamp"].max()
        window_sec = max((t_max - t_min) / 1000, 1.0)

        # Group by entity (src_ip, event_type)
        entities: dict[str, list] = {}
        for _, row in df.iterrows():
            src_ip = row["src_ip"] or "unknown"
            event_type = row["event_type"]
            entity_id = f"{src_ip}:{event_type}"
            entities.setdefault(entity_id, []).append(row)

        features = {}
        for entity_id, rows in entities.items():
            vec = self._compute_entity_features(rows, window_sec)
            features[entity_id] = vec

        return features

    def _compute_entity_features(self, rows: list, window_sec: float) -> list[float]:
        """Compute 31 features for one entity's events."""
        n = len(rows)

        # ---- Group A: Volume & Rate ----
        f1 = float(n)
        f2 = n / window_sec
        dst_ips = set(r["dst_ip"] for r in rows if r.get("dst_ip"))
        f3 = float(len(dst_ips))
        dst_ports = set(r["dst_port"] for r in rows if r.get("dst_port") is not None)
        f4 = float(len(dst_ports))
        domains = set(r["domain"] for r in rows if r.get("domain"))
        f5 = float(len(domains))
        bytes_out = sum((r.get("bytes_out") or 0) for r in rows)
        f6 = float(bytes_out)
        bytes_in = sum((r.get("bytes_in") or 0) for r in rows)
        f7 = float(bytes_in)
        f8 = float(bytes_out) / (float(bytes_in) + 1)

        # ---- Group B: Temporal Patterns ----
        timestamps = sorted(r["timestamp"] for r in rows)
        iats = []
        for i in range(1, len(timestamps)):
            iat = (timestamps[i] - timestamps[i - 1]) / 1000.0
            if iat > 0:
                iats.append(iat)

        if iats:
            mean_iat = sum(iats) / len(iats)
            f9 = mean_iat
            if len(iats) > 1:
                variance = sum((x - mean_iat) ** 2 for x in iats) / (len(iats) - 1)
                f10 = math.sqrt(variance)
            else:
                f10 = 0.0
            f11 = f10 / max(mean_iat, 1e-6)  # burstiness = CV
            # IAT entropy (binned)
            if len(iats) >= 5:
                bins = min(10, len(iats) // 2)
                if bins >= 2:
                    bin_edges = [min(iats) + (max(iats) - min(iats)) * i / bins for i in range(bins + 1)]
                    hist = [0] * bins
                    for iat in iats:
                        for b in range(bins):
                            if bin_edges[b] <= iat < bin_edges[b + 1]:
                                hist[b] += 1
                                break
                    total = sum(hist)
                    if total > 0:
                        f12 = -sum((h / total) * math.log2(max(h, 1) / total) for h in hist)
                    else:
                        f12 = 0.0
                else:
                    f12 = 0.0
            else:
                f12 = 0.0
        else:
            f9 = f10 = f11 = f12 = 0.0

        # Business hour fraction (08:00-18:00 UTC)
        business_count = 0
        for ts in timestamps:
            hour = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).hour
            if 8 <= hour < 18:
                business_count += 1
        f13 = business_count / max(n, 1)

        # Beacon score (simplified autocorrelation)
        f14 = self._compute_beacon_score(timestamps)

        # ---- Group C: Target Diversity ----
        # IP entropy
        ip_counts = Counter(r["dst_ip"] for r in rows if r.get("dst_ip"))
        f15 = self._entropy(ip_counts.values())

        # Port entropy
        port_counts = Counter(str(r["dst_port"]) for r in rows if r.get("dst_port") is not None)
        f16 = self._entropy(port_counts.values())

        # Rare IP fraction
        rare_count = sum(1 for ip in dst_ips if self.global_ip_counts.get(ip, 0) < 5)
        f17 = rare_count / max(len(dst_ips), 1)

        # New IP fraction
        new_count = sum(1 for ip in dst_ips if ip not in self.historical_ips)
        f18 = new_count / max(len(dst_ips), 1)

        # Geo diversity (placeholder — requires GeoIP DB)
        f19 = 0.0

        # ---- Group D: DNS-specific ----
        dns_domains = [r["domain"] for r in rows if r.get("domain")]
        if dns_domains:
            domain_lens = [len(d) for d in dns_domains]
            f20 = sum(domain_lens) / len(domain_lens)
            domain_entropies = [shannon_entropy(d) for d in dns_domains]
            f21 = sum(domain_entropies) / len(domain_entropies)
            nxdomains = sum(1 for r in rows if r.get("dns_rcode") == "NXDOMAIN")
            f22 = nxdomains / max(len(dns_domains), 1)
            high_cv = 0
            for d in dns_domains:
                body = d.rsplit(".", 1)[0] if "." in d else d
                if len(body) > 0 and consonant_vowel_ratio(body) > 4.0:
                    high_cv += 1
            f23 = high_cv / max(len(dns_domains), 1)
            f24 = 0.0  # DNS TTL requires additional data
        else:
            f20 = f21 = f22 = f23 = f24 = 0.0

        # ---- Group E: Auth & Access ----
        auth_rows = [r for r in rows if r.get("event_type") in ("auth_success", "auth_failure")]
        if auth_rows:
            auth_fails = sum(1 for r in auth_rows if r["event_type"] == "auth_failure")
            f25 = auth_fails / len(auth_rows)
            users = set(r.get("user") for r in auth_rows if r.get("user"))
            f26 = float(len(users))
            off_hours = 0
            for r in auth_rows:
                hour = datetime.fromtimestamp(r["timestamp"] / 1000, tz=timezone.utc).hour
                if hour < 8 or hour >= 18:
                    off_hours += 1
            f27 = off_hours / max(len(auth_rows), 1)
            f28 = 1.0 if any(r.get("user") and r["user"] not in self.historical_ips for r in auth_rows) else 0.0
        else:
            f25 = f26 = f27 = f28 = 0.0

        # ---- Group F: WAF-specific ----
        waf_rows = [r for r in rows if r.get("event_type") == "waf_alert"]
        if waf_rows:
            f29 = len(waf_rows) / max(n, 1)
            f30 = float(len(set(r.get("waf_rule_id") for r in waf_rows if r.get("waf_rule_id"))))
            severities = [r.get("severity") or 0 for r in waf_rows]
            f31 = float(max(severities)) if severities else 0.0
        else:
            f29 = f30 = f31 = 0.0

        return [f1, f2, f3, f4, f5, f6, f7, f8,
                f9, f10, f11, f12, f13, f14, f15, f16,
                f17, f18, f19, f20, f21, f22, f23, f24,
                f25, f26, f27, f28, f29, f30, f31]

    def _compute_beacon_score(self, timestamps: list[int]) -> float:
        """Simple autocorrelation-based beacon detection for C2."""
        if len(timestamps) < 10:
            return 0.0
        iats = [0.0]
        for i in range(1, len(timestamps)):
            iats.append((timestamps[i] - timestamps[i - 1]) / 1000.0)
        iats = iats[1:]
        if not iats:
            return 0.0

        mean_iat = sum(iats) / len(iats)
        if mean_iat == 0:
            return 0.0

        # Compute autocorrelation at lag 1
        mean = sum(iats) / len(iats)
        numerator = sum((iats[i] - mean) * (iats[i - 1] - mean) for i in range(1, len(iats)))
        denominator = sum((x - mean) ** 2 for x in iats) + 1e-10
        ac1 = numerator / denominator

        # High autocorrelation + low variance = beaconing
        std = math.sqrt(sum((x - mean) ** 2 for x in iats) / max(len(iats) - 1, 1))
        if mean_iat > 0:
            regularity = 1.0 - (std / mean_iat)  # closer to 1 = more regular
        else:
            regularity = 0.0

        return max(0.0, ac1 * regularity)

    @staticmethod
    def _entropy(counts) -> float:
        """Shannon entropy from count distribution."""
        total = sum(counts)
        if total == 0:
            return 0.0
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / total
                entropy -= p * math.log2(p)
        return entropy
