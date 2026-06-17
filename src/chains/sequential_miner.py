"""Sequential pattern mining for rare event sequences (PrefixSpan-based)."""

from collections import defaultdict, Counter
from typing import Optional


class SequentialMiner:
    """Mines rare event sequences from per-host event timelines.

    Uses a simplified PrefixSpan-like algorithm to find sequences that:
    1. Occur in < 1% of hosts (rare)
    2. Include at least one anomalous event
    3. Span multiple distinct IPs
    """

    def __init__(self, min_support: int = 2, max_pattern_length: int = 8,
                 max_gap_seconds: int = 300, min_distinct_ips: int = 2,
                 rarity_ratio: float = 0.01):
        self.min_support = min_support
        self.max_pattern_length = max_pattern_length
        self.max_gap_seconds = max_gap_seconds
        self.min_distinct_ips = min_distinct_ips
        self.rarity_ratio = rarity_ratio

    def mine(self, host_sequences: dict[str, list[dict]]) -> list[dict]:
        """Mine rare sequential patterns from host event sequences.

        Args:
            host_sequences: {host_id: [{event_type, dst_ip, timestamp, is_anomalous}, ...]}

        Returns:
            List of rare pattern dicts with pattern, support, rarity_score
        """
        # Build list of sequences
        sequences = []
        host_ids = []
        for host, events in sorted(host_sequences.items()):
            # Sort events by time
            events = sorted(events, key=lambda e: e.get("timestamp", 0))
            seq = [(e.get("event_type", "unknown"), e.get("dst_ip", "")) for e in events]
            sequences.append(seq)
            host_ids.append(host)

        n_hosts = len(host_ids)
        if n_hosts < 2:
            return []

        patterns = self._prefix_span(sequences, n_hosts)

        # Filter: rare + contains anomaly + multiple distinct IPs
        results = []
        for pattern, support in patterns:
            rarity = support / n_hosts
            if rarity >= self.rarity_ratio:
                continue  # not rare enough
            if support < self.min_support:
                continue

            # Check distinct IPs
            ips = set(ip for _, ip in pattern if ip)
            if len(ips) < self.min_distinct_ips:
                continue

            results.append({
                "pattern": pattern,
                "support": support,
                "rarity": rarity,
                "rarity_score": 1.0 - rarity,
                "distinct_ips": len(ips),
            })

        results.sort(key=lambda r: r["rarity_score"], reverse=True)
        return results

    def _prefix_span(self, sequences: list, n_hosts: int) -> list:
        """Simplified PrefixSpan: grow patterns via frequent extensions."""
        patterns = []

        # Start with single-item patterns
        for item in self._unique_items(sequences):
            self._grow_pattern([item], sequences, patterns, n_hosts)

        return patterns

    def _grow_pattern(self, prefix: list, sequences: list,
                      patterns_out: list, n_hosts: int, depth: int = 1):
        """Recursively grow pattern by appending frequent items."""
        if depth > self.max_pattern_length:
            return

        # Count support
        support = self._count_support(prefix, sequences)
        if support < self.min_support:
            return

        # Record this pattern
        patterns_out.append((list(prefix), support))

        # Find candidate extensions
        candidates = Counter()
        projected = self._project_database(prefix, sequences)
        for seq in projected:
            # Get next possible items after this prefix
            for i in range(min(len(seq), 3)):  # look ahead up to 3
                if seq[i] not in [p for p in prefix]:
                    candidates[seq[i]] += 1

        # Extend with frequent items
        for item, count in candidates.most_common(50):
            if count >= self.min_support:
                self._grow_pattern(prefix + [item], sequences, patterns_out, n_hosts, depth + 1)

    def _count_support(self, pattern: list, sequences: list) -> int:
        """Count sequences containing the pattern as a subsequence."""
        count = 0
        for seq in sequences:
            if self._is_subsequence(pattern, seq):
                count += 1
        return count

    def _is_subsequence(self, pattern: list, sequence: list) -> bool:
        """Check if pattern is a subsequence of sequence."""
        if not pattern:
            return True
        p_idx = 0
        for item in sequence:
            if item == pattern[p_idx]:
                p_idx += 1
                if p_idx >= len(pattern):
                    return True
        return False

    def _project_database(self, pattern: list, sequences: list) -> list:
        """Project sequences to suffixes after pattern occurrences."""
        projected = []
        for seq in sequences:
            # Find first occurrence of pattern
            p_idx = 0
            start = 0
            for i, item in enumerate(seq):
                if item == pattern[p_idx]:
                    p_idx += 1
                    if p_idx == 1:
                        start = i
                    if p_idx >= len(pattern):
                        projected.append(seq[start + len(pattern):])
                        break
        return projected

    def _unique_items(self, sequences: list) -> list:
        """Get all unique items across all sequences."""
        items = set()
        for seq in sequences:
            for item in seq:
                items.add(item)
        return sorted(items)
