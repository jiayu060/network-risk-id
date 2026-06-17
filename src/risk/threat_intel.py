"""Threat intelligence IOC matching."""

import json
import os
from pathlib import Path
from typing import Optional


class ThreatIntelMatcher:
    """Matches detected entities against known threat intelligence IOCs."""

    def __init__(self, ioc_dir: str = "data/threat_intel"):
        self.ioc_dir = ioc_dir
        self._iocs: dict[str, set] = {
            "ip": set(),
            "domain": set(),
            "url": set(),
        }
        self._loaded = False

    def load_feeds(self):
        """Load IOCs from local threat intel files."""
        if not os.path.isdir(self.ioc_dir):
            return

        feed_dir = Path(self.ioc_dir)
        for f in feed_dir.glob("*.json"):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                    for entry in data if isinstance(data, list) else [data]:
                        self._add_ioc(entry)
            except Exception:
                pass

        for f in feed_dir.glob("*.txt"):
            try:
                with open(f) as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self._classify_and_add(line)
            except Exception:
                pass

        self._loaded = True

    def _add_ioc(self, entry: dict):
        """Add an IOC entry from a structured feed."""
        ioc_type = entry.get("type", "").lower()
        value = entry.get("value") or entry.get("indicator") or entry.get("ioc")
        if value and ioc_type in self._iocs:
            self._iocs[ioc_type].add(value)

    def _classify_and_add(self, value: str):
        """Classify and add a raw IOC string."""
        import re
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
            self._iocs["ip"].add(value)
        elif "." in value and not value.startswith("http"):
            self._iocs["domain"].add(value)
        elif value.startswith("http"):
            self._iocs["url"].add(value)

    def check_ip(self, ip: str) -> Optional[dict]:
        """Check if an IP matches known bad IOCs. Returns match info or None."""
        if not self._loaded:
            return None
        if ip in self._iocs["ip"]:
            return {"match": "ip", "value": ip, "confidence": 0.9, "source": "threat_intel"}
        return None

    def check_domain(self, domain: str) -> Optional[dict]:
        """Check if a domain matches known bad IOCs."""
        if not self._loaded:
            return None
        if domain in self._iocs["domain"]:
            return {"match": "domain", "value": domain, "confidence": 0.8, "source": "threat_intel"}
        # Also check parent domains
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._iocs["domain"]:
                return {"match": "domain", "value": parent, "confidence": 0.5,
                        "source": "threat_intel", "note": "parent domain match"}
        return None

    def check_entity(self, entity_id: str, entity_type: str = "ip") -> Optional[dict]:
        """Generic entity check against IOCs."""
        if entity_type == "ip":
            return self.check_ip(entity_id)
        elif entity_type == "domain":
            return self.check_domain(entity_id)
        return None

    def enrich_entity(self, entity_id: str, entity_type: str) -> dict:
        """Enrich entity with threat intel."""
        result = {
            "entity": entity_id,
            "type": entity_type,
            "threat_intel_match": False,
            "match_details": None,
        }
        match = self.check_entity(entity_id, entity_type)
        if match:
            result["threat_intel_match"] = True
            result["match_details"] = match
        return result

    def add_manual_ioc(self, ioc_type: str, value: str):
        """Manually add an IOC (from analyst feedback)."""
        if ioc_type in self._iocs:
            self._iocs[ioc_type].add(value)
            # Persist
            os.makedirs(self.ioc_dir, exist_ok=True)
            manual_file = os.path.join(self.ioc_dir, "manual_iocs.json")
            existing = []
            if os.path.exists(manual_file):
                try:
                    with open(manual_file) as f:
                        existing = json.load(f)
                except Exception:
                    pass
            existing.append({"type": ioc_type, "value": value, "source": "analyst"})
            with open(manual_file, "w") as f:
                json.dump(existing, f)
