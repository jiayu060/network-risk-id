"""Attack chain classification — maps chains to Lockheed Martin Cyber Kill Chain and MITRE ATT&CK."""

from src.core.types import AttackChain

# Chain type -> (Kill-Chain phases, MITRE techniques, description template)
_CHAIN_TEMPLATES = {
    "c2_beacon": {
        "phases": ["Command & Control"],
        "mitre": ["T1071", "T1071.001", "T1573"],
        "priority": 1,
        "desc": "C2 beaconing detected: periodic communication pattern with external infrastructure",
    },
    "lateral_movement": {
        "phases": ["Lateral Movement"],
        "mitre": ["T1021", "T1078", "T1550"],
        "priority": 1,
        "desc": "Lateral movement: authentication from {src} pivoting through {pivot} to {target}",
    },
    "data_exfil": {
        "phases": ["Actions on Objectives", "Exfiltration"],
        "mitre": ["T1041", "T1048", "T1567"],
        "priority": 1,
        "desc": "Data exfiltration: large outbound transfer to rare external destination",
    },
    "dga_activity": {
        "phases": ["Command & Control"],
        "mitre": ["T1568", "T1568.002"],
        "priority": 2,
        "desc": "DGA activity: host generating algorithmically-generated domain names",
    },
    "recon_scan": {
        "phases": ["Reconnaissance", "Discovery"],
        "mitre": ["T1046", "T1595"],
        "priority": 3,
        "desc": "Reconnaissance scanning: probing multiple ports/targets",
    },
    "credential_theft": {
        "phases": ["Credential Access"],
        "mitre": ["T1003", "T1110", "T1555"],
        "priority": 1,
        "desc": "Credential access: brute-force or credential dumping pattern detected",
    },
    "ransomware_pattern": {
        "phases": ["Impact", "Command & Control"],
        "mitre": ["T1486", "T1070", "T1485"],
        "priority": 1,
        "desc": "Ransomware pattern: mass file writes + deletion + beaconing",
    },
    "privilege_escalation": {
        "phases": ["Privilege Escalation"],
        "mitre": ["T1068", "T1134", "T1548"],
        "priority": 2,
        "desc": "Privilege escalation: token manipulation or unusual privilege assignment",
    },
    "supply_chain": {
        "phases": ["Initial Access"],
        "mitre": ["T1195", "T1195.002"],
        "priority": 2,
        "desc": "Supply chain compromise: software update contacting rare domain",
    },
    "suspicious_activity": {
        "phases": ["Unknown"],
        "mitre": [],
        "priority": 3,
        "desc": "Suspicious activity pattern requiring further investigation",
    },
}


class ChainClassifier:
    """Classifies attack chains and enriches them with kill-chain and MITRE mappings."""

    def classify(self, chain: AttackChain) -> AttackChain:
        """Enrich an AttackChain with kill-chain and MITRE information."""
        template = _CHAIN_TEMPLATES.get(
            chain.chain_type,
            _CHAIN_TEMPLATES["suspicious_activity"],
        )

        chain.kill_chain_phases = template["phases"]
        if not chain.mitre_techniques:
            chain.mitre_techniques = template["mitre"]
        chain.investigation_priority = template["priority"]

        # Generate description
        if not chain.description:
            chain.description = self._generate_description(chain, template)

        return chain

    def classify_batch(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Classify multiple chains."""
        return [self.classify(c) for c in chains]

    def _generate_description(self, chain: AttackChain, template: dict) -> str:
        """Generate human-readable description from chain data."""
        desc = template["desc"]

        # Fill in entity names
        entities = {n.role: n.entity for n in chain.nodes}
        for role, entity in entities.items():
            desc = desc.replace(f"{{{role}}}", entity)

        # Add evidence summary
        if chain.edges:
            edge_types = set(e.edge_type for e in chain.edges)
            desc += f". Involves {len(chain.nodes)} entities across {len(chain.edges)} connections"
            desc += f" ({', '.join(sorted(edge_types))})"

        affected = len(set(n.entity for n in chain.nodes if n.entity_type == "ip"))
        if affected > 1:
            desc += f". Affected hosts: {affected}"

        return desc

    @staticmethod
    def get_priority_label(priority: int) -> str:
        labels = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW", 5: "INFO"}
        return labels.get(priority, "UNKNOWN")
