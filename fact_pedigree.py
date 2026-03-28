"""
fact_pedigree.py
IOTBSM Fact Pedigree & Intelligence Fact Management

Implements Definitions 6, 17-23 from the IOTBSM:
  - Intelligence facts (threat intel reports)
  - Fact pedigree (signature chain / provenance)
  - Intended vs. unintended receiver classification
  - Fact expiration

Based on: Hexmoor, H., Wilson, S., & Bhattaram, S. (2006).
A theoretical inter-organizational trust-based security model.
The Knowledge Engineering Review, 21(2), 127-161.
"""

import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict
from enum import Enum


# ---------------------------------------------------------------------------
# Intelligence Fact Categories (defense/intelligence domain)
# ---------------------------------------------------------------------------
class ThreatCategory(Enum):
    CYBER_INTRUSION = "Cyber Intrusion"
    MALWARE = "Malware / Ransomware"
    INSIDER_THREAT = "Insider Threat"
    PHYSICAL_SECURITY = "Physical Security"
    SIGINT = "Signals Intelligence"
    HUMINT = "Human Intelligence"
    OSINT = "Open Source Intelligence"
    SUPPLY_CHAIN = "Supply Chain Compromise"


class ClassificationLevel(Enum):
    UNCLASSIFIED = 0
    CONFIDENTIAL = 1
    SECRET = 2
    TOP_SECRET = 3


# ---------------------------------------------------------------------------
# Intelligence Fact (Definition 6)
# ---------------------------------------------------------------------------
@dataclass
class IntelFact:
    """
    Represents a piece of threat intelligence — the 'fact' in IOTBSM.
    
    Each fact has:
      - A unique identifier (cycle + initiator, per Definition 18)
      - Semantic content (the intelligence itself)
      - A classification level
      - A threat category
      - An expiration interval (Definition 32)
      - A fact pedigree (Definition 19)
    """
    fact_id: str
    cycle_created: int
    initiator_id: str
    content: str
    category: ThreatCategory
    classification: ClassificationLevel
    expiration_interval: int  # number of cycles fact can be shared after creation
    
    # Fact pedigree — ordered list of (entity_id, cycle) signatures
    pedigree: List[tuple] = field(default_factory=list)
    
    # Set of entity IDs currently holding this fact
    current_holders: Set[str] = field(default_factory=set)
    
    # Classification of receivers (set by initiator during audit)
    intended_receivers: Set[str] = field(default_factory=set)
    unintended_receivers: Set[str] = field(default_factory=set)
    
    # Whether the fact has been shared across an org boundary (via BS)
    crossed_org_boundary: bool = False
    pseudo_initiator_id: Optional[str] = None  # BS that relayed across boundary

    def sign(self, entity_id: str, cycle: int):
        """
        Entity signs the fact pedigree upon receipt (Definition 19).
        Adds entity signature to the provenance chain.
        """
        self.pedigree.append((entity_id, cycle))
        self.current_holders.add(entity_id)

    def is_expired(self, current_cycle: int) -> bool:
        """
        Definition 32: A fact expires after expiration_interval cycles.
        """
        return (current_cycle - self.cycle_created) > self.expiration_interval

    def get_fact_path(self) -> List[str]:
        """Return ordered list of entity IDs in the traversal path."""
        return [entry[0] for entry in self.pedigree]

    def get_provenance_summary(self) -> str:
        """Human-readable provenance chain."""
        path = " -> ".join([f"{eid}@cycle{cyc}" for eid, cyc in self.pedigree])
        return f"[{self.fact_id}] {self.initiator_id} -> {path}"

    def classify_receiver(self, entity_id: str, is_intended: bool):
        """
        Definitions 20-23: Classify a receiver as intended or unintended.
        Called by the initiator (or pseudo-initiator) during pedigree audit.
        """
        if is_intended:
            self.intended_receivers.add(entity_id)
            self.unintended_receivers.discard(entity_id)
        else:
            self.unintended_receivers.add(entity_id)
            self.intended_receivers.discard(entity_id)

    def has_security_breach(self) -> bool:
        """True if any unintended receivers exist."""
        return len(self.unintended_receivers) > 0

    def __repr__(self):
        return (f"IntelFact({self.fact_id}, {self.category.value}, "
                f"{self.classification.name}, holders={len(self.current_holders)})")


# ---------------------------------------------------------------------------
# Fact Warehouse — the shared repository of intelligence facts
# ---------------------------------------------------------------------------
THREAT_INTEL_WAREHOUSE = [
    {
        "content": "APT-41 using spear-phishing with macro-enabled Office documents targeting defense contractors.",
        "category": ThreatCategory.CYBER_INTRUSION,
        "classification": ClassificationLevel.SECRET,
    },
    {
        "content": "Novel ransomware strain 'BlackSerpent' targeting ICS/SCADA systems in energy sector.",
        "category": ThreatCategory.MALWARE,
        "classification": ClassificationLevel.SECRET,
    },
    {
        "content": "Insider threat indicators: anomalous data exfiltration patterns on classified networks at 0200-0400 local.",
        "category": ThreatCategory.INSIDER_THREAT,
        "classification": ClassificationLevel.TOP_SECRET,
    },
    {
        "content": "Physical surveillance detected near secure facility perimeter; unknown vehicle with RF shielding.",
        "category": ThreatCategory.PHYSICAL_SECURITY,
        "classification": ClassificationLevel.CONFIDENTIAL,
    },
    {
        "content": "Intercepted comms indicate adversary awareness of Operation IRONWALL timeline.",
        "category": ThreatCategory.SIGINT,
        "classification": ClassificationLevel.TOP_SECRET,
    },
    {
        "content": "HUMINT source reports foreign intelligence officer recruiting cleared personnel at tech conferences.",
        "category": ThreatCategory.HUMINT,
        "classification": ClassificationLevel.SECRET,
    },
    {
        "content": "Open source analysis: adversary-linked forum discussing vulnerabilities in DoD supply chain software.",
        "category": ThreatCategory.OSINT,
        "classification": ClassificationLevel.UNCLASSIFIED,
    },
    {
        "content": "Compromised firmware identified in network switches sourced from third-party vendor batch #X-447.",
        "category": ThreatCategory.SUPPLY_CHAIN,
        "classification": ClassificationLevel.SECRET,
    },
    {
        "content": "C2 infrastructure identified: 185.220.101.x/24 linked to nation-state intrusion campaigns.",
        "category": ThreatCategory.CYBER_INTRUSION,
        "classification": ClassificationLevel.SECRET,
    },
    {
        "content": "Malicious kernel-level rootkit 'GhostNeedle' detected on air-gapped network endpoints.",
        "category": ThreatCategory.MALWARE,
        "classification": ClassificationLevel.TOP_SECRET,
    },
    {
        "content": "Lateral movement TTPs: adversary using living-off-the-land binaries to evade EDR solutions.",
        "category": ThreatCategory.CYBER_INTRUSION,
        "classification": ClassificationLevel.SECRET,
    },
    {
        "content": "Supply chain alert: compromised cryptographic library found in defense contractor toolchain.",
        "category": ThreatCategory.SUPPLY_CHAIN,
        "classification": ClassificationLevel.TOP_SECRET,
    },
]


# ---------------------------------------------------------------------------
# Fact Factory
# ---------------------------------------------------------------------------
class FactFactory:
    """Creates IntelFact instances from the warehouse."""

    def __init__(self, expiration_interval: int = 5):
        self.expiration_interval = expiration_interval
        self._warehouse = THREAT_INTEL_WAREHOUSE.copy()
        self._index = 0

    def create_fact(self, cycle: int, initiator_id: str) -> IntelFact:
        """
        Create a new intelligence fact.
        Cycles through the warehouse; each fact gets a unique ID
        per Definition 18 (cycle number + initiator initial).
        """
        template = self._warehouse[self._index % len(self._warehouse)]
        self._index += 1

        fact_id = f"F{cycle}-{initiator_id[:3].upper()}-{str(uuid.uuid4())[:4].upper()}"

        fact = IntelFact(
            fact_id=fact_id,
            cycle_created=cycle,
            initiator_id=initiator_id,
            content=template["content"],
            category=template["category"],
            classification=template["classification"],
            expiration_interval=self.expiration_interval,
        )
        # Initiator signs their own fact
        fact.sign(initiator_id, cycle)
        return fact


# ---------------------------------------------------------------------------
# Pedigree Auditor
# ---------------------------------------------------------------------------
class PedigreeAuditor:
    """
    Performs pedigree audits on behalf of fact initiators.
    Classifies each receiver in the pedigree as intended or unintended.
    Implements Definitions 20-23 and the ISP conditions.
    """

    def audit(self, fact: IntelFact, trust_store, 
              org_registry: Dict[str, str],
              bs_registry: Set[str],
              trust_thresholds) -> dict:
        """
        Audit a fact's pedigree to identify intended vs. unintended receivers.

        Args:
            fact:             The fact to audit
            trust_store:      TrustRelationStore instance
            org_registry:     Dict mapping entity_id -> org_id
            bs_registry:      Set of current boundary spanner IDs
            trust_thresholds: Object with threshold values

        Returns:
            Dict with 'intended', 'unintended', and 'breach' keys
        """
        initiator = fact.initiator_id
        initiator_org = org_registry.get(initiator, "unknown")
        path = fact.get_fact_path()

        intended = []
        unintended = []

        # Walk the path (skip the initiator at index 0)
        for i in range(1, len(path)):
            prev_entity = path[i - 1]
            curr_entity = path[i]
            curr_org = org_registry.get(curr_entity, "unknown")

            is_bs = curr_entity in bs_registry
            prev_is_bs = prev_entity in bs_registry
            cross_org = curr_org != initiator_org

            if cross_org and is_bs and prev_is_bs:
                # Inter-org BS-to-BS exchange: check ITR4 and org-level trust
                bs_trust = trust_store.get(prev_entity, curr_entity)
                threshold = trust_thresholds.tt_bs_bs_inter

                prev_org = org_registry.get(prev_entity, "unknown")
                # Also check org-level trust (ITR5)
                org_trust = trust_store.get(prev_org, curr_org)
                org_threshold = trust_thresholds.tt_org_org

                if bs_trust >= threshold and org_trust >= org_threshold:
                    fact.classify_receiver(curr_entity, True)
                    intended.append(curr_entity)
                else:
                    fact.classify_receiver(curr_entity, False)
                    unintended.append(curr_entity)
            else:
                # Intra-org exchange: check standard agent trust threshold
                trust_val = trust_store.get(prev_entity, curr_entity)
                threshold = trust_thresholds.tt_agent_agent
                if trust_val >= threshold:
                    fact.classify_receiver(curr_entity, True)
                    intended.append(curr_entity)
                else:
                    fact.classify_receiver(curr_entity, False)
                    unintended.append(curr_entity)

        return {
            "intended": intended,
            "unintended": unintended,
            "breach": len(unintended) > 0,
            "fact_id": fact.fact_id,
            "initiator": initiator,
        }
