"""
agents.py
IEOTBSM Agent and Organization Classes

Implements:
  - AnalystAgent: rule-based, produces/consumes intelligence facts
  - BoundarySpannerAgent: hybrid LLM+rule-based, inter-org gatekeeper
  - Organization: manages agents, fact request repository, BS regulatory process

Based on: Hexmoor, H., Wilson, S., & Bhattaram, S. (2006).
A theoretical inter-organizational trust-based security model.
The Knowledge Engineering Review, 21(2), 127-161.
"""

import random
from dataclasses import dataclass, field
from typing import List, Optional, Set, Dict
from fact_pedigree import IntelFact, FactFactory, ThreatCategory
from llm_interface import MockLLMAssessor, create_assessor_for_agency, IntelAssessment
from trust_model import TrustRelationStore


# ---------------------------------------------------------------------------
# Analyst Agent (Definition 4) — rule-based
# ---------------------------------------------------------------------------
@dataclass
class AnalystAgent:
    """
    An analyst agent within an organization.
    Produces intelligence facts and has a required fact.
    Does NOT cross organizational boundaries directly.
    """
    agent_id: str
    org_id: str
    required_category: ThreatCategory
    is_boundary_spanner: bool = False

    # Facts currently accessible to this agent
    accessible_facts: List[IntelFact] = field(default_factory=list)
    # Facts this agent has generated in the current cycle
    generated_fact: Optional[IntelFact] = None
    # Whether this agent's current requirement is satisfied
    satisfied: bool = False
    # Reliability score (used in BS regulatory process)
    reliability: float = 0.0

    def generate_fact(self, cycle: int, factory: FactFactory) -> IntelFact:
        """Produce a new intelligence fact this cycle."""
        self.generated_fact = factory.create_fact(cycle, self.agent_id)
        return self.generated_fact

    def check_satisfaction(self) -> bool:
        """
        Definition 15: An agent is satisfied iff its required fact
        matches a fact in its accessible set.
        """
        for fact in self.accessible_facts:
            if fact.category == self.required_category:
                self.satisfied = True
                return True
        self.satisfied = False
        return False

    def receive_fact(self, fact: IntelFact, cycle: int,
                     sender_id: str, trust_store: TrustRelationStore,
                     threshold: float) -> bool:
        """
        Receive a fact from a sender if trust threshold is met (ISP1).
        Returns True if fact was accepted.
        """
        if trust_store.get(sender_id, self.agent_id) >= threshold:
            if fact not in self.accessible_facts:
                self.accessible_facts.append(fact)
                fact.sign(self.agent_id, cycle)
            return True
        return False

    def is_willing(self) -> bool:
        """
        Definition 16: Agent is willing to receive if not yet satisfied.
        """
        return not self.satisfied

    def reset_cycle(self):
        """Reset per-cycle state."""
        self.accessible_facts = []
        self.generated_fact = None
        self.satisfied = False

    def __repr__(self):
        role = "BS" if self.is_boundary_spanner else "Agent"
        return f"{role}({self.agent_id}@{self.org_id})"


# ---------------------------------------------------------------------------
# Boundary Spanner Agent (Definition 5) — hybrid LLM + rule-based
# ---------------------------------------------------------------------------
@dataclass
class BoundarySpannerAgent:
    """
    A boundary spanner agent — organizational gatekeeper and inter-org conduit.
    
    Hybrid architecture:
      - Rule-based: enforces trust thresholds, TPMs, fact pedigree management
      - LLM-based: semantically assesses incoming intelligence for relevance
                   and sharing recommendations (mocked)
    
    Key properties:
      - Does NOT generate personal facts
      - Adopts ALL fact requirements from the org's fact request repository
      - Maintains inter-org trust relations with BS of partner orgs
      - Is selected/deselected via reliability ranking (BS regulatory process)
    """
    bs_id: str
    org_id: str
    assessor: MockLLMAssessor

    # Facts received from within the org (to relay outward)
    inbound_facts: List[IntelFact] = field(default_factory=list)
    # Facts received from partner BS (to relay inward)
    external_facts: List[IntelFact] = field(default_factory=list)
    # Current fact requirements (from org's repository)
    fact_requirements: Set[ThreatCategory] = field(default_factory=set)
    # Assessments performed this cycle
    assessments: List[IntelAssessment] = field(default_factory=list)
    # Reliability score
    reliability: float = 0.0
    # Partner BS IDs this BS has trust relations with
    partner_bs_ids: Set[str] = field(default_factory=set)

    def adopt_requirements(self, categories: Set[ThreatCategory]):
        """BS adopts all requirements from the fact request repository."""
        self.fact_requirements = categories.copy()

    def receive_inbound(self, fact: IntelFact, cycle: int,
                        sender_id: str, trust_store: TrustRelationStore,
                        threshold: float) -> bool:
        """Receive a fact from an internal agent."""
        if trust_store.get(sender_id, self.bs_id) >= threshold:
            if fact not in self.inbound_facts:
                self.inbound_facts.append(fact)
                fact.sign(self.bs_id, cycle)
            return True
        return False

    def assess_and_relay(self, fact: IntelFact, partner_bs_id: str,
                         partner_org_id: str, cycle: int,
                         trust_store: TrustRelationStore,
                         io_trust: float,
                         bs_threshold: float,
                         org_threshold: float) -> Optional[IntelFact]:
        """
        LLM assessment + rule-based trust gate for inter-org relay.
        
        The hybrid decision:
          1. LLM assesses relevance and recommends whether to share
          2. Rule-based engine checks BS trust threshold (ITR4)
          3. Rule-based engine checks inter-org trust threshold (ITR5)
          4. Only if ALL conditions pass does the fact cross the boundary
        
        Returns the fact if relayed, None otherwise.
        """
        # Step 1: LLM semantic assessment
        assessment = self.assessor.assess(fact, partner_agency=partner_org_id)
        self.assessments.append(assessment)

        # Step 2: LLM recommendation gate
        if not assessment.share_recommendation:
            return None

        # Step 3: Rule-based BS trust gate (ITR4)
        bs_trust = trust_store.get(self.bs_id, partner_bs_id)
        if bs_trust < bs_threshold:
            return None

        # Step 4: Rule-based inter-org trust gate (ITR5)
        if io_trust < org_threshold:
            return None

        # All gates passed — relay the fact across the boundary
        fact.crossed_org_boundary = True
        fact.pseudo_initiator_id = self.bs_id
        fact.sign(partner_bs_id, cycle)
        self.external_facts.append(fact)
        return fact

    def is_willing(self) -> bool:
        """BS is always willing (represents all org requirements)."""
        return True

    def reset_cycle(self):
        """Reset per-cycle state."""
        self.inbound_facts = []
        self.external_facts = []
        self.assessments = []

    def __repr__(self):
        return f"BS({self.bs_id}@{self.org_id}, partners={len(self.partner_bs_ids)})"


# ---------------------------------------------------------------------------
# Organization (Definition 3)
# ---------------------------------------------------------------------------
class Organization:
    """
    An organization in the inter-organizational network.
    
    Manages:
      - Constituent analyst agents
      - Boundary spanner agents (elected via regulatory process)
      - Fact request repository
      - Intra-org trust relations
      - Reliability ranking for BS selection
    """

    def __init__(self, org_id: str, num_agents: int = 5,
                 bs_fraction: float = 0.3,
                 expiration_interval: int = 6):
        self.org_id = org_id
        self.bs_fraction = bs_fraction
        self.fact_factory = FactFactory(expiration_interval=expiration_interval)

        # Create analyst agents with varied intelligence requirements
        categories = list(ThreatCategory)
        self.agents: List[AnalystAgent] = []
        for i in range(num_agents):
            agent_id = f"{org_id}_A{i+1}"
            required = categories[i % len(categories)]
            agent = AnalystAgent(
                agent_id=agent_id,
                org_id=org_id,
                required_category=required,
                reliability=random.uniform(0.3, 0.9)
            )
            self.agents.append(agent)

        # Boundary spanners (initially empty, populated by regulatory process)
        self.boundary_spanners: List[BoundarySpannerAgent] = []

        # Fact request repository (Definition 7)
        self.fact_request_repository: Set[ThreatCategory] = set()

        # Metrics
        self.satisfied_count = 0
        self.intended_count = 0
        self.unintended_count = 0

    @property
    def num_bs(self) -> int:
        return max(1, int(len(self.agents) * self.bs_fraction))

    @property
    def all_entity_ids(self) -> List[str]:
        agent_ids = [a.agent_id for a in self.agents]
        bs_ids = [b.bs_id for b in self.boundary_spanners]
        return agent_ids + bs_ids

    @property
    def bs_ids(self) -> List[str]:
        return [b.bs_id for b in self.boundary_spanners]

    def update_fact_repository(self):
        """Collect unsatisfied requirements from all agents."""
        self.fact_request_repository = set()
        for agent in self.agents:
            if not agent.satisfied:
                self.fact_request_repository.add(agent.required_category)

    def run_bs_regulatory_process(self, trust_store: TrustRelationStore,
                                  cycle: int):
        """
        Boundary Spanner Regulatory Process (Section 4.7).
        
        Ranks all agents by reliability, promotes top bs_fraction to BS role.
        Demotes existing BSs not in top ranked.
        
        In the IEOTBSM, reliability is based on trustworthiness (in-degree
        weighted trust from the trust graph). Here we use a simplified
        reliability metric updated each cycle.
        """
        # Update reliability scores based on trust relations
        for agent in self.agents:
            agent.reliability = self._compute_reliability(
                agent.agent_id, trust_store)

        # Sort by reliability descending
        sorted_agents = sorted(self.agents,
                               key=lambda a: a.reliability, reverse=True)
        top_agents = sorted_agents[:self.num_bs]
        top_ids = {a.agent_id for a in top_agents}

        # Demote existing BSs not in top ranked
        for bs in self.boundary_spanners:
            if bs.bs_id not in top_ids:
                # Convert back to analyst agent
                for agent in self.agents:
                    if agent.agent_id == bs.bs_id:
                        agent.is_boundary_spanner = False

        # Promote top agents to BS
        new_bss = []
        for agent in top_agents:
            if not agent.is_boundary_spanner:
                # New promotion
                agent.is_boundary_spanner = True

            assessor = create_assessor_for_agency(self.org_id, agent.agent_id)
            bs = BoundarySpannerAgent(
                bs_id=agent.agent_id,
                org_id=self.org_id,
                assessor=assessor,
                reliability=agent.reliability
            )
            bs.adopt_requirements(self.fact_request_repository)
            new_bss.append(bs)

        self.boundary_spanners = new_bss

    def _compute_reliability(self, entity_id: str,
                             trust_store: TrustRelationStore) -> float:
        """
        Simplified reliability metric from Section 4.7.
        Based on weighted average of incoming trust relations.
        """
        incoming_trusts = []
        for other_agent in self.agents:
            if other_agent.agent_id != entity_id:
                t = trust_store.get(other_agent.agent_id, entity_id)
                if t > 0:
                    incoming_trusts.append(t)

        if not incoming_trusts:
            return random.uniform(0.2, 0.5)

        direct_avg = sum(incoming_trusts) / len(incoming_trusts)
        # Weight by number of direct relations
        return direct_avg * (len(incoming_trusts) / len(self.agents))

    def initialize_intra_org_trust(self, trust_store: TrustRelationStore):
        """Initialize random trust relations between agents (ITR1)."""
        for agent_i in self.agents:
            for agent_j in self.agents:
                if agent_i.agent_id != agent_j.agent_id:
                    # Random initial trust in [0.3, 1.0]
                    trust_store.initialize_random(
                        agent_i.agent_id, agent_j.agent_id,
                        low=0.3, high=1.0)

    def reset_cycle_metrics(self):
        self.satisfied_count = 0
        self.intended_count = 0
        self.unintended_count = 0
        for agent in self.agents:
            agent.reset_cycle()
        for bs in self.boundary_spanners:
            bs.reset_cycle()

    def __repr__(self):
        return (f"Organization({self.org_id}, "
                f"agents={len(self.agents)}, "
                f"bs={len(self.boundary_spanners)})")
