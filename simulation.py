"""
simulation.py
IOTBSM Main Simulation Engine

Implements the Modified Trust-based Information Sharing Algorithm (Figure 5)
for the inter-organizational context with classified threat intelligence.

Tracks IA (Information Availability) and SM (Security Measure) across cycles,
logging all fact-sharing events, trust updates, and breach detections.

Based on: Hexmoor, H., Wilson, S., & Bhattaram, S. (2006).
A theoretical inter-organizational trust-based security model.
The Knowledge Engineering Review, 21(2), 127-161.
"""

import random
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional
from agents import Organization, AnalystAgent, BoundarySpannerAgent
from fact_pedigree import IntelFact, PedigreeAuditor
from trust_model import TrustRelationStore, InterOrgTrustTracker
from trust_policy import TrustPolicyEngine, TPMType

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger("IOTBSM")


# ---------------------------------------------------------------------------
# Cycle Metrics (Definitions 26-31)
# ---------------------------------------------------------------------------
@dataclass
class CycleMetrics:
    cycle: int
    total_facts_shared: int = 0       # Definition 26
    information_availability: int = 0  # Definition 27 (IA)
    security_measure: int = 0          # Definition 29 (SM)
    satisfied_agents: int = 0
    intended_receivers: int = 0
    unintended_receivers: int = 0
    breaches_detected: int = 0
    tpm_applications: int = 0
    inter_org_trusts: Dict[str, float] = field(default_factory=dict)
    facts_crossed_boundary: int = 0
    llm_assessments: int = 0
    llm_share_recommended: int = 0

    @property
    def pct_ia(self) -> float:
        """Definition 28: Percentage IA (capped at 100%)."""
        if self.total_facts_shared == 0:
            return 0.0
        return min(100.0, (self.information_availability / self.total_facts_shared) * 100)

    @property
    def pct_sm(self) -> float:
        """Definition 30: Percentage SM."""
        if self.total_facts_shared == 0:
            return 0.0
        return min(100.0, (self.security_measure / self.total_facts_shared) * 100)


# ---------------------------------------------------------------------------
# IOTBSM Simulation
# ---------------------------------------------------------------------------
class IOTBSMSimulation:
    """
    Full IOTBSM simulation implementing the algorithm in Figure 5.
    
    Supports three agencies (organizations) with hybrid LLM+rule-based
    boundary spanners sharing classified threat intelligence.
    """

    def __init__(self,
                 num_cycles: int = 30,
                 bs_regulatory_rate: int = 5,     # β from Figure 5
                 tpm_type: TPMType = TPMType.TPM1,
                 decrement_factor: float = 0.1,
                 alpha: float = 0.6,               # IOT weight in Eq. 7
                 seed: int = 42):

        random.seed(seed)
        self.num_cycles = num_cycles
        self.bs_regulatory_rate = bs_regulatory_rate  # β
        self.alpha = alpha

        # Core components
        self.trust_store = TrustRelationStore()
        self.io_trust_tracker = InterOrgTrustTracker()
        self.tpm_engine = TrustPolicyEngine(tpm_type, decrement_factor)
        self.pedigree_auditor = PedigreeAuditor()

        # Create three intelligence agencies
        self.organizations: List[Organization] = [
            Organization("Agency_A", num_agents=6, bs_fraction=0.33,
                         expiration_interval=8),
            Organization("Agency_B", num_agents=5, bs_fraction=0.40,
                         expiration_interval=8),
            Organization("Agency_C", num_agents=4, bs_fraction=0.25,
                         expiration_interval=8),
        ]

        # Registries for pedigree auditing
        self.org_registry: Dict[str, str] = {}   # entity_id -> org_id
        self.bs_registry: set = set()             # current BS IDs

        # Active facts in the network
        self.active_facts: List[IntelFact] = []

        # Metrics per cycle
        self.metrics_history: List[CycleMetrics] = []

        # Event log
        self.event_log: List[dict] = []

        # Initialize
        self._initialize()

    # -----------------------------------------------------------------------
    # Initialization
    # -----------------------------------------------------------------------
    def _initialize(self):
        """Set up trust relations, org registries, initial BS selection."""

        # Register all entities
        for org in self.organizations:
            for agent in org.agents:
                self.org_registry[agent.agent_id] = org.org_id

        # Initialize intra-org trust (ITR1)
        for org in self.organizations:
            org.initialize_intra_org_trust(self.trust_store)

        # Initialize inter-org trust pairs (ITR5, Eq. 5)
        org_ids = [o.org_id for o in self.organizations]
        for i, org_m in enumerate(org_ids):
            for j, org_n in enumerate(org_ids):
                if org_m != org_n:
                    # Low initial inter-org trust (agencies are cautious)
                    self.io_trust_tracker.initialize_pair(
                        org_m, org_n, tau_0=random.uniform(0.15, 0.35))
                    # Initialize org-org trust in store
                    self.trust_store.set(
                        org_m, org_n,
                        self.io_trust_tracker.get_trust(org_m, org_n))

        # Run initial BS regulatory process
        for org in self.organizations:
            org.update_fact_repository()
            org.run_bs_regulatory_process(self.trust_store, cycle=0)

        self._update_bs_registry()
        self._initialize_inter_bs_trust()

    def _update_bs_registry(self):
        """Update the global BS registry."""
        self.bs_registry = set()
        for org in self.organizations:
            for bs in org.boundary_spanners:
                self.bs_registry.add(bs.bs_id)
                self.org_registry[bs.bs_id] = org.org_id

    def _initialize_inter_bs_trust(self):
        """
        Initialize inter-boundary-spanner trust relations (ITR4).
        Every BS has at least one relation to a BS in each other org.
        """
        for org_m in self.organizations:
            for org_n in self.organizations:
                if org_m.org_id == org_n.org_id:
                    continue
                for bs_m in org_m.boundary_spanners:
                    for bs_n in org_n.boundary_spanners:
                        init_val = random.uniform(0.2, 0.6)
                        self.trust_store.set(bs_m.bs_id, bs_n.bs_id, init_val)
                        bs_m.partner_bs_ids.add(bs_n.bs_id)

    # -----------------------------------------------------------------------
    # Main Simulation Loop (Figure 5)
    # -----------------------------------------------------------------------
    def run(self) -> List[CycleMetrics]:
        """Execute the full simulation."""
        print(f"\n{'='*60}")
        print("  IOTBSM SIMULATION — Classified Threat Intel Sharing")
        print(f"  Agencies: {[o.org_id for o in self.organizations]}")
        print(f"  Cycles: {self.num_cycles} | β={self.bs_regulatory_rate} | "
              f"TPM: {self.tpm_engine.tpm_type.value}")
        print(f"{'='*60}\n")

        for cycle in range(1, self.num_cycles + 1):
            metrics = self._run_cycle(cycle)
            self.metrics_history.append(metrics)

            if cycle % 5 == 0 or cycle == 1:
                self._print_cycle_summary(metrics)

        self._print_final_summary()
        return self.metrics_history

    def _run_cycle(self, cycle: int) -> CycleMetrics:
        """
        Execute one simulation cycle (Figure 5 algorithm).
        """
        metrics = CycleMetrics(cycle=cycle)

        # Step 1: Reset per-cycle state
        for org in self.organizations:
            org.reset_cycle_metrics()

        # Step 2: BS Regulatory Process (every β cycles)
        if cycle % self.bs_regulatory_rate == 0:
            for org in self.organizations:
                org.update_fact_repository()
                org.run_bs_regulatory_process(self.trust_store, cycle)
            self._update_bs_registry()

        # Step 3: Update fact repositories
        for org in self.organizations:
            org.update_fact_repository()
            for bs in org.boundary_spanners:
                bs.adopt_requirements(org.fact_request_repository)

        # Step 4: Each agent generates a fact
        cycle_facts = []
        for org in self.organizations:
            for agent in org.agents:
                if not agent.is_boundary_spanner:
                    fact = agent.generate_fact(cycle, org.fact_factory)
                    agent.accessible_facts.append(fact)
                    cycle_facts.append((agent, fact, org))

        # Step 5: Check fact requirements for each agent
        for org in self.organizations:
            for agent in org.agents:
                if not agent.is_boundary_spanner:
                    if agent.check_satisfaction():
                        metrics.satisfied_agents += 1

        # Step 6: Intra-org fact sharing
        shared_intra = self._share_intra_org(cycle, cycle_facts)
        metrics.total_facts_shared += shared_intra

        # Step 7: Inter-org fact sharing (via boundary spanners)
        shared_inter, bs_metrics = self._share_inter_org(cycle, cycle_facts)
        metrics.total_facts_shared += shared_inter
        metrics.facts_crossed_boundary += bs_metrics["crossed"]
        metrics.llm_assessments += bs_metrics["assessments"]
        metrics.llm_share_recommended += bs_metrics["recommended"]

        # Step 8: Pedigree audit — classify receivers, detect breaches
        breach_results = self._audit_pedigrees(cycle)
        metrics.intended_receivers = breach_results["intended"]
        metrics.unintended_receivers = breach_results["unintended"]
        metrics.breaches_detected = breach_results["breaches"]
        metrics.tpm_applications = breach_results["tpm_applied"]

        # Step 9: Compute IA and SM (Definitions 27, 29)
        # IA = satisfied agents + intended receivers (disjoint sets)
        # SM = unintended receivers
        # Total facts shared is the denominator for percentages
        metrics.information_availability = (metrics.satisfied_agents +
                                            metrics.intended_receivers)
        metrics.security_measure = metrics.unintended_receivers
        # Ensure total_facts_shared is at least IA + SM for valid percentages
        if metrics.total_facts_shared == 0:
            metrics.total_facts_shared = max(1,
                metrics.information_availability + metrics.security_measure)

        # Step 10: Update inter-organizational trust (Eq. 5 & 6)
        io_trusts = self._update_inter_org_trust()
        metrics.inter_org_trusts = io_trusts

        # Step 11: Expire old facts
        self._expire_facts(cycle)

        return metrics

    # -----------------------------------------------------------------------
    # Intra-org Sharing
    # -----------------------------------------------------------------------
    def _share_intra_org(self, cycle: int,
                         cycle_facts: list) -> int:
        """Share facts among agents within each organization."""
        shared = 0
        for org in self.organizations:
            unsatisfied_agents = [a for a in org.agents
                                  if not a.is_boundary_spanner
                                  and not a.satisfied]

            for agent, fact, fact_org in cycle_facts:
                if fact_org.org_id != org.org_id:
                    continue
                if fact.is_expired(cycle):
                    continue

                # Share with unsatisfied agents
                for recipient in unsatisfied_agents:
                    if recipient.agent_id == agent.agent_id:
                        continue
                    if recipient.receive_fact(
                            fact, cycle, agent.agent_id,
                            self.trust_store,
                            self.trust_store.tt_agent_agent):
                        shared += 1
                        recipient.check_satisfaction()

                # Offer to boundary spanners for inter-org relay
                for bs in org.boundary_spanners:
                    trust_val = self.trust_store.get(agent.agent_id, bs.bs_id)
                    if trust_val >= self.trust_store.tt_agent_bs:
                        if fact not in bs.inbound_facts:
                            bs.inbound_facts.append(fact)
                            if fact not in self.active_facts:
                                self.active_facts.append(fact)

        return shared

    # -----------------------------------------------------------------------
    # Inter-org Sharing (via Boundary Spanners)
    # -----------------------------------------------------------------------
    def _share_inter_org(self, cycle: int, cycle_facts: list) -> Tuple[int, dict]:
        """
        Boundary spanners relay facts across organizational boundaries.
        Hybrid: LLM assesses relevance, rule engine checks trust thresholds.
        """
        shared = 0
        crossed = 0
        assessments = 0
        recommended = 0

        for org_m in self.organizations:
            for org_n in self.organizations:
                if org_m.org_id == org_n.org_id:
                    continue

                io_trust = self.io_trust_tracker.get_trust(
                    org_m.org_id, org_n.org_id)

                for bs_m in org_m.boundary_spanners:
                    for bs_n in org_n.boundary_spanners:
                        for fact in bs_m.inbound_facts:
                            if fact.is_expired(cycle):
                                continue

                            # Update instantaneous BS trust (Eq. 7)
                            from trust_model import instantaneous_bs_trust
                            prev_bs_trust = self.trust_store.get(
                                bs_m.bs_id, bs_n.bs_id)
                            new_bs_trust = instantaneous_bs_trust(
                                io_trust, prev_bs_trust, self.alpha)
                            self.trust_store.set(
                                bs_m.bs_id, bs_n.bs_id, new_bs_trust)

                            # Hybrid relay attempt
                            result = bs_m.assess_and_relay(
                                fact, bs_n.bs_id, org_n.org_id,
                                cycle, self.trust_store,
                                io_trust,
                                self.trust_store.tt_bs_bs_inter,
                                self.trust_store.tt_org_org)

                            assessments += 1
                            if result is not None:
                                shared += 1
                                crossed += 1
                                recommended += 1

                                # Record interaction for IOT growth (Eq. 5)
                                self.io_trust_tracker.record_interaction(
                                    org_m.org_id, org_n.org_id)

                                self._log_event(cycle, "INTER_ORG_SHARE", {
                                    "from_bs": bs_m.bs_id,
                                    "to_bs": bs_n.bs_id,
                                    "from_org": org_m.org_id,
                                    "to_org": org_n.org_id,
                                    "fact_id": fact.fact_id,
                                    "io_trust": round(io_trust, 3),
                                })

        return shared, {
            "crossed": crossed,
            "assessments": assessments,
            "recommended": recommended
        }

    # -----------------------------------------------------------------------
    # Pedigree Audit
    # -----------------------------------------------------------------------
    def _audit_pedigrees(self, cycle: int) -> dict:
        """Audit all active facts, classify receivers, apply TPMs on breaches."""
        total_intended = 0
        total_unintended = 0
        total_breaches = 0
        total_tpm = 0

        for fact in self.active_facts:
            if fact.is_expired(cycle):
                continue

            result = self.pedigree_auditor.audit(
                fact, self.trust_store,
                self.org_registry,
                self.bs_registry,
                self.trust_store)

            total_intended += len(result["intended"])
            total_unintended += len(result["unintended"])

            if result["breach"]:
                total_breaches += 1
                # Apply selected TPM to each unintended receiver
                for ur in result["unintended"]:
                    tpm_result = self.tpm_engine.apply(
                        fact, ur, self.trust_store)
                    if tpm_result.breach_contained:
                        total_tpm += 1
                        self._log_event(cycle, "BREACH_DETECTED", {
                            "fact_id": fact.fact_id,
                            "unintended_receiver": ur,
                            "tpm": self.tpm_engine.tpm_type.name,
                            "trust_updates": tpm_result.trust_updates,
                        })

        return {
            "intended": total_intended,
            "unintended": total_unintended,
            "breaches": total_breaches,
            "tpm_applied": total_tpm
        }

    # -----------------------------------------------------------------------
    # Inter-org Trust Update
    # -----------------------------------------------------------------------
    def _update_inter_org_trust(self) -> Dict[str, float]:
        """Update all inter-org trust values using Equations 5 & 6."""
        io_trusts = {}
        for org_m in self.organizations:
            for org_n in self.organizations:
                if org_m.org_id == org_n.org_id:
                    continue
                self.io_trust_tracker.update_trust(
                    org_m.org_id, org_n.org_id,
                    self.trust_store,
                    org_m.bs_ids,
                    org_n.bs_ids)
                trust_val = self.io_trust_tracker.get_trust(
                    org_m.org_id, org_n.org_id)
                self.trust_store.set(org_m.org_id, org_n.org_id, trust_val)
                key = f"{org_m.org_id}->{org_n.org_id}"
                io_trusts[key] = round(trust_val, 3)
        return io_trusts

    # -----------------------------------------------------------------------
    # Fact Expiration
    # -----------------------------------------------------------------------
    def _expire_facts(self, cycle: int):
        """Remove expired facts from the active pool."""
        self.active_facts = [f for f in self.active_facts
                             if not f.is_expired(cycle)]

    # -----------------------------------------------------------------------
    # Logging
    # -----------------------------------------------------------------------
    def _log_event(self, cycle: int, event_type: str, data: dict):
        self.event_log.append({
            "cycle": cycle,
            "event": event_type,
            **data
        })

    # -----------------------------------------------------------------------
    # Reporting
    # -----------------------------------------------------------------------
    def _print_cycle_summary(self, m: CycleMetrics):
        print(f"  Cycle {m.cycle:3d} | IA: {m.pct_ia:6.1f}% | "
              f"SM: {m.pct_sm:5.1f}% | "
              f"Facts: {m.total_facts_shared:3d} | "
              f"Breaches: {m.breaches_detected:2d} | "
              f"Cross-Org: {m.facts_crossed_boundary:2d} | "
              f"LLM: {m.llm_assessments:2d}↗{m.llm_share_recommended:2d}")

    def _print_final_summary(self):
        if not self.metrics_history:
            return
        final = self.metrics_history[-1]
        total_breaches = sum(m.breaches_detected for m in self.metrics_history)
        total_crossed = sum(m.facts_crossed_boundary for m in self.metrics_history)
        total_llm = sum(m.llm_assessments for m in self.metrics_history)

        print(f"\n{'='*60}")
        print("  FINAL SIMULATION SUMMARY")
        print(f"{'='*60}")
        print(f"  Final IA:            {final.pct_ia:.1f}%")
        print(f"  Final SM:            {final.pct_sm:.1f}%")
        print(f"  Total Breaches:      {total_breaches}")
        print(f"  Facts Crossed Orgs:  {total_crossed}")
        print(f"  Total LLM Calls:     {total_llm}")
        print(f"  Inter-org Trusts:")
        for pair, trust in sorted(final.inter_org_trusts.items()):
            print(f"    {pair}: {trust:.3f}")
        print(f"{'='*60}\n")

    def get_io_trust_history(self) -> Dict[str, List[float]]:
        """Extract inter-org trust time series for visualization."""
        history = {}
        for m in self.metrics_history:
            for pair, trust in m.inter_org_trusts.items():
                if pair not in history:
                    history[pair] = []
                history[pair].append(trust)
        return history
