"""
trust_model.py
IEOTBSM Core Trust Model
Implements the trust relation matrix, logistic growth calculus (Equations 5 & 6),
and instantaneous inter-boundary-spanner trust (Equation 7).

Based on: Hexmoor, H., Wilson, S., & Bhattaram, S. (2006).
A theoretical inter-organizational trust-based security model.
The Knowledge Engineering Review, 21(2), 127-161.
"""

import math
import random
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional


# ---------------------------------------------------------------------------
# Trust value type alias
# ---------------------------------------------------------------------------
TrustValue = float  # always in [0.0, 1.0]


def clamp(value: float) -> TrustValue:
    """Clamp a trust value to [0.0, 1.0]."""
    return max(0.0, min(1.0, value))


# ---------------------------------------------------------------------------
# Equation 5 – Logistic (Verhulst) inter-organizational trust growth
# ---------------------------------------------------------------------------
def inter_org_trust(tau_0: float, r: float, i: int) -> TrustValue:
    """
    Equation 5: Logistic growth of inter-organizational trust.

    τ_i(o_m, o_n, r_i^mn) = τ_0^mn / (τ_0^mn + (1 - τ_0^mn) * e^(-r * i))

    Args:
        tau_0: Initial trust between organizations o_m and o_n (τ_0^mn)
        r:     Growth rate (average of inter-BS trust relations, from Eq. 6)
        i:     Total number of interactions (fact-sharing events)

    Returns:
        Current inter-organizational trust value in [0.0, 1.0]
    """
    if i <= 0:
        return clamp(tau_0)
    denom = tau_0 + (1.0 - tau_0) * math.exp(-r * i)
    if denom == 0:
        return 1.0
    return clamp(tau_0 / denom)


# ---------------------------------------------------------------------------
# Equation 6 – Rate of inter-organizational trust growth
# ---------------------------------------------------------------------------
def compute_growth_rate(bs_trust_matrix: Dict[Tuple[str, str], TrustValue],
                        bs_ids_m: list,
                        bs_ids_n: list) -> float:
    """
    Equation 6: Average inter-BS trust used as the growth rate r.

    r_i^mn = (Σ_j Σ_k τ(b_j^m, b_k^n)) / (xy)^x

    where x = |BS in o_m|, y = |BS in o_n|

    Args:
        bs_trust_matrix: Dict mapping (bs_id_m, bs_id_n) -> trust value
        bs_ids_m:        Boundary spanner IDs for the trustor organization
        bs_ids_n:        Boundary spanner IDs for the trustee organization

    Returns:
        Growth rate r (a small positive float)
    """
    x = len(bs_ids_m)
    y = len(bs_ids_n)
    if x == 0 or y == 0:
        return 0.0

    total = 0.0
    count = 0
    for bm in bs_ids_m:
        for bn in bs_ids_n:
            trust = bs_trust_matrix.get((bm, bn), 0.0)
            total += trust
            count += 1

    if count == 0:
        return 0.0

    avg = total / count
    # Scale down by (xy)^x per Equation 6
    scale = (x * y) ** x
    return avg / scale if scale > 0 else avg


# ---------------------------------------------------------------------------
# Equation 7 – Instantaneous inter-boundary-spanner trust
# ---------------------------------------------------------------------------
def instantaneous_bs_trust(io_trust: TrustValue,
                           prev_bs_trust: TrustValue,
                           alpha: float = 0.6) -> TrustValue:
    """
    Equation 7: Instantaneous trust of a boundary spanner in another BS,
    weighted by inter-organizational trust.

    τ_i(b_j^m, b_k^n) = τ_i(o_m, o_n) * α + τ_{i-1}(b_j^m, b_k^n) * (1 - α)

    Alpha represents the weight given to inter-organizational trust.
    Literature suggests alpha > 0.5 (IOT has greater influence).

    Args:
        io_trust:      Current inter-organizational trust τ_i(o_m, o_n)
        prev_bs_trust: Previous inter-BS trust τ_{i-1}(b_j^m, b_k^n)
        alpha:         Weight for IOT influence (default 0.6, per paper guidance)

    Returns:
        Updated instantaneous inter-BS trust value in [0.0, 1.0]
    """
    return clamp(io_trust * alpha + prev_bs_trust * (1.0 - alpha))


# ---------------------------------------------------------------------------
# Trust Relation Store
# ---------------------------------------------------------------------------
@dataclass
class TrustRelationStore:
    """
    Manages all trust relations in the IEOTBSM:
      ITR1: agent_i  -> agent_j  (same org)
      ITR2: agent_i  -> bs_j     (same org)
      ITR3: bs_i     -> agent_j  (same org)
      ITR4: bs_i^m   -> bs_j^n   (different orgs)
      ITR5: org_m    -> org_n

    Trust relations are:
      - Reflexive  (entity trusts itself = 1.0)
      - NOT symmetric
      - NOT transitive
    """
    relations: Dict[Tuple[str, str], TrustValue] = field(default_factory=dict)

    # Trust thresholds (TT1–TT5)
    tt_agent_agent: float = 0.4      # TT1
    tt_agent_bs: float = 0.4         # TT2/3
    tt_bs_bs_inter: float = 0.5      # TT4 (inter-org BS threshold)
    tt_org_org: float = 0.3          # TT5

    def set(self, entity_x: str, entity_y: str, value: TrustValue):
        """Set trust of x in y."""
        if entity_x == entity_y:
            self.relations[(entity_x, entity_y)] = 1.0  # reflexivity
        else:
            self.relations[(entity_x, entity_y)] = clamp(value)

    def get(self, entity_x: str, entity_y: str) -> TrustValue:
        """Get trust of x in y. Returns 0.0 if no relation exists."""
        if entity_x == entity_y:
            return 1.0
        return self.relations.get((entity_x, entity_y), 0.0)

    def has_relation(self, entity_x: str, entity_y: str) -> bool:
        """Check if a trust relation exists between x and y."""
        return (entity_x, entity_y) in self.relations

    def update(self, entity_x: str, entity_y: str, delta: float):
        """Reduce trust of x in y by delta (used by TPMs)."""
        current = self.get(entity_x, entity_y)
        new_val = max(0.0, current - delta)
        self.relations[(entity_x, entity_y)] = new_val

    def initialize_random(self, entity_x: str, entity_y: str,
                          low: float = 0.3, high: float = 1.0):
        """Initialize a trust relation with a random value."""
        self.set(entity_x, entity_y, random.uniform(low, high))

    def get_all_relations_from(self, entity_x: str) -> Dict[str, TrustValue]:
        """Get all trust relations originating from entity_x."""
        return {ey: v for (ex, ey), v in self.relations.items() if ex == entity_x}

    def meets_threshold(self, entity_x: str, entity_y: str,
                        threshold: float) -> bool:
        """Check if trust of x in y meets or exceeds threshold."""
        return self.get(entity_x, entity_y) >= threshold


# ---------------------------------------------------------------------------
# Inter-organizational Trust Tracker
# ---------------------------------------------------------------------------
@dataclass
class InterOrgTrustTracker:
    """
    Tracks inter-organizational trust over time using the logistic growth model.
    Maintains interaction counts and growth rates per org pair.
    """
    initial_trusts: Dict[Tuple[str, str], float] = field(default_factory=dict)
    interaction_counts: Dict[Tuple[str, str], int] = field(default_factory=dict)
    current_trusts: Dict[Tuple[str, str], float] = field(default_factory=dict)
    growth_rates: Dict[Tuple[str, str], float] = field(default_factory=dict)

    def initialize_pair(self, org_m: str, org_n: str,
                        tau_0: Optional[float] = None):
        """Initialize trust between two organizations."""
        if tau_0 is None:
            tau_0 = random.uniform(0.1, 0.5)  # low initial trust
        self.initial_trusts[(org_m, org_n)] = tau_0
        self.current_trusts[(org_m, org_n)] = tau_0
        self.interaction_counts[(org_m, org_n)] = 0
        self.growth_rates[(org_m, org_n)] = 0.0

    def record_interaction(self, org_m: str, org_n: str):
        """Record a fact-sharing interaction between boundary spanners."""
        key = (org_m, org_n)
        self.interaction_counts[key] = self.interaction_counts.get(key, 0) + 1

    def update_trust(self, org_m: str, org_n: str,
                     bs_trust_store: TrustRelationStore,
                     bs_ids_m: list, bs_ids_n: list):
        """
        Recompute inter-organizational trust using Equations 5 & 6.
        """
        key = (org_m, org_n)
        tau_0 = self.initial_trusts.get(key, 0.2)
        i = self.interaction_counts.get(key, 0)

        # Build BS trust matrix for Equation 6
        bs_matrix = {}
        for bm in bs_ids_m:
            for bn in bs_ids_n:
                bs_matrix[(bm, bn)] = bs_trust_store.get(bm, bn)

        r = compute_growth_rate(bs_matrix, bs_ids_m, bs_ids_n)
        self.growth_rates[key] = r
        self.current_trusts[key] = inter_org_trust(tau_0, r, i)

    def get_trust(self, org_m: str, org_n: str) -> float:
        """Get current inter-organizational trust."""
        return self.current_trusts.get((org_m, org_n), 0.0)

    def get_history(self) -> Dict[Tuple[str, str], dict]:
        """Return full trust state for reporting."""
        result = {}
        for key in self.current_trusts:
            result[key] = {
                "initial": self.initial_trusts.get(key, 0.0),
                "current": self.current_trusts[key],
                "interactions": self.interaction_counts.get(key, 0),
                "growth_rate": self.growth_rates.get(key, 0.0)
            }
        return result
