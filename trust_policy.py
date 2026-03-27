"""
trust_policy.py
IEOTBSM Trust Policy Models (TPM1, TPM2, TPM3)

Implements Definitions 24-25 and Equations 9-13 from the IEOTBSM.
Trust policy models regulate interaction trust relations after a security
breach (unintended receiver) is detected.

TPM1: Exponential reduction based on degree of responsibility (most lenient)
TPM2: Uniform reduction for all entities in path
TPM3: Initiator reduces trust in all path members directly (most restrictive)

Based on: Hexmoor, H., Wilson, S., & Bhattaram, S. (2006).
A theoretical inter-organizational trust-based security model.
The Knowledge Engineering Review, 21(2), 127-161.
"""

from enum import Enum
from typing import List, Dict
from dataclasses import dataclass


class TPMType(Enum):
    TPM1 = "TPM1 - Proportional Responsibility"
    TPM2 = "TPM2 - Uniform Responsibility"
    TPM3 = "TPM3 - Initiator-Direct Reduction"


@dataclass
class TPMResult:
    """Records the outcome of a trust policy model application."""
    tpm_type: TPMType
    fact_id: str
    initiator: str
    unintended_receiver: str
    path: List[str]
    trust_updates: Dict[str, float]  # entity_pair_str -> delta applied
    breach_contained: bool


class TrustPolicyEngine:
    """
    Applies trust policy models (TPM1, TPM2, TPM3) when a security breach
    is detected (i.e., an unintended receiver exists in a fact's pedigree).

    Equations implemented:
      Eq. 9:  Degree of Responsibility (depth in fact path)
      Eq. 10: Trust update value = δ^(depth_j - depth_k + 1)
      Eq. 11: τ(e_{k-1}, e_k) = τ(e_{k-1}, e_k) - TrustUpdate(e_k)  [TPM1]
      Eq. 12: τ(e_{k-1}, e_k) = τ(e_{k-1}, e_k) - δ                  [TPM2]
      Eq. 13: τ(e_i, e_k)     = τ(e_i, e_k) - δ                      [TPM3]
    """

    def __init__(self, tpm_type: TPMType = TPMType.TPM1,
                 decrement_factor: float = 0.1):
        """
        Args:
            tpm_type:         Which trust policy model to apply
            decrement_factor: δ (user-defined trust decrement, in [0.0, 1.0])
        """
        self.tpm_type = tpm_type
        self.delta = decrement_factor

    def apply(self, fact, unintended_receiver: str,
              trust_store) -> TPMResult:
        """
        Apply the selected TPM to a fact that has an unintended receiver.

        Args:
            fact:               IntelFact with pedigree
            unintended_receiver: entity_id of the unintended receiver
            trust_store:        TrustRelationStore to update

        Returns:
            TPMResult documenting all trust updates made
        """
        path = fact.get_fact_path()
        initiator = fact.initiator_id
        updates = {}

        if unintended_receiver not in path:
            return TPMResult(
                tpm_type=self.tpm_type,
                fact_id=fact.fact_id,
                initiator=initiator,
                unintended_receiver=unintended_receiver,
                path=path,
                trust_updates={},
                breach_contained=False
            )

        ur_depth = path.index(unintended_receiver)  # Eq. 9: depth of UR

        if self.tpm_type == TPMType.TPM1:
            updates = self._apply_tpm1(path, ur_depth, trust_store)
        elif self.tpm_type == TPMType.TPM2:
            updates = self._apply_tpm2(path, ur_depth, trust_store)
        elif self.tpm_type == TPMType.TPM3:
            updates = self._apply_tpm3(initiator, path, ur_depth, trust_store)

        return TPMResult(
            tpm_type=self.tpm_type,
            fact_id=fact.fact_id,
            initiator=initiator,
            unintended_receiver=unintended_receiver,
            path=path,
            trust_updates=updates,
            breach_contained=True
        )

    def _apply_tpm1(self, path: List[str], ur_depth: int,
                    trust_store) -> Dict[str, float]:
        """
        TPM1 (Equations 9-11): Exponential reduction proportional to
        degree of responsibility.

        Entities later in the chain bear greater responsibility.
        Trust update = δ^(depth_j - depth_k + 1) for each consecutive pair.
        """
        updates = {}
        # Walk backwards from unintended receiver to initiator
        for k in range(ur_depth, 0, -1):
            entity_k = path[k]
            entity_prev = path[k - 1]

            # Eq. 9: degree of responsibility = depth in path
            depth_k = k
            depth_j = ur_depth  # unintended receiver depth

            # Eq. 10: trust update
            exponent = depth_j - depth_k + 1
            trust_update = (self.delta ** exponent)

            # Eq. 11: apply update
            trust_store.update(entity_prev, entity_k, trust_update)
            pair_key = f"({entity_prev},{entity_k})"
            updates[pair_key] = trust_update

        return updates

    def _apply_tpm2(self, path: List[str], ur_depth: int,
                    trust_store) -> Dict[str, float]:
        """
        TPM2 (Equation 12): Uniform reduction for every consecutive pair
        in the path leading to the unintended receiver.

        More restrictive than TPM1 — equal blame for all path members.
        """
        updates = {}
        for k in range(ur_depth, 0, -1):
            entity_k = path[k]
            entity_prev = path[k - 1]

            # Eq. 12: uniform decrement
            trust_store.update(entity_prev, entity_k, self.delta)
            pair_key = f"({entity_prev},{entity_k})"
            updates[pair_key] = self.delta

        return updates

    def _apply_tpm3(self, initiator: str, path: List[str],
                    ur_depth: int, trust_store) -> Dict[str, float]:
        """
        TPM3 (Equation 13): Initiator directly reduces trust in every
        entity in the path up to the unintended receiver.

        Most restrictive — targets the initiator's own trust relations
        to cut off the channel at its source.
        """
        updates = {}
        for k in range(1, ur_depth + 1):
            entity_k = path[k]
            if trust_store.has_relation(initiator, entity_k):
                # Eq. 13: initiator reduces trust in path member
                trust_store.update(initiator, entity_k, self.delta)
                pair_key = f"({initiator},{entity_k})"
                updates[pair_key] = self.delta

        return updates

    def set_tpm(self, tpm_type: TPMType):
        """Switch the active trust policy model."""
        self.tpm_type = tpm_type

    def set_decrement(self, delta: float):
        """Update the trust decrement factor."""
        self.delta = max(0.0, min(1.0, delta))
