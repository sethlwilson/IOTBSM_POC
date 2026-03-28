"""
llm_interface.py
IOTBSM LLM Interface — Mocked Semantic Intelligence Assessor

In the hybrid architecture, boundary spanners use an LLM to semantically
assess incoming intelligence facts for relevance to their agency's current
requirements. This module mocks those LLM calls for portability.

In production, this would call the Anthropic Claude API with:
  POST https://api.anthropic.com/v1/messages
  model: claude-sonnet-4-20250514

The mock simulates realistic LLM behavior:
  - Relevance scoring based on category/classification matching
  - Threat summary generation
  - Sharing recommendation with reasoning
"""

import random
from dataclasses import dataclass
from typing import Optional
from fact_pedigree import IntelFact, ThreatCategory, ClassificationLevel


# ---------------------------------------------------------------------------
# LLM Assessment Result
# ---------------------------------------------------------------------------
@dataclass
class IntelAssessment:
    """
    Result of a boundary spanner's LLM-powered assessment of an intel fact.
    """
    fact_id: str
    relevance_score: float        # 0.0 to 1.0
    threat_summary: str           # Brief LLM-generated summary
    share_recommendation: bool    # Should this be shared with partner agencies?
    reasoning: str                # LLM's reasoning
    assessed_by: str              # Boundary spanner ID


# ---------------------------------------------------------------------------
# Mock LLM Response Templates
# ---------------------------------------------------------------------------
THREAT_SUMMARIES = {
    ThreatCategory.CYBER_INTRUSION: [
        "Nation-state actor conducting targeted intrusion campaign against defense infrastructure.",
        "Advanced persistent threat leveraging zero-day exploits in classified network segments.",
        "Coordinated cyber operation targeting cleared defense contractors for IP exfiltration.",
    ],
    ThreatCategory.MALWARE: [
        "Novel destructive malware variant with ICS/SCADA targeting capability identified.",
        "Ransomware campaign with military-grade encryption targeting government endpoints.",
        "Sophisticated rootkit with persistence mechanism evading standard detection tools.",
    ],
    ThreatCategory.INSIDER_THREAT: [
        "Behavioral indicators consistent with unauthorized classified data exfiltration.",
        "Anomalous access patterns suggest potential insider with malicious intent.",
        "Cleared personnel exhibiting pre-indicators of espionage activity.",
    ],
    ThreatCategory.PHYSICAL_SECURITY: [
        "Physical reconnaissance activity detected near sensitive facility perimeter.",
        "Suspicious surveillance consistent with pre-operational intelligence gathering.",
        "Unauthorized access attempt to restricted area with RF interception equipment.",
    ],
    ThreatCategory.SIGINT: [
        "Intercepted communications reveal adversary operational awareness.",
        "SIGINT collection indicates adversary has penetrated communications security.",
        "Electronic intelligence confirms adversary monitoring of classified channels.",
    ],
    ThreatCategory.HUMINT: [
        "Human intelligence source confirms active adversary recruitment operations.",
        "HUMINT report indicates foreign intelligence officer targeting cleared personnel.",
        "Asset reports adversary running access agent operation against defense sector.",
    ],
    ThreatCategory.OSINT: [
        "Open source indicators suggest adversary conducting pre-attack reconnaissance.",
        "Social media and forum analysis reveals adversary interest in defense vulnerabilities.",
        "Public intelligence confirms adversary awareness of sensitive program details.",
    ],
    ThreatCategory.SUPPLY_CHAIN: [
        "Compromised hardware component identified in critical defense system supply chain.",
        "Third-party vendor compromise introduces backdoor into classified network infrastructure.",
        "Supply chain integrity failure exposes classified systems to persistent access.",
    ],
}

REASONING_TEMPLATES = [
    "Intelligence aligns with current threat picture for {category}. Sharing recommended to enable coordinated defensive response.",
    "High confidence assessment: this indicator matches known TTPs of priority adversary. Cross-agency awareness critical.",
    "Moderate relevance to agency mission area. Sharing supports whole-of-government threat picture.",
    "Direct operational relevance. Time-sensitive nature requires immediate inter-agency dissemination.",
    "Intelligence fills gap in current threat assessment. Sharing enables deconfliction of collection efforts.",
    "Corroborates existing HUMINT reporting. Cross-agency validation strengthens source credibility.",
    "Novel threat vector requiring specialized agency expertise. Sharing enables collaborative mitigation.",
]

NO_SHARE_REASONING = [
    "Intelligence falls outside agency authorities. Recommend routing through appropriate channels.",
    "Classification level exceeds current inter-agency sharing agreement parameters.",
    "Low relevance to requesting agency mission area. Retain pending relevant requirement.",
    "Source protection concerns preclude sharing at this classification level.",
]


# ---------------------------------------------------------------------------
# Mock LLM Assessor
# ---------------------------------------------------------------------------
class MockLLMAssessor:
    """
    Simulates an LLM-powered boundary spanner intelligence assessor.
    
    In a production system, this would call Claude via:
        POST https://api.anthropic.com/v1/messages
    
    The mock produces realistic outputs based on:
      - Category match between fact and agency focus areas
      - Classification level compatibility
      - Random variance to simulate LLM non-determinism
    """

    def __init__(self, agency_focus_areas: list[ThreatCategory],
                 max_classification: ClassificationLevel,
                 assessor_id: str):
        """
        Args:
            agency_focus_areas:  Categories this agency prioritizes
            max_classification:  Highest classification this BS can handle
            assessor_id:         Boundary spanner ID
        """
        self.focus_areas = agency_focus_areas
        self.max_classification = max_classification
        self.assessor_id = assessor_id

    def assess(self, fact: IntelFact,
               partner_agency: Optional[str] = None) -> IntelAssessment:
        """
        Assess an intel fact for relevance and sharing recommendation.
        
        Mocks what would be a Claude API call with prompt like:
        
        "You are a senior intelligence analyst at a defense agency.
         Assess the following threat intelligence for relevance to
         our agency's current requirements and provide a sharing
         recommendation with reasoning.
         
         Intelligence: {fact.content}
         Classification: {fact.classification.name}
         Category: {fact.category.value}
         Partner Agency: {partner_agency}
         
         Respond in JSON with: relevance_score, summary, recommend_share, reasoning"
        """
        # Simulate relevance scoring
        base_score = self._compute_base_relevance(fact)
        
        # Add LLM-like variance
        noise = random.gauss(0, 0.1)
        relevance = max(0.0, min(1.0, base_score + noise))

        # Classification gate
        if fact.classification.value > self.max_classification.value:
            # Can't process above clearance level
            return IntelAssessment(
                fact_id=fact.fact_id,
                relevance_score=0.0,
                threat_summary="[CLASSIFICATION LEVEL EXCEEDS AUTHORITY]",
                share_recommendation=False,
                reasoning="Intelligence classification exceeds boundary spanner authorization.",
                assessed_by=self.assessor_id
            )

        # Generate mock summary
        summaries = THREAT_SUMMARIES.get(fact.category, ["Threat intelligence requiring assessment."])
        summary = random.choice(summaries)

        # Sharing recommendation
        recommend_share = relevance >= 0.45 and random.random() > 0.15

        # Generate reasoning
        if recommend_share:
            reasoning_template = random.choice(REASONING_TEMPLATES)
            reasoning = reasoning_template.format(category=fact.category.value)
        else:
            reasoning = random.choice(NO_SHARE_REASONING)

        return IntelAssessment(
            fact_id=fact.fact_id,
            relevance_score=round(relevance, 3),
            threat_summary=summary,
            share_recommendation=recommend_share,
            reasoning=reasoning,
            assessed_by=self.assessor_id
        )

    def _compute_base_relevance(self, fact: IntelFact) -> float:
        """Compute base relevance score based on category match."""
        if fact.category in self.focus_areas:
            # Primary focus area — high relevance
            base = random.uniform(0.65, 0.95)
        else:
            # Secondary / out-of-focus — moderate to low relevance
            base = random.uniform(0.25, 0.60)

        # Classification bonus: more sensitive = more relevant (in this domain)
        classification_bonus = fact.classification.value * 0.05
        return base + classification_bonus


# ---------------------------------------------------------------------------
# LLM Assessor Factory
# ---------------------------------------------------------------------------
def create_assessor_for_agency(agency_id: str,
                               bs_id: str) -> MockLLMAssessor:
    """
    Create an agency-appropriate mock LLM assessor.
    Maps agency IDs to realistic focus areas and clearance levels.
    """
    agency_profiles = {
        "Agency_A": {  # Cyber-focused (e.g., NSA/CISA analog)
            "focus": [ThreatCategory.CYBER_INTRUSION,
                      ThreatCategory.MALWARE,
                      ThreatCategory.SUPPLY_CHAIN],
            "clearance": ClassificationLevel.TOP_SECRET,
        },
        "Agency_B": {  # Human intelligence (e.g., CIA analog)
            "focus": [ThreatCategory.HUMINT,
                      ThreatCategory.INSIDER_THREAT,
                      ThreatCategory.SIGINT],
            "clearance": ClassificationLevel.TOP_SECRET,
        },
        "Agency_C": {  # Physical/operational security (e.g., DIA analog)
            "focus": [ThreatCategory.PHYSICAL_SECURITY,
                      ThreatCategory.OSINT,
                      ThreatCategory.INSIDER_THREAT],
            "clearance": ClassificationLevel.SECRET,
        },
    }

    profile = agency_profiles.get(agency_id, {
        "focus": list(ThreatCategory),
        "clearance": ClassificationLevel.SECRET,
    })

    return MockLLMAssessor(
        agency_focus_areas=profile["focus"],
        max_classification=profile["clearance"],
        assessor_id=bs_id
    )
