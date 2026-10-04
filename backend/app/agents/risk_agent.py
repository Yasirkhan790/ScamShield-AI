from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.agents.evidence_fusion_agent import (
    EvidenceFusionResult,
)

from app.models.analysis import (
    AIObservation,
    RiskLevel,
)


CATEGORY_RULES = {
    "social_engineering": {
        "weight": 8,
        "cap": 24,
    },

    "credential_theft": {
        "weight": 18,
        "cap": 36,
    },

    "financial_fraud": {
        "weight": 16,
        "cap": 36,
    },

    "impersonation": {
        "weight": 12,
        "cap": 24,
    },

    "account_takeover": {
        "weight": 16,
        "cap": 32,
    },

    "job_scam": {
        "weight": 15,
        "cap": 30,
    },

    "investment_scam": {
        "weight": 17,
        "cap": 34,
    },

    "prize_scam": {
        "weight": 15,
        "cap": 30,
    },

    "romance_scam": {
        "weight": 14,
        "cap": 28,
    },

    "malware_and_device_access": {
        "weight": 20,
        "cap": 40,
    },

    "identity_theft": {
        "weight": 18,
        "cap": 36,
    },

    "delivery_scam": {
        "weight": 14,
        "cap": 28,
    },

    "marketplace_scam": {
        "weight": 14,
        "cap": 28,
    },

    "loan_scam": {
        "weight": 15,
        "cap": 30,
    },

    "charity_scam": {
        "weight": 12,
        "cap": 24,
    },

    "url_risk": {
        "weight": 12,
        "cap": 40,
    },
}


@dataclass(frozen=True)
class RiskDecision:
    score: int
    level: RiskLevel
    adjustments: list[str]


def _risk_level(
    score: int,
) -> RiskLevel:

    if score <= 29:
        return "LOW"

    if score <= 59:
        return "MEDIUM"

    if score <= 79:
        return "HIGH"

    return "CRITICAL"


def _taxonomy_score(
    fusion: EvidenceFusionResult,
) -> int:

    score = 0

    for (
        category,
        count,
    ) in fusion.category_counts.items():

        config = CATEGORY_RULES.get(
            category
        )

        if not config:
            continue

        contribution = min(
            count
            * config["weight"],
            config["cap"],
        )

        score += contribution

    return min(
        score,
        100,
    )


class RiskAgent:
    """
    Final deterministic ScamShield V2 risk agent.

    Rules:
    1. Existing strong V1 deterministic scores are preserved.
    2. Taxonomy + ML may strengthen weak/ambiguous cases.
    3. AI enriches semantic evidence but never changes the
       numeric score directly.
    4. Mitigation context can reduce false positives.
    """

    def calculate(
        self,
        legacy_score: int,
        fusion: EvidenceFusionResult,
        ml_result: Any = None,
        ai_observations: list[
            AIObservation
        ] | None = None,
    ) -> RiskDecision:

        # Kept for interface compatibility and explainability.
        ai_observations = (
            ai_observations
            or []
        )

        adjustments: list[str] = []

        # ====================================================
        # 1. MITIGATION-ONLY MESSAGE
        #
        # Example:
        # Never share your OTP with anyone.
        # ====================================================

        if (
            not fusion.normalized_indicators
            and fusion.mitigating_indicators
        ):

            score = min(
                legacy_score,
                10,
            )

            adjustments.append(
                "Mitigation context suppressed "
                "suspicious keyword-only signals."
            )

            return RiskDecision(
                score=score,

                level=_risk_level(
                    score
                ),

                adjustments=adjustments,
            )

        # ====================================================
        # 2. PRESERVE ESTABLISHED HIGH-RISK V1 RESULTS
        #
        # Existing regression-tested deterministic cases
        # scoring 60+ remain unchanged.
        #
        # Additional ML / taxonomy / AI evidence is still
        # exposed in the response and agent trace.
        # ====================================================

        if legacy_score >= 60:

            score = legacy_score

            if fusion.normalized_indicators:

                adjustments.append(
                    "V2 taxonomy evidence confirmed "
                    "the existing deterministic risk "
                    "without changing the established score."
                )

            if (
                ml_result is not None
                and getattr(
                    ml_result,
                    "status",
                    None,
                )
                == "used"
            ):

                adjustments.append(
                    "ML evidence was recorded as "
                    "supporting evidence only."
                )

            if ai_observations:

                adjustments.append(
                    "Semantic AI observations enriched "
                    "the explanation without changing "
                    "the deterministic score."
                )

            return RiskDecision(
                score=score,

                level=_risk_level(
                    score
                ),

                adjustments=adjustments,
            )

        # ====================================================
        # 3. WEAK / AMBIGUOUS CASES
        #
        # V2 taxonomy may strengthen cases that V1 rules
        # under-detected, such as paraphrased credential
        # requests.
        # ====================================================

        taxonomy_score = (
            _taxonomy_score(
                fusion
            )
        )

        score = max(
            legacy_score,
            taxonomy_score,
        )

        if (
            taxonomy_score
            > legacy_score
        ):

            adjustments.append(
                "Normalized taxonomy evidence raised "
                "the weak deterministic base score."
            )

        categories = set(
            fusion.category_counts
        )

        # ====================================================
        # 4. COMPOUND V2 RULES
        # ====================================================

        if (
            "credential_theft"
            in categories
            and "account_takeover"
            in categories
        ):

            score += 12

            adjustments.append(
                "Credential theft combined with "
                "account-takeover pressure: +12."
            )

        if (
            "prize_scam"
            in categories
            and "financial_fraud"
            in categories
        ):

            score += 18

            adjustments.append(
                "Prize claim combined with "
                "payment request: +18."
            )

        if (
            "job_scam"
            in categories
            and "financial_fraud"
            in categories
        ):

            score += 15

            adjustments.append(
                "Job offer combined with "
                "payment request: +15."
            )

        if (
            "investment_scam"
            in categories
            and "financial_fraud"
            in categories
        ):

            score += 15

            adjustments.append(
                "Investment promise combined with "
                "payment pressure: +15."
            )

        if (
            "malware_and_device_access"
            in categories
            and (
                "account_takeover"
                in categories
                or "impersonation"
                in categories
            )
        ):

            score += 15

            adjustments.append(
                "Device-access request combined with "
                "account or impersonation signals: +15."
            )

        # ====================================================
        # 5. TRAINED ML SUPPORT
        #
        # Only fixed deterministic bonuses are allowed.
        # The raw model score never becomes risk_score.
        # ====================================================

        if (
            ml_result is not None
            and getattr(
                ml_result,
                "status",
                None,
            )
            == "used"
            and getattr(
                ml_result,
                "predicted_label",
                None,
            )
            == "scam"
        ):

            scam_score = float(
                getattr(
                    ml_result,
                    "scam_score",
                    0.0,
                )
                or 0.0
            )

            threshold = float(
                getattr(
                    ml_result,
                    "selected_threshold",
                    0.5,
                )
                or 0.5
            )

            if scam_score >= 0.90:

                bonus = 12

            elif scam_score >= 0.75:

                bonus = 8

            elif scam_score >= threshold:

                bonus = 5

            else:

                bonus = 0

            if bonus:

                score += bonus

                adjustments.append(
                    "Trained ML scam evidence applied "
                    "through a fixed deterministic rule: "
                    f"+{bonus}."
                )

        # ====================================================
        # 6. AI DOES NOT MODIFY NUMERIC SCORE
        # ====================================================

        if ai_observations:

            adjustments.append(
                "Semantic AI observations enriched "
                "the evidence explanation but did "
                "not alter the numeric risk score."
            )

        # ====================================================
        # 7. MITIGATION DEDUCTION
        # ====================================================

        if fusion.mitigating_indicators:

            deduction = min(
                35,

                len(
                    fusion.mitigating_indicators
                )
                * 12,
            )

            score -= deduction

            adjustments.append(
                "Verified mitigation context reduced "
                f"the deterministic score by "
                f"{deduction}."
            )

        # ====================================================
        # 8. CLAMP 0-100
        # ====================================================

        score = max(
            0,

            min(
                int(
                    round(
                        score
                    )
                ),
                100,
            ),
        )

        return RiskDecision(
            score=score,

            level=_risk_level(
                score
            ),

            adjustments=adjustments,
        )


risk_agent = RiskAgent()