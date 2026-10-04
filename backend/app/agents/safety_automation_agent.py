from __future__ import annotations

from app.models.analysis import (
    IncidentReport,
    RiskLevel,
)


class SafetyAutomationAgent:
    """
    Creates a structured incident report for HIGH or
    CRITICAL ScamShield results.

    This agent does not send messages, contact banks,
    call police, or perform irreversible external actions.
    It produces a safe structured escalation package for
    the user and application.
    """

    def build_incident_report(
        self,
        *,
        category: str,
        risk_score: int,
        risk_level: RiskLevel,
        normalized_indicators: list[str],
        mitigating_indicators: list[str],
        recommended_actions: list[str],
        input_type: str,
    ) -> IncidentReport | None:

        # Only HIGH / CRITICAL cases trigger automation.
        if risk_level not in {
            "HIGH",
            "CRITICAL",
        }:
            return None

        evidence = list(
            normalized_indicators[:10]
        )

        if not evidence:
            evidence = [
                "Multiple suspicious signals detected"
            ]

        if risk_level == "CRITICAL":
            escalation_reason = (
                "The analysis reached CRITICAL risk. "
                "Multiple high-risk indicators or compound "
                "fraud patterns require immediate caution."
            )

            title = (
                "Critical Scam Risk Incident"
            )

        else:
            escalation_reason = (
                "The analysis reached HIGH risk and "
                "contains strong scam or phishing evidence "
                "that should be independently verified."
            )

            title = (
                "High Scam Risk Incident"
            )

        actions = list(
            recommended_actions[:6]
        )

        # Add core escalation actions if they are not already
        # present in equivalent wording.
        defaults = [
            (
                "Stop interacting with the sender or "
                "destination until it is independently verified."
            ),
            (
                "Do not send money, passwords, OTPs, PINs, "
                "card details, recovery codes, or identity documents."
            ),
            (
                "Contact the relevant organization using its "
                "official website, app, or trusted phone number."
            ),
            (
                "Preserve screenshots, messages, URLs, transaction "
                "details, and timestamps as evidence."
            ),
        ]

        existing = {
            item.strip().lower()
            for item in actions
        }

        for item in defaults:
            if item.lower() not in existing:
                actions.append(
                    item
                )

            if len(actions) >= 6:
                break

        mitigation_note = ""

        if mitigating_indicators:
            mitigation_note = (
                " Mitigating context was also detected and "
                "was considered before escalation."
            )

        summary = (
            f"ScamShield classified this {input_type} analysis "
            f"as {risk_level} risk with an application-defined "
            f"score of {risk_score}/100. "
            f"Primary category: {category}."
            f"{mitigation_note}"
        )

        return IncidentReport(
            triggered=True,

            priority=risk_level,

            title=title,

            summary=summary,

            category=category,

            risk_score=risk_score,

            risk_level=risk_level,

            evidence=evidence,

            recommended_actions=
                actions[:6],

            escalation_reason=
                escalation_reason,
        )


safety_automation_agent = (
    SafetyAutomationAgent()
)