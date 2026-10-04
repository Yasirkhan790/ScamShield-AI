from app.models.analysis import (
    AgentTraceEntry,
    MessageAnalysisResponse,
)

from app.services.message_analysis_service import (
    analyze_message_content,
)


class MessageAgent:
    """
    Specialized agent responsible for coordinating
    message-based scam analysis.

    The underlying message-analysis service performs:

    - deterministic rule analysis
    - trained local ML inference
    - semantic AI analysis when available
    - V2 taxonomy normalization
    - mitigating-context detection
    - evidence fusion
    - deterministic final risk scoring
    - HIGH/CRITICAL incident automation
    """

    def analyze(
        self,
        message: str,
    ) -> MessageAnalysisResponse:

        result = analyze_message_content(
            message
        )

        trace: list[
            AgentTraceEntry
        ] = []

        # ====================================================
        # MESSAGE AGENT
        # ====================================================

        trace.append(
            AgentTraceEntry(
                agent="Message Agent",

                status="used",

                summary=(
                    "Coordinated message analysis across "
                    "deterministic rules, trained ML, "
                    "taxonomy normalization, semantic AI, "
                    "risk scoring, and safety automation."
                ),
            )
        )

        # ====================================================
        # DETERMINISTIC RULE ENGINE
        # ====================================================

        trace.append(
            AgentTraceEntry(
                agent="Deterministic Rules",

                status="used",

                summary=(
                    f"Detected "
                    f"{len(result.indicators)} "
                    f"raw rule-based indicator(s)."
                ),
            )
        )

        # ====================================================
        # TRAINED ML CLASSIFIER
        # ====================================================

        if (
            result.ml_status == "used"
            and result.ml_scam_score
            is not None
        ):

            ml_summary = (
                "Local trained model predicted "
                f"{result.ml_predicted_label} "
                f"with supporting model score "
                f"{result.ml_scam_score:.3f} "
                f"using frozen threshold "
                f"{result.ml_selected_threshold:.2f}."
            )

        elif (
            result.ml_status
            == "disabled"
        ):

            ml_summary = (
                "Local ML classifier is disabled. "
                "Analysis continued using available "
                "deterministic components."
            )

        else:

            ml_summary = (
                "Local ML classifier was unavailable "
                "or entered fallback mode. "
                "Analysis continued safely."
            )

        trace.append(
            AgentTraceEntry(
                agent="ML Classifier",

                status=result.ml_status,

                summary=ml_summary,
            )
        )

        # ====================================================
        # SEMANTIC AI
        # ====================================================

        if (
            result.ai_status
            == "used"
        ):

            ai_summary = (
                "Structured semantic AI analysis "
                "completed successfully."
            )

        elif (
            result.ai_status
            == "disabled"
        ):

            ai_summary = (
                "Semantic AI is disabled. "
                "The local ScamShield pipeline "
                "continued without it."
            )

        else:

            ai_summary = (
                "Semantic AI entered fallback mode. "
                "Local rules, ML, taxonomy, and "
                "deterministic scoring continued."
            )

        trace.append(
            AgentTraceEntry(
                agent="Semantic AI",

                status=result.ai_status,

                summary=ai_summary,
            )
        )

        # ====================================================
        # EVIDENCE FUSION AGENT
        # ====================================================

        positive_count = len(
            result.normalized_indicators
        )

        mitigation_count = len(
            result.mitigating_indicators
        )

        sources = (
            ", ".join(
                result.evidence_sources
            )
            if result.evidence_sources
            else "local evidence"
        )

        trace.append(
            AgentTraceEntry(
                agent="Evidence Fusion Agent",

                status="used",

                summary=(
                    f"Normalized "
                    f"{positive_count} "
                    f"positive indicator(s) and "
                    f"{mitigation_count} "
                    f"mitigating indicator(s) using "
                    f"taxonomy "
                    f"{result.taxonomy_version or 'unknown'}. "
                    f"Evidence sources: {sources}."
                ),
            )
        )

        # ====================================================
        # RISK AGENT
        # ====================================================

        if result.risk_adjustments:

            adjustment_summary = (
                " ".join(
                    result.risk_adjustments[
                        :3
                    ]
                )
            )

        else:

            adjustment_summary = (
                "No additional deterministic "
                "risk adjustments were required."
            )

        trace.append(
            AgentTraceEntry(
                agent="Risk Agent",

                status="used",

                summary=(
                    "Applied deterministic evidence-fusion "
                    f"rules and produced "
                    f"{result.risk_level} risk at "
                    f"{result.risk_score}/100. "
                    f"{adjustment_summary}"
                ),
            )
        )

        # ====================================================
        # SAFETY / AUTOMATION AGENT
        # ====================================================

        if (
            result.incident_report
            is not None
        ):

            incident = (
                result.incident_report
            )

            automation_summary = (
                f"{incident.priority} risk triggered "
                "a structured incident report with "
                f"{len(incident.evidence)} "
                f"evidence item(s) and "
                f"{len(incident.recommended_actions)} "
                f"recommended action(s)."
            )

        else:

            automation_summary = (
                "Risk level did not require "
                "HIGH/CRITICAL incident escalation."
            )

        trace.append(
            AgentTraceEntry(
                agent="Safety / Automation Agent",

                status="used",

                summary=automation_summary,
            )
        )

        # ====================================================
        # ASSIGN REAL BACKEND EXECUTION TRACE
        # ====================================================

        result.agent_trace = trace

        return result


message_agent = MessageAgent()