from app.models.analysis import (
    AgentTraceEntry,
    URLAnalysisResponse,
)

from app.services.url_analysis_service import (
    analyze_url_content,
)


class URLAgent:
    """
    Specialized URL analysis agent.

    ScamShield inspects the submitted URL string and
    does not visit the destination website.
    """

    def analyze(
        self,
        url: str,
    ) -> URLAnalysisResponse:

        result = (
            analyze_url_content(
                url
            )
        )

        trace = [
            AgentTraceEntry(
                agent="URL Agent",

                status="used",

                summary=(
                    "Coordinated local structural "
                    "URL analysis."
                ),
            ),

            AgentTraceEntry(
                agent="URL Heuristics",

                status="used",

                summary=(
                    f"Detected "
                    f"{len(result.indicators)} "
                    f"structural URL warning signal(s) "
                    f"without visiting the destination."
                ),
            ),

            AgentTraceEntry(
                agent="Semantic AI",

                status=result.ai_status,

                summary=(
                    (
                        "Structured semantic URL "
                        "analysis completed."
                    )
                    if result.ai_status == "used"
                    else (
                        "Semantic AI was "
                        f"{result.ai_status}. "
                        "Local URL analysis continued."
                    )
                ),
            ),

            AgentTraceEntry(
                agent="Evidence Fusion Agent",

                status="used",

                summary=(
                    f"Normalized "
                    f"{len(result.normalized_indicators)} "
                    f"URL indicator(s) using taxonomy "
                    f"{result.taxonomy_version}."
                ),
            ),

            AgentTraceEntry(
                agent="Risk Agent",

                status="used",

                summary=(
                    "Applied deterministic URL evidence "
                    f"rules and produced "
                    f"{result.risk_level} risk at "
                    f"{result.risk_score}/100."
                ),
            ),

            AgentTraceEntry(
                agent="Safety / Automation Agent",

                status="used",

                summary=(
                    (
                        "HIGH/CRITICAL URL risk triggered "
                        "a structured incident report."
                    )
                    if result.incident_report
                    is not None
                    else (
                        "URL risk did not require "
                        "incident escalation."
                    )
                ),
            ),
        ]

        result.agent_trace = (
            trace
        )

        return result


url_agent = URLAgent()