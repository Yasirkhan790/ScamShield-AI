from app.models.analysis import (
    AgentTraceEntry,
    ScreenshotAnalysisResponse,
)

from app.services.screenshot_analysis_service import (
    analyze_screenshot_content,
)


class VisionAgent:
    """
    Specialized screenshot-analysis agent.

    Responsibilities:
    1. Coordinate screenshot text extraction.
    2. Reuse the ScamShield V2 message-analysis pipeline.
    3. Report the actual backend execution path.
    """

    def analyze(
        self,
        image_bytes: bytes,
        mime_type: str,
        file_name: str | None,
    ) -> ScreenshotAnalysisResponse:

        result = (
            analyze_screenshot_content(
                image_bytes,
                mime_type,
                file_name,
            )
        )

        trace = [
            AgentTraceEntry(
                agent="Vision Agent",
                status="used",
                summary=(
                    "Coordinated screenshot analysis "
                    "and routed extracted text through "
                    "the ScamShield V2 message pipeline."
                ),
            ),

            AgentTraceEntry(
                agent="Multimodal Text Extraction",
                status="used",
                summary=(
                    "Extracted visible screenshot text "
                    f"using "
                    f"{result.text_extraction_provider}."
                ),
            ),

            AgentTraceEntry(
                agent="Deterministic Rules",
                status="used",
                summary=(
                    f"Detected "
                    f"{len(result.indicators)} "
                    f"raw message indicator(s) in "
                    f"the extracted text."
                ),
            ),

            AgentTraceEntry(
                agent="ML Classifier",
                status=result.ml_status,
                summary=(
                    (
                        "Local trained model predicted "
                        f"{result.ml_predicted_label} "
                        f"with model score "
                        f"{result.ml_scam_score:.3f}."
                    )
                    if (
                        result.ml_status == "used"
                        and result.ml_scam_score
                        is not None
                    )
                    else (
                        "Local ML classifier was "
                        f"{result.ml_status}."
                    )
                ),
            ),

            AgentTraceEntry(
                agent="Semantic AI",
                status=result.ai_status,
                summary=(
                    (
                        "Structured semantic analysis "
                        "completed on extracted text."
                    )
                    if result.ai_status == "used"
                    else (
                        "Semantic AI was "
                        f"{result.ai_status}. "
                        "Local analysis continued."
                    )
                ),
            ),

            AgentTraceEntry(
                agent="Evidence Fusion Agent",
                status="used",
                summary=(
                    f"Normalized "
                    f"{len(result.normalized_indicators)} "
                    f"positive indicator(s) and "
                    f"{len(result.mitigating_indicators)} "
                    f"mitigating indicator(s) using "
                    f"taxonomy "
                    f"{result.taxonomy_version}."
                ),
            ),

            AgentTraceEntry(
                agent="Risk Agent",
                status="used",
                summary=(
                    "Applied deterministic fusion rules "
                    f"and produced "
                    f"{result.risk_level} risk at "
                    f"{result.risk_score}/100."
                ),
            ),

            AgentTraceEntry(
                agent="Safety / Automation Agent",
                status="used",
                summary=(
                    (
                        "HIGH/CRITICAL screenshot risk "
                        "triggered a structured incident "
                        "report."
                    )
                    if result.incident_report
                    is not None
                    else (
                        "Screenshot risk did not require "
                        "incident escalation."
                    )
                ),
            ),
        ]

        result.agent_trace = trace

        return result


vision_agent = VisionAgent()