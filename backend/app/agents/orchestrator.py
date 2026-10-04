from app.agents.message_agent import (
    message_agent,
)

from app.agents.url_agent import (
    url_agent,
)

from app.agents.vision_agent import (
    vision_agent,
)

from app.models.analysis import (
    AgentTraceEntry,
    MessageAnalysisResponse,
    ScreenshotAnalysisResponse,
    URLAnalysisResponse,
)


class ScamShieldOrchestrator:
    """
    Central bounded agentic router.

    It selects the appropriate specialized agent
    based on input type and records the actual
    backend execution path.
    """

    def analyze_message(
        self,
        message: str,
    ) -> MessageAnalysisResponse:

        result = message_agent.analyze(
            message
        )

        result.agent_trace.insert(
            0,
            AgentTraceEntry(
                agent="Orchestrator / Router Agent",
                status="used",
                summary=(
                    "Validated request context and "
                    "routed input to Message Agent."
                ),
            ),
        )

        return result

    def analyze_url(
        self,
        url: str,
    ) -> URLAnalysisResponse:

        result = url_agent.analyze(
            url
        )

        result.agent_trace.insert(
            0,
            AgentTraceEntry(
                agent="Orchestrator / Router Agent",
                status="used",
                summary=(
                    "Validated request context and "
                    "routed input to URL Agent."
                ),
            ),
        )

        return result

    def analyze_screenshot(
        self,
        image_bytes: bytes,
        mime_type: str,
        file_name: str | None,
    ) -> ScreenshotAnalysisResponse:

        result = vision_agent.analyze(
            image_bytes,
            mime_type,
            file_name,
        )

        result.agent_trace.insert(
            0,
            AgentTraceEntry(
                agent="Orchestrator / Router Agent",
                status="used",
                summary=(
                    "Validated request context and "
                    "routed input to Vision Agent."
                ),
            ),
        )

        return result


scamshield_orchestrator = (
    ScamShieldOrchestrator()
)