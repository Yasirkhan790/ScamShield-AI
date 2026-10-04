from app.agents.orchestrator import (
    scamshield_orchestrator,
)

from app.models.analysis import (
    MessageAnalysisResponse,
    ScreenshotAnalysisResponse,
    URLAnalysisResponse,
)


class ScamShieldAgent:
    """
    Backward-compatible facade used by existing API
    endpoints.

    Internally all requests now pass through the
    ScamShield multi-agent orchestrator.
    """

    def analyze_message(
        self,
        message: str,
    ) -> MessageAnalysisResponse:

        return (
            scamshield_orchestrator
            .analyze_message(
                message
            )
        )

    def analyze_url(
        self,
        url: str,
    ) -> URLAnalysisResponse:

        return (
            scamshield_orchestrator
            .analyze_url(
                url
            )
        )

    def analyze_screenshot(
        self,
        image_bytes: bytes,
        mime_type: str,
        file_name: str | None,
    ) -> ScreenshotAnalysisResponse:

        return (
            scamshield_orchestrator
            .analyze_screenshot(
                image_bytes,
                mime_type,
                file_name,
            )
        )


scamshield_agent = ScamShieldAgent()