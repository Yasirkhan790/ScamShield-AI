from app.models.analysis import MessageAnalysisResponse, ScreenshotAnalysisResponse, URLAnalysisResponse
from app.services.message_analysis_service import analyze_message_content
from app.services.screenshot_analysis_service import analyze_screenshot_content
from app.services.url_analysis_service import analyze_url_content


class ScamShieldAgent:
    """Small agentic orchestrator for the hackathon MVP."""

    def analyze_message(self, message: str) -> MessageAnalysisResponse:
        return analyze_message_content(message)

    def analyze_url(self, url: str) -> URLAnalysisResponse:
        return analyze_url_content(url)

    def analyze_screenshot(
        self,
        image_bytes: bytes,
        mime_type: str,
        file_name: str | None,
    ) -> ScreenshotAnalysisResponse:
        return analyze_screenshot_content(image_bytes, mime_type, file_name)


scamshield_agent = ScamShieldAgent()
