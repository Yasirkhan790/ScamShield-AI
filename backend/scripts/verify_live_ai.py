"""Verify that the configured real AI provider is reachable and returns validated JSON."""

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from dotenv import load_dotenv

load_dotenv(BACKEND_ROOT.parent / ".env")
load_dotenv(BACKEND_ROOT / ".env")

from app.ai.provider import get_ai_provider
from app.services.message_analysis_service import analyze_message_content


def main() -> None:
    provider = get_ai_provider()
    if provider is None:
        print("AI provider is not configured. Set AI_PROVIDER, AI_API_KEY, and AI_MODEL in .env.")
        raise SystemExit(2)

    print(f"Configured provider: {provider.name}")
    result = analyze_message_content(
        "URGENT: Your bank account has been suspended. Verify your account immediately."
    )
    print(f"AI status: {result.ai_status}")
    print(f"Category: {result.category}")
    print(f"Risk: {result.risk_score}/100 {result.risk_level}")

    if result.ai_status != "used":
        print("Live AI verification failed or fell back to deterministic analysis.")
        raise SystemExit(1)

    print("LIVE AI VERIFICATION PASSED")


if __name__ == "__main__":
    main()
