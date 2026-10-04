from app.agents.safety_automation_agent import (
    safety_automation_agent,
)

from app.services.message_analysis_service import (
    analyze_message_content,
)


def test_high_risk_creates_incident_report(
    monkeypatch,
):
    monkeypatch.setenv(
        "AI_PROVIDER",
        "disabled",
    )

    result = analyze_message_content(
        (
            "URGENT: Your bank account has been suspended. "
            "Send your password and OTP immediately."
        )
    )

    assert result.risk_level in {
        "HIGH",
        "CRITICAL",
    }

    assert (
        result.incident_report
        is not None
    )

    assert (
        result.incident_report.triggered
        is True
    )

    assert (
        result.incident_report.priority
        in {
            "HIGH",
            "CRITICAL",
        }
    )

    assert (
        result.incident_report
        .recommended_actions
    )


def test_low_risk_has_no_incident_report(
    monkeypatch,
):
    monkeypatch.setenv(
        "AI_PROVIDER",
        "disabled",
    )

    result = analyze_message_content(
        "Our project meeting starts at 2 PM tomorrow."
    )

    assert result.risk_level == "LOW"

    assert (
        result.incident_report
        is None
    )


def test_incident_agent_does_not_trigger_for_medium():
    report = (
        safety_automation_agent
        .build_incident_report(
            category="Other / Suspicious",

            risk_score=45,

            risk_level="MEDIUM",

            normalized_indicators=[
                "urgency",
            ],

            mitigating_indicators=[],

            recommended_actions=[
                "Verify the sender independently."
            ],

            input_type="message",
        )
    )

    assert report is None