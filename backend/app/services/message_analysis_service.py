from app.ai.service import analyze_message_with_ai

from app.agents.evidence_fusion_agent import (
    evidence_fusion_agent,
)

from app.agents.risk_agent import (
    risk_agent,
)

from app.agents.safety_automation_agent import (
    safety_automation_agent,
)

from app.ml.classifier import (
    analyze_text_with_ml,
)

from app.models.analysis import (
    AIObservation,
    MessageAnalysisResponse,
)

from app.tools.message_analyzer import (
    analyze_message,
)

from app.tools.risk_engine import (
    calculate_risk,
)

from app.tools.safety_advisor import (
    generate_safety_advice,
)

from app.tools.scam_classifier import (
    classify_scam,
)


DISCLAIMER = (
    "ScamShield provides an AI-assisted risk assessment "
    "based on available indicators. It cannot guarantee "
    "that content is safe or malicious. The score is an "
    "application-defined indicator, not a probability."
)


def build_summary(
    category: str,
    score: int,
    indicator_count: int,
) -> str:

    if indicator_count == 0:
        return (
            "No strong scam pattern was detected. "
            "Continue to verify unusual requests "
            "independently."
        )

    return (
        f"The message shows {indicator_count} "
        f"suspicious indicator(s) associated with "
        f"{category}. The application-defined risk "
        f"score is {score}/100. It is not a verified "
        f"probability of fraud."
    )


def _merge_actions(
    base: list[str],
    extra: list[str],
) -> list[str]:

    merged: list[str] = []

    for action in [
        *base,
        *extra,
    ]:

        normalized = action.strip()

        if (
            normalized
            and normalized.lower()
            not in {
                item.lower()
                for item in merged
            }
        ):
            merged.append(
                normalized
            )

    return merged[:6]


def analyze_message_content(
    message: str,
) -> MessageAnalysisResponse:

    # ========================================================
    # 1. DETERMINISTIC RULE ENGINE
    # ========================================================

    indicators = analyze_message(
        message
    )

    legacy_score, _ = (
        calculate_risk(
            indicators
        )
    )

    category, secondary = (
        classify_scam(
            indicators
        )
    )

    deterministic_actions = (
        generate_safety_advice(
            indicators
        )
    )

    # ========================================================
    # 2. TRAINED LOCAL ML CLASSIFIER
    #
    # ML provides supporting evidence only.
    # It does not directly set the final 0-100 risk score.
    # ========================================================

    ml_result = (
        analyze_text_with_ml(
            message
        )
    )

    # ========================================================
    # 3. SEMANTIC / GENERATIVE AI
    #
    # If the provider is disabled, quota-limited, or fails,
    # the local pipeline continues safely.
    # ========================================================

    ai_result = (
        analyze_message_with_ai(
            message,
            indicators,
        )
    )

    ai_observations: list[
        AIObservation
    ] = []

    ai_summary: str | None = None

    actions = list(
        deterministic_actions
    )

    if (
        ai_result.analysis
        is not None
    ):

        analysis = (
            ai_result.analysis
        )

        category = (
            analysis.category
        )

        secondary = (
            analysis.secondary_categories
        )

        ai_summary = (
            analysis.summary
        )

        ai_observations = [
            AIObservation(
                name=item.name,
                description=item.description,
                severity=item.severity,
            )
            for item
            in analysis.observations
        ]

        actions = _merge_actions(
            deterministic_actions,
            analysis.recommended_actions,
        )

    # ========================================================
    # 4. EVIDENCE FUSION AGENT
    #
    # Combines:
    # - deterministic rules
    # - taxonomy normalization
    # - trained ML evidence
    # - semantic AI observations
    # - mitigating context
    # ========================================================

    fusion = (
        evidence_fusion_agent
        .fuse_message(
            message=message,

            indicators=indicators,

            ml_result=ml_result,

            ai_observations=
                ai_observations,
        )
    )

    # ========================================================
    # 5. DETERMINISTIC RISK AGENT
    #
    # Final application score is produced only through
    # fixed and explainable rules.
    # ========================================================

    risk = (
        risk_agent.calculate(
            legacy_score=
                legacy_score,

            fusion=fusion,

            ml_result=
                ml_result,

            ai_observations=
                ai_observations,
        )
    )

    score = (
        risk.score
    )

    level = (
        risk.level
    )

    # ========================================================
    # 6. MITIGATION-AWARE FINAL CLASSIFICATION
    #
    # Example:
    # "Never share your OTP or password with anyone."
    #
    # This contains scam-related vocabulary but is legitimate
    # security advice.
    # ========================================================

    if (
        fusion.mitigating_indicators
        and not fusion.normalized_indicators
        and score <= 29
    ):

        category = (
            "No Strong Scam Pattern Detected"
        )

        secondary = []

        summary = (
            "The message appears to contain "
            "legitimate security or scam-awareness "
            "guidance rather than a request to perform "
            "a suspicious action."
        )

    elif ai_summary:

        summary = (
            ai_summary
        )

    else:

        evidence_count = (
            len(
                fusion.normalized_indicators
            )
            if fusion.normalized_indicators
            else len(
                indicators
            )
        )

        summary = build_summary(
            category,
            score,
            evidence_count,
        )

    # ========================================================
    # 7. HIGH / CRITICAL INCIDENT AUTOMATION
    #
    # Creates a structured incident report only.
    # It does not perform external irreversible actions.
    # ========================================================

    incident_report = (
        safety_automation_agent
        .build_incident_report(
            category=category,

            risk_score=score,

            risk_level=level,

            normalized_indicators=
                fusion.normalized_indicators,

            mitigating_indicators=
                fusion.mitigating_indicators,

            recommended_actions=
                actions,

            input_type="message",
        )
    )

    # ========================================================
    # 8. FINAL RESPONSE
    # ========================================================

    return MessageAnalysisResponse(
        summary=summary,

        category=category,

        secondary_categories=
            secondary,

        risk_score=
            score,

        risk_level=
            level,

        indicators=
            indicators,

        ai_observations=
            ai_observations,

        ai_status=
            ai_result.status,

        ai_provider=
            ai_result.provider,

        ml_status=
            ml_result.status,

        ml_model_version=
            ml_result.model_version,

        ml_scam_score=
            ml_result.scam_score,

        ml_predicted_label=
            ml_result.predicted_label,

        ml_selected_threshold=
            ml_result.selected_threshold,

        taxonomy_version=
            fusion.taxonomy_version,

        normalized_indicators=
            fusion.normalized_indicators,

        mitigating_indicators=
            fusion.mitigating_indicators,

        evidence_sources=
            fusion.evidence_sources,

        risk_adjustments=
            risk.adjustments,

        incident_report=
            incident_report,

        recommended_actions=
            actions,

        disclaimer=
            DISCLAIMER,

        analysis_steps=[
            "Inspect message content",

            "Detect deterministic warning signals",

            "Run trained local ML classifier",

            "Request structured semantic AI analysis when configured",

            "Normalize evidence against ScamShield V2 taxonomy",

            "Detect mitigating security or awareness context",

            "Fuse deterministic, ML, AI, and taxonomy evidence",

            "Calculate final deterministic risk score",

            "Run HIGH/CRITICAL incident automation when required",

            "Generate final safety guidance",
        ],
    )