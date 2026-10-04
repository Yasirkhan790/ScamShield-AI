from app.ai.service import analyze_url_with_ai

from app.agents.evidence_fusion_agent import (
    evidence_fusion_agent,
)

from app.agents.risk_agent import (
    risk_agent,
)

from app.agents.safety_automation_agent import (
    safety_automation_agent,
)

from app.models.analysis import (
    AIObservation,
    URLAnalysisResponse,
)

from app.tools.url_analyzer import (
    analyze_url,
)

from app.tools.url_risk_engine import (
    calculate_url_risk,
)

from app.tools.url_safety_advisor import (
    generate_url_safety_advice,
)


DISCLAIMER = (
    "ScamShield provides an AI-assisted heuristic risk "
    "assessment based on the submitted URL string and "
    "detected indicators. It does not prove that a website "
    "is safe or malicious and does not visit the destination."
)


def classify_url_risk(
    score: int,
    indicator_codes: set[str],
) -> tuple[str, list[str]]:

    phishing_signals = {
        "domain_mismatch",
        "userinfo_obfuscation",
        "ip_address_host",
        "suspicious_keywords",
        "punycode_domain",
    }

    if (
        score >= 60
        and indicator_codes
        & phishing_signals
    ):
        return (
            "Phishing",
            [
                "Other / Suspicious",
            ],
        )

    if score >= 30:
        return (
            "Other / Suspicious",
            [],
        )

    return (
        "No Strong Scam Pattern Detected",
        [],
    )


def build_url_summary(
    category: str,
    score: int,
    indicator_count: int,
    host: str,
) -> str:

    if indicator_count == 0:
        return (
            f"No strong structural warning was detected "
            f"in {host}. This result does not verify the "
            f"destination or guarantee that it is safe."
        )

    return (
        f"The URL contains {indicator_count} structural "
        f"warning signal(s) associated with {category}. "
        f"The application-defined risk score is "
        f"{score}/100. ScamShield inspected the URL "
        f"structure only and did not visit the destination."
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

        normalized = (
            action.strip()
        )

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


def analyze_url_content(
    url: str,
) -> URLAnalysisResponse:

    # ========================================================
    # 1. LOCAL URL ANALYSIS
    # ========================================================

    (
        normalized_url,
        host,
        uses_https,
        indicators,
    ) = analyze_url(
        url
    )

    legacy_score, _ = (
        calculate_url_risk(
            indicators
        )
    )

    codes = {
        item.code
        for item in indicators
    }

    category, secondary = (
        classify_url_risk(
            legacy_score,
            codes,
        )
    )

    deterministic_actions = (
        generate_url_safety_advice(
            indicators
        )
    )

    # ========================================================
    # 2. SEMANTIC AI
    #
    # Safe fallback remains active if provider is disabled
    # or quota is unavailable.
    # ========================================================

    ai_result = (
        analyze_url_with_ai(
            normalized_url,
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
    # 3. EVIDENCE FUSION
    # ========================================================

    fusion = (
        evidence_fusion_agent
        .fuse_url(
            url=normalized_url,

            indicators=indicators,

            ai_observations=
                ai_observations,
        )
    )

    # ========================================================
    # 4. DETERMINISTIC RISK AGENT
    # ========================================================

    risk = (
        risk_agent.calculate(
            legacy_score=
                legacy_score,

            fusion=fusion,

            ml_result=None,

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

    # Keep AI semantic category when AI succeeded.
    # Otherwise classify from deterministic URL evidence.
    if (
        ai_result.analysis
        is None
    ):
        category, secondary = (
            classify_url_risk(
                score,
                codes,
            )
        )

    summary = (
        ai_summary
        or build_url_summary(
            category,
            score,
            len(
                fusion.normalized_indicators
                or indicators
            ),
            host,
        )
    )

    # ========================================================
    # 5. SAFETY / INCIDENT AUTOMATION
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

            input_type="URL",
        )
    )

    # ========================================================
    # 6. FINAL RESPONSE
    # ========================================================

    return URLAnalysisResponse(
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

        normalized_url=
            normalized_url,

        host=
            host,

        uses_https=
            uses_https,

        analysis_steps=[
            "Validate and normalize URL",

            "Inspect hostname, protocol, and obfuscation signals",

            "Request structured semantic AI analysis when configured",

            "Normalize evidence against ScamShield V2 taxonomy",

            "Fuse URL heuristic and semantic evidence",

            "Calculate final deterministic URL risk",

            "Run HIGH/CRITICAL incident automation",

            "Generate final URL safety guidance",
        ],
    )