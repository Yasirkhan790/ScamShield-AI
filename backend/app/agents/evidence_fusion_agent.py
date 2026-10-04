from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
import json
import re

from app.models.analysis import (
    AIObservation,
    Indicator,
)


# ============================================================
# TAXONOMY PATH
# ============================================================

TAXONOMY_PATH = (
    Path(__file__).resolve().parents[1]
    / "knowledge"
    / "indicator_taxonomy.json"
)


# ============================================================
# RESULT MODEL
# ============================================================

@dataclass(frozen=True)
class EvidenceFusionResult:
    taxonomy_version: str
    normalized_indicators: list[str]
    mitigating_indicators: list[str]
    evidence_sources: list[str]
    category_counts: dict[str, int]


# ============================================================
# LOAD TAXONOMY
# ============================================================

@lru_cache(maxsize=1)
def _load_taxonomy() -> dict:
    if not TAXONOMY_PATH.exists():
        raise RuntimeError(
            f"Indicator taxonomy not found: {TAXONOMY_PATH}"
        )

    return json.loads(
        TAXONOMY_PATH.read_text(
            encoding="utf-8"
        )
    )


@lru_cache(maxsize=1)
def _taxonomy_indexes():
    taxonomy = _load_taxonomy()

    indicator_to_category: dict[str, str] = {}

    for category, indicators in taxonomy.get(
        "positive_indicators",
        {},
    ).items():

        for indicator in indicators:
            indicator_to_category[indicator] = category

    mitigating_indicators = set(
        taxonomy.get(
            "mitigating_indicators",
            [],
        )
    )

    return (
        taxonomy,
        indicator_to_category,
        mitigating_indicators,
    )


# ============================================================
# V1 RULE -> V2 TAXONOMY
# ============================================================

RULE_MAP: dict[str, list[str]] = {
    "urgency": [
        "urgency",
        "time_pressure",
    ],

    "account_threat": [
        "account_suspension_claim",
        "fear_or_threat",
    ],

    "credential_request": [
        "login_credentials_request",
    ],

    "payment_request": [
        "upfront_payment",
    ],

    "prize_claim": [
        "unexpected_prize",
    ],

    "job_scam_signal": [
        "guaranteed_job",
    ],

    "investment_claim": [
        "guaranteed_returns",
    ],

    "impersonation_language": [
        "company_impersonation",
    ],
}


# ============================================================
# URL RULE -> V2 TAXONOMY
# ============================================================

URL_RULE_MAP: dict[str, str] = {
    "no_https":
        "non_https_sensitive_page",

    "ip_address_host":
        "ip_address_url",

    "excessive_subdomains":
        "excessive_subdomains",

    "punycode_domain":
        "punycode_domain",

    "unusual_characters":
        "encoded_url",

    "suspicious_keywords":
        "suspicious_path",

    "url_shortener":
        "url_shortener",

    "domain_mismatch":
        "brand_domain_mismatch",

    "userinfo_obfuscation":
        "misleading_subdomain",

    "unusual_port":
        "unusual_port",
}


# ============================================================
# MESSAGE SEMANTIC NORMALIZATION
# ============================================================

SEMANTIC_PATTERNS: list[
    tuple[str, str]
] = [

    # --------------------------------------------------------
    # SOCIAL ENGINEERING
    # --------------------------------------------------------

    (
        "urgency",
        r"\b(urgent|urgently|immediately|act now|right now|final warning)\b",
    ),

    (
        "time_pressure",
        r"\b(within \d+ (?:minutes?|hours?)|today only|limited time|deadline)\b",
    ),

    (
        "fear_or_threat",
        r"\b(suspended|blocked|locked|legal action|lose access|arrest)\b",
    ),

    (
        "authority_pressure",
        r"\b(police|government|tax authority|security department)\b",
    ),

    (
        "secrecy_request",
        r"\b(do not tell|don't tell|keep this secret|confidential between us)\b",
    ),

    (
        "communication_channel_change",
        r"\b(move to whatsapp|continue on whatsapp|continue on telegram|private chat)\b",
    ),


    # --------------------------------------------------------
    # CREDENTIAL THEFT
    # --------------------------------------------------------

    (
        "password_request",
        r"\bpassword\b",
    ),

    (
        "otp_request",
        r"\botp\b",
    ),

    (
        "pin_request",
        r"\bpin\b",
    ),

    (
        "verification_code_request",
        (
            r"\b(?:verification|security|confirmation|authentication)"
            r"\s*(?:code|number|digits?)\b"
            r"|"
            r"\bsix[- ]digit\s+(?:code|number|digits?)\b"
        ),
    ),

    (
        "recovery_code_request",
        r"\brecovery code\b",
    ),

    (
        "security_answer_request",
        r"\bsecurity (?:answer|question answer)\b",
    ),

    (
        "card_details_request",
        r"\b(card details|credit card|debit card|card number)\b",
    ),

    (
        "cvv_request",
        r"\bcvv\b",
    ),

    (
        "login_credentials_request",
        r"\b(login credentials?|username and password|sign[- ]in details)\b",
    ),

    (
        "fake_identity_verification",
        r"\bverify (?:your )?(?:identity|account|profile)\b",
    ),


    # --------------------------------------------------------
    # FINANCIAL FRAUD
    # --------------------------------------------------------

    (
        "upfront_payment",
        r"\b(upfront payment|pay first|payment first)\b",
    ),

    (
        "processing_fee",
        r"\bprocessing (?:fee|charge)\b",
    ),

    (
        "registration_fee",
        r"\bregistration (?:fee|charge|payment)\b",
    ),

    (
        "release_fee",
        r"\b(release fee|release charge|clearance fee|clearance charge)\b",
    ),

    (
        "bank_transfer_request",
        r"\b(bank transfer|wire transfer|transfer to this account)\b",
    ),

    (
        "crypto_payment_request",
        r"\b(bitcoin|crypto|cryptocurrency|usdt|crypto wallet)\b",
    ),

    (
        "gift_card_request",
        r"\bgift cards?\b",
    ),

    (
        "refund_fee",
        r"\brefund.{0,25}(?:fee|charge|payment)\b",
    ),

    (
        "advance_payment",
        r"\b(advance payment|pay in advance|advance fee)\b",
    ),


    # --------------------------------------------------------
    # ACCOUNT TAKEOVER
    # --------------------------------------------------------

    (
        "account_suspension_claim",
        r"\baccount.{0,30}(?:suspended|blocked|locked|closed)\b",
    ),

    (
        "fake_security_alert",
        r"\b(unusual activity|security alert|suspicious login|unusual login)\b",
    ),

    (
        "fake_verification_request",
        r"\bverify (?:your )?(?:account|identity|login|profile)\b",
    ),

    (
        "password_reset_request",
        r"\b(reset your password|password reset required)\b",
    ),

    (
        "account_recovery_request",
        r"\b(restore your account|recover your account|account recovery)\b",
    ),


    # --------------------------------------------------------
    # PRIZE SCAM
    # --------------------------------------------------------

    (
        "unexpected_prize",
        r"\b(won|winner|cash reward|cash prize|prize)\b",
    ),

    (
        "lottery_claim",
        r"\blottery\b",
    ),

    (
        "giveaway_claim",
        r"\bgiveaway\b",
    ),

    (
        "claim_fee",
        r"\b(claim fee|claim charge|claim payment)\b",
    ),

    (
        "reward_activation_fee",
        r"\breward.{0,30}(?:activation fee|activation charge)\b",
    ),

    (
        "unexpected_cash_reward",
        r"\b(cash reward|cash award|cash bonus)\b",
    ),


    # --------------------------------------------------------
    # JOB SCAM
    # --------------------------------------------------------

    (
        "unrealistic_salary",
        r"\b(?:earn|salary).{0,20}(?:\$?\d{3,}|per day|daily)\b",
    ),

    (
        "guaranteed_job",
        r"\b(guaranteed job|guaranteed employment|guaranteed hiring)\b",
    ),

    (
        "no_interview_job",
        r"\b(no interview|without an interview)\b",
    ),

    (
        "registration_payment",
        (
            r"\b(?:job|position|work)"
            r".{0,50}"
            r"registration (?:fee|payment|charge)\b"
        ),
    ),

    (
        "training_fee",
        r"\btraining (?:fee|charge|payment)\b",
    ),

    (
        "equipment_payment",
        r"\b(?:pay|purchase|buy).{0,30}equipment\b",
    ),

    (
        "job_offer_without_application",
        (
            r"\b(?:hired|selected for (?:a )?(?:job|position))"
            r".{0,50}"
            r"(?:without applying|immediately)\b"
        ),
    ),

    (
        "move_to_private_chat",
        r"\b(continue on whatsapp|continue on telegram|move to private chat)\b",
    ),


    # --------------------------------------------------------
    # INVESTMENT SCAM
    # --------------------------------------------------------

    (
        "guaranteed_returns",
        r"\bguaranteed.{0,25}(?:return|profit|income)\b",
    ),

    (
        "risk_free_investment",
        r"\b(no risk|risk[- ]free investment|zero risk)\b",
    ),

    (
        "unrealistic_profit",
        r"\b\d+\s*percent return\b|\b\d+%\s*(?:return|profit)\b",
    ),

    (
        "investment_pressure",
        r"\b(?:invest|deposit).{0,30}(?:today|now|immediately)\b",
    ),

    (
        "crypto_investment_request",
        r"\b(crypto investment|bitcoin investment|crypto trading opportunity)\b",
    ),


    # --------------------------------------------------------
    # IMPERSONATION
    # --------------------------------------------------------

    (
        "bank_impersonation",
        r"\b(your bank|bank security|bank department|bank officer)\b",
    ),

    (
        "government_impersonation",
        r"\b(government department|tax authority|government officer)\b",
    ),

    (
        "police_impersonation",
        r"\b(police department|police officer|law enforcement officer)\b",
    ),

    (
        "technical_support_impersonation",
        r"\b(technical support|support team|support agent)\b",
    ),

    (
        "recruiter_impersonation",
        r"\b(recruiter|recruitment department|recruitment officer|hr manager)\b",
    ),

    (
        "delivery_company_impersonation",
        r"\b(delivery company|courier company|parcel service)\b",
    ),


    # --------------------------------------------------------
    # MALWARE / DEVICE ACCESS
    # --------------------------------------------------------

    (
        "apk_install_request",
        r"\binstall.{0,20}\.apk\b|\binstall this apk\b",
    ),

    (
        "unknown_software_install",
        r"\binstall (?:this|the) (?:application|app|software|program)\b",
    ),

    (
        "remote_access_request",
        r"\b(remote access|remote control)\b",
    ),

    (
        "screen_share_request",
        r"\bshare your screen\b",
    ),

    (
        "disable_antivirus_request",
        r"\bdisable (?:your )?(?:antivirus|security software)\b",
    ),

    (
        "macro_enable_request",
        r"\b(enable macros|enable the macro)\b",
    ),


    # --------------------------------------------------------
    # IDENTITY THEFT
    # --------------------------------------------------------

    (
        "national_id_request",
        r"\b(national id|national identity)\b",
    ),

    (
        "cnic_request",
        r"\bcnic\b",
    ),

    (
        "passport_request",
        r"\bpassport\b",
    ),

    (
        "selfie_verification_request",
        r"\b(?:send|upload).{0,20}selfie\b",
    ),

    (
        "bank_statement_request",
        r"\bbank statement\b",
    ),

    (
        "identity_document_request",
        r"\b(identity card|id card|identity document)\b",
    ),

    (
        "personal_information_request",
        r"\b(personal information|personal details|date of birth)\b",
    ),


    # --------------------------------------------------------
    # DELIVERY SCAM
    # --------------------------------------------------------

    (
        "unexpected_package",
        r"\b(unexpected package|package waiting|parcel waiting)\b",
    ),

    (
        "delivery_fee_request",
        r"\bdelivery (?:fee|charge|payment)\b",
    ),

    (
        "customs_fee_request",
        r"\bcustoms (?:fee|charge|payment)\b",
    ),

    (
        "redelivery_payment",
        r"\bredelivery (?:fee|charge|payment)\b",
    ),

    (
        "fake_tracking_link",
        r"\b(tracking link|track your parcel here)\b",
    ),


    # --------------------------------------------------------
    # MARKETPLACE
    # --------------------------------------------------------

    (
        "off_platform_payment",
        r"\bpay outside (?:the )?(?:platform|marketplace)\b",
    ),

    (
        "fake_escrow",
        r"\b(fake escrow|use our escrow)\b",
    ),

    (
        "overpayment_refund",
        r"\boverpaid.{0,30}refund\b",
    ),


    # --------------------------------------------------------
    # LOAN SCAM
    # --------------------------------------------------------

    (
        "guaranteed_loan",
        r"\bguaranteed loan\b",
    ),

    (
        "advance_fee_loan",
        r"\bloan.{0,40}(?:advance fee|upfront fee)\b",
    ),

    (
        "loan_processing_fee",
        r"\bloan processing fee\b",
    ),

    (
        "loan_without_checks",
        r"\b(loan without checks|no credit check loan)\b",
    ),


    # --------------------------------------------------------
    # CHARITY
    # --------------------------------------------------------

    (
        "urgent_donation_pressure",
        r"\b(?:donate|donation).{0,30}(?:urgent|immediately|today)\b",
    ),

    (
        "personal_account_donation",
        r"\bdonation.{0,40}personal (?:bank )?account\b",
    ),

    (
        "crypto_donation_request",
        r"\bdonation.{0,30}(?:bitcoin|crypto|cryptocurrency)\b",
    ),


    # --------------------------------------------------------
    # ROMANCE
    # --------------------------------------------------------

    (
        "rapid_emotional_attachment",
        r"\b(i love you already|we are meant to be|soulmate)\b",
    ),

    (
        "emergency_money_request",
        r"\b(?:emergency|urgent).{0,40}(?:send money|need money|financial help)\b",
    ),

    (
        "travel_money_request",
        r"\b(?:send|need).{0,20}money.{0,30}(?:travel|ticket|flight)\b",
    ),

    (
        "medical_money_request",
        r"\b(?:send|need).{0,20}money.{0,30}(?:medical|hospital|treatment)\b",
    ),
]


# ============================================================
# MITIGATION PATTERNS
# ============================================================

MITIGATION_PATTERNS: list[
    tuple[str, str]
] = [

    (
        "never_share_otp_warning",
        (
            r"\b("
            r"never|do not|don't|should not|"
            r"shouldn't|will never"
            r")"
            r".{0,30}"
            r"(share|send|give|provide)"
            r".{0,40}"
            r"(otp|password|verification code|security code|pin)"
        ),
    ),

    (
        "legitimate_security_advice",
        (
            r"\b("
            r"for your security|"
            r"security reminder|"
            r"security advice|"
            r"never share|"
            r"do not share|"
            r"will never ask|"
            r"official banking app|"
            r"official website"
            r")\b"
        ),
    ),

    (
        "security_education_context",
        (
            r"\b("
            r"security awareness|"
            r"security education|"
            r"fraud awareness|"
            r"scam awareness|"
            r"phishing awareness"
            r")\b"
        ),
    ),

    (
        "user_reporting_scam",
        (
            r"\b("
            r"i am reporting|"
            r"i'm reporting|"
            r"reporting"
            r")"
            r".{0,25}"
            r"(scam|fraud|phishing)\b"
        ),
    ),

    (
        "quoted_scam_example",
        (
            r"\b("
            r"example of a scam|"
            r"example of scam|"
            r"example of phishing|"
            r"scam example|"
            r"phishing example"
            r")\b"
        ),
    ),

    (
        "expected_transaction_confirmation",
        (
            r"\b("
            r"i recognize|"
            r"i made|"
            r"i authorized|"
            r"i expected"
            r")"
            r".{0,35}"
            r"(transaction|payment|purchase)\b"
        ),
    ),

    (
        "user_initiated_verification",
        (
            r"\b("
            r"i requested|"
            r"i initiated|"
            r"i started"
            r")"
            r".{0,35}"
            r"(verification|password reset|login)\b"
        ),
    ),
]


# ============================================================
# HELPERS
# ============================================================

def _valid_positive_indicator(
    indicator: str,
) -> bool:

    (
        _,
        indicator_to_category,
        _,
    ) = _taxonomy_indexes()

    return (
        indicator
        in indicator_to_category
    )


def _valid_mitigation(
    indicator: str,
) -> bool:

    (
        _,
        _,
        mitigating_indicators,
    ) = _taxonomy_indexes()

    return (
        indicator
        in mitigating_indicators
    )


def _add_valid(
    output: set[str],
    values: list[str],
) -> None:

    for value in values:

        if _valid_positive_indicator(
            value
        ):
            output.add(
                value
            )


def _semantic_matches(
    text: str,
) -> set[str]:

    found: set[str] = set()

    for (
        indicator,
        pattern,
    ) in SEMANTIC_PATTERNS:

        if re.search(
            pattern,
            text,
            re.IGNORECASE,
        ):

            if _valid_positive_indicator(
                indicator
            ):
                found.add(
                    indicator
                )

    return found


def _mitigation_matches(
    text: str,
) -> set[str]:

    found: set[str] = set()

    for (
        indicator,
        pattern,
    ) in MITIGATION_PATTERNS:

        if (
            _valid_mitigation(
                indicator
            )
            and re.search(
                pattern,
                text,
                re.IGNORECASE,
            )
        ):

            found.add(
                indicator
            )

    return found


def _active_solicitation(
    text: str,
) -> bool:
    """
    Detect whether the message is actively asking the
    recipient to perform a suspicious action.

    Negated safety instructions are removed first.

    Example:

        Never share your OTP.

    should NOT count as active solicitation.
    """

    cleaned = re.sub(
        (
            r"\b("
            r"never|do not|don't|"
            r"should not|shouldn't|will never"
            r")\s+"
            r"(share|send|give|provide|pay|"
            r"transfer|click|install)"
        ),
        "",
        text,
        flags=re.IGNORECASE,
    )

    return bool(
        re.search(
            (
                r"\b("
                r"send|share|provide|forward|"
                r"reply with|pay|transfer|deposit|"
                r"install|click|give me|give us|"
                r"upload|buy"
                r")\b"
            ),
            cleaned,
            re.IGNORECASE,
        )
    )


def _category_counts(
    indicators: set[str],
) -> dict[str, int]:

    (
        _,
        indicator_to_category,
        _,
    ) = _taxonomy_indexes()

    counts: dict[str, int] = {}

    for indicator in indicators:

        category = (
            indicator_to_category.get(
                indicator
            )
        )

        if not category:
            continue

        counts[category] = (
            counts.get(
                category,
                0,
            )
            + 1
        )

    return counts


# ============================================================
# EVIDENCE FUSION AGENT
# ============================================================

class EvidenceFusionAgent:
    """
    Combines evidence from:

    - deterministic rules
    - local taxonomy matching
    - trained ML
    - structured AI observations
    - mitigating context

    This agent DOES NOT set the final numeric risk score.
    That is handled by RiskAgent.
    """

    # ========================================================
    # MESSAGE
    # ========================================================

    def fuse_message(
        self,
        message: str,
        indicators: list[Indicator],
        ml_result: Any,
        ai_observations: list[
            AIObservation
        ],
    ) -> EvidenceFusionResult:

        (
            taxonomy,
            _,
            _,
        ) = _taxonomy_indexes()

        normalized: set[str] = set()

        evidence_sources: set[str] = set()

        # ----------------------------------------------------
        # Mitigation context
        # ----------------------------------------------------

        mitigating = (
            _mitigation_matches(
                message
            )
        )

        if mitigating:

            evidence_sources.add(
                "mitigation-context"
            )

        # ----------------------------------------------------
        # Existing deterministic rules
        # ----------------------------------------------------

        for indicator in indicators:

            mapped = RULE_MAP.get(
                indicator.code,
                [],
            )

            if mapped:

                _add_valid(
                    normalized,
                    mapped,
                )

        if indicators:

            evidence_sources.add(
                "deterministic-rules"
            )

        # ----------------------------------------------------
        # Local semantic/taxonomy matching
        # ----------------------------------------------------

        semantic = (
            _semantic_matches(
                message
            )
        )

        if semantic:

            normalized.update(
                semantic
            )

            evidence_sources.add(
                "taxonomy-normalizer"
            )

        # ----------------------------------------------------
        # AI observations
        # ----------------------------------------------------

        if ai_observations:

            for observation in (
                ai_observations
            ):

                observation_text = (
                    f"{observation.name} "
                    f"{observation.description}"
                )

                normalized.update(
                    _semantic_matches(
                        observation_text
                    )
                )

            evidence_sources.add(
                "semantic-ai"
            )

        # ----------------------------------------------------
        # ML evidence source
        # ----------------------------------------------------

        if (
            getattr(
                ml_result,
                "status",
                None,
            )
            == "used"
        ):

            evidence_sources.add(
                "trained-ml"
            )

        # ----------------------------------------------------
        # Mitigation suppression
        # ----------------------------------------------------

        if (
            mitigating
            and not _active_solicitation(
                message
            )
        ):

            normalized.clear()

        return EvidenceFusionResult(
            taxonomy_version=str(
                taxonomy.get(
                    "version",
                    "unknown",
                )
            ),

            normalized_indicators=sorted(
                normalized
            ),

            mitigating_indicators=sorted(
                mitigating
            ),

            evidence_sources=sorted(
                evidence_sources
            ),

            category_counts=
                _category_counts(
                    normalized
                ),
        )

    # ========================================================
    # URL
    # ========================================================

    def fuse_url(
        self,
        url: str,
        indicators: list[Indicator],
        ai_observations: list[
            AIObservation
        ],
    ) -> EvidenceFusionResult:

        (
            taxonomy,
            _,
            _,
        ) = _taxonomy_indexes()

        normalized: set[str] = set()

        evidence_sources: set[str] = set()

        # ----------------------------------------------------
        # URL heuristic mapping
        # ----------------------------------------------------

        for indicator in indicators:

            mapped = (
                URL_RULE_MAP.get(
                    indicator.code
                )
            )

            if (
                mapped
                and _valid_positive_indicator(
                    mapped
                )
            ):

                normalized.add(
                    mapped
                )

        if indicators:

            evidence_sources.add(
                "url-heuristics"
            )

        # ----------------------------------------------------
        # URL text semantic matching
        # ----------------------------------------------------

        semantic = (
            _semantic_matches(
                url
            )
        )

        if semantic:

            normalized.update(
                semantic
            )

            evidence_sources.add(
                "taxonomy-normalizer"
            )

        # ----------------------------------------------------
        # AI observations
        # ----------------------------------------------------

        if ai_observations:

            for observation in (
                ai_observations
            ):

                observation_text = (
                    f"{observation.name} "
                    f"{observation.description}"
                )

                normalized.update(
                    _semantic_matches(
                        observation_text
                    )
                )

            evidence_sources.add(
                "semantic-ai"
            )

        return EvidenceFusionResult(
            taxonomy_version=str(
                taxonomy.get(
                    "version",
                    "unknown",
                )
            ),

            normalized_indicators=sorted(
                normalized
            ),

            mitigating_indicators=[],

            evidence_sources=sorted(
                evidence_sources
            ),

            category_counts=
                _category_counts(
                    normalized
                ),
        )


# ============================================================
# SHARED INSTANCE
#
# IMPORTANT:
# message_analysis_service imports this exact name.
# ============================================================

evidence_fusion_agent = EvidenceFusionAgent()