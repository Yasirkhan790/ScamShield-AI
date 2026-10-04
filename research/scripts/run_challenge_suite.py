from pathlib import Path
import json

import joblib


MODEL_FILE = Path(
    "research/models/"
    "scamshield_text_model_candidate.joblib"
)

METADATA_FILE = Path(
    "research/models/"
    "scamshield_text_model_candidate.metadata.json"
)

REPORT_FILE = Path(
    "research/reports/"
    "hardened_candidate_challenge_results.json"
)


CHALLENGE_CASES = [
    {
        "id": "C01",
        "name": "Direct OTP request",
        "text": (
            "Send your OTP immediately to verify your account."
        ),
        "expected": "scam",
    },
    {
        "id": "C02",
        "name": "OTP paraphrase",
        "text": (
            "Tell me the six-digit security code "
            "that was just sent to your phone."
        ),
        "expected": "scam",
    },
    {
        "id": "C03",
        "name": "Credential paraphrase",
        "text": (
            "Please forward the confirmation digits "
            "you received so we can restore your access."
        ),
        "expected": "scam",
    },
    {
        "id": "C04",
        "name": "Benign OTP warning",
        "text": (
            "Never share your OTP or password "
            "with anyone."
        ),
        "expected": "legitimate",
    },
    {
        "id": "C05",
        "name": "Prize and release fee",
        "text": (
            "Congratulations. You won a cash reward. "
            "Pay the release fee today to claim it."
        ),
        "expected": "scam",
    },
    {
        "id": "C06",
        "name": "Job scam",
        "text": (
            "Work from home with guaranteed hiring. "
            "Pay the registration fee today to start."
        ),
        "expected": "scam",
    },
    {
        "id": "C07",
        "name": "Investment scam",
        "text": (
            "Guaranteed 300 percent return in seven days. "
            "There is no risk. Deposit your money today."
        ),
        "expected": "scam",
    },
    {
        "id": "C08",
        "name": "Normal meeting message",
        "text": (
            "Our meeting has been moved to "
            "3 PM tomorrow."
        ),
        "expected": "legitimate",
    },
    {
        "id": "C09",
        "name": "Fake account alert",
        "text": (
            "Your account will be suspended today. "
            "Confirm your login information immediately "
            "to avoid losing access."
        ),
        "expected": "scam",
    },
    {
        "id": "C10",
        "name": "Legitimate security advice",
        "text": (
            "For your security, use the official banking "
            "app and never give your password or "
            "verification code to another person."
        ),
        "expected": "legitimate",
    },
]


def main():

    print(
        "=" * 65
    )

    print(
        "ScamShield AI V2 - Hardened Candidate Challenge"
    )

    print(
        "=" * 65
    )

    if not MODEL_FILE.exists():

        raise RuntimeError(
            "Candidate model does not exist. "
            "Run train_hardened_candidate.py first."
        )

    if not METADATA_FILE.exists():

        raise RuntimeError(
            "Candidate metadata does not exist."
        )

    metadata = json.loads(
        METADATA_FILE.read_text(
            encoding="utf-8"
        )
    )

    threshold = float(
        metadata[
            "selected_threshold"
        ]
    )

    model = joblib.load(
        MODEL_FILE
    )

    classes = list(
        model.classes_
    )

    scam_index = classes.index(
        "scam"
    )

    print(
        "\nCandidate model:"
    )

    print(
        metadata[
            "model_version"
        ]
    )

    print(
        "\nValidation-selected threshold:",
        round(
            threshold,
            4,
        ),
    )

    passed = 0

    results = []

    for case in CHALLENGE_CASES:

        probabilities = (
            model.predict_proba(
                [
                    case[
                        "text"
                    ]
                ]
            )[0]
        )

        scam_score = float(
            probabilities[
                scam_index
            ]
        )

        if (
            scam_score
            >= threshold
        ):

            prediction = "scam"

        else:

            prediction = "legitimate"

        correct = (
            prediction
            == case[
                "expected"
            ]
        )

        if correct:
            passed += 1

        results.append(
            {
                "id":
                    case[
                        "id"
                    ],

                "name":
                    case[
                        "name"
                    ],

                "text":
                    case[
                        "text"
                    ],

                "expected":
                    case[
                        "expected"
                    ],

                "prediction":
                    prediction,

                "scam_score":
                    round(
                        scam_score,
                        6,
                    ),

                "correct":
                    correct,
            }
        )

        print(
            "\n"
            + "-" * 65
        )

        print(
            case[
                "id"
            ],
            "-",
            case[
                "name"
            ],
        )

        print(
            "Expected:",
            case[
                "expected"
            ],
        )

        print(
            "Prediction:",
            prediction,
        )

        print(
            "Scam score:",
            f"{scam_score:.4f}",
        )

        print(
            "Result:",
            (
                "PASS"
                if correct
                else "FAIL"
            ),
        )

    total = len(
        CHALLENGE_CASES
    )

    score = (
        passed
        / total
    )

    target_passed = (
        passed >= 8
    )

    report = {
        "model_version":
            metadata[
                "model_version"
            ],

        "threshold":
            threshold,

        "passed":
            passed,

        "total":
            total,

        "score":
            round(
                score,
                4,
            ),

        "target":
            "8/10 or better",

        "target_passed":
            target_passed,

        "evaluation_note":
            (
                "This challenge suite has already "
                "been used during development. "
                "It is a robustness check, not a "
                "blind statistical evaluation."
            ),

        "results":
            results,
    }

    REPORT_FILE.write_text(
        json.dumps(
            report,
            indent=2,
        ),

        encoding="utf-8",
    )

    print(
        "\n"
        + "=" * 65
    )

    print(
        "HARDENED CANDIDATE CHALLENGE RESULT"
    )

    print(
        "=" * 65
    )

    print(
        f"Passed: {passed}/{total}"
    )

    print(
        f"Score: {score:.1%}"
    )

    if target_passed:

        print(
            "STATUS: CHALLENGE TARGET PASS"
        )

    else:

        print(
            "STATUS: CHALLENGE TARGET NOT MET"
        )

    print(
        "\nReport:"
    )

    print(
        REPORT_FILE
    )


if __name__ == "__main__":
    main()