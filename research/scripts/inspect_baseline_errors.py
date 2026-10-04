from pathlib import Path
import json

import joblib
import pandas as pd


TEST_FILE = Path(
    "research/data/splits/test.csv"
)

MODEL_FILE = Path(
    "research/models/scamshield_text_model.joblib"
)

METADATA_FILE = Path(
    "research/models/scamshield_text_model.metadata.json"
)

OUTPUT_DIR = Path(
    "research/data/processed"
)

REPORT_DIR = Path(
    "research/reports"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


def main():

    print("=" * 60)
    print(
        "ScamShield AI V2 - Baseline Error Analysis"
    )
    print("=" * 60)

    # ---------------------------------------------
    # Load model metadata
    # ---------------------------------------------

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

    print(
        f"\nFrozen threshold: {threshold:.2f}"
    )

    # ---------------------------------------------
    # Load model
    # ---------------------------------------------

    model = joblib.load(
        MODEL_FILE
    )

    # ---------------------------------------------
    # Load untouched test results
    # ---------------------------------------------

    df = pd.read_csv(
        TEST_FILE,
        low_memory=False,
    )

    df = df.dropna(
        subset=[
            "text",
            "label",
        ]
    ).copy()

    # ---------------------------------------------
    # Calculate scam scores
    # ---------------------------------------------

    probabilities = (
        model.predict_proba(
            df["text"]
        )
    )

    classes = list(
        model.classes_
    )

    scam_index = classes.index(
        "scam"
    )

    df["scam_score"] = (
        probabilities[
            :,
            scam_index,
        ]
    )

    df["prediction"] = (
        df["scam_score"]
        >= threshold
    ).map(
        {
            True: "scam",
            False: "legitimate",
        }
    )

    # ---------------------------------------------
    # Identify mistakes
    # ---------------------------------------------

    errors = df[
        df["label"]
        != df["prediction"]
    ].copy()

    errors["error_type"] = ""

    errors.loc[
        (
            (errors["label"] == "scam")
            &
            (
                errors["prediction"]
                == "legitimate"
            )
        ),
        "error_type",
    ] = "false_negative"

    errors.loc[
        (
            (
                errors["label"]
                == "legitimate"
            )
            &
            (
                errors["prediction"]
                == "scam"
            )
        ),
        "error_type",
    ] = "false_positive"

    false_negatives = errors[
        errors["error_type"]
        == "false_negative"
    ].copy()

    false_positives = errors[
        errors["error_type"]
        == "false_positive"
    ].copy()

    print(
        f"\nTotal test records: {len(df):,}"
    )

    print(
        f"Total errors: {len(errors):,}"
    )

    print(
        "False negatives: "
        f"{len(false_negatives):,}"
    )

    print(
        "False positives: "
        f"{len(false_positives):,}"
    )

    # ---------------------------------------------
    # Save full error records locally
    # ---------------------------------------------

    error_file = (
        OUTPUT_DIR /
        "baseline_test_errors.csv"
    )

    errors.to_csv(
        error_file,
        index=False,
        encoding="utf-8",
    )

    # ---------------------------------------------
    # Show most confident false negatives
    # ---------------------------------------------

    print(
        "\n"
        + "=" * 60
    )

    print(
        "MOST IMPORTANT FALSE NEGATIVES"
    )

    print(
        "=" * 60
    )

    fn_sorted = (
        false_negatives
        .sort_values(
            "scam_score",
            ascending=True,
        )
        .head(15)
    )

    for _, row in fn_sorted.iterrows():

        text = str(
            row["text"]
        )

        if len(text) > 300:
            text = (
                text[:300]
                + "..."
            )

        print(
            "\nScam score:",
            round(
                row["scam_score"],
                4,
            ),
        )

        print(
            "Source:",
            row.get(
                "source",
                "unknown",
            ),
        )

        print(
            "Text:",
            text,
        )

    # ---------------------------------------------
    # Show strongest false positives
    # ---------------------------------------------

    print(
        "\n"
        + "=" * 60
    )

    print(
        "STRONGEST FALSE POSITIVES"
    )

    print(
        "=" * 60
    )

    fp_sorted = (
        false_positives
        .sort_values(
            "scam_score",
            ascending=False,
        )
        .head(15)
    )

    for _, row in fp_sorted.iterrows():

        text = str(
            row["text"]
        )

        if len(text) > 300:
            text = (
                text[:300]
                + "..."
            )

        print(
            "\nScam score:",
            round(
                row["scam_score"],
                4,
            ),
        )

        print(
            "Source:",
            row.get(
                "source",
                "unknown",
            ),
        )

        print(
            "Text:",
            text,
        )

    # ---------------------------------------------
    # Summary report
    # ---------------------------------------------

    report = (
        "ScamShield AI V2 Baseline Error Analysis\n"
        "=========================================\n\n"
        f"Frozen threshold: {threshold:.2f}\n"
        f"Test records: {len(df):,}\n"
        f"Total errors: {len(errors):,}\n"
        f"False negatives: {len(false_negatives):,}\n"
        f"False positives: {len(false_positives):,}\n\n"
        "Important:\n"
        "These test errors are for analysis only.\n"
        "Do not tune the frozen model threshold "
        "using test-set results.\n"
    )

    report_path = (
        REPORT_DIR /
        "baseline_error_summary.txt"
    )

    report_path.write_text(
        report,
        encoding="utf-8",
    )

    print(
        "\n"
        + "=" * 60
    )

    print(
        report
    )

    print(
        "Full local errors saved:"
    )

    print(
        error_file
    )


if __name__ == "__main__":
    main()