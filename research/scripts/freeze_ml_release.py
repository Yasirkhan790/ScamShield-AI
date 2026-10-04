from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import shutil


RESEARCH_MODEL = Path(
    "research/models/scamshield_text_model.joblib"
)

RESEARCH_METADATA = Path(
    "research/models/scamshield_text_model.metadata.json"
)

CHALLENGE_REPORT = Path(
    "research/reports/challenge_suite_results.json"
)

GROUP_REPORT = Path(
    "research/reports/group_split_summary.txt"
)

DATASET_REPORT = Path(
    "research/reports/master_dataset_summary.txt"
)

TAXONOMY_FILE = Path(
    "backend/app/knowledge/indicator_taxonomy.json"
)

BACKEND_ML_DIR = Path(
    "backend/app/ml"
)

BACKEND_ARTIFACT_DIR = (
    BACKEND_ML_DIR / "artifacts"
)

RELEASE_MODEL = (
    BACKEND_ARTIFACT_DIR /
    "scamshield_text_model.joblib"
)

RELEASE_METADATA = (
    BACKEND_ML_DIR /
    "metadata.json"
)


def sha256_file(path):

    hasher = hashlib.sha256()

    with open(path, "rb") as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            hasher.update(chunk)

    return hasher.hexdigest()


def require_file(path):

    if not path.exists():

        raise RuntimeError(
            f"Required file missing: {path}"
        )


def main():

    print("=" * 65)
    print(
        "ScamShield AI V2 - Freeze ML Release"
    )
    print("=" * 65)

    required_files = [
        RESEARCH_MODEL,
        RESEARCH_METADATA,
        CHALLENGE_REPORT,
        GROUP_REPORT,
        DATASET_REPORT,
        TAXONOMY_FILE,
    ]

    for path in required_files:
        require_file(path)

    metadata = json.loads(
        RESEARCH_METADATA.read_text(
            encoding="utf-8"
        )
    )

    challenge = json.loads(
        CHALLENGE_REPORT.read_text(
            encoding="utf-8"
        )
    )

    taxonomy = json.loads(
        TAXONOMY_FILE.read_text(
            encoding="utf-8"
        )
    )

    group_report = (
        GROUP_REPORT.read_text(
            encoding="utf-8"
        )
    )

    # ------------------------------------------------
    # RELEASE GATES
    # ------------------------------------------------

    print("\nChecking release gates...")

    if (
        "STATUS: GROUP SPLIT PASS"
        not in group_report
    ):

        raise RuntimeError(
            "Leakage-safe split has not passed."
        )

    if (
        "Cross-split group leakage: 0"
        not in group_report
    ):

        raise RuntimeError(
            "Cross-split group leakage "
            "is not confirmed as zero."
        )

    challenge_passed = int(
        challenge.get(
            "passed",
            0,
        )
    )

    challenge_total = int(
        challenge.get(
            "total",
            0,
        )
    )

    if challenge_total != 10:

        raise RuntimeError(
            "Expected a 10-case challenge suite."
        )

    if challenge_passed < 8:

        raise RuntimeError(
            "Challenge target not met. "
            f"Result: {challenge_passed}/10"
        )

    test_metrics = metadata.get(
        "test_metrics",
        {}
    )

    test_recall = float(
        test_metrics.get(
            "recall_scam",
            0,
        )
    )

    test_f1 = float(
        test_metrics.get(
            "f1_scam",
            0,
        )
    )

    if test_recall < 0.85:

        raise RuntimeError(
            "Test scam recall is below "
            "the PRD release target."
        )

    if test_f1 < 0.85:

        raise RuntimeError(
            "Test scam F1 is below "
            "the PRD release target."
        )

    current_hash = sha256_file(
        RESEARCH_MODEL
    )

    recorded_hash = metadata.get(
        "model_sha256"
    )

    if (
        recorded_hash
        and recorded_hash != current_hash
    ):

        raise RuntimeError(
            "Model SHA-256 does not match "
            "research metadata."
        )

    print(
        "Leakage gate: PASS"
    )

    print(
        f"Challenge gate: PASS "
        f"({challenge_passed}/10)"
    )

    print(
        "Test recall gate: PASS "
        f"({test_recall:.4f})"
    )

    print(
        "Test F1 gate: PASS "
        f"({test_f1:.4f})"
    )

    print(
        "Model integrity: PASS"
    )

    # ------------------------------------------------
    # COPY RELEASE ARTIFACT
    # ------------------------------------------------

    BACKEND_ARTIFACT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        RESEARCH_MODEL,
        RELEASE_MODEL,
    )

    release_hash = sha256_file(
        RELEASE_MODEL
    )

    if release_hash != current_hash:

        raise RuntimeError(
            "Copied model hash verification failed."
        )

    # ------------------------------------------------
    # BUILD PRODUCTION METADATA
    # ------------------------------------------------

    production_metadata = {
        "release_status":
            "frozen",

        "model_version":
            metadata.get(
                "model_version"
            ),

        "model_type":
            metadata.get(
                "model_type"
            ),

        "selected_threshold":
            metadata.get(
                "selected_threshold"
            ),

        "threshold_selection":
            metadata.get(
                "threshold_selection"
            ),

        "taxonomy_version":
            taxonomy.get(
                "version",
                "unknown",
            ),

        "training_records":
            metadata.get(
                "train_records"
            ),

        "validation_records":
            metadata.get(
                "validation_records"
            ),

        "test_records":
            metadata.get(
                "test_records"
            ),

        "validation_metrics":
            metadata.get(
                "validation_metrics"
            ),

        "test_metrics":
            metadata.get(
                "test_metrics"
            ),

        "challenge_suite": {
            "passed":
                challenge_passed,

            "total":
                challenge_total,

            "target_passed":
                challenge_passed >= 8,
        },

        "near_duplicate_threshold":
            metadata.get(
                "near_duplicate_threshold"
            ),

        "cross_split_group_leakage":
            0,

        "python_version":
            metadata.get(
                "python_version"
            ),

        "scikit_learn_version":
            metadata.get(
                "scikit_learn_version"
            ),

        "pandas_version":
            metadata.get(
                "pandas_version"
            ),

        "numpy_version":
            metadata.get(
                "numpy_version"
            ),

        "joblib_version":
            metadata.get(
                "joblib_version"
            ),

        "model_sha256":
            release_hash,

        "artifact":
            "artifacts/scamshield_text_model.joblib",

        "frozen_at_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "score_warning":
            (
                "model_scam_score is supporting "
                "model evidence and is not a "
                "verified real-world fraud probability"
            ),
    }

    RELEASE_METADATA.write_text(
        json.dumps(
            production_metadata,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("\n" + "=" * 65)

    print(
        "ML RELEASE FROZEN SUCCESSFULLY"
    )

    print("=" * 65)

    print(
        f"\nModel:"
        f"\n{RELEASE_MODEL}"
    )

    print(
        f"\nMetadata:"
        f"\n{RELEASE_METADATA}"
    )

    print(
        f"\nSHA-256:"
        f"\n{release_hash}"
    )

    print(
        "\nFrozen threshold:",
        production_metadata[
            "selected_threshold"
        ],
    )

    print(
        "\nIMPORTANT:"
    )

    print(
        "Do not retrain or retune this artifact "
        "during backend integration."
    )


if __name__ == "__main__":
    main()