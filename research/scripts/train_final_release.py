from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import platform
import shutil

import joblib
import numpy as np
import pandas as pd
import sklearn

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.neighbors import NearestNeighbors

# Reuse the hardened model architecture and reviewed
# training-only hardening examples.
from train_hardened_candidate import (
    HARDENING_EXAMPLES,
    HARDENING_SAMPLE_WEIGHT,
    build_model,
)


# ============================================================
# PATHS
# ============================================================

FINAL_SPLIT_DIR = Path(
    "research/data/final_splits"
)

TRAIN_FILE = (
    FINAL_SPLIT_DIR /
    "train_final.csv"
)

VALIDATION_FILE = (
    FINAL_SPLIT_DIR /
    "validation_final.csv"
)

HOLDOUT_FILE = (
    FINAL_SPLIT_DIR /
    "release_holdout.csv"
)

FINAL_SPLIT_REPORT = Path(
    "research/reports/final_release_split_summary.txt"
)

CHALLENGE_REPORT = Path(
    "research/reports/hardened_candidate_challenge_results.json"
)

MASTER_DATASET_REPORT = Path(
    "research/reports/master_dataset_summary.txt"
)

TAXONOMY_FILE = Path(
    "backend/app/knowledge/indicator_taxonomy.json"
)

RESEARCH_MODEL_DIR = Path(
    "research/models"
)

RESEARCH_REPORT_DIR = Path(
    "research/reports"
)

BACKEND_ML_DIR = Path(
    "backend/app/ml"
)

BACKEND_ARTIFACT_DIR = (
    BACKEND_ML_DIR /
    "artifacts"
)

FINAL_RESEARCH_MODEL = (
    RESEARCH_MODEL_DIR /
    "scamshield_text_model_final.joblib"
)

FINAL_METRICS_FILE = (
    RESEARCH_REPORT_DIR /
    "final_release_metrics.json"
)

FINAL_THRESHOLD_SWEEP = (
    RESEARCH_REPORT_DIR /
    "final_release_threshold_sweep.csv"
)

BACKEND_MODEL = (
    BACKEND_ARTIFACT_DIR /
    "scamshield_text_model.joblib"
)

BACKEND_METADATA = (
    BACKEND_ML_DIR /
    "metadata.json"
)


MODEL_VERSION = (
    "scamshield-text-v2-release-1"
)

SIMILARITY_THRESHOLD = 0.92


# ============================================================
# HELPERS
# ============================================================

def require_file(path):

    if not path.exists():

        raise RuntimeError(
            f"Required file is missing: {path}"
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


def load_split(path):

    df = pd.read_csv(
        path,
        low_memory=False,
    )

    df = df.dropna(
        subset=[
            "text",
            "label",
        ]
    ).copy()

    df["text"] = (
        df["text"]
        .astype(str)
        .str.strip()
    )

    df = df[
        df["label"].isin(
            [
                "scam",
                "legitimate",
            ]
        )
    ].copy()

    return df


# ============================================================
# RELEASE GATES
# ============================================================

def check_prerequisites():

    print(
        "\nChecking final release prerequisites..."
    )

    required = [
        TRAIN_FILE,
        VALIDATION_FILE,
        HOLDOUT_FILE,
        FINAL_SPLIT_REPORT,
        CHALLENGE_REPORT,
        TAXONOMY_FILE,
    ]

    for path in required:
        require_file(path)

    split_report = (
        FINAL_SPLIT_REPORT.read_text(
            encoding="utf-8"
        )
    )

    if (
        "STATUS: FINAL SPLIT PASS"
        not in split_report
    ):

        raise RuntimeError(
            "Final release split has not passed."
        )

    if (
        "Cross-split group leakage: 0"
        not in split_report
    ):

        raise RuntimeError(
            "Final release split does not "
            "confirm zero group leakage."
        )

    challenge = json.loads(
        CHALLENGE_REPORT.read_text(
            encoding="utf-8"
        )
    )

    passed = int(
        challenge.get(
            "passed",
            0,
        )
    )

    total = int(
        challenge.get(
            "total",
            0,
        )
    )

    if (
        total != 10
        or passed < 8
    ):

        raise RuntimeError(
            "Hardened candidate challenge gate "
            f"failed: {passed}/{total}"
        )

    print(
        "Final split gate: PASS"
    )

    print(
        f"Challenge gate: PASS ({passed}/{total})"
    )

    return challenge


# ============================================================
# HARDENING DATA
# ============================================================

def build_hardening_dataframe():

    records = []

    for index, (
        text,
        label,
    ) in enumerate(
        HARDENING_EXAMPLES,
        start=1,
    ):

        records.append(
            {
                "record_id":
                    f"final-hardening-{index:04d}",

                "text":
                    text,

                "label":
                    label,
            }
        )

    return pd.DataFrame(
        records
    )


# ============================================================
# REMOVE HARDENING LEAKAGE
# ============================================================

def remove_hardening_overlap(
    hardening_df,
    validation_df,
    holdout_df,
):

    print(
        "\nChecking hardening examples "
        "against protected splits..."
    )

    protected_df = pd.concat(
        [
            validation_df[
                ["text"]
            ],

            holdout_df[
                ["text"]
            ],
        ],

        ignore_index=True,
    )

    combined_text = pd.concat(
        [
            hardening_df[
                "text"
            ],

            protected_df[
                "text"
            ],
        ],

        ignore_index=True,
    )

    vectorizer = TfidfVectorizer(
        analyzer="char_wb",

        ngram_range=(
            3,
            5,
        ),

        min_df=1,

        sublinear_tf=True,
    )

    matrix = (
        vectorizer.fit_transform(
            combined_text
        )
    )

    hardening_count = len(
        hardening_df
    )

    hardening_matrix = (
        matrix[
            :hardening_count
        ]
    )

    protected_matrix = (
        matrix[
            hardening_count:
        ]
    )

    nearest = NearestNeighbors(
        n_neighbors=1,

        metric="cosine",

        algorithm="brute",

        n_jobs=-1,
    )

    nearest.fit(
        protected_matrix
    )

    distances, _ = (
        nearest.kneighbors(
            hardening_matrix
        )
    )

    similarities = (
        1.0
        - distances[:, 0]
    )

    hardening_df = (
        hardening_df.copy()
    )

    hardening_df[
        "_protected_similarity"
    ] = similarities

    before = len(
        hardening_df
    )

    # Remove any hardening example that is too similar
    # to validation or final release holdout data.
    hardening_df = hardening_df[
        hardening_df[
            "_protected_similarity"
        ]
        < SIMILARITY_THRESHOLD
    ].copy()

    removed = (
        before
        - len(
            hardening_df
        )
    )

    hardening_df = (
        hardening_df.drop(
            columns=[
                "_protected_similarity"
            ]
        )
    )

    print(
        "Hardening records removed due to "
        "protected-split similarity:",
        removed,
    )

    print(
        "Hardening records retained:",
        len(
            hardening_df
        ),
    )

    return hardening_df


# ============================================================
# MODEL SCORES
# ============================================================

def get_scam_scores(
    model,
    texts,
):

    probabilities = (
        model.predict_proba(
            texts
        )
    )

    classes = list(
        model.classes_
    )

    scam_index = (
        classes.index(
            "scam"
        )
    )

    return probabilities[
        :,
        scam_index,
    ]


# ============================================================
# METRICS
# ============================================================

def calculate_metrics(
    labels,
    scores,
    threshold,
):

    actual = (
        labels == "scam"
    ).astype(
        int
    )

    predicted = (
        scores >= threshold
    ).astype(
        int
    )

    matrix = confusion_matrix(
        actual,
        predicted,
        labels=[
            0,
            1,
        ],
    )

    tn, fp, fn, tp = (
        matrix.ravel()
    )

    return {
        "threshold":
            float(
                threshold
            ),

        "accuracy":
            float(
                accuracy_score(
                    actual,
                    predicted,
                )
            ),

        "precision_scam":
            float(
                precision_score(
                    actual,
                    predicted,
                    zero_division=0,
                )
            ),

        "recall_scam":
            float(
                recall_score(
                    actual,
                    predicted,
                    zero_division=0,
                )
            ),

        "f1_scam":
            float(
                f1_score(
                    actual,
                    predicted,
                    zero_division=0,
                )
            ),

        "true_negative":
            int(
                tn
            ),

        "false_positive":
            int(
                fp
            ),

        "false_negative":
            int(
                fn
            ),

        "true_positive":
            int(
                tp
            ),
    }


# ============================================================
# VALIDATION-ONLY THRESHOLD
# ============================================================

def tune_threshold(
    labels,
    scores,
):

    print(
        "\nSelecting threshold from "
        "FINAL VALIDATION split only..."
    )

    rows = []

    for threshold in np.arange(
        0.10,
        0.901,
        0.01,
    ):

        rows.append(
            calculate_metrics(
                labels,
                scores,
                threshold,
            )
        )

    results = pd.DataFrame(
        rows
    )

    results.to_csv(
        FINAL_THRESHOLD_SWEEP,
        index=False,
        encoding="utf-8",
    )

    eligible = results[
        results[
            "recall_scam"
        ]
        >= 0.85
    ].copy()

    if not eligible.empty:

        eligible = (
            eligible.sort_values(
                by=[
                    "f1_scam",
                    "precision_scam",
                    "recall_scam",
                ],

                ascending=[
                    False,
                    False,
                    False,
                ],
            )
        )

        selected = (
            eligible.iloc[0]
        )

        reason = (
            "Highest final-validation scam F1 "
            "among thresholds with recall >= 0.85"
        )

    else:

        results = (
            results.sort_values(
                by=[
                    "f1_scam",
                    "recall_scam",
                ],

                ascending=[
                    False,
                    False,
                ],
            )
        )

        selected = (
            results.iloc[0]
        )

        reason = (
            "No final-validation threshold "
            "reached scam recall 0.85. "
            "Highest validation F1 selected."
        )

    return (
        float(
            selected[
                "threshold"
            ]
        ),
        reason,
    )


# ============================================================
# PRINT
# ============================================================

def print_metrics(
    title,
    metrics,
):

    print(
        "\n"
        + "=" * 65
    )

    print(
        title
    )

    print(
        "=" * 65
    )

    print(
        f"Threshold: {metrics['threshold']:.2f}"
    )

    print(
        f"Accuracy:  {metrics['accuracy']:.4f}"
    )

    print(
        f"Precision: {metrics['precision_scam']:.4f}"
    )

    print(
        f"Recall:    {metrics['recall_scam']:.4f}"
    )

    print(
        f"F1:        {metrics['f1_scam']:.4f}"
    )

    print(
        "\nConfusion matrix:"
    )

    print(
        f"TN: {metrics['true_negative']}"
    )

    print(
        f"FP: {metrics['false_positive']}"
    )

    print(
        f"FN: {metrics['false_negative']}"
    )

    print(
        f"TP: {metrics['true_positive']}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 65
    )

    print(
        "ScamShield AI V2 - FINAL RELEASE TRAINING"
    )

    print(
        "=" * 65
    )

    # Prevent repeated peeking at final holdout.
    if FINAL_METRICS_FILE.exists():

        raise RuntimeError(
            "Final release metrics already exist. "
            "The release holdout has already been "
            "evaluated. Do not evaluate it again."
        )

    challenge = (
        check_prerequisites()
    )

    train_df = (
        load_split(
            TRAIN_FILE
        )
    )

    validation_df = (
        load_split(
            VALIDATION_FILE
        )
    )

    holdout_df = (
        load_split(
            HOLDOUT_FILE
        )
    )

    print(
        "\nFinal split sizes:"
    )

    print(
        "Train:",
        len(
            train_df
        ),
    )

    print(
        "Validation:",
        len(
            validation_df
        ),
    )

    print(
        "Release holdout:",
        len(
            holdout_df
        ),
    )

    hardening_df = (
        build_hardening_dataframe()
    )

    hardening_df = (
        remove_hardening_overlap(
            hardening_df,
            validation_df,
            holdout_df,
        )
    )

    # ========================================================
    # TRAINING DATA ONLY
    # ========================================================

    augmented_train = pd.concat(
        [
            train_df[
                [
                    "text",
                    "label",
                ]
            ],

            hardening_df[
                [
                    "text",
                    "label",
                ]
            ],
        ],

        ignore_index=True,
    )

    sample_weights = np.concatenate(
        [
            np.ones(
                len(
                    train_df
                ),
                dtype=float,
            ),

            np.full(
                len(
                    hardening_df
                ),
                HARDENING_SAMPLE_WEIGHT,
                dtype=float,
            ),
        ]
    )

    print(
        "\nTraining records after hardening:",
        len(
            augmented_train
        ),
    )

    # ========================================================
    # TRAIN
    # ========================================================

    model = build_model()

    print(
        "\nTraining final model..."
    )

    model.fit(
        augmented_train[
            "text"
        ],

        augmented_train[
            "label"
        ],

        classifier__sample_weight=
            sample_weights,
    )

    print(
        "Final model training completed."
    )

    # ========================================================
    # FINAL VALIDATION
    # ========================================================

    validation_scores = (
        get_scam_scores(
            model,
            validation_df[
                "text"
            ],
        )
    )

    (
        threshold,
        threshold_reason,
    ) = tune_threshold(
        validation_df[
            "label"
        ],
        validation_scores,
    )

    validation_metrics = (
        calculate_metrics(
            validation_df[
                "label"
            ],
            validation_scores,
            threshold,
        )
    )

    print_metrics(
        "FINAL VALIDATION RESULTS",
        validation_metrics,
    )

    print(
        "\nThreshold frozen:"
    )

    print(
        round(
            threshold,
            4,
        )
    )

    # ========================================================
    # SAVE MODEL BEFORE HOLDOUT EVALUATION
    # ========================================================

    joblib.dump(
        model,
        FINAL_RESEARCH_MODEL,
    )

    model_hash = (
        sha256_file(
            FINAL_RESEARCH_MODEL
        )
    )

    # ========================================================
    # FINAL RELEASE HOLDOUT
    #
    # DO THIS ONCE.
    # ========================================================

    print(
        "\n"
        + "!" * 65
    )

    print(
        "EVALUATING FRESH RELEASE HOLDOUT ONCE"
    )

    print(
        "!" * 65
    )

    holdout_scores = (
        get_scam_scores(
            model,
            holdout_df[
                "text"
            ],
        )
    )

    holdout_metrics = (
        calculate_metrics(
            holdout_df[
                "label"
            ],
            holdout_scores,
            threshold,
        )
    )

    print_metrics(
        "FINAL RELEASE HOLDOUT RESULTS",
        holdout_metrics,
    )

    # ========================================================
    # SAVE METRICS IMMEDIATELY
    # ========================================================

    taxonomy = json.loads(
        TAXONOMY_FILE.read_text(
            encoding="utf-8"
        )
    )

    release_metrics = {
        "model_version":
            MODEL_VERSION,

        "release_status":
            "evaluated",

        "selected_threshold":
            threshold,

        "threshold_selection":
            threshold_reason,

        "train_records":
            len(
                train_df
            ),

        "hardening_records":
            len(
                hardening_df
            ),

        "hardening_sample_weight":
            HARDENING_SAMPLE_WEIGHT,

        "validation_records":
            len(
                validation_df
            ),

        "release_holdout_records":
            len(
                holdout_df
            ),

        "validation_metrics":
            validation_metrics,

        "release_holdout_metrics":
            holdout_metrics,

        "challenge_result": {
            "passed":
                challenge[
                    "passed"
                ],

            "total":
                challenge[
                    "total"
                ],
        },

        "near_duplicate_threshold":
            SIMILARITY_THRESHOLD,

        "cross_split_group_leakage":
            0,

        "taxonomy_version":
            taxonomy.get(
                "version",
                "unknown",
            ),

        "python_version":
            platform.python_version(),

        "scikit_learn_version":
            sklearn.__version__,

        "pandas_version":
            pd.__version__,

        "numpy_version":
            np.__version__,

        "joblib_version":
            joblib.__version__,

        "model_sha256":
            model_hash,

        "evaluated_at_utc":
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

    FINAL_METRICS_FILE.write_text(
        json.dumps(
            release_metrics,
            indent=2,
        ),

        encoding="utf-8",
    )

    # ========================================================
    # RELEASE GATES
    # ========================================================

    holdout_recall = (
        holdout_metrics[
            "recall_scam"
        ]
    )

    holdout_f1 = (
        holdout_metrics[
            "f1_scam"
        ]
    )

    print(
        "\nChecking final release gates..."
    )

    if (
        holdout_recall < 0.85
        or holdout_f1 < 0.85
    ):

        print(
            "\nFINAL MODEL NOT RELEASED"
        )

        print(
            "The holdout metrics were saved "
            "truthfully, but one or more PRD "
            "targets were not met."
        )

        return

    print(
        "Holdout scam recall gate: PASS"
    )

    print(
        "Holdout scam F1 gate: PASS"
    )

    # ========================================================
    # COPY PRODUCTION ARTIFACT
    # ========================================================

    BACKEND_ARTIFACT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    shutil.copy2(
        FINAL_RESEARCH_MODEL,
        BACKEND_MODEL,
    )

    copied_hash = (
        sha256_file(
            BACKEND_MODEL
        )
    )

    if copied_hash != model_hash:

        raise RuntimeError(
            "Production artifact SHA-256 mismatch."
        )

    artifact_size = (
        BACKEND_MODEL.stat().st_size
        / 1024
        / 1024
    )

    production_metadata = {
        **release_metrics,

        "release_status":
            "frozen",

        "artifact":
            "artifacts/scamshield_text_model.joblib",

        "artifact_size_mb":
            round(
                artifact_size,
                3,
            ),

        "frozen_at_utc":
            datetime.now(
                timezone.utc
            ).isoformat(),
    }

    BACKEND_METADATA.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    BACKEND_METADATA.write_text(
        json.dumps(
            production_metadata,
            indent=2,
        ),

        encoding="utf-8",
    )

    print(
        "\n"
        + "=" * 65
    )

    print(
        "FINAL ML RELEASE FROZEN SUCCESSFULLY"
    )

    print(
        "=" * 65
    )

    print(
        "\nProduction model:"
    )

    print(
        BACKEND_MODEL
    )

    print(
        "\nProduction metadata:"
    )

    print(
        BACKEND_METADATA
    )

    print(
        "\nSHA-256:"
    )

    print(
        model_hash
    )

    print(
        "\nModel size:"
    )

    print(
        f"{artifact_size:.2f} MB"
    )

    print(
        "\nFrozen threshold:"
    )

    print(
        round(
            threshold,
            4,
        )
    )

    print(
        "\nIMPORTANT:"
    )

    print(
        "Do not retrain or retune this frozen "
        "artifact during backend integration."
    )


if __name__ == "__main__":
    main()