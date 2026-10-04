from pathlib import Path
import hashlib
import json
import platform

import joblib
import numpy as np
import pandas as pd
import sklearn

from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


SPLIT_DIR = Path("research/data/splits")
MODEL_DIR = Path("research/models")
REPORT_DIR = Path("research/reports")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


MODEL_VERSION = "scamshield-text-v2-baseline-1"


def load_split(name):
    path = SPLIT_DIR / f"{name}.csv"

    df = pd.read_csv(
        path,
        low_memory=False,
    )

    df = df.dropna(
        subset=["text", "label"]
    ).copy()

    df["text"] = (
        df["text"]
        .astype(str)
        .str.strip()
    )

    return df


def build_model():

    word_features = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.98,
        max_features=20000,
        sublinear_tf=True,
    )

    char_features = TfidfVectorizer(
        analyzer="char_wb",
        lowercase=True,
        ngram_range=(3, 5),
        min_df=2,
        max_features=15000,
        sublinear_tf=True,
    )

    features = FeatureUnion(
        [
            ("word_tfidf", word_features),
            ("char_tfidf", char_features),
        ]
    )

    classifier = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        solver="liblinear",
        random_state=42,
    )

    return Pipeline(
        [
            ("features", features),
            ("classifier", classifier),
        ]
    )


def get_scam_scores(model, texts):

    probabilities = model.predict_proba(
        texts
    )

    classes = list(
        model.classes_
    )

    scam_index = classes.index(
        "scam"
    )

    return probabilities[
        :,
        scam_index,
    ]


def calculate_metrics(
    labels,
    scores,
    threshold,
):

    actual = (
        labels == "scam"
    ).astype(int)

    predicted = (
        scores >= threshold
    ).astype(int)

    matrix = confusion_matrix(
        actual,
        predicted,
        labels=[0, 1],
    )

    tn, fp, fn, tp = (
        matrix.ravel()
    )

    return {
        "threshold": float(threshold),

        "accuracy": float(
            accuracy_score(
                actual,
                predicted,
            )
        ),

        "precision_scam": float(
            precision_score(
                actual,
                predicted,
                zero_division=0,
            )
        ),

        "recall_scam": float(
            recall_score(
                actual,
                predicted,
                zero_division=0,
            )
        ),

        "f1_scam": float(
            f1_score(
                actual,
                predicted,
                zero_division=0,
            )
        ),

        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }


def tune_threshold(
    labels,
    scores,
):

    print(
        "\nTuning threshold using VALIDATION ONLY..."
    )

    results = []

    thresholds = np.arange(
        0.05,
        0.951,
        0.01,
    )

    for threshold in thresholds:

        metrics = calculate_metrics(
            labels,
            scores,
            threshold,
        )

        results.append(
            metrics
        )

    results_df = pd.DataFrame(
        results
    )

    results_df.to_csv(
        REPORT_DIR /
        "threshold_sweep.csv",
        index=False,
    )

    # PRD release target:
    # scam recall >= 0.85.
    eligible = results_df[
        results_df[
            "recall_scam"
        ] >= 0.85
    ].copy()

    if len(eligible) > 0:

        eligible = eligible.sort_values(
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

        selected = (
            eligible.iloc[0]
        )

        selection_reason = (
            "Highest validation F1 among "
            "thresholds with scam recall >= 0.85"
        )

    else:

        results_df = (
            results_df.sort_values(
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
            results_df.iloc[0]
        )

        selection_reason = (
            "No threshold reached recall 0.85. "
            "Selected highest validation F1."
        )

    threshold = float(
        selected["threshold"]
    )

    return (
        threshold,
        selection_reason,
    )


def sha256_file(path):

    hasher = hashlib.sha256()

    with open(
        path,
        "rb",
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            hasher.update(
                chunk
            )

    return hasher.hexdigest()


def print_metrics(
    title,
    metrics,
):

    print(
        "\n" + "=" * 60
    )

    print(title)

    print(
        "=" * 60
    )

    print(
        f"Threshold: {metrics['threshold']:.2f}"
    )

    print(
        f"Accuracy:  {metrics['accuracy']:.4f}"
    )

    print(
        "Precision: "
        f"{metrics['precision_scam']:.4f}"
    )

    print(
        "Recall:    "
        f"{metrics['recall_scam']:.4f}"
    )

    print(
        "F1:        "
        f"{metrics['f1_scam']:.4f}"
    )

    print(
        "\nConfusion matrix values:"
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


def main():

    print("=" * 60)
    print(
        "ScamShield AI V2 - Baseline ML Training"
    )
    print("=" * 60)

    train_df = load_split(
        "train"
    )

    validation_df = load_split(
        "validation"
    )

    test_df = load_split(
        "test"
    )

    print(
        f"\nTrain records: {len(train_df):,}"
    )

    print(
        f"Validation records: {len(validation_df):,}"
    )

    print(
        f"Test records: {len(test_df):,}"
    )

    print(
        "\nTraining label distribution:"
    )

    print(
        train_df[
            "label"
        ].value_counts()
    )

    model = build_model()

    print(
        "\nTraining word + character TF-IDF "
        "Logistic Regression..."
    )

    model.fit(
        train_df["text"],
        train_df["label"],
    )

    print(
        "Training completed."
    )

    # ------------------------------------------------
    # VALIDATION
    # ------------------------------------------------

    validation_scores = (
        get_scam_scores(
            model,
            validation_df["text"],
        )
    )

    (
        selected_threshold,
        selection_reason,
    ) = tune_threshold(
        validation_df["label"],
        validation_scores,
    )

    validation_metrics = (
        calculate_metrics(
            validation_df["label"],
            validation_scores,
            selected_threshold,
        )
    )

    print_metrics(
        "VALIDATION RESULTS",
        validation_metrics,
    )

    print(
        "\nThreshold selection:"
    )

    print(
        selection_reason
    )

    # ------------------------------------------------
    # TEST
    # Threshold is now frozen.
    # ------------------------------------------------

    print(
        "\nThreshold frozen."
    )

    print(
        "Evaluating untouched TEST set..."
    )

    test_scores = (
        get_scam_scores(
            model,
            test_df["text"],
        )
    )

    test_metrics = (
        calculate_metrics(
            test_df["label"],
            test_scores,
            selected_threshold,
        )
    )

    print_metrics(
        "UNTOUCHED TEST RESULTS",
        test_metrics,
    )

    # ------------------------------------------------
    # SAVE MODEL
    # ------------------------------------------------

    model_path = (
        MODEL_DIR /
        "scamshield_text_model.joblib"
    )

    joblib.dump(
        model,
        model_path,
    )

    model_hash = sha256_file(
        model_path
    )

    metadata = {
        "model_version":
            MODEL_VERSION,

        "model_type":
            "word_char_tfidf_logistic_regression",

        "selected_threshold":
            selected_threshold,

        "threshold_selection":
            selection_reason,

        "train_records":
            len(train_df),

        "validation_records":
            len(validation_df),

        "test_records":
            len(test_df),

        "validation_metrics":
            validation_metrics,

        "test_metrics":
            test_metrics,

        "near_duplicate_threshold":
            0.92,

        "cross_split_group_leakage":
            0,

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

        "score_warning":
            (
                "model_scam_score is a model output "
                "and is not a verified real-world "
                "fraud probability"
            ),
    }

    metadata_path = (
        MODEL_DIR /
        "scamshield_text_model.metadata.json"
    )

    metadata_path.write_text(
        json.dumps(
            metadata,
            indent=2,
        ),
        encoding="utf-8",
    )

    report_path = (
        REPORT_DIR /
        "baseline_threshold_metrics.json"
    )

    report_path.write_text(
        json.dumps(
            metadata,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        "\nModel saved:"
    )

    print(
        model_path
    )

    print(
        "\nModel SHA-256:"
    )

    print(
        model_hash
    )

    print(
        "\nMetrics report:"
    )

    print(
        report_path
    )

    print(
        "\nIMPORTANT:"
    )

    print(
        "Do not change the threshold using test results."
    )


if __name__ == "__main__":
    main()