from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.pipeline import FeatureUnion
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)


SPLIT_DIR = Path(
    "research/data/splits"
)

MODEL_DIR = Path(
    "research/models"
)

REPORT_DIR = Path(
    "research/reports"
)

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


def load_split(name):

    path = SPLIT_DIR / f"{name}.csv"

    df = pd.read_csv(
        path,
        low_memory=False,
    )

    df = df.dropna(
        subset=["text", "label"]
    )

    return df


def build_model():

    features = FeatureUnion(
        [
            (
                "word_tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    ngram_range=(1, 2),
                    min_df=2,
                    max_df=0.98,
                    max_features=20000,
                    sublinear_tf=True,
                ),
            ),
            (
                "char_tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    lowercase=True,
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=15000,
                    sublinear_tf=True,
                ),
            ),
        ]
    )

    classifier = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42,
    )

    return Pipeline(
        [
            ("features", features),
            ("classifier", classifier),
        ]
    )


def evaluate(
    model,
    df,
    split_name,
):

    predictions = model.predict(
        df["text"]
    )

    scam_true = (
        df["label"] == "scam"
    ).astype(int)

    scam_pred = (
        predictions == "scam"
    ).astype(int)

    metrics = {
        "accuracy": accuracy_score(
            df["label"],
            predictions,
        ),
        "precision_scam": precision_score(
            scam_true,
            scam_pred,
            zero_division=0,
        ),
        "recall_scam": recall_score(
            scam_true,
            scam_pred,
            zero_division=0,
        ),
        "f1_scam": f1_score(
            scam_true,
            scam_pred,
            zero_division=0,
        ),
    }

    print(
        f"\n{'=' * 60}"
    )

    print(
        f"{split_name.upper()} RESULTS"
    )

    print(
        "=" * 60
    )

    for name, value in metrics.items():

        print(
            f"{name}: {value:.4f}"
        )

    print(
        "\nClassification report:"
    )

    print(
        classification_report(
            df["label"],
            predictions,
            digits=4,
            zero_division=0,
        )
    )

    print(
        "Confusion matrix:"
    )

    print(
        confusion_matrix(
            df["label"],
            predictions,
            labels=[
                "legitimate",
                "scam",
            ],
        )
    )

    return metrics


def main():

    print("=" * 60)
    print(
        "ScamShield AI V2 - Baseline Trainer"
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
        f"\nTraining records: {len(train_df):,}"
    )

    model = build_model()

    print(
        "\nTraining TF-IDF + "
        "Logistic Regression..."
    )

    model.fit(
        train_df["text"],
        train_df["label"],
    )

    print(
        "\nTraining completed."
    )

    validation_metrics = evaluate(
        model,
        validation_df,
        "validation",
    )

    test_metrics = evaluate(
        model,
        test_df,
        "test",
    )

    model_path = (
        MODEL_DIR /
        "scamshield_baseline.joblib"
    )

    joblib.dump(
        model,
        model_path,
    )

    print(
        f"\nModel saved: {model_path}"
    )

    metrics = {
        "model": (
            "word_char_tfidf_"
            "logistic_regression"
        ),
        "validation": validation_metrics,
        "test": test_metrics,
    }

    metrics_path = (
        REPORT_DIR /
        "baseline_metrics.json"
    )

    with open(
        metrics_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metrics,
            file,
            indent=2,
        )

    print(
        f"Metrics saved: {metrics_path}"
    )


if __name__ == "__main__":
    main()