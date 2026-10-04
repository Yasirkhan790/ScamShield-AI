from pathlib import Path
import re

import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.neighbors import NearestNeighbors


INPUT_FILE = Path(
    "research/data/processed/master_text_dataset.csv"
)

SPLIT_DIR = Path(
    "research/data/splits"
)

PROCESSED_DIR = Path(
    "research/data/processed"
)

REPORT_DIR = Path(
    "research/reports"
)

SPLIT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

PROCESSED_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


RANDOM_STATE = 42

# Starting threshold for near-duplicate investigation.
# We can adjust only after inspecting results.
SIMILARITY_THRESHOLD = 0.92


def normalize_text(text):
    """Basic model text cleanup."""

    text = str(text)

    text = text.replace("\x00", " ")
    text = text.replace("\r", " ")
    text = text.replace("\n", " ")

    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    return text.strip()


def make_leakage_key(text):
    """
    Stronger normalization used ONLY for duplicate/leakage detection.

    Examples that differ only by URL, email, phone number,
    transaction number, etc. can become the same template.
    """

    text = normalize_text(
        text
    ).casefold()

    # Replace URLs
    text = re.sub(
        r"https?://\S+|www\.\S+",
        " urltoken ",
        text,
    )

    # Replace email addresses
    text = re.sub(
        r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b",
        " emailtoken ",
        text,
    )

    # Replace numbers
    text = re.sub(
        r"\b\d+\b",
        " numbertoken ",
        text,
    )

    # Remove most punctuation
    text = re.sub(
        r"[^\w\s]",
        " ",
        text,
    )

    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    return text.strip()


def prepare_dataset():

    print("\nLoading master dataset...")

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False,
    )

    original_count = len(df)

    print(
        f"Master records: {original_count:,}"
    )

    # Only reliable binary labels
    df = df[
        df["label"].isin(
            [
                "scam",
                "legitimate",
            ]
        )
    ].copy()

    print(
        f"Binary-labeled records: {len(df):,}"
    )

    df = df.dropna(
        subset=[
            "text",
            "label",
        ]
    ).copy()

    df["text"] = (
        df["text"]
        .apply(normalize_text)
    )

    df = df[
        df["text"].str.len() >= 3
    ].copy()

    df["_leakage_key"] = (
        df["text"]
        .apply(make_leakage_key)
    )

    df = df[
        df["_leakage_key"].str.len() >= 3
    ].copy()

    # --------------------------------------------------------
    # Conflicting labels
    # --------------------------------------------------------

    label_counts = (
        df.groupby(
            "_leakage_key"
        )["label"]
        .nunique()
    )

    conflicting_keys = set(
        label_counts[
            label_counts > 1
        ].index
    )

    conflicting_rows = df[
        df["_leakage_key"].isin(
            conflicting_keys
        )
    ].copy()

    print(
        "Rows with conflicting normalized labels:",
        len(conflicting_rows),
    )

    # Save locally for investigation
    if not conflicting_rows.empty:

        conflicting_rows.to_csv(
            PROCESSED_DIR /
            "conflicting_label_records.csv",
            index=False,
            encoding="utf-8",
        )

    # Exclude conflicting templates from training data
    df = df[
        ~df["_leakage_key"].isin(
            conflicting_keys
        )
    ].copy()

    # --------------------------------------------------------
    # Template/exact duplicates
    # --------------------------------------------------------

    before_dedupe = len(df)

    df = df.drop_duplicates(
        subset=[
            "_leakage_key"
        ],
        keep="first",
    ).copy()

    duplicates_removed = (
        before_dedupe - len(df)
    )

    print(
        "Duplicate/template rows removed:",
        duplicates_removed,
    )

    print(
        f"Final records before split: {len(df):,}"
    )

    return (
        df,
        original_count,
        len(conflicting_rows),
        duplicates_removed,
    )


def create_splits(df):

    print(
        "\nCreating stratified 70/15/15 splits..."
    )

    train_df, temporary_df = (
        train_test_split(
            df,
            test_size=0.30,
            random_state=RANDOM_STATE,
            stratify=df["label"],
        )
    )

    validation_df, test_df = (
        train_test_split(
            temporary_df,
            test_size=0.50,
            random_state=RANDOM_STATE,
            stratify=temporary_df["label"],
        )
    )

    print(
        f"Train:      {len(train_df):,}"
    )

    print(
        f"Validation: {len(validation_df):,}"
    )

    print(
        f"Test:       {len(test_df):,}"
    )

    return (
        train_df,
        validation_df,
        test_df,
    )


def find_near_duplicates(
    reference_df,
    query_df,
    reference_matrix,
    query_matrix,
    reference_name,
    query_name,
):

    print(
        f"\nChecking {query_name} against "
        f"{reference_name}..."
    )

    nearest = NearestNeighbors(
        n_neighbors=1,
        metric="cosine",
        algorithm="brute",
        n_jobs=-1,
    )

    nearest.fit(
        reference_matrix
    )

    distances, indices = (
        nearest.kneighbors(
            query_matrix
        )
    )

    candidates = []

    for query_position in range(
        len(query_df)
    ):

        similarity = (
            1.0
            - float(
                distances[
                    query_position,
                    0,
                ]
            )
        )

        if (
            similarity
            < SIMILARITY_THRESHOLD
        ):
            continue

        reference_position = int(
            indices[
                query_position,
                0,
            ]
        )

        query_row = (
            query_df.iloc[
                query_position
            ]
        )

        reference_row = (
            reference_df.iloc[
                reference_position
            ]
        )

        candidates.append(
            {
                "reference_split":
                    reference_name,

                "query_split":
                    query_name,

                "similarity":
                    round(
                        similarity,
                        6,
                    ),

                "reference_record_id":
                    reference_row[
                        "record_id"
                    ],

                "query_record_id":
                    query_row[
                        "record_id"
                    ],

                "reference_label":
                    reference_row[
                        "label"
                    ],

                "query_label":
                    query_row[
                        "label"
                    ],

                "reference_source":
                    reference_row[
                        "source"
                    ],

                "query_source":
                    query_row[
                        "source"
                    ],
            }
        )

    print(
        "Near-duplicate candidates:",
        len(candidates),
    )

    return candidates


def run_similarity_check(
    train_df,
    validation_df,
    test_df,
):

    print(
        "\nBuilding temporary TF-IDF representation "
        "for leakage detection..."
    )

    all_text = pd.concat(
        [
            train_df["text"],
            validation_df["text"],
            test_df["text"],
        ],
        ignore_index=True,
    )

    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=25000,
        sublinear_tf=True,
        dtype="float32",
    )

    vectorizer.fit(
        all_text
    )

    print(
        "Transforming splits..."
    )

    train_matrix = (
        vectorizer.transform(
            train_df["text"]
        )
    )

    validation_matrix = (
        vectorizer.transform(
            validation_df["text"]
        )
    )

    test_matrix = (
        vectorizer.transform(
            test_df["text"]
        )
    )

    candidates = []

    # Validation -> Train
    candidates.extend(
        find_near_duplicates(
            train_df,
            validation_df,
            train_matrix,
            validation_matrix,
            "train",
            "validation",
        )
    )

    # Test -> Train
    candidates.extend(
        find_near_duplicates(
            train_df,
            test_df,
            train_matrix,
            test_matrix,
            "train",
            "test",
        )
    )

    # Test -> Validation
    candidates.extend(
        find_near_duplicates(
            validation_df,
            test_df,
            validation_matrix,
            test_matrix,
            "validation",
            "test",
        )
    )

    return pd.DataFrame(
        candidates
    )


def save_splits(
    train_df,
    validation_df,
    test_df,
):

    columns_to_drop = [
        "_leakage_key"
    ]

    train_output = train_df.drop(
        columns=columns_to_drop,
        errors="ignore",
    )

    validation_output = validation_df.drop(
        columns=columns_to_drop,
        errors="ignore",
    )

    test_output = test_df.drop(
        columns=columns_to_drop,
        errors="ignore",
    )

    train_output.to_csv(
        SPLIT_DIR / "train.csv",
        index=False,
        encoding="utf-8",
    )

    validation_output.to_csv(
        SPLIT_DIR / "validation.csv",
        index=False,
        encoding="utf-8",
    )

    test_output.to_csv(
        SPLIT_DIR / "test.csv",
        index=False,
        encoding="utf-8",
    )


def save_report(
    original_count,
    final_count,
    conflicting_count,
    duplicates_removed,
    train_df,
    validation_df,
    test_df,
    candidates_df,
):

    report_path = (
        REPORT_DIR /
        "leakage_check_summary.txt"
    )

    candidate_path = (
        PROCESSED_DIR /
        "near_duplicate_candidates.csv"
    )

    if not candidates_df.empty:

        candidates_df.to_csv(
            candidate_path,
            index=False,
            encoding="utf-8",
        )

    cross_split_candidates = (
        len(candidates_df)
    )

    lines = [
        "ScamShield AI V2 Leakage Check",
        "=" * 55,
        "",
        f"Original master records: {original_count:,}",
        f"Final binary records after cleanup: {final_count:,}",
        (
            "Conflicting-label rows excluded: "
            f"{conflicting_count:,}"
        ),
        (
            "Duplicate/template rows removed: "
            f"{duplicates_removed:,}"
        ),
        "",
        "Split sizes:",
        f"Train: {len(train_df):,}",
        f"Validation: {len(validation_df):,}",
        f"Test: {len(test_df):,}",
        "",
        (
            "Near-duplicate similarity threshold: "
            f"{SIMILARITY_THRESHOLD:.2f}"
        ),
        (
            "Cross-split near-duplicate candidates: "
            f"{cross_split_candidates:,}"
        ),
        "",
    ]

    if cross_split_candidates == 0:

        lines.extend(
            [
                "STATUS: PASS FOR THIS CHECK",
                (
                    "No cross-split candidate reached "
                    "the configured similarity threshold."
                ),
            ]
        )

    else:

        lines.extend(
            [
                "STATUS: REVIEW REQUIRED",
                (
                    "Do not publish final ML metrics yet."
                ),
                (
                    "Inspect and resolve candidate groups "
                    "before freezing the evaluation split."
                ),
            ]
        )

    content = "\n".join(
        lines
    )

    report_path.write_text(
        content,
        encoding="utf-8",
    )

    print(
        "\n" + content
    )

    print(
        f"\nSummary saved: {report_path}"
    )

    if not candidates_df.empty:

        print(
            "Candidate records saved locally:"
        )

        print(
            candidate_path
        )


def main():

    print("=" * 60)
    print(
        "ScamShield AI V2 - Leakage Safe Split Builder"
    )
    print("=" * 60)

    (
        df,
        original_count,
        conflicting_count,
        duplicates_removed,
    ) = prepare_dataset()

    (
        train_df,
        validation_df,
        test_df,
    ) = create_splits(
        df
    )

    candidates_df = (
        run_similarity_check(
            train_df,
            validation_df,
            test_df,
        )
    )

    save_splits(
        train_df,
        validation_df,
        test_df,
    )

    save_report(
        original_count=original_count,
        final_count=len(df),
        conflicting_count=conflicting_count,
        duplicates_removed=duplicates_removed,
        train_df=train_df,
        validation_df=validation_df,
        test_df=test_df,
        candidates_df=candidates_df,
    )


if __name__ == "__main__":
    main()