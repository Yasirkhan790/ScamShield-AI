from pathlib import Path
import re

import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.neighbors import NearestNeighbors


INPUT_FILE = Path(
    "research/data/processed/master_text_dataset.csv"
)

OUTPUT_DIR = Path(
    "research/data/splits"
)

REPORT_DIR = Path(
    "research/reports"
)

PROCESSED_DIR = Path(
    "research/data/processed"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

PROCESSED_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


RANDOM_STATE = 42

SIMILARITY_THRESHOLD = 0.92

NEIGHBORS = 8


# ============================================================
# UNION FIND
# ============================================================

class UnionFind:

    def __init__(self, size):

        self.parent = list(
            range(size)
        )

        self.rank = [
            0
        ] * size

    def find(self, value):

        while (
            self.parent[value]
            != value
        ):

            self.parent[value] = (
                self.parent[
                    self.parent[value]
                ]
            )

            value = (
                self.parent[value]
            )

        return value

    def union(self, first, second):

        root_first = self.find(
            first
        )

        root_second = self.find(
            second
        )

        if (
            root_first
            == root_second
        ):
            return

        if (
            self.rank[root_first]
            < self.rank[root_second]
        ):

            self.parent[root_first] = (
                root_second
            )

        elif (
            self.rank[root_first]
            > self.rank[root_second]
        ):

            self.parent[root_second] = (
                root_first
            )

        else:

            self.parent[root_second] = (
                root_first
            )

            self.rank[root_first] += 1


# ============================================================
# NORMALIZATION
# ============================================================

def clean_text(text):

    text = str(text)

    text = text.replace(
        "\x00",
        " ",
    )

    text = text.replace(
        "\r",
        " ",
    )

    text = text.replace(
        "\n",
        " ",
    )

    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    return text.strip()


def leakage_key(text):

    text = clean_text(
        text
    ).casefold()

    # URLs
    text = re.sub(
        r"https?://\S+|www\.\S+",
        " urltoken ",
        text,
    )

    # Email addresses
    text = re.sub(
        r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b",
        " emailtoken ",
        text,
    )

    # Numbers
    text = re.sub(
        r"\b\d+\b",
        " numbertoken ",
        text,
    )

    # Punctuation
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


# ============================================================
# LOAD DATA
# ============================================================

def load_dataset():

    print("=" * 60)

    print(
        "ScamShield AI V2 - Group-Aware Split Builder"
    )

    print("=" * 60)

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False,
    )

    print(
        f"\nMaster records: {len(df):,}"
    )

    df = df[
        df["label"].isin(
            [
                "scam",
                "legitimate",
            ]
        )
    ].copy()

    df = df.dropna(
        subset=[
            "text",
            "label",
        ]
    )

    df["text"] = (
        df["text"]
        .apply(clean_text)
    )

    df = df[
        df["text"].str.len() >= 3
    ].copy()

    df["_leakage_key"] = (
        df["text"]
        .apply(leakage_key)
    )

    print(
        f"Binary records: {len(df):,}"
    )

    return df


# ============================================================
# REMOVE EXACT/TEMPLATE CONFLICTS
# ============================================================

def remove_template_conflicts(
    df
):

    print(
        "\nChecking normalized template conflicts..."
    )

    labels_per_key = (
        df.groupby(
            "_leakage_key"
        )["label"]
        .nunique()
    )

    conflicting_keys = set(
        labels_per_key[
            labels_per_key > 1
        ].index
    )

    conflict_df = df[
        df["_leakage_key"].isin(
            conflicting_keys
        )
    ].copy()

    print(
        "Conflicting-label rows:",
        len(conflict_df),
    )

    if not conflict_df.empty:

        conflict_df.to_csv(
            PROCESSED_DIR /
            "group_split_conflicts.csv",
            index=False,
        )

    df = df[
        ~df["_leakage_key"].isin(
            conflicting_keys
        )
    ].copy()

    before = len(df)

    df = df.drop_duplicates(
        subset="_leakage_key",
        keep="first",
    ).copy()

    print(
        "Exact/template duplicates removed:",
        before - len(df),
    )

    df = df.reset_index(
        drop=True
    )

    return df


# ============================================================
# DISCOVER NEAR-DUPLICATE GROUPS
# ============================================================

def build_similarity_groups(
    df
):

    print(
        "\nBuilding TF-IDF fingerprints..."
    )

    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=25000,
        sublinear_tf=True,
        dtype="float32",
    )

    matrix = vectorizer.fit_transform(
        df["text"]
    )

    print(
        "Finding near-duplicate neighbours..."
    )

    number_neighbors = min(
        NEIGHBORS,
        len(df),
    )

    nearest = NearestNeighbors(
        n_neighbors=number_neighbors,
        metric="cosine",
        algorithm="brute",
        n_jobs=-1,
    )

    nearest.fit(
        matrix
    )

    distances, indices = (
        nearest.kneighbors(
            matrix
        )
    )

    groups = UnionFind(
        len(df)
    )

    relationships = 0

    for row_index in range(
        len(df)
    ):

        for neighbour_position in range(
            1,
            number_neighbors,
        ):

            other_index = int(
                indices[
                    row_index,
                    neighbour_position,
                ]
            )

            similarity = (
                1.0
                - float(
                    distances[
                        row_index,
                        neighbour_position,
                    ]
                )
            )

            if (
                similarity
                >= SIMILARITY_THRESHOLD
            ):

                groups.union(
                    row_index,
                    other_index,
                )

                relationships += 1

    print(
        "Near-duplicate relationships found:",
        relationships,
    )

    df["similarity_group"] = [
        groups.find(index)
        for index in range(
            len(df)
        )
    ]

    group_sizes = (
        df["similarity_group"]
        .value_counts()
    )

    duplicate_groups = (
        group_sizes[
            group_sizes > 1
        ]
    )

    print(
        "Near-duplicate groups:",
        len(duplicate_groups),
    )

    print(
        "Rows belonging to duplicate groups:",
        int(
            duplicate_groups.sum()
        ),
    )

    return df


# ============================================================
# REMOVE GROUP LABEL CONFLICTS
# ============================================================

def remove_group_conflicts(
    df
):

    print(
        "\nChecking label consistency inside groups..."
    )

    label_counts = (
        df.groupby(
            "similarity_group"
        )["label"]
        .nunique()
    )

    bad_groups = set(
        label_counts[
            label_counts > 1
        ].index
    )

    conflict_rows = df[
        df["similarity_group"].isin(
            bad_groups
        )
    ].copy()

    print(
        "Rows in conflicting near-duplicate groups:",
        len(conflict_rows),
    )

    if not conflict_rows.empty:

        conflict_rows.to_csv(
            PROCESSED_DIR /
            "near_duplicate_label_conflicts.csv",
            index=False,
        )

    clean_df = df[
        ~df["similarity_group"].isin(
            bad_groups
        )
    ].copy()

    return clean_df


# ============================================================
# GROUP-LEVEL SPLIT
# ============================================================

def split_groups(
    df
):

    print(
        "\nCreating group-level split..."
    )

    group_table = (
        df.groupby(
            "similarity_group"
        )
        .agg(
            label=(
                "label",
                "first",
            ),
            row_count=(
                "label",
                "size",
            ),
        )
        .reset_index()
    )

    print(
        "Unique groups:",
        len(group_table),
    )

    train_groups, temp_groups = (
        train_test_split(
            group_table,
            test_size=0.30,
            random_state=RANDOM_STATE,
            stratify=group_table[
                "label"
            ],
        )
    )

    validation_groups, test_groups = (
        train_test_split(
            temp_groups,
            test_size=0.50,
            random_state=RANDOM_STATE,
            stratify=temp_groups[
                "label"
            ],
        )
    )

    train_ids = set(
        train_groups[
            "similarity_group"
        ]
    )

    validation_ids = set(
        validation_groups[
            "similarity_group"
        ]
    )

    test_ids = set(
        test_groups[
            "similarity_group"
        ]
    )

    train_df = df[
        df["similarity_group"].isin(
            train_ids
        )
    ].copy()

    validation_df = df[
        df["similarity_group"].isin(
            validation_ids
        )
    ].copy()

    test_df = df[
        df["similarity_group"].isin(
            test_ids
        )
    ].copy()

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


# ============================================================
# VERIFY GROUP LEAKAGE
# ============================================================

def verify_group_leakage(
    train_df,
    validation_df,
    test_df,
):

    train_groups = set(
        train_df[
            "similarity_group"
        ]
    )

    validation_groups = set(
        validation_df[
            "similarity_group"
        ]
    )

    test_groups = set(
        test_df[
            "similarity_group"
        ]
    )

    train_validation = (
        train_groups
        & validation_groups
    )

    train_test = (
        train_groups
        & test_groups
    )

    validation_test = (
        validation_groups
        & test_groups
    )

    total_leaks = (
        len(train_validation)
        + len(train_test)
        + len(validation_test)
    )

    print(
        "\nCross-split duplicate-group leakage:",
        total_leaks,
    )

    return total_leaks


# ============================================================
# SAVE
# ============================================================

def save_results(
    train_df,
    validation_df,
    test_df,
    leakage_count,
):

    drop_columns = [
        "_leakage_key",
        "similarity_group",
    ]

    train_output = (
        train_df.drop(
            columns=drop_columns,
            errors="ignore",
        )
    )

    validation_output = (
        validation_df.drop(
            columns=drop_columns,
            errors="ignore",
        )
    )

    test_output = (
        test_df.drop(
            columns=drop_columns,
            errors="ignore",
        )
    )

    train_output.to_csv(
        OUTPUT_DIR / "train.csv",
        index=False,
    )

    validation_output.to_csv(
        OUTPUT_DIR /
        "validation.csv",
        index=False,
    )

    test_output.to_csv(
        OUTPUT_DIR / "test.csv",
        index=False,
    )

    report = [
        "ScamShield AI V2 Group-Aware Split Report",
        "=" * 55,
        "",
        (
            "Near-duplicate threshold: "
            f"{SIMILARITY_THRESHOLD}"
        ),
        "",
        f"Train records: {len(train_df):,}",
        (
            "Validation records: "
            f"{len(validation_df):,}"
        ),
        f"Test records: {len(test_df):,}",
        "",
        (
            "Cross-split group leakage: "
            f"{leakage_count}"
        ),
        "",
    ]

    if leakage_count == 0:

        report.append(
            "STATUS: GROUP SPLIT PASS"
        )

    else:

        report.append(
            "STATUS: REVIEW REQUIRED"
        )

    content = "\n".join(
        report
    )

    (
        REPORT_DIR /
        "group_split_summary.txt"
    ).write_text(
        content,
        encoding="utf-8",
    )

    print(
        "\n" + content
    )


# ============================================================
# MAIN
# ============================================================

def main():

    df = load_dataset()

    df = remove_template_conflicts(
        df
    )

    df = build_similarity_groups(
        df
    )

    df = remove_group_conflicts(
        df
    )

    (
        train_df,
        validation_df,
        test_df,
    ) = split_groups(
        df
    )

    leakage_count = (
        verify_group_leakage(
            train_df,
            validation_df,
            test_df,
        )
    )

    save_results(
        train_df,
        validation_df,
        test_df,
        leakage_count,
    )


if __name__ == "__main__":
    main()