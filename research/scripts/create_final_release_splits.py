from pathlib import Path
import json
import re

import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.neighbors import NearestNeighbors


MASTER_FILE = Path(
    "research/data/processed/master_text_dataset.csv"
)

CHALLENGE_REPORT = Path(
    "research/reports/hardened_candidate_challenge_results.json"
)

OUTPUT_DIR = Path(
    "research/data/final_splits"
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


# New split seed for the final release cycle.
FINAL_RANDOM_STATE = 20261003

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

        if (
            self.parent[value]
            != value
        ):

            self.parent[value] = (
                self.find(
                    self.parent[value]
                )
            )

        return self.parent[value]

    def union(
        self,
        first,
        second,
    ):

        root_first = (
            self.find(
                first
            )
        )

        root_second = (
            self.find(
                second
            )
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
# CLEANING
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

    text = (
        clean_text(
            text
        )
        .casefold()
    )

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

    # Most punctuation
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
# CHECK HARDENED CANDIDATE
# ============================================================

def check_candidate_gate():

    print(
        "\nChecking hardened candidate challenge gate..."
    )

    if not CHALLENGE_REPORT.exists():

        raise RuntimeError(
            "Hardened candidate challenge report "
            "does not exist. Run the hardened "
            "candidate challenge suite first."
        )

    report = json.loads(
        CHALLENGE_REPORT.read_text(
            encoding="utf-8"
        )
    )

    passed = int(
        report.get(
            "passed",
            0,
        )
    )

    total = int(
        report.get(
            "total",
            0,
        )
    )

    print(
        f"Challenge result: {passed}/{total}"
    )

    if total != 10:

        raise RuntimeError(
            "Expected 10 challenge cases."
        )

    if passed < 8:

        raise RuntimeError(
            "Hardened candidate still does not "
            "meet the 8/10 challenge target. "
            "Do not create final release split yet."
        )

    print(
        "Candidate challenge gate: PASS"
    )


# ============================================================
# LOAD BINARY DATA
# ============================================================

def load_dataset():

    print(
        "\nLoading master dataset..."
    )

    df = pd.read_csv(
        MASTER_FILE,
        low_memory=False,
    )

    print(
        f"Master records: {len(df):,}"
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
        .apply(
            clean_text
        )
    )

    df = df[
        df["text"].str.len()
        >= 3
    ].copy()

    df["_leakage_key"] = (
        df["text"]
        .apply(
            leakage_key
        )
    )

    print(
        f"Binary records: {len(df):,}"
    )

    return df


# ============================================================
# REMOVE TEMPLATE DUPLICATES / CONFLICTS
# ============================================================

def clean_templates(df):

    print(
        "\nChecking template conflicts..."
    )

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

    conflicts = df[
        df["_leakage_key"]
        .isin(
            conflicting_keys
        )
    ].copy()

    print(
        "Conflicting rows:",
        len(conflicts),
    )

    if not conflicts.empty:

        conflicts.to_csv(
            PROCESSED_DIR /
            "final_release_template_conflicts.csv",

            index=False,
            encoding="utf-8",
        )

    df = df[
        ~df["_leakage_key"]
        .isin(
            conflicting_keys
        )
    ].copy()

    before = len(
        df
    )

    df = df.drop_duplicates(
        subset=[
            "_leakage_key"
        ],

        keep="first",
    ).copy()

    print(
        "Template duplicates removed:",
        before - len(df),
    )

    return df.reset_index(
        drop=True
    )


# ============================================================
# BUILD SIMILARITY GROUPS
# ============================================================

def build_groups(df):

    print(
        "\nBuilding near-duplicate groups..."
    )

    vectorizer = TfidfVectorizer(
        analyzer="char_wb",

        ngram_range=(
            3,
            5,
        ),

        min_df=2,

        max_features=25000,

        sublinear_tf=True,

        dtype="float32",
    )

    matrix = (
        vectorizer.fit_transform(
            df["text"]
        )
    )

    nearest_count = min(
        NEIGHBORS,
        len(df),
    )

    nearest = NearestNeighbors(
        n_neighbors=nearest_count,

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

    union_find = UnionFind(
        len(df)
    )

    relationship_count = 0

    for row_index in range(
        len(df)
    ):

        for neighbour_position in range(
            1,
            nearest_count,
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

                union_find.union(
                    row_index,
                    other_index,
                )

                relationship_count += 1

    df["similarity_group"] = [
        union_find.find(
            index
        )
        for index in range(
            len(df)
        )
    ]

    print(
        "Near-duplicate relationships:",
        relationship_count,
    )

    print(
        "Unique similarity groups:",
        df[
            "similarity_group"
        ].nunique(),
    )

    return df


# ============================================================
# REMOVE GROUP LABEL CONFLICTS
# ============================================================

def remove_group_conflicts(df):

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
        df["similarity_group"]
        .isin(
            bad_groups
        )
    ].copy()

    print(
        "\nRows in conflicting similarity groups:",
        len(conflict_rows),
    )

    if not conflict_rows.empty:

        conflict_rows.to_csv(
            PROCESSED_DIR /
            "final_release_group_conflicts.csv",

            index=False,
            encoding="utf-8",
        )

    df = df[
        ~df["similarity_group"]
        .isin(
            bad_groups
        )
    ].copy()

    return df


# ============================================================
# FINAL GROUP SPLIT
# ============================================================

def split_dataset(df):

    print(
        "\nCreating FINAL group-aware "
        "70/15/15 split..."
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

    train_groups, temp_groups = (
        train_test_split(
            group_table,

            test_size=0.30,

            random_state=
                FINAL_RANDOM_STATE,

            stratify=
                group_table[
                    "label"
                ],
        )
    )

    validation_groups, holdout_groups = (
        train_test_split(
            temp_groups,

            test_size=0.50,

            random_state=
                FINAL_RANDOM_STATE,

            stratify=
                temp_groups[
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

    holdout_ids = set(
        holdout_groups[
            "similarity_group"
        ]
    )

    train_df = df[
        df["similarity_group"]
        .isin(
            train_ids
        )
    ].copy()

    validation_df = df[
        df["similarity_group"]
        .isin(
            validation_ids
        )
    ].copy()

    holdout_df = df[
        df["similarity_group"]
        .isin(
            holdout_ids
        )
    ].copy()

    return (
        train_df,
        validation_df,
        holdout_df,
    )


# ============================================================
# VERIFY ZERO GROUP LEAKAGE
# ============================================================

def verify_groups(
    train_df,
    validation_df,
    holdout_df,
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

    holdout_groups = set(
        holdout_df[
            "similarity_group"
        ]
    )

    overlap = (
        len(
            train_groups
            & validation_groups
        )
        +
        len(
            train_groups
            & holdout_groups
        )
        +
        len(
            validation_groups
            & holdout_groups
        )
    )

    return overlap


# ============================================================
# SAVE
# ============================================================

def save_results(
    train_df,
    validation_df,
    holdout_df,
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

    holdout_output = (
        holdout_df.drop(
            columns=drop_columns,
            errors="ignore",
        )
    )

    train_output.to_csv(
        OUTPUT_DIR /
        "train_final.csv",

        index=False,
        encoding="utf-8",
    )

    validation_output.to_csv(
        OUTPUT_DIR /
        "validation_final.csv",

        index=False,
        encoding="utf-8",
    )

    holdout_output.to_csv(
        OUTPUT_DIR /
        "release_holdout.csv",

        index=False,
        encoding="utf-8",
    )

    report = [
        "ScamShield AI V2 Final Release Split",
        "=" * 55,
        "",
        (
            "Random state: "
            f"{FINAL_RANDOM_STATE}"
        ),
        (
            "Near-duplicate threshold: "
            f"{SIMILARITY_THRESHOLD}"
        ),
        "",
        (
            "Train records: "
            f"{len(train_output):,}"
        ),
        (
            "Validation records: "
            f"{len(validation_output):,}"
        ),
        (
            "Release holdout records: "
            f"{len(holdout_output):,}"
        ),
        "",
        (
            "Cross-split group leakage: "
            f"{leakage_count}"
        ),
        "",
    ]

    if leakage_count == 0:

        report.extend(
            [
                "STATUS: FINAL SPLIT PASS",
                "",
                (
                    "IMPORTANT: Do not inspect or use "
                    "release_holdout.csv for threshold "
                    "selection or model development."
                ),
            ]
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
        "final_release_split_summary.txt"
    ).write_text(
        content,
        encoding="utf-8",
    )

    print(
        "\n"
        + content
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print(
        "=" * 65
    )

    print(
        "ScamShield AI V2 - Final Release Split Builder"
    )

    print(
        "=" * 65
    )

    check_candidate_gate()

    df = load_dataset()

    df = clean_templates(
        df
    )

    df = build_groups(
        df
    )

    df = remove_group_conflicts(
        df
    )

    (
        train_df,
        validation_df,
        holdout_df,
    ) = split_dataset(
        df
    )

    leakage_count = (
        verify_groups(
            train_df,
            validation_df,
            holdout_df,
        )
    )

    save_results(
        train_df,
        validation_df,
        holdout_df,
        leakage_count,
    )


if __name__ == "__main__":
    main()