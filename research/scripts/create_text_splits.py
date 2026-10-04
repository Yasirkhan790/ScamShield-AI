from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


INPUT_FILE = Path(
    "research/data/processed/master_text_dataset.csv"
)

OUTPUT_DIR = Path(
    "research/data/splits"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


def main():

    print("=" * 60)
    print("ScamShield AI V2 - Dataset Splitter")
    print("=" * 60)

    df = pd.read_csv(
        INPUT_FILE,
        low_memory=False,
    )

    print(f"\nMaster records: {len(df):,}")

    # Only reliable binary labels for model V1
    df = df[
        df["label"].isin(
            ["scam", "legitimate"]
        )
    ].copy()

    df = df.dropna(
        subset=["text", "label"]
    )

    df["text"] = (
        df["text"]
        .astype(str)
        .str.strip()
    )

    df = df[
        df["text"].str.len() >= 3
    ]

    print(
        f"Usable labeled records: {len(df):,}"
    )

    print("\nLabel distribution:")
    print(
        df["label"].value_counts()
    )

    # 70% training
    # 30% temporary
    train_df, temp_df = train_test_split(
        df,
        test_size=0.30,
        random_state=42,
        stratify=df["label"],
    )

    # Half of remaining 30%
    # 15% validation + 15% test
    validation_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        random_state=42,
        stratify=temp_df["label"],
    )

    train_df.to_csv(
        OUTPUT_DIR / "train.csv",
        index=False,
        encoding="utf-8",
    )

    validation_df.to_csv(
        OUTPUT_DIR / "validation.csv",
        index=False,
        encoding="utf-8",
    )

    test_df.to_csv(
        OUTPUT_DIR / "test.csv",
        index=False,
        encoding="utf-8",
    )

    print("\nSplit sizes:")

    print(
        f"Train:      {len(train_df):,}"
    )

    print(
        f"Validation: {len(validation_df):,}"
    )

    print(
        f"Test:       {len(test_df):,}"
    )

    print("\nTraining distribution:")
    print(
        train_df["label"]
        .value_counts()
    )

    print("\nValidation distribution:")
    print(
        validation_df["label"]
        .value_counts()
    )

    print("\nTest distribution:")
    print(
        test_df["label"]
        .value_counts()
    )

    print(
        "\nDataset splitting completed."
    )


if __name__ == "__main__":
    main()