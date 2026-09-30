from pathlib import Path
import hashlib
import re

import pandas as pd


RAW_DIR = Path("research/data/raw")
PROCESSED_DIR = Path("research/data/processed")
REPORTS_DIR = Path("research/reports")

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


OUTPUT_COLUMNS = [
    "record_id",
    "text",
    "label",
    "category",
    "language",
    "indicators",
    "source",
    "source_label",
    "label_quality",
    "source_type",
    "is_synthetic",
    "review_status",
    "notes",
]


def clean_text(value):
    if pd.isna(value):
        return ""

    text = str(value)

    text = text.replace("\x00", " ")
    text = text.replace("\r", " ")
    text = text.replace("\n", " ")

    text = re.sub(r"\s+", " ", text)

    return text.strip()


def make_record_id(source, text):
    value = f"{source}|{text}".encode(
        "utf-8",
        errors="ignore",
    )

    digest = hashlib.sha256(value).hexdigest()

    return digest[:16]


# ============================================================
# SMS DATASET
# ============================================================

def process_sms():
    path = RAW_DIR / "uci_sms_spam.csv"

    print("\nProcessing SMS dataset...")

    df = pd.read_csv(path)

    print("Original SMS rows:", len(df))
    print("SMS columns:", list(df.columns))

    df["text"] = df["text"].apply(clean_text)
    df["source_label"] = (
        df["label"]
        .astype(str)
        .str.strip()
        .str.lower()
    )

    records = []

    for _, row in df.iterrows():

        text = row["text"]
        source_label = row["source_label"]

        if not text:
            continue

        if source_label == "ham":
            label = "legitimate"
            category = "none"
            quality = "moderate"
            review_status = "source_labeled"

        elif source_label == "spam":
            # Important:
            # Spam is NOT automatically the same as scam.
            label = "needs_review"
            category = "unknown"
            quality = "weak"
            review_status = "needs_review"

        else:
            label = "needs_review"
            category = "unknown"
            quality = "weak"
            review_status = "needs_review"

        records.append(
            {
                "record_id": make_record_id(
                    "uci_sms",
                    text,
                ),
                "text": text,
                "label": label,
                "category": category,
                "language": "en",
                "indicators": "",
                "source": "uci_sms_spam_collection",
                "source_label": source_label,
                "label_quality": quality,
                "source_type": "public_dataset",
                "is_synthetic": False,
                "review_status": review_status,
                "notes": "",
            }
        )

    result = pd.DataFrame(records)

    print("Clean SMS rows:", len(result))

    return result


# ============================================================
# PHISHING EMAIL DATASET
# ============================================================

def normalize_email_label(value):
    value = str(value).strip().lower()

    if "phishing" in value:
        return (
            "scam",
            "phishing",
            "strong",
            "source_labeled",
        )

    if (
        "safe" in value
        or "legitimate" in value
        or "benign" in value
        or value == "ham"
    ):
        return (
            "legitimate",
            "none",
            "strong",
            "source_labeled",
        )

    return (
        "needs_review",
        "unknown",
        "weak",
        "needs_review",
    )


def process_email():
    path = RAW_DIR / "phishing_email.csv"

    print("\nProcessing email dataset...")

    df = pd.read_csv(
        path,
        low_memory=False,
    )

    print("Original email rows:", len(df))
    print("Email columns:", list(df.columns))

    # Remove unnecessary exported index columns
    unnamed_columns = [
        col
        for col in df.columns
        if str(col).lower().startswith("unnamed")
    ]

    if unnamed_columns:
        df = df.drop(
            columns=unnamed_columns,
            errors="ignore",
        )

    if "Email Text" not in df.columns:
        raise RuntimeError(
            "Could not find 'Email Text' column."
        )

    if "Email Type" not in df.columns:
        raise RuntimeError(
            "Could not find 'Email Type' column."
        )

    records = []

    for _, row in df.iterrows():

        text = clean_text(
            row["Email Text"]
        )

        source_label = str(
            row["Email Type"]
        ).strip()

        if not text:
            continue

        (
            label,
            category,
            quality,
            review_status,
        ) = normalize_email_label(
            source_label
        )

        records.append(
            {
                "record_id": make_record_id(
                    "phishing_email",
                    text,
                ),
                "text": text,
                "label": label,
                "category": category,
                "language": "en",
                "indicators": "",
                "source": "phishing_email_dataset",
                "source_label": source_label,
                "label_quality": quality,
                "source_type": "public_dataset",
                "is_synthetic": False,
                "review_status": review_status,
                "notes": "",
            }
        )

    result = pd.DataFrame(records)

    print("Clean email rows:", len(result))

    return result


# ============================================================
# MANUAL SEED DATA
# ============================================================

def process_seed():
    path = RAW_DIR / "scamshield_seed.csv"

    if not path.exists():
        return pd.DataFrame(
            columns=OUTPUT_COLUMNS
        )

    print("\nProcessing ScamShield seed data...")

    df = pd.read_csv(path)

    if len(df) == 0:
        print("Seed dataset currently contains no records.")

        return pd.DataFrame(
            columns=OUTPUT_COLUMNS
        )

    records = []

    for _, row in df.iterrows():

        text = clean_text(
            row.get("text", "")
        )

        if not text:
            continue

        label = str(
            row.get(
                "label",
                "needs_review",
            )
        ).strip().lower()

        records.append(
            {
                "record_id": make_record_id(
                    "scamshield_seed",
                    text,
                ),
                "text": text,
                "label": label,
                "category": row.get(
                    "category",
                    "unknown",
                ),
                "language": row.get(
                    "language",
                    "en",
                ),
                "indicators": row.get(
                    "indicators",
                    "",
                ),
                "source": "scamshield_seed",
                "source_label": label,
                "label_quality": "strong",
                "source_type": "manual",
                "is_synthetic": bool(
                    row.get(
                        "is_synthetic",
                        False,
                    )
                ),
                "review_status": row.get(
                    "review_status",
                    "reviewed",
                ),
                "notes": row.get(
                    "notes",
                    "",
                ),
            }
        )

    return pd.DataFrame(records)


# ============================================================
# DUPLICATE HANDLING
# ============================================================

def remove_duplicates(df):

    print("\nChecking duplicates...")

    before = len(df)

    df["_dedupe_text"] = (
        df["text"]
        .astype(str)
        .str.casefold()
        .str.strip()
    )

    duplicate_count = (
        df.duplicated(
            subset=["_dedupe_text"],
            keep=False,
        ).sum()
    )

    print(
        "Rows involved in exact duplicates:",
        duplicate_count,
    )

    # Prefer stronger labels when duplicates exist
    quality_priority = {
        "strong": 0,
        "moderate": 1,
        "weak": 2,
    }

    df["_quality_priority"] = (
        df["label_quality"]
        .map(quality_priority)
        .fillna(3)
    )

    df = df.sort_values(
        by="_quality_priority"
    )

    df = df.drop_duplicates(
        subset=["_dedupe_text"],
        keep="first",
    )

    df = df.drop(
        columns=[
            "_dedupe_text",
            "_quality_priority",
        ]
    )

    after = len(df)

    print(
        "Removed duplicate rows:",
        before - after,
    )

    return df


# ============================================================
# REPORT
# ============================================================

def create_report(df):

    report_path = (
        REPORTS_DIR /
        "master_dataset_summary.txt"
    )

    lines = []

    lines.append(
        "ScamShield AI V2 Master Dataset Summary"
    )
    lines.append("=" * 50)

    lines.append(
        f"Total records: {len(df):,}"
    )

    lines.append("")
    lines.append("Label distribution:")
    lines.append(
        df["label"]
        .value_counts(dropna=False)
        .to_string()
    )

    lines.append("")
    lines.append("Source distribution:")
    lines.append(
        df["source"]
        .value_counts(dropna=False)
        .to_string()
    )

    lines.append("")
    lines.append("Label quality:")
    lines.append(
        df["label_quality"]
        .value_counts(dropna=False)
        .to_string()
    )

    lines.append("")
    lines.append("Review status:")
    lines.append(
        df["review_status"]
        .value_counts(dropna=False)
        .to_string()
    )

    content = "\n".join(lines)

    report_path.write_text(
        content,
        encoding="utf-8",
    )

    print("\n" + content)

    print(
        f"\nReport saved: {report_path}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print(
        "ScamShield AI V2 - Master Dataset Builder"
    )
    print("=" * 60)

    sms_df = process_sms()

    email_df = process_email()

    seed_df = process_seed()

    master = pd.concat(
        [
            sms_df,
            email_df,
            seed_df,
        ],
        ignore_index=True,
    )

    print(
        "\nCombined rows before cleaning:",
        len(master),
    )

    master = master[
        master["text"].str.len() >= 3
    ].copy()

    master = remove_duplicates(
        master
    )

    master = master[
        OUTPUT_COLUMNS
    ]

    output_path = (
        PROCESSED_DIR /
        "master_text_dataset.csv"
    )

    master.to_csv(
        output_path,
        index=False,
        encoding="utf-8",
    )

    print(
        f"\nMaster dataset saved: {output_path}"
    )

    create_report(master)


if __name__ == "__main__":
    main()