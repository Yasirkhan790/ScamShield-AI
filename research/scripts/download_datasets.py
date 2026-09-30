from io import BytesIO
from pathlib import Path
from urllib.request import Request, urlopen
import zipfile

import pandas as pd
from datasets import load_dataset
from ucimlrepo import fetch_ucirepo

RAW_DIR = Path("research/data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)


def download_sms_dataset():
    print("\n[1/3] Downloading UCI SMS Spam Collection...")

    url = (
        "https://archive.ics.uci.edu/static/public/228/"
        "sms+spam+collection.zip"
    )

    request = Request(
        url,
        headers={"User-Agent": "Mozilla/5.0"},
    )

    with urlopen(request, timeout=60) as response:
        zip_data = response.read()

    with zipfile.ZipFile(BytesIO(zip_data)) as archive:
        sms_file = None

        for name in archive.namelist():
            if name.endswith("SMSSpamCollection"):
                sms_file = name
                break

        if sms_file is None:
            raise RuntimeError(
                "SMSSpamCollection file not found."
            )

        content = archive.read(sms_file).decode(
            "utf-8",
            errors="replace",
        )

    records = []

    for line in content.splitlines():
        if not line.strip():
            continue

        parts = line.split("\t", 1)

        if len(parts) == 2:
            label, text = parts

            records.append(
                {
                    "label": label.strip(),
                    "text": text.strip(),
                }
            )


    df = pd.DataFrame(records)

    output = RAW_DIR / "uci_sms_spam.csv"

    df.to_csv(
        output,
        index=False,
        encoding="utf-8",
    )

    print(f"Saved: {output}")
    print(f"Rows: {len(df):,}")
    print(df["label"].value_counts())


def download_email_dataset():
    print("\n[2/3] Downloading phishing email dataset...")

    dataset = load_dataset(
        "zefang-liu/phishing-email-dataset",
        split="train",
    )

    df = dataset.to_pandas()

    output = RAW_DIR / "phishing_email.csv"

    df.to_csv(
        output,
        index=False,
        encoding="utf-8",
    )

    print(f"Saved: {output}")
    print(f"Rows: {len(df):,}")
    print(f"Columns: {list(df.columns)}")


def download_url_dataset():
    print("\n[3/3] Downloading UCI PhiUSIIL phishing URL dataset...")

    output = RAW_DIR / "phiusiil_urls.csv"

    # Do not download again if we already have a valid file
    if output.exists() and output.stat().st_size > 1_000_000:
        print(f"Already downloaded: {output}")
        return

    url = (
        "https://archive.ics.uci.edu/static/public/967/"
        "phiusiil+phishing+url+dataset.zip"
    )

    request = Request(
        url,
        headers={"User-Agent": "Mozilla/5.0"},
    )

    zip_data = None

    # Retry up to 3 times if connection breaks
    for attempt in range(1, 4):
        try:
            print(f"Download attempt {attempt}/3...")

            with urlopen(request, timeout=120) as response:
                zip_data = response.read()

            print(
                f"Downloaded {len(zip_data) / 1024 / 1024:.2f} MB"
            )

            break

        except Exception as exc:
            print(f"Attempt {attempt} failed: {exc}")

            if attempt == 3:
                raise RuntimeError(
                    "Could not download the PhiUSIIL dataset "
                    "after 3 attempts."
                ) from exc

    try:
        with zipfile.ZipFile(BytesIO(zip_data)) as archive:

            print("Archive files:")
            print(archive.namelist())

            csv_file = None

            for name in archive.namelist():
                if name.endswith(
                    "PhiUSIIL_Phishing_URL_Dataset.csv"
                ):
                    csv_file = name
                    break

            if csv_file is None:
                raise RuntimeError(
                    "PhiUSIIL CSV was not found inside the ZIP."
                )

            with archive.open(csv_file) as source:
                df = pd.read_csv(
                    source,
                    low_memory=False,
                )

    except zipfile.BadZipFile as exc:
        raise RuntimeError(
            "The downloaded PhiUSIIL ZIP file is invalid."
        ) from exc

    df.to_csv(
        output,
        index=False,
        encoding="utf-8",
    )

    print(f"Saved: {output}")
    print(f"Rows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    if "label" in df.columns:
        print("\nLabel distribution:")
        print(df["label"].value_counts())


def main():
    print("=" * 60)
    print("ScamShield AI V2 Dataset Downloader")
    print("=" * 60)

    download_sms_dataset()
    download_email_dataset()
    download_url_dataset()

    print("\n" + "=" * 60)
    print("Dataset download completed.")
    print("=" * 60)


if __name__ == "__main__":
    main()