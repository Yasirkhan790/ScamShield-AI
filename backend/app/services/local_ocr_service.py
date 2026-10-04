from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
import os
import shutil

import pytesseract
from PIL import Image, ImageEnhance, ImageOps


@dataclass(frozen=True)
class LocalOCRResult:
    status: str
    provider: str | None
    text: str
    error: str | None = None


def _enabled() -> bool:
    raw = os.getenv(
        "LOCAL_OCR_ENABLED",
        "false",
    )

    return (
        raw.strip().lower()
        not in {
            "0",
            "false",
            "no",
            "off",
            "disabled",
        }
    )


def local_ocr_health() -> dict:
    enabled = _enabled()

    executable = shutil.which(
        "tesseract"
    )

    return {
        "enabled": enabled,
        "ready": (
            enabled
            and executable is not None
        ),
        "provider": (
            "tesseract"
            if executable
            else None
        ),
    }


def extract_text_with_local_ocr(
    image_bytes: bytes,
) -> LocalOCRResult:

    if not _enabled():
        return LocalOCRResult(
            status="disabled",
            provider=None,
            text="",
        )

    executable = shutil.which(
        "tesseract"
    )

    if not executable:
        return LocalOCRResult(
            status="fallback",
            provider="tesseract",
            text="",
            error=(
                "Tesseract executable is not installed."
            ),
        )

    try:
        image = Image.open(
            BytesIO(
                image_bytes
            )
        )

        # Prevent unexpectedly huge decoded images.
        if (
            image.width * image.height
            > 25_000_000
        ):
            return LocalOCRResult(
                status="fallback",
                provider="tesseract",
                text="",
                error=(
                    "Decoded image dimensions are too large."
                ),
            )

        image = ImageOps.exif_transpose(
            image
        )

        image = image.convert(
            "L"
        )

        image = ImageOps.autocontrast(
            image
        )

        image = ImageEnhance.Contrast(
            image
        ).enhance(
            1.5
        )

        text = pytesseract.image_to_string(
            image,
            config="--psm 6",
        ).strip()

        if not text:
            return LocalOCRResult(
                status="fallback",
                provider="tesseract",
                text="",
                error=(
                    "No readable text was detected."
                ),
            )

        return LocalOCRResult(
            status="used",
            provider="tesseract",
            text=text[:10000],
        )

    except Exception as exc:
        return LocalOCRResult(
            status="fallback",
            provider="tesseract",
            text="",
            error=str(
                exc
            ),
        )