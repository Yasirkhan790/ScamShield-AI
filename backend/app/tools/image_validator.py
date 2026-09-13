import os

SUPPORTED_IMAGE_TYPES = {
    "image/png": "png",
    "image/jpeg": "jpeg",
    "image/webp": "webp",
}


class ImageValidationError(ValueError):
    pass


def screenshot_max_bytes() -> int:
    raw = os.getenv("SCREENSHOT_MAX_BYTES", str(5 * 1024 * 1024))
    try:
        value = int(raw)
    except ValueError:
        value = 5 * 1024 * 1024
    return max(1024, value)


def validate_image_bytes(data: bytes, mime_type: str) -> str:
    normalized_type = (mime_type or "").split(";", 1)[0].strip().lower()
    if normalized_type not in SUPPORTED_IMAGE_TYPES:
        raise ImageValidationError("Only PNG, JPG/JPEG, and WEBP screenshots are supported")

    if not data:
        raise ImageValidationError("The uploaded screenshot is empty")

    if normalized_type == "image/png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ImageValidationError("The file content does not match a valid PNG image")

    if normalized_type == "image/jpeg" and not data.startswith(b"\xff\xd8\xff"):
        raise ImageValidationError("The file content does not match a valid JPEG image")

    if normalized_type == "image/webp":
        if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
            raise ImageValidationError("The file content does not match a valid WEBP image")

    return normalized_type
