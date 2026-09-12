import io
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

def extract_text_from_image(image_bytes: bytes) -> Tuple[Optional[str], bool, str]:
    if not image_bytes:
        return None, False, "Uploaded image is empty."
        
    try:
        from PIL import Image
        import pytesseract
        
        image = Image.open(io.BytesIO(image_bytes))
        extracted_text = pytesseract.image_to_string(image).strip()
        
        if not extracted_text:
            return None, True, "No readable text found in image."
            
        return extracted_text, True, "Text extracted successfully."
    except ImportError:
        logger.warning("pytesseract or PIL is not installed.")
        return None, False, "OCR library is not configured on the server."
    except Exception as e:
        logger.error(f"OCR extraction failed: {e}")
        return None, False, f"Could not read image text: {str(e)}"
