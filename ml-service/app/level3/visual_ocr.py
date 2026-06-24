"""
Visual OCR Analysis — Level 3

Uses EasyOCR to extract text embedded in screenshot images.
This defeats visual obfuscation techniques where phishing text is
rendered as an image (bypassing HTML text analysis).

Extracted text is:
1. Re-scored through urgency/fear pattern matching
2. Checked for brand names + credential prompts
3. Used as supplementary input for sentiment scoring
"""

import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("linkd.visual_ocr")

# Patterns for credential harvesting in extracted OCR text
OCR_CREDENTIAL_PATTERNS = [
    re.compile(r"(enter|type)\s+your\s+(password|email|username)", re.IGNORECASE),
    re.compile(r"sign\s+in", re.IGNORECASE),
    re.compile(r"log\s+in", re.IGNORECASE),
    re.compile(r"verify\s+(your\s+)?(account|identity)", re.IGNORECASE),
    re.compile(r"account\s+(suspended|locked|expired)", re.IGNORECASE),
    re.compile(r"confirm\s+your\s+(password|email)", re.IGNORECASE),
]

OCR_BRAND_NAMES = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "twitter", "linkedin", "github", "netflix", "spotify",
    "bank of america", "wells fargo", "chase", "citibank",
]


class VisualOCRAnalyzer:
    """Singleton EasyOCR analyzer with lazy loading."""

    _instance: Optional["VisualOCRAnalyzer"] = None

    def __init__(self):
        self._reader = None
        self._loaded = False

    @classmethod
    def get_instance(cls) -> "VisualOCRAnalyzer":
        if cls._instance is None:
            cls._instance = cls()
        if not cls._instance._loaded:
            cls._instance._load_reader()
        return cls._instance

    def _load_reader(self):
        """Initialize EasyOCR reader (downloads model on first run)."""
        try:
            import easyocr
            logger.info("Loading EasyOCR reader (English)...")
            # GPU=False for compatibility; set True if CUDA is available
            self._reader = easyocr.Reader(["en"], gpu=False, verbose=False)
            self._loaded = True
            logger.info("✅ EasyOCR reader loaded.")
        except Exception as e:
            logger.error(f"Failed to load EasyOCR: {e}")
            self._loaded = False
            raise

    def analyze(self, screenshot_path: str) -> Dict[str, Any]:
        """
        Extract text from a screenshot and score for phishing indicators.

        Args:
            screenshot_path: Absolute path to the screenshot PNG/JPEG

        Returns:
            Dictionary with ocr_score, extracted_text, detected_brands, flags
        """
        if not os.path.exists(screenshot_path):
            return {
                "ocr_score": 0.0,
                "extracted_text": "",
                "error": "Screenshot file not found",
            }

        extracted_text = ""
        confidence_scores: List[float] = []

        # ── Run EasyOCR ──────────────────────────────────────────────────
        try:
            results = self._reader.readtext(screenshot_path, detail=1, paragraph=False)
            text_parts = []
            for (_, text, confidence) in results:
                text_parts.append(text)
                confidence_scores.append(confidence)
            extracted_text = " ".join(text_parts)
        except Exception as e:
            logger.error(f"EasyOCR inference error: {e}")
            return {
                "ocr_score": 0.0,
                "extracted_text": "",
                "error": str(e),
            }

        if not extracted_text.strip():
            return {
                "ocr_score": 0.0,
                "extracted_text": "",
                "avg_confidence": 0.0,
            }

        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0

        # ── Pattern Matching on OCR Text ─────────────────────────────────
        flags = []
        score = 0.0
        text_lower = extracted_text.lower()

        # Credential harvesting patterns
        credential_hits = 0
        for pattern in OCR_CREDENTIAL_PATTERNS:
            if pattern.search(extracted_text):
                credential_hits += 1

        if credential_hits > 0:
            flags.append(f"ocr_credential_patterns_{credential_hits}")
            score += min(credential_hits * 0.2, 0.6)

        # Brand names detected in OCR text (visual impersonation)
        detected_brands = [b for b in OCR_BRAND_NAMES if b in text_lower]
        if detected_brands:
            flags.append(f"ocr_brand_detected_{','.join(detected_brands)}")
            score += 0.3

        # Password or "Enter password" text visible as image
        if re.search(r"password", text_lower):
            flags.append("ocr_password_text_visible")
            score += 0.25

        # Social engineering phrases
        urgency_terms = ["urgent", "warning", "alert", "suspended", "blocked", "expires"]
        urgency_hits = sum(1 for t in urgency_terms if t in text_lower)
        if urgency_hits > 0:
            flags.append(f"ocr_urgency_terms_{urgency_hits}")
            score += min(urgency_hits * 0.1, 0.3)

        ocr_score = round(min(score, 1.0), 4)

        return {
            "ocr_score": ocr_score,
            "extracted_text": extracted_text[:2000],
            "avg_confidence": round(avg_confidence, 3),
            "credential_hits": credential_hits,
            "detected_brands": detected_brands,
            "flags": flags,
            "text_length": len(extracted_text),
        }
