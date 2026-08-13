"""
ML feature pre-extractor for generated HTML pages.

Mirrors the inference-time feature extraction pipeline in ml-service/level3/.
Extracts visible text, parsed forms, and structured features that Colab can
use directly for model training without additional preprocessing.

Features extracted:
  - visible_text: stripped text content (for sentiment/transformer models)
  - parsed_forms: form structures matching ML service FormData format
  - urgency_score: regex-based urgency text detection (0-1)
  - fear_score: lexicon-based fear text detection (0-1)
  - URL structural features (entropy, digit ratio, etc.)
  - HTML structural features (eval calls, hidden inputs, favicon)
  - Brand detection in text
"""

import json
import math
import re
from html.parser import HTMLParser
from .visual_structure_features import extract_visual_structure_features


# ── Text extraction ────────────────────────────────────────────────────────────

class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()

        self._skip_tags = {
            "script",
            "style",
            "noscript",
            "template",
            "svg",
            "canvas",
        }

        self._skip_depth = 0
        self._in_title = False

        self._title_parts: list[str] = []
        self._body_parts: list[str] = []
        self._in_body = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()

        if tag == "title":
            self._in_title = True
            return

        if tag == "body":
            self._in_body = True
            return

        if self._in_body and tag in self._skip_tags:
            self._skip_depth += 1

    def handle_endtag(self, tag):
        tag = tag.lower()

        if tag == "title":
            self._in_title = False
            return

        if tag == "body":
            self._in_body = False
            return

        if (
            self._in_body
            and tag in self._skip_tags
            and self._skip_depth > 0
        ):
            self._skip_depth -= 1

    def handle_data(self, data):
        text = data.strip()

        if not text:
            return

        if self._in_title:
            self._title_parts.append(text)
            return

        if self._in_body and self._skip_depth == 0:
            self._body_parts.append(text)

    def get_title(self) -> str:
        return " ".join(self._title_parts)

    def get_body_text(self) -> str:
        return " ".join(self._body_parts)


def extract_text_features(html: str) -> dict:
    extractor = _TextExtractor()
    extractor.feed(html)

    title = extractor.get_title()
    body_text = extractor.get_body_text()

    combined = " ".join(
        part for part in [title, body_text] if part
    )

    return {
        "document_title": title,
        "body_visible_text": body_text,
        "visible_text": combined,
    }


# ── Form extraction ────────────────────────────────────────────────────────────

class _FormExtractor(HTMLParser):
    """Parse HTML forms into structured dicts matching ML service FormData."""

    def __init__(self):
        super().__init__()
        self._forms: list[dict] = []
        self._current_form: dict | None = None
        self._current_input: dict | None = None

    def handle_starttag(self, tag, attrs):
        attr = dict(attrs)
        if tag == "form":
            self._current_form = {
                "action": attr.get("action", ""),
                "method": attr.get("method", "get").lower(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "type": attr.get("type", "text"),
                "name": attr.get("name", ""),
                "id": attr.get("id", ""),
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self._forms.append(self._current_form)
            self._current_form = None

    def get_forms(self) -> list[dict]:
        return self._forms


def extract_forms(html: str) -> list[dict]:
    """Parse HTML and return form structures matching ML service format."""
    extractor = _FormExtractor()
    extractor.feed(html)
    return extractor.get_forms()


# ── Keywords for Urgency / Fear / Creds / Authority / Reward / Doc lexicons ─────

URGENCY_WORDS = [
    "urgent", "immediately", "expires", "suspended", "limited", "deadline",
    "act now", "time-sensitive", "hurry", "last chance", "final warning",
    "within 24 hours", "within 1 hour", "before it's too late", "don't delay",
    "temporary", "temporary hold", "renew now", "update now", "verify now",
    "confirm now", "complete now", "today only", "ends today", "by end of day",
    "important", "update", "action required", "security alert",
    "update your information", "restore access", "account settings",
    "expires today", "before the next billing cycle"
]

FEAR_WORDS = [
    "compromised", "unauthorized", "suspicious", "breach", "exposed", "at risk",
    "data loss", "account locked", "locked out", "permanently deleted",
    "fraudulent", "flagged", "illegal", "violation", "termination",
    "law enforcement", "legal action", "investigation", "detected",
    "malware", "virus", "hack", "stolen", "leaked",
]

CREDENTIAL_WORDS = [
    "password", "username", "sign in", "login", "credentials", "ssn",
    "social security", "credit card", "debit card", "pin", "otp",
    "two-factor", "2fa", "verification code", "confirm identity",
    "verify your identity", "bank account", "routing number",
]

AUTHORITY_WORDS = [
    "administrator", "admin", "security team", "security department",
    "it department", "help desk", "compliance", "support team", 
    "system administrator", "verification department", "official notice", 
    "management"
]


REWARD_WORDS = [
    "winner", "won", "reward", "gift", "bonus", "free", "prize",
    "promotion", "discount", "exclusive offer", "claim", "voucher"
]

DOCUMENT_WORDS = [
    "upload document", "upload id", "identity document", "passport",
    "driver license", "national id", "proof of identity",
    "verification document", "id card", "pdf upload", "attach file",
    "upload"
]


def _lexicon_score(text: str, lexicon: list[str]) -> float:
    """Compute a normalized score (0-1) based on lexicon word hits."""
    lower = text.lower()
    hits = sum(1 for w in lexicon if w in lower)
    return round(min(hits / max(len(lexicon)*0.15, 1), 1.0), 3)


# ── URL features ──────────────────────────────────────────────────────────────

SENSITIVE_URL_WORDS = ["secure", "account", "verify", "update", "login", "banking",
                       "signin", "auth", "sso", "confirm", "validate"]


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_url_features(url: str) -> dict:
    """Extract structural features from a URL."""
    url_len = len(url)
    digits = sum(1 for c in url if c.isdigit())
    letters = sum(1 for c in url if c.isalpha())
    url_lower = url.lower()

    return {
        "url_entropy": round(_shannon_entropy(url), 4),
        "url_digit_ratio": round(digits / url_len, 4) if url_len > 0 else 0,
        "url_letter_ratio": round(letters / url_len, 4) if url_len > 0 else 0,
        "url_num_dots": url.count("."),
        "url_num_slashes": url.count("/"),
        "url_num_hyphens": url.count("-"),
        "url_num_equals": url.count("="),
        "url_num_question": url.count("?"),
        "url_num_ampersand": url.count("&"),
        "url_num_percent": url.count("%"),
        "url_num_double_slash": max(0, url.count("//") - 1),
        "url_num_sensitive_words": sum(1 for w in SENSITIVE_URL_WORDS if w in url_lower),
        "url_has_at_symbol": "@" in url,
    }


# ── HTML features ─────────────────────────────────────────────────────────────

def extract_html_features(html: str) -> dict:
    """Extract phishing-kit fingerprint features from HTML."""
    html_lower = html.lower()

    # Count inline script content
    inline_scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE)
    # Only count scripts without src (inline)
    inline_only = [s for s in inline_scripts if s.strip()]

    all_script_text = " ".join(inline_only)

    return {
        "html_num_eval_calls": len(re.findall(r"\beval\s*\(", all_script_text)),
        "html_num_unescape_calls": len(re.findall(r"\b(?:unescape|decodeURIComponent)\s*\(", all_script_text)),
        "html_has_right_click_disabled": bool(
            re.search(r"oncontextmenu\s*=\s*[\"'][^\"']*return\s+false", html, re.IGNORECASE)
        ),
        "sfh_is_empty": "action=\"\"" in html or "action=''" in html or 'action=""' in html_lower,
        "sfh_is_about_blank": "about:blank" in html_lower,
        "html_has_favicon": bool(re.search(r'<link[^>]+rel\s*=\s*["\'](?:shortcut\s+)?icon["\']', html, re.IGNORECASE)),
        "html_num_hidden_inputs": len(re.findall(r'<input[^>]+type\s*=\s*["\']hidden["\']', html, re.IGNORECASE)),
    }


# ── Brand detection ───────────────────────────────────────────────────────────

KNOWN_BRANDS = [
    "google", "microsoft", "paypal", "apple", "facebook", "amazon",
    "instagram", "linkedin", "netflix", "twitter", "github", "dropbox",
    "youtube", "spotify", "zoom", "slack", "stripe", "shopify",
]


def detect_brands_in_text(text: str) -> list[str]:
    """Detect known brand names in visible text."""
    lower = text.lower()
    return [b for b in KNOWN_BRANDS if f" {b} " in f" {lower} "]


# ── Main extraction ───────────────────────────────────────────────────────────

def extract_features(
    html: str,
    url: str = "",
    ocr_text: str = ""
) -> dict:
    """
    Extract all ML-relevant features from a generated HTML page.

    Args:
        html: Full HTML string.
        url: The simulated URL of the page.
        ocr_text: Raster image text

    Returns:
        Dict with all pre-extracted features ready for CSV/JSONL output.
    """
    text_features = extract_text_features(html)

    document_title = text_features["document_title"]
    visible_text = text_features["visible_text"]
    body_visible_text = text_features["body_visible_text"]

    all_text_parts = [document_title, body_visible_text, visible_text, ocr_text]


    all_text = " ".join(x for x in all_text_parts if x)

    forms = extract_forms(html)
    url_features = extract_url_features(url) if url else {}
    html_features = extract_html_features(html)

    # Form-specific features
    has_password = any(
        inp.get("type") == "password"
        for form in forms
        for inp in form.get("inputs", [])
    )
    hidden_count = sum(
        sum(1 for inp in form.get("inputs", []) if inp.get("type") == "hidden")
        for form in forms
    )
    form_action = forms[0].get("action", "") if forms else ""
    form_method = forms[0].get("method", "get") if forms else "get"

    # Calculate scores from all texts - title, visible texts and OCRed texts
    urgency_score = _lexicon_score(
        all_text,
        URGENCY_WORDS
    )


    fear_score = _lexicon_score(
        all_text,
        FEAR_WORDS
    )


    credential_score = _lexicon_score(
        all_text,
        CREDENTIAL_WORDS
    )


    authority_score = _lexicon_score(
        all_text,
        AUTHORITY_WORDS
    )


    reward_score = _lexicon_score(
        all_text,
        REWARD_WORDS
    )


    document_upload_score = _lexicon_score(
        all_text,
        DOCUMENT_WORDS
    )

    # Brand detection
    brands_found = detect_brands_in_text(visible_text)

    visual_structure_features = extract_visual_structure_features(html)

    return {
        "document_title": document_title,
        "body_visible_text": body_visible_text,
        "visible_text": visible_text,
        "parsed_forms": json.dumps(forms),
        "form_action": form_action,
        "form_method": form_method,
        "has_password_field": has_password,
        "hidden_fields_count": hidden_count,
        "urgency_score": urgency_score,
        "fear_score": fear_score,
        "authority_score": authority_score,
        "reward_score": reward_score,
        "document_upload_score": document_upload_score,
        "credential_keyword_score": credential_score,
        "brand_in_text": json.dumps(brands_found),
        **url_features,
        **html_features,
        **visual_structure_features,
    }
