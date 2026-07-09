"""
Form Behavior Analysis — Level 3

Analyzes HTML form actions and input types to detect:
1. Cross-origin POST destinations (data exfiltration)
2. HTTPS → HTTP downgrade in form submissions
3. Hidden field data collection
4. Suspicious action URL patterns
5. Password fields combined with brand impersonation
"""

import logging
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger("linkd.form_behavior")

# Data exfiltration endpoints (common phishing kit patterns)
EXFILTRATION_PATTERNS = [
    r"formspree\.io",
    r"getform\.io",
    r"formcarry\.com",
    r"pageclip\.co",
    r"netlify\.com/submissions",
    r"submit\.jotform\.com",
    r"api\.staticforms\.xyz",
    r"docs\.google\.com/forms",  # Legitimate but used for phishing
    r"\.php$",  # PHP form handlers are common in phishing kits
    r"gate\.php",
    r"post\.php",
    r"submit\.php",
    r"login\.php",
    r"check\.php",
    r"verify\.php",
]

EXFILTRATION_REGEX = re.compile("|".join(EXFILTRATION_PATTERNS), re.IGNORECASE)


def analyze_form_behavior(
    page_url: str,
    forms: List[Dict[str, Any]],
    html: str = "",
) -> Dict[str, Any]:
    """
    Analyze form behavior signals for phishing indicators.

    Args:
        page_url: The URL of the scanned page
        forms: List of form dicts from HTML parser
        html: Raw HTML for deeper BeautifulSoup analysis

    Returns:
        Dictionary with form_score and detailed flags
    """
    flags = []
    score = 0.0
    detail = {}

    page_origin = _get_origin(page_url)
    page_scheme = urlparse(page_url).scheme

    # ── Deep parse with BeautifulSoup ────────────────────────────────────
    soup = None
    if html:
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            pass

    # ── Analyze Each Form ──────────────────────────────────────────────────
    suspicious_forms = []

    for i, form in enumerate(forms or []):
        action = form.get("action", "").strip()
        method = form.get("method", "get").lower()
        inputs = form.get("inputs", [])

        form_flags = []
        form_score = 0.0

        # 1. Password field presence
        has_password = any(
            inp.get("type", "").lower() == "password"
            for inp in inputs
        )
        if has_password:
            form_flags.append("has_password_field")
            form_score += 0.3

        # 2. Cross-origin form action
        if action and action.startswith("http"):
            form_origin = _get_origin(action)
            if form_origin and form_origin != page_origin:
                form_flags.append("cross_origin_form_action")
                form_score += 0.5
                detail[f"form_{i}_cross_origin"] = f"{page_origin} → {form_origin}"

        # 3. HTTPS → HTTP downgrade
        if page_scheme == "https" and action.startswith("http:"):
            form_flags.append("https_to_http_downgrade")
            form_score += 0.4

        # 4. Known exfiltration endpoints
        if action and EXFILTRATION_REGEX.search(action):
            form_flags.append("known_exfiltration_endpoint")
            form_score += 0.35
            detail[f"form_{i}_exfil_action"] = action[:100]

        # 5. POST method with password field (stronger signal)
        if method == "post" and has_password:
            form_flags.append("post_with_password")
            form_score += 0.2

        # 6. Hidden inputs (potential data smuggling)
        hidden_count = sum(
            1 for inp in inputs
            if inp.get("type", "").lower() == "hidden"
        )
        if hidden_count > 3:
            form_flags.append(f"many_hidden_fields_{hidden_count}")
            form_score += 0.15

        # 7. No action (data to same page with JS extraction)
        if not action or action == "#":
            form_flags.append("no_action_suspicious")
            form_score += 0.1

        if form_flags:
            suspicious_forms.append({
                "index": i,
                "action": action[:100],
                "method": method,
                "flags": form_flags,
                "form_score": round(min(form_score, 1.0), 3),
            })

    # ── BeautifulSoup Deep Scan ───────────────────────────────────────────
    if soup:
        # Check for autocomplete="off" on password fields (phishing kit pattern)
        pwd_fields = soup.find_all("input", {"type": "password"})
        for field in pwd_fields:
            if field.get("autocomplete") == "off":
                flags.append("password_autocomplete_off")
                score += 0.15
                break

        # Detect forms inside iframes (nested login pages)
        iframes = soup.find_all("iframe")
        for iframe in iframes:
            src = iframe.get("src", "")
            if src and _get_origin(src) != page_origin:
                flags.append("cross_origin_iframe")
                score += 0.25
                break

    # ── Aggregate ─────────────────────────────────────────────────────────
    if suspicious_forms:
        # Take max form score + small bonus for each additional suspicious form
        max_form_score = max(f["form_score"] for f in suspicious_forms)
        bonus = min((len(suspicious_forms) - 1) * 0.05, 0.2)
        score += max_form_score + bonus

    total_score = round(min(score, 1.0), 3)

    if total_score > 0.3:
        flags.append("suspicious_form_detected")

    return {
        "form_score": total_score,
        "flags": flags,
        "suspicious_forms": suspicious_forms,
        "total_forms_analyzed": len(forms or []),
        **detail,
    }


def _get_origin(url: str) -> str:
    """Extract scheme + hostname from a URL."""
    try:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return ""
