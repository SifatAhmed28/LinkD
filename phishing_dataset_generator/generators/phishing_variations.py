"""
Phishing variation strategies.

Each strategy applies a different social engineering tactic on top of a base
HTML page to create diverse phishing samples. Strategies include urgency,
authority spoofing, fear induction, reward bait, and document phishing.

The dispatch function `apply_variation()` selects and applies a strategy
based on a weighted random choice.
"""

import random


# ── Urgency texts ──────────────────────────────────────────────────────────────

URGENCY_TEXTS = [
    "Your account will be suspended in 24 hours. Verify your identity now to avoid disruption.",
    "Unusual sign-in activity detected on your account. Confirm within 1 hour to prevent lockout.",
    "Your account has been temporarily limited. Update your information to restore access.",
    "Security Alert: We detected an unauthorized login attempt. Verify your account immediately.",
    "Your session expires in 30 minutes. Re-authenticate now to continue.",
    "Action Required: Complete your account verification by end of business today.",
    "Your free trial ends today. Update payment info to keep your account active.",
    "Important: Your account settings need to be updated before the next billing cycle.",
]

# ── Authority texts ────────────────────────────────────────────────────────────

AUTHORITY_TEXTS = [
    "From: IT Security Team — Password expires today. Update immediately.",
    "From: System Administrator — Mandatory security update required for all accounts.",
    "From: Help Desk — We detected a login from an unrecognized device. Please verify.",
    "From: Compliance Department — Complete your annual security review by end of day.",
    "From: Account Management — Your account needs to be re-verified per new policy.",
    "From: Network Operations — Suspicious network activity detected on your account.",
    "From: Executive IT — All employees must update credentials by Friday.",
]

# ── Fear texts ─────────────────────────────────────────────────────────────────

FEAR_TEXTS = [
    "Your account has been compromised. Immediate action required to prevent data loss.",
    "Suspicious activity detected: Your personal data may have been exposed. Secure your account now.",
    "Warning: Your account shows signs of unauthorized access. Change your password immediately.",
    "Critical: Your account will be permanently deleted in 48 hours if not verified.",
    "Alert: Multiple failed login attempts detected. Your account is at risk of being locked.",
    "Your payment method has been flagged for fraudulent activity. Verify to avoid suspension.",
    "Data Breach Notice: Your credentials may have been leaked. Update your password now.",
]

# ── Reward texts ───────────────────────────────────────────────────────────────

REWARD_TEXTS = [
    "Congratulations! You've been selected for a $500 gift card. Sign in to claim your reward.",
    "You've won a free premium subscription for 12 months! Log in to activate your reward.",
    "Exclusive offer: Upgrade your account to Premium for free. This offer expires in 24 hours.",
    "Your loyalty reward is ready! Sign in to redeem your $200 account credit.",
    "Special promotion: Get 6 months free with your next purchase. Claim your offer now.",
    "You've been chosen for early access to our newest feature. Sign in to unlock it.",
    "As a valued customer, you qualify for a 50% discount. Apply before it expires tonight.",
]

# ── Strategy registry ──────────────────────────────────────────────────────────

STRATEGIES = {
    "credential_harvest": {
        "description": "Standard login form — no additional text injection",
        "weight": 0.30,
    },
    "urgency": {
        "description": "Injects urgency/time-pressure text to rush the victim",
        "weight": 0.15,
    },
    "authority": {
        "description": "Spoofs authority figure (IT dept, admin, compliance)",
        "weight": 0.10,
    },
    "fear": {
        "description": "Injects fear-inducing language about account compromise",
        "weight": 0.10,
    },
    "reward": {
        "description": "Baits victim with fake reward/gift/prize",
        "weight": 0.10,
    },
    "document_phish": {
        "description": "Asks for document upload / identity verification",
        "weight": 0.10,
    },
    "screenshot_overlay": {
        "description": "Full-page screenshot of legitimate site with transparent form overlay — defeats HTML-based detection",
        "weight": 0.15,
    },
}


def pick_strategy() -> str:
    """Pick a random strategy weighted by the STRATEGIES config."""
    names = list(STRATEGIES.keys())
    weights = [STRATEGIES[s]["weight"] for s in names]
    return random.choices(names, weights=weights, k=1)[0]


def apply_variation(html: str, strategy: str, brand_name: str = "your") -> tuple[str, dict]:
    """
    Apply a phishing variation strategy to a base HTML page.

    Args:
        html: The base HTML page (usually from html_builder.build_login_page).
        strategy: One of the STRATEGIES keys.
        brand_name: Brand display name for template substitution.

    Returns:
        (modified_html, variation_metadata)
    """
    metadata = {
        "phishing_strategy": strategy,
        "urgency_text_injected": False,
        "authority_text_injected": False,
        "fear_text_injected": False,
        "reward_text_injected": False,
        "document_fields_injected": False,
    }

    if strategy == "credential_harvest":
        return html, metadata

    if strategy == "urgency":
        text = random.choice(URGENCY_TEXTS)
        return _inject_banner(html, text, "#fff3cd", "#ffc107", "#856404"), metadata | {
            "urgency_text_injected": True,
            "injected_text": text,
        }

    if strategy == "authority":
        text = random.choice(AUTHORITY_TEXTS)
        return _inject_banner(html, text, "#d1ecf1", "#bee5eb", "#0c5460"), metadata | {
            "authority_text_injected": True,
            "injected_text": text,
        }

    if strategy == "fear":
        text = random.choice(FEAR_TEXTS)
        return _inject_banner(html, text, "#f8d7da", "#f5c6cb", "#721c24"), metadata | {
            "fear_text_injected": True,
            "injected_text": text,
        }

    if strategy == "reward":
        text = random.choice(REWARD_TEXTS)
        return _inject_banner(html, text, "#d4edda", "#c3e6cb", "#155724"), metadata | {
            "reward_text_injected": True,
            "injected_text": text,
        }

    if strategy == "document_phish":
        return _inject_document_fields(html), metadata | {
            "document_fields_injected": True,
        }

    # Fallback — unknown strategy, return unchanged
    return html, metadata


def _inject_banner(html: str, text: str, bg: str, border: str, color: str) -> str:
    """Inject a colored alert banner after the first <div class="card">."""
    banner = (
        f'<div style="background:{bg};border:1px solid {border};border-radius:6px;'
        f'padding:12px 16px;margin-bottom:20px;font-size:14px;color:{color};text-align:center;">'
        f'{text}</div>'
    )
    marker = '<div class="card">'
    if marker in html:
        return html.replace(marker, f"{marker}\n{banner}", 1)
    # Fallback: inject before </form>
    marker2 = '</form>'
    if marker2 in html:
        return html.replace(marker2, f"{banner}\n{marker2}", 1)
    return html


def _inject_document_fields(html: str) -> str:
    """Inject document upload / identity fields into the form."""
    fields = (
        '<div class="form-group">\n'
        '    <label for="full_name">Full Legal Name</label>\n'
        '    <input type="text" name="full_name" id="full_name" placeholder="John Doe" autocomplete="off">\n'
        '</div>\n'
        '<div class="form-group">\n'
        '    <label for="id_number">ID / SSN Last 4 Digits</label>\n'
        '    <input type="text" name="id_number" id="id_number" placeholder="XXXX" maxlength="4" autocomplete="off">\n'
        '</div>\n'
        '<div class="form-group">\n'
        '    <label for="doc_upload">Upload ID Document</label>\n'
        '    <input type="file" name="doc_upload" id="doc_upload" accept=".jpg,.png,.pdf">\n'
        '</div>'
    )
    # Inject before the submit button
    marker = '<button type="submit"'
    if marker in html:
        return html.replace(marker, f"{fields}\n{marker}", 1)
    # Fallback: inject before </form>
    marker2 = '</form>'
    if marker2 in html:
        return html.replace(marker2, f"{fields}\n{marker2}", 1)
    return html
