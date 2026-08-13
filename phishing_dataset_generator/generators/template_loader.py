"""
Template loader and placeholder substitution engine.

Loads brand login page HTML templates from templates/brands/ and
replaces placeholders ({{FORM_ACTION}}, {{HIDDEN_FIELDS}}, {{PLATFORM_URL}})
with appropriate values for phishing or legitimate page generation.
"""

import os
import random
import yaml
from pathlib import Path
from .attacker_domains import generate_random_combo, URL_PATH_PHRASES, FAKE_DOMAINS_PHRASES


def load_brands_meta(meta_path: str) -> dict:
    """Load brands_meta.yaml and return brand configurations."""
    with open(meta_path, "r") as f:
        return yaml.safe_load(f)


def load_template(template_path: str) -> str:
    """Load an HTML template file and return its content."""
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()


def _rand_token(length: int = 32) -> str:
    """Generate a random hex token."""
    return ''.join(random.choices('abcdef0123456789', k=length))


# --- Form action URL generators ---

def generate_phishing_action_url(platform_domain: str) -> str:
    """
    Generate a plausible form action URL hosted on the 3rd-party platform.

    Returns URLs like: https://auth-verify.github.io/signin
    These look like they could be legitimate SSO/auth pages.
    """
    subdomain = generate_random_combo(FAKE_DOMAINS_PHRASES, "domain")
    url_path = generate_random_combo(URL_PATH_PHRASES)
    url_path = '/' + url_path.lstrip('/')
    return f"https://{subdomain}.{platform_domain}{url_path}"


def generate_legitimate_action_url(real_domains: list[str]) -> str:
    """
    Generate a legitimate form action URL using the brand's real domain.

    Returns URLs like: https://accounts.google.com/signin
    """
    domain = real_domains[0] if real_domains else "example.com"
    path = random.choice(["/signin", "/login", "/auth", "/session", ""])
    return f"https://{domain}{path}"


# --- Hidden field generators ---

HIDDEN_FIELD_TEMPLATES = [
    ('redirect', 'https://{platform}/dashboard'),
    ('continue', 'https://{platform}/welcome'),
    ('_next', '/account'),
    ('source', 'email_campaign'),
    ('ref', '{token}'),
    ('ts', '{timestamp}'),
    ('session_id', '{token}'),
    ('flow_id', '{token}'),
    ('context', 'web_login'),
    ('service', 'account'),
]


def generate_hidden_fields(count: int, platform_domain: str) -> str:
    """
    Generate hidden <input> fields.

    Returns raw HTML string to substitute into {{HIDDEN_FIELDS}}.
    For legitimate pages, returns just a CSRF token.
    For phishing pages, returns tracking/exfiltration fields.
    """
    if count <= 0:
        return ""

    fields = []
    used_names = set()

    for _ in range(count):
        name, value_tmpl = random.choice(HIDDEN_FIELD_TEMPLATES)
        # Avoid duplicate field names
        while name in used_names:
            name, value_tmpl = random.choice(HIDDEN_FIELD_TEMPLATES)
        used_names.add(name)

        value = value_tmpl.format(
            platform=platform_domain,
            token=_rand_token(24),
            timestamp=str(random.randint(1700000000, 1800000000)),
        )
        fields.append(f'    <input type="hidden" name="{name}" value="{value}">')

    return "\n".join(fields)


def generate_csrf_field() -> str:
    """Generate a single CSRF token hidden field (for legitimate pages)."""
    return f'    <input type="hidden" name="csrf_token" value="{_rand_token(32)}">'


# --- Main substitution engine ---

def apply_template(html: str,
                   form_action: str,
                   hidden_fields: str,
                   platform_url: str) -> str:
    """
    Replace all placeholders in a template with actual values.

    Returns the final HTML string.
    """
    result = html.replace("{{FORM_ACTION}}", form_action)
    result = result.replace("{{HIDDEN_FIELDS}}", hidden_fields)
    result = result.replace("{{PLATFORM_URL}}", platform_url)
    return result


def load_and_build(template_dir: str,
                   brand_meta: dict,
                   platform_domain: str,
                   is_phishing: bool,
                   hidden_field_count: int = 0) -> tuple[str, str]:
    """
    Load a brand template and return (final_html, form_action_url).

    For phishing: form points to 3rd-party platform, hidden fields injected.
    For legitimate: form points to real domain, just a CSRF token.
    """
    html_file = brand_meta["html_file"]
    template_path = os.path.join(template_dir, html_file)

    if not os.path.exists(template_path):
        raise FileNotFoundError(f"Template not found: {template_path}")

    html = load_template(template_path)

    # Generate form action
    if is_phishing:
        form_action = generate_phishing_action_url(platform_domain)
        hidden = generate_hidden_fields(hidden_field_count, platform_domain)
    else:
        form_action = generate_legitimate_action_url(brand_meta.get("real_domains", []))
        hidden = generate_csrf_field()

    # Hosting platform URL (where the page is "deployed")
    subdomain = random.choice(PHISHING_SUBDOMAINS if is_phishing else ["app", "www", "login", "accounts"])
    platform_url = f"{subdomain}.{platform_domain}"

    # Substitute
    final_html = apply_template(html, form_action, hidden, platform_url)

    return final_html, form_action
