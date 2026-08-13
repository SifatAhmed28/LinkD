"""
Legitimate page generator.

Builds diverse legitimate pages (landing, about, docs, blog) using html_builder.
For the "login" page type, uses html_builder.build_login_page with the brand's
real domain as the form action.
"""

import random

from . import html_builder
from .legitimate_variations import pick_page_type, generate_legitimate_variation

LEGITIMATE_EXTERNAL_AUTH_DOMAINS = [
    "login.microsoftonline.com",
    "accounts.google.com",
    "auth0.com",
    "okta.com",
]

LEGITIMATE_HIDDEN_FIELD_TEMPLATES = [
    ("csrf_token", "{token}"),
    ("state", "{token}"),
    ("nonce", "{token}"),
    ("continue", "https://{domain}/"),
    ("return_to", "/"),
    ("locale", "en-US"),
    ("flow_id", "{token}"),
    ("session_id", "{token}"),
]

def _rand_token(length: int = 32) -> str:
    return "".join(random.choices("abcdef0123456789", k=length))

def _generate_legitimate_hidden_fields(count: int, real_domain: str) -> str:
    if count <= 0:
        return ""

    fields = []
    used_names: set[str] = set()

    # Sample without replacement where possible.
    choices = LEGITIMATE_HIDDEN_FIELD_TEMPLATES.copy()
    random.shuffle(choices)

    for name, value_tmpl in choices[: min(count, len(choices))]:
        used_names.add(name)
        value = value_tmpl.format(domain=real_domain, token=_rand_token(24))
        fields.append(
            f'    <input type="hidden" name="{name}" value="{value}">'
        )

    # If a caller asks for more than the template count, add unique benign fields.
    while len(fields) < count:
        name = f"meta_{len(fields)}"
        if name in used_names:
            continue
        used_names.add(name)
        fields.append(
            f'    <input type="hidden" name="{name}" value="{_rand_token(16)}">'
        )

    return "\n".join(fields)


def _generate_legitimate_login_action(
    real_domain: str,
    cross_domain_probability: float = 0.25,
) -> str:
    """
    Generate a legitimate login form action.

    Most forms submit to the brand's own domain, but some use a
    third-party authentication/identity provider. Those cases
    legitimately produce form_action_brand_domain_mismatch=True.
    """
    url_path = random.choice([
        "login",
        "signin",
        "log-in",
        "sign-in",
    ])

    # Generate cross-domain form action url
    if random.random() < cross_domain_probability:
        external_domain = random.choice(
            LEGITIMATE_EXTERNAL_AUTH_DOMAINS
        )

        # Avoid accidentally choosing the brand's own domain.
        if (
            external_domain == real_domain
            or external_domain.endswith("." + real_domain)
        ):
            alternatives = [
                domain
                for domain in LEGITIMATE_EXTERNAL_AUTH_DOMAINS
                if (
                    domain != real_domain
                    and not domain.endswith("." + real_domain)
                )
            ]

            if alternatives:
                external_domain = random.choice(alternatives)

        return f"https://{external_domain}/{url_path}"

    return f"https://{real_domain}/{url_path}"


def generate_legitimate_page(
    brand_key: str,
    brand: dict,
    platform_name: str | None,
    platform_domain: str | None,
    page_type: str | None = None,
    page_type_weights: dict | None = None,
    hidden_field_count: int | None = None,
    visual_variant: str | None = None,
    index: int = 0,
) -> tuple[str, dict]:
    """
    Generate a legitimate page of a random type.

    Args:
        brand_key: Brand key (e.g., "google").
        brand: Brand metadata dict from html_builder.BRANDS.
        platform_name: Platform display name (e.g., "github_io").
        platform_domain: Platform domain (e.g., "github.io").
        page_type: Specific page type. If None, picks randomly.
        page_type_weights: Weights for page type selection. If None, uses defaults.
        hidden_field_count: Number of Hidden Fields to generate.
        visual_variant:
          None / "standard"    -> normal legitimate page
          "screenshot_overlay" -> legitimate raster-overlay login control
        index: Page index for filename generation.

    Returns:
        (html_string, metadata_dict)
    """
    if visual_variant == "screenshot_overlay":
        page_type = "login"
    elif page_type is None:
        page_type = pick_page_type(page_type_weights)

    real_domain = brand["real_domains"][0] if brand.get("real_domains") else "example.com"
    # For "login" page type, use the standard login builder with real domain
    if page_type == "login":
        if hidden_field_count is None:
            hidden_field_count = random.randint(0, 4)

        form_action = _generate_legitimate_login_action(
            real_domain=real_domain,
            cross_domain_probability=0.25,
        )
        hidden_fields = _generate_legitimate_hidden_fields(
            hidden_field_count, real_domain
        )
        
        if visual_variant == "screenshot_overlay":
            # Same structural construction as phishing screenshot overlays.
            # The negative control is legitimate because it submits to the
            # official brand domain.
            html, raster_meta = html_builder.build_screenshot_overlay_page(
                brand,
                form_action,
                hidden_fields,
                platform_domain or real_domain,
            )

            metadata = {
                "label": 0,
                "platform": platform_name,
                "platform_domain": platform_domain,
                "brand": brand.get("name", brand_key),
                "real_domain": real_domain,
                "form_action": form_action,
                "has_password_field": True,
                "hidden_fields_count": hidden_field_count,
                "page_type": "login",
                "phishing_strategy": "none",
                "annotation_visual_modality": "raster_image_overlay",
                "annotation_visible_text_location": "image_pixels",
                "annotation_requires_visual_analysis": True,
                "raster_text_ground_truth": raster_meta["raster_text_ground_truth"],
                "urgency_text_injected": False,
                "authority_text_injected": False,
                "fear_text_injected": False,
                "reward_text_injected": False,
                "document_fields_injected": False,
            }
            return html, metadata

        html = html_builder.build_login_page(
            brand,
            form_action,
            hidden_fields,
        )

        metadata = {
            "label": 0,
            "platform": platform_name,
            "platform_domain": platform_domain,
            "brand": brand.get("name", brand_key),
            "real_domain": real_domain,
            "form_action": form_action,
            "has_password_field": True,
            "hidden_fields_count": hidden_field_count,
            "page_type": "login",
            "phishing_strategy": "none",
            "urgency_text_injected": False,
            "authority_text_injected": False,
            "fear_text_injected": False,
            "reward_text_injected": False,
            "document_fields_injected": False,
        }
        return html, metadata

    html, var_meta = generate_legitimate_variation(
        brand, page_type, platform_domain
    )

    metadata = {
        "label": 0,
        "platform": platform_name,
        "platform_domain": platform_domain,
        "brand": brand.get("name", brand_key),
        "real_domain": real_domain,
        "page_type": page_type,
        "phishing_strategy": "none",
        "urgency_text_injected": False,
        "authority_text_injected": False,
        "fear_text_injected": False,
        "reward_text_injected": False,
        "document_fields_injected": False,
        **var_meta,
    }

    return html, metadata