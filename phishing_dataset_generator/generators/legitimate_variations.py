"""
Legitimate page variation generators.

Creates diverse legitimate page types (landing, about, docs, blog) so the
legitimate class is not limited to login pages. Each page type builds a
complete HTML document with realistic content and no credential-harvesting forms.

The dispatch function `pick_page_type()` selects a page type based on
weighted random choice configured in dataset_config.yaml.
"""

import random

from . import html_builder


# ── Page type registry ─────────────────────────────────────────────────────────

PAGE_TYPES = {
    "landing": {
        "description": "Marketing/product landing page",
        "builder": html_builder.build_landing_page,
    },
    "about": {
        "description": "Company about/team page",
        "builder": html_builder.build_about_page,
    },
    "docs": {
        "description": "Documentation/help center page",
        "builder": html_builder.build_docs_page,
    },
    "blog": {
        "description": "Blog post page",
        "builder": html_builder.build_blog_page,
    },
    "profile": {
        "description": "Account/profile settings page",
        "builder": html_builder.build_profile_page,
    }
}

# Default weights — overridden by dataset_config.yaml
DEFAULT_WEIGHTS = {
    "landing": 0.25,
    "about": 0.20,
    "docs": 0.20,
    "blog": 0.20,
    "profile": 0.15,
}


def pick_page_type(weights: dict | None = None) -> str:
    """
    Pick a random legitimate page type, weighted by config.

    Args:
        weights: Dict of page_type → weight. If None, uses DEFAULT_WEIGHTS.

    Returns:
        One of the PAGE_TYPES keys.
    """
    w = weights or DEFAULT_WEIGHTS
    types = list(w.keys())
    probs = [w[t] for t in types]
    return random.choices(types, weights=probs, k=1)[0]


def generate_legitimate_variation(
    brand: dict,
    page_type: str,
    platform_domain: str = "",
) -> tuple[str, dict]:
    """
    Generate a legitimate page of the given type.

    Args:
        brand: Brand metadata dict (from html_builder.BRANDS).
        page_type: One of the PAGE_TYPES keys.
        platform_domain: Hosting platform domain (for metadata).

    Returns:
        (html_string, metadata_dict)
    """
    if page_type not in PAGE_TYPES:
        raise ValueError(f"Unknown page type: '{page_type}'. Available: {list(PAGE_TYPES.keys())}")

    builder = PAGE_TYPES[page_type]["builder"]
    html = builder(brand)

    # For login type, use html_builder.build_login_page with real domain
    real_domain = brand["real_domains"][0] if brand.get("real_domains") else "example.com"
    form_action = f"https://{real_domain}/login"

    metadata = {
        "page_type": page_type,
        "form_action": form_action,
        "form_action_type": "same_origin",
        "has_domain_mismatch": False,
        "has_password_field": page_type == "login",
        "hidden_fields_count": 0,
    }

    return html, metadata
