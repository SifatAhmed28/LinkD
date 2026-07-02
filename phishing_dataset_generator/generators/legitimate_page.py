"""
Legitimate page generator.

Loads a brand's real login page template, replaces placeholders with
legitimate values (real domain form action, no tracking fields).
"""

from .template_loader import load_and_build


def generate_legitimate_page(
    template_dir: str,
    brand_meta: dict,
    platform_name: str,
    platform_domain: str,
    index: int = 0,
) -> tuple[str, dict]:
    """
    Generate a legitimate page from a brand template.

    Returns (html_string, metadata_dict).
    """
    html, form_action = load_and_build(
        template_dir=template_dir,
        brand_meta=brand_meta,
        platform_domain=platform_domain,
        is_phishing=False,
        hidden_field_count=0,
    )

    real_domains = brand_meta.get("real_domains", [])
    real_domain = real_domains[0] if real_domains else "unknown"

    metadata = {
        "label": 0,
        "platform": platform_name,
        "platform_domain": platform_domain,
        "brand": brand_meta.get("brand_name", "unknown"),
        "real_domain": real_domain,
        "form_action": form_action,
        "form_action_type": "same_origin",
        "has_domain_mismatch": False,
        "hidden_fields_count": 0,
        # "html_template": brand_meta.get("html_file", ""),
    }

    return html, metadata
