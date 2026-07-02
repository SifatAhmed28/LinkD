"""
Phishing page generator.

Loads a brand's real login page template, replaces placeholders to
create a credential-harvesting page hosted on a 3rd-party trusted service.
"""

from .template_loader import load_and_build


def generate_phishing_page(
    template_dir: str,
    brand_meta: dict,
    platform_name: str,
    platform_domain: str,
    hidden_field_count: int = 2,
    index: int = 0,
) -> tuple[str, dict]:
    """
    Generate a phishing page from a brand template.

    Returns (html_string, metadata_dict).
    """
    html, form_action = load_and_build(
        template_dir=template_dir,
        brand_meta=brand_meta,
        platform_domain=platform_domain,
        is_phishing=True,
        hidden_field_count=hidden_field_count,
    )

    # Determine form action type from the generated URL
    if platform_domain in form_action:
        form_action_type = "same_platform_origin"
    elif form_action.startswith("https://"):
        form_action_type = "cross_origin_https"
    elif form_action.startswith("http://"):
        form_action_type = "cross_origin_http"
    else:
        form_action_type = "other"

    # Parse real domain from brand metadata
    real_domains = brand_meta.get("real_domains", [])
    real_domain = real_domains[0] if real_domains else "unknown"

    # Check if form action domain mismatches the brand's real domain
    has_domain_mismatch = real_domain not in form_action

    metadata = {
        "label": 1,
        "platform": platform_name,
        "platform_domain": platform_domain,
        "brand": brand_meta.get("brand_name", "unknown"),
        "real_domain": real_domain,
        "form_action": form_action,
        "form_action_type": form_action_type,
        "has_domain_mismatch": has_domain_mismatch,
        "hidden_fields_count": hidden_field_count,
        # "html_template": brand_meta.get("html_file", ""),
    }

    return html, metadata
