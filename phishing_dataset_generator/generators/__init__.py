"""
Generators package for synthetic phishing dataset creation.

Uses real brand login page HTML templates. The generator loads templates
from templates/brands/ and replaces placeholders to create phishing
(credential-harvesting) and legitimate page variants.
"""

from .template_loader import (
    load_brands_meta,
    load_template,
    load_and_build,
    generate_phishing_action_url,
    generate_legitimate_action_url,
    generate_hidden_fields,
)
from .phishing_page import generate_phishing_page
from .legitimate_page import generate_legitimate_page
