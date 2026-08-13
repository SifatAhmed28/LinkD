"""
Generators package for synthetic phishing dataset creation.

Supports two generation paths:
  1. Programmatic HTML generation (html_builder.py) — no saved templates needed
  2. Template-based generation (template_loader.py) — uses saved brand HTML templates

Both paths feed into feature_extractor.py for ML-ready output.
"""

from .html_builder import BRANDS, get_brand, get_all_brand_keys
from .feature_extractor import extract_features, extract_text_features, extract_forms
from .phishing_variations import STRATEGIES, pick_strategy, apply_variation
from .attacker_domains import generate_attacker_domain, pick_attacker_strategy, ATTACKER_STRATEGIES
from .legitimate_variations import PAGE_TYPES as LEGITIMATE_PAGE_TYPES, pick_page_type
from .phishing_page import generate_phishing_page
from .legitimate_page import generate_legitimate_page
from .template_loader import load_brands_meta
