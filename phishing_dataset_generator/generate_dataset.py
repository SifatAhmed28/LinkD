#!/usr/bin/env python3
"""
Phishing Dataset Generator for ML-based Detection Research.

Generates phishing pages (hosted on 3rd-party trusted services) and diverse
legitimate pages, with pre-extracted ML features ready for Google Colab training.

Output:
  - HTML files in dataset/phishing/ and dataset/legitimate/
  - dataset_meta.csv with 27+ columns including visible_text, parsed_forms,
    urgency_score, fear_score, URL features, and HTML features.

Usage:
    python generate_dataset.py                         # default config
    python generate_dataset.py --config my_config.yaml # custom config
    python generate_dataset.py --phishing 100 --legitimate 100
    python generate_dataset.py --seed 123
    python generate_dataset.py --output /tmp/dataset
"""

import argparse
import csv
import hashlib
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from generators.html_builder import BRANDS, get_brand
from generators.phishing_page import generate_phishing_page
from generators.legitimate_page import generate_legitimate_page
from generators.feature_extractor import extract_features
from generators.template_loader import load_brands_meta
from generators.legit_phish_utility import classify_form_action, hostname, belongs_to_domain, resolve_form_action, generate_platform_url, get_tld_risk
import json

from generators.visual_structure_features import export_embedded_raster_assets


def load_config(config_path: str) -> dict:
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def weighted_choice(items: list[dict], weight_key: str = "weight") -> dict:
    weights = [item[weight_key] for item in items]
    return random.choices(items, weights=weights, k=1)[0]


def create_output_dirs(output_dir: str, phishing_subdir: str, legitimate_subdir: str):
    Path(os.path.join(output_dir, phishing_subdir)).mkdir(parents=True, exist_ok=True)
    Path(os.path.join(output_dir, legitimate_subdir)).mkdir(parents=True, exist_ok=True)


def compute_content_hash(html: str) -> str:
    return hashlib.sha256(html.encode("utf-8")).hexdigest()


def resolve_config_path(path: str) -> str:
    """Resolve config path, trying script directory as fallback."""
    if os.path.exists(path):
        return path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    alt = os.path.join(script_dir, path)
    if os.path.exists(alt):
        return alt
    return path


def _pick_hosting_mode(config: dict) -> str:
    """Pick third_party or first_party based on config weights."""
    modes = config.get("hosting_modes", {"third_party": 0.50, "first_party": 0.50})
    names = list(modes.keys())
    weights = [modes[n] for n in names]
    return random.choices(names, weights=weights, k=1)[0]


def _simulate_resolved_real_domain(
    metadata: dict,
    config: dict,
) -> str | None:
    """
    Simulate production brand-domain resolution.

    The generator knows the true domain, but a production detector may
    fail to resolve it (or fail to find a real domain).
    """
    ground_truth_domain = metadata.get("real_domain")

    if not ground_truth_domain:
        return None

    unknown_rate = (
        config.get("generation", {}).get("brand_domain_unknown_rate", 0.15)
    )

    if random.random() < unknown_rate:
        return None

    return ground_truth_domain


def _apply_consistent_form_domain_features(
    metadata: dict,
    features: dict,
    simulated_url: str,
    platform_domain: str | None,
    resolved_real_domain: str | None,
) -> None:
    """Calculate form-action and domain-consistency features identically.

    Extracted HTML is authoritative for form_action when it is present.
    """
    real_domain = metadata.get("real_domain")

    extracted_action = features.get("form_action")
    form_action = (
        extracted_action
        if extracted_action is not None
        else metadata.get("form_action", "")
    ) or ""

    metadata["form_action"] = form_action
    
    # Store production-resolution state.
    metadata["resolved_real_domain"] = resolved_real_domain
    metadata["brand_domain_known"] = (
        resolved_real_domain is not None
    )

    metadata["form_action_type"] = classify_form_action(
        page_url=simulated_url,
        form_action_url=form_action,
        platform_domain=platform_domain,
        resolved_real_domain=resolved_real_domain,
    )

    # ------------------------------------------------------------
    # Page ↔ brand mismatch
    # ------------------------------------------------------------

    page_host = hostname(simulated_url)
    if resolved_real_domain is None:
        page_mismatch = None
    else:
        page_mismatch = not belongs_to_domain(
            page_host,
            resolved_real_domain,
        )

    metadata["page_brand_domain_mismatch"] = not belongs_to_domain(
        page_host, real_domain
    )
    metadata["page_brand_domain_mismatch"] = page_mismatch

    # ------------------------------------------------------------
    # Form ↔ brand mismatch
    # ------------------------------------------------------------

    resolved_action = resolve_form_action(simulated_url, form_action)
    action_host = hostname(resolved_action) if resolved_action else ""

    if not action_host:
        # No network destination exists.
        form_mismatch = None

    elif resolved_real_domain is None:
        # Form destination exists, but we don't know the
        # brand's reference domain.
        form_mismatch = None

    else:
        form_mismatch = not belongs_to_domain(
            action_host,
            resolved_real_domain,
        )

    metadata["form_action_brand_domain_mismatch"] = form_mismatch

    # Backward-compatibility alias. New code should use the explicit field above.
    metadata["has_domain_mismatch"] = form_mismatch


def generate_phishing_dataset(config: dict, output_dir: str,
                               available_brands: dict,
                               saved_templates: dict,
                               template_dir: str,
                               brands_meta: dict | None) -> list[dict]:
    """Generate all phishing pages. Returns list of metadata dicts."""
    size = config["sizes"]["phishing"]
    platforms = config["platforms"]
    brand_keys = list(available_brands.keys())
    hidden_field_range = config["generation"]["hidden_fields_phishing"]
    dirs = config["output"]

    all_metadata = []

    for i in range(size):
        # Pick hosting mode (third_party vs first_party)
        hosting_mode = _pick_hosting_mode(config)

        # No platform for attacker owned domains
        platform = None
        platform_name = None
        platform_domain = None

        # Platforms defined only for 3rd parties
        if hosting_mode == "third_party":
            # Select platform (always needed for third_party; first_party ignores it)
            platform = weighted_choice(platforms)
            platform_name = platform["name"]
            platform_domain = platform["domain"]

        # Select brand
        brand_key = random.choice(brand_keys)
        brand = available_brands[brand_key]

        # Random hidden field count
        hidden_count = random.randint(hidden_field_range[0], hidden_field_range[1])

        # Generate page
        page_html, metadata = generate_phishing_page(
            brand_key=brand_key,
            brand=brand,
            platform_name=platform_name,
            platform_domain=platform_domain,
            hidden_field_count=hidden_count,
            hosting_mode=hosting_mode,
            index=i,
            has_saved_template=saved_templates.get(brand_key, False),
            template_dir=template_dir,
            brands_meta=brands_meta,
        )

        # Filename — use domain label for first_party, platform for third_party
        brand_slug = brand_key.lower().replace(" ", "_")
        if hosting_mode == "first_party":
            domain_label = metadata.get("attacker_domain", "unknown").replace(".", "_")
            filename = f"attacker_{domain_label}_{brand_slug}_{i:04d}.html"
        else:
            filename = f"{platform_name}_{brand_slug}_{i:04d}.html"
        filepath = os.path.join(output_dir, dirs["phishing_subdir"], filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(page_html)

        # Export any embedded PNG/JPEG assets from the generated HTML
        sample_id = f"phish_{i:04d}"

        absolute_raster_paths = export_embedded_raster_assets(
            html=page_html,
            output_dir=os.path.join(output_dir, "raster_assets"),
            sample_id=sample_id,
        )

        # Store paths relative to the dataset output directory.
        raster_paths = [
            os.path.relpath(path, start=output_dir).replace(os.sep, "/")
            for path in absolute_raster_paths
        ]

        # Extract ML features
        if hosting_mode == "first_party":
            simulated_url = f"https://{metadata['attacker_domain']}{metadata['url_path']}"
        else:
            simulated_url = metadata["url"]
        features = extract_features(
            page_html,
            simulated_url,
            ocr_text=metadata.get(
                "raster_text_ground_truth",
                ""
            )
        )

        # Merge base metadata with extracted features
        metadata["id"] = f"phish_{i:04d}"
        metadata["url"] = simulated_url
        metadata["filename"] = filename
        metadata["content_hash"] = compute_content_hash(page_html)
        metadata["file_size_bytes"] = len(page_html.encode("utf-8"))

        # CSV cannot safely store a Python list directly
        metadata["raster_asset_paths"] = json.dumps(raster_paths)

        # Convenient single-path column
        metadata["primary_raster_asset_path"] = (
            raster_paths[0] if raster_paths else ""
        )
        
        metadata["page_type"] = metadata.get("page_type") or "login"

        metadata.update(features)

        resolved_real_domain = _simulate_resolved_real_domain(
            metadata,
            config,
        )

        _apply_consistent_form_domain_features(
            metadata=metadata,
            features=features,
            simulated_url=simulated_url,
            platform_domain=platform_domain,
            resolved_real_domain=resolved_real_domain,
        )

        all_metadata.append(metadata)

        if (i + 1) % 100 == 0 or i == 0:
            print(f"  [phishing] Generated {i + 1}/{size} pages...", flush=True)

    return all_metadata


def generate_legitimate_dataset(
    config: dict,
    output_dir: str,
    available_brands: dict,
    screenshot_overlay_count: int = 0,
) -> list[dict]:
    """Generate all legitimate pages. Returns list of metadata dicts."""
    size = config["sizes"]["legitimate"]
    platforms = config["platforms"]
    brand_keys = list(available_brands.keys())
    dirs = config["output"]
    page_type_weights = config.get("legitimate_types", {
        "login": 0.30, "landing": 0.25, "about": 0.20, "docs": 0.15, "blog": 0.10
    })
    legitimate_hidden_range = config.get("generation", {}).get(
        "hidden_fields_legitimate", [0, 4]
    )

    all_metadata = []

    # Match legitimate raster-overlay controls to phishing screenshot overlays.
    screenshot_overlay_count = max(
        0,
        min(int(screenshot_overlay_count), size),
    )
    screenshot_overlay_indices = set(
        random.sample(range(size), screenshot_overlay_count)
    )

    for i in range(size):
        legitimate_hidden_count = random.randint(
            legitimate_hidden_range[0], legitimate_hidden_range[1]
        )
        hosting_mode = _pick_hosting_mode(config)
        if hosting_mode == "third_party":
            platform = weighted_choice(platforms)
            platform_name = platform["name"]
            platform_domain = platform["domain"]
        else:
            platform_name = None
            platform_domain = None

        brand_key = random.choice(brand_keys)
        brand = available_brands[brand_key]

        real_domain = (
            brand["real_domains"][0]
            if brand.get("real_domains")
            else "example.com"
        )

        use_screenshot_overlay = i in screenshot_overlay_indices

        page_html, metadata = generate_legitimate_page(
            brand_key=brand_key,
            brand=brand,
            platform_name=platform_name,
            platform_domain=platform_domain,
            page_type_weights=page_type_weights,
            hidden_field_count=legitimate_hidden_count,
            visual_variant=(
                "screenshot_overlay"
                if use_screenshot_overlay
                else None
            ),
            index=i,
        )

        brand_slug = brand_key.lower().replace(" ", "_")

        page_type = metadata.get("page_type", "landing")

        if hosting_mode == "first_party":
            filename = f"first_party_{brand_slug}_{i:04d}.html"
            first_party_paths = {
                "login": "/login",
                "landing": "/",
                "about": "/about",
                "docs": "/help",
                "blog": f"/blog/post-{i:04d}",
            }

            url_path = first_party_paths.get(
                page_type,
                f"/page-{i:04d}",
            )

            simulated_url = f"https://{real_domain}{url_path}"
            tld = real_domain.split(".")[-1]
        else:
            filename = f"{platform_name}_{brand_slug}_{i:04d}.html"
            platform_url = generate_platform_url(platform_domain)
            simulated_url = platform_url
            url_path = urlsplit(simulated_url).path
            tld = platform_domain.split(".")[-1]
        # tld risk score
        tld_risk_score = get_tld_risk(tld)

        filepath = os.path.join(output_dir, dirs["legitimate_subdir"], filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(page_html)

        # Export embedded raster assets for legitimate overlay controls too.
        sample_id = f"legit_{i:04d}"
        absolute_raster_paths = export_embedded_raster_assets(
            html=page_html,
            output_dir=os.path.join(output_dir, "raster_assets"),
            sample_id=sample_id,
        )
        raster_paths = [
            os.path.relpath(path, start=output_dir).replace(os.sep, "/")
            for path in absolute_raster_paths
        ]

        # Extract ML features
        features = extract_features(
            page_html,
            simulated_url,
            ocr_text=metadata.get(
                "raster_text_ground_truth",
                ""
            )
        )

        metadata["hosting_mode"] = hosting_mode
        metadata["platform"] = platform_name
        metadata["platform_domain"] = platform_domain

        metadata["id"] = f"legit_{i:04d}"
        metadata["url"] = simulated_url
        metadata["url_path"] = url_path
        metadata["tld_risk_score"] = tld_risk_score

        metadata["filename"] = filename
        metadata["content_hash"] = compute_content_hash(page_html)
        metadata["file_size_bytes"] = len(page_html.encode("utf-8"))
        metadata["raster_asset_paths"] = json.dumps(raster_paths)
        metadata["primary_raster_asset_path"] = (
            raster_paths[0] if raster_paths else ""
        )
        metadata.update(features)

        resolved_real_domain = _simulate_resolved_real_domain(
            metadata,
            config,
        )

        _apply_consistent_form_domain_features(
            metadata=metadata,
            features=features,
            simulated_url=simulated_url,
            platform_domain=platform_domain,
            resolved_real_domain=resolved_real_domain,
        )


        all_metadata.append(metadata)

        if (i + 1) % 100 == 0 or i == 0:
            print(f"  [legitimate] Generated {i + 1}/{size} pages...", flush=True)

    return all_metadata


def write_metadata_csv(all_metadata: list[dict], output_path: str):
    """Write all metadata to CSV, preserving column order."""
    if not all_metadata:
        return

    # Define column order for readability
    priority_columns = [
        "id", "label", "url", "hosting_mode", "platform", "platform_domain", "brand",
        "real_domain", "page_type", "phishing_strategy",
        "form_action", "form_action_type", "page_brand_domain_mismatch",
        "form_action_brand_domain_mismatch", "has_domain_mismatch",
        "has_password_field", "hidden_fields_count",
        "attacker_domain", "attacker_domain_label", "attacker_tld",
        "attacker_strategy", "tld_risk_score",
        "urgency_score", "fear_score", "credential_keyword_score",
        "visible_text", "parsed_forms", "brand_in_text",
        "form_method",
    ]

    # URL features
    url_cols = [
        "url_entropy", "url_digit_ratio", "url_letter_ratio",
        "url_num_dots", "url_num_slashes", "url_num_hyphens",
        "url_num_equals", "url_num_question", "url_num_ampersand",
        "url_num_percent", "url_num_double_slash", "url_num_sensitive_words",
        "url_has_at_symbol",
    ]

    # HTML features
    html_cols = [
        "html_num_eval_calls", "html_num_unescape_calls",
        "html_has_right_click_disabled", "sfh_is_empty", "sfh_is_about_blank",
        "html_has_favicon", "html_num_hidden_inputs",
    ]

    # Variation flags
    variation_cols = [
        "urgency_text_injected", "authority_text_injected",
        "fear_text_injected", "reward_text_injected",
        "document_fields_injected",
    ]

    # File metadata
    file_cols = ["filename", "content_hash", "file_size_bytes"]

    # Build ordered column list
    ordered = priority_columns + url_cols + html_cols + variation_cols + file_cols

    # Add any remaining columns not in the ordered list
    all_keys: set[str] = set()
    for meta in all_metadata:
        all_keys.update(meta.keys())

    remaining = [k for k in all_keys if k not in ordered]
    fieldnames = ordered + sorted(remaining)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_metadata)


def print_summary(phishing_meta: list[dict], legitimate_meta: list[dict]):
    total = len(phishing_meta) + len(legitimate_meta)
    print(f"\n{'='*60}")
    print(f"  Dataset Generation Complete")
    print(f"{'='*60}")
    print(f"  Total pages:     {total}")
    print(f"  Phishing:        {len(phishing_meta)}")
    print(f"  Legitimate:      {len(legitimate_meta)}")
    print()

    # Platform distribution
    platform_counts = Counter(m.get("platform") or "Others" for m in phishing_meta + legitimate_meta)
    print("  Platform Distribution:")
    for platform, count in platform_counts.most_common():
        print(f"    {platform:20s} {count:5d} ({count/total*100:.1f}%)")
    print()

    # Brand distribution (phishing)
    brand_counts = Counter(m["brand"] for m in phishing_meta)
    print("  Brand Distribution (phishing):")
    for brand, count in brand_counts.most_common():
        print(f"    {brand:20s} {count:5d}")
    print()

    # Strategy distribution (phishing)
    strategy_counts = Counter(m.get("phishing_strategy", "unknown") for m in phishing_meta)
    print("  Phishing Strategy Distribution:")
    for strategy, count in strategy_counts.most_common():
        print(f"    {strategy:20s} {count:5d}")
    print()

    # Hosting mode distribution (phishing)
    mode_counts = Counter(m.get("hosting_mode", "unknown") for m in phishing_meta)
    print("  Hosting Mode Distribution:")
    for mode, count in mode_counts.most_common():
        print(f"    {mode:20s} {count:5d}")
    print()

    # Attacker domain strategy distribution
    attacker_counts = Counter(m.get("attacker_strategy", "n/a") for m in phishing_meta if m.get("hosting_mode") == "first_party")
    if attacker_counts:
        print("  Attacker Domain Strategy Distribution:")
        for strat, count in attacker_counts.most_common():
            print(f"    {strat:20s} {count:5d}")
        print()

    # Page type distribution (legitimate)
    type_counts = Counter(m.get("page_type", "unknown") for m in legitimate_meta)
    print("  Legitimate Page Type Distribution:")
    for pt, count in type_counts.most_common():
        print(f"    {pt:20s} {count:5d}")
    print()

    # Feature coverage
    has_visible_text = sum(1 for m in phishing_meta + legitimate_meta if m.get("visible_text"))
    has_forms = sum(1 for m in phishing_meta + legitimate_meta if m.get("parsed_forms") and m["parsed_forms"] != "[]")
    print(f"  Feature Coverage:")
    print(f"    visible_text populated:  {has_visible_text}/{total}")
    print(f"    parsed_forms populated:  {has_forms}/{total}")
    print()

    page_mismatch = sum(
        1 for m in phishing_meta + legitimate_meta
        if m.get("page_brand_domain_mismatch") is True
    )
    form_mismatch = sum(
        1 for m in phishing_meta + legitimate_meta
        if m.get("form_action_brand_domain_mismatch") is True
    )
    print(f"  Page/brand domain mismatches: {page_mismatch}/{total}")
    print(f"  Form-action/brand mismatches: {form_mismatch}/{total}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic phishing dataset with ML-ready features."
    )
    parser.add_argument("--config", "-c", default="dataset_config.yaml")
    parser.add_argument("--seed", "-s", type=int, default=None)
    parser.add_argument("--phishing", "-p", type=int, default=None)
    parser.add_argument("--legitimate", "-l", type=int, default=None)
    parser.add_argument("--output", "-o", default=None)
    args = parser.parse_args()

    start_time = time.time()

    # Load main config
    config_path = resolve_config_path(args.config)
    if not os.path.exists(config_path):
        print(f"Error: Config file not found: {args.config}", file=sys.stderr)
        sys.exit(1)
    config = load_config(config_path)

    # Apply CLI overrides
    if args.seed is not None:
        config["seed"] = args.seed
    if args.phishing is not None:
        config["sizes"]["phishing"] = args.phishing
    if args.legitimate is not None:
        config["sizes"]["legitimate"] = args.legitimate
    if args.output is not None:
        config["output"]["dir"] = args.output

    # Set seed
    seed = config.get("seed", 42)
    random.seed(seed)
    print(f"Random seed: {seed}")

    # Resolve paths relative to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(script_dir, config["output"]["dir"])
    template_dir = os.path.join(script_dir, "templates", "brands")
    brands_meta_path = os.path.join(script_dir, "templates", "brands_meta.yaml")

    # Build available brands from html_builder (all 12 are always available)
    available_brands = {}
    for key in config["brands"]:
        try:
            available_brands[key] = get_brand(key)
        except KeyError as e:
            print(f"  WARNING: {e}", file=sys.stderr)

    if not available_brands:
        print("Error: No valid brands in config.", file=sys.stderr)
        sys.exit(1)

    # Check for saved HTML templates (fallback path)
    saved_templates: dict[str, bool] = {}
    brands_meta = None
    if os.path.exists(brands_meta_path):
        brands_meta = load_brands_meta(brands_meta_path)
        for brand_key in available_brands:
            meta = brands_meta.get(brand_key)
            if meta:
                tpl_path = os.path.join(template_dir, meta.get("html_file", ""))
                saved_templates[brand_key] = os.path.exists(tpl_path)
            else:
                saved_templates[brand_key] = False
    else:
        for brand_key in available_brands:
            saved_templates[brand_key] = False

    template_count = sum(1 for v in saved_templates.values() if v)
    print(f"Available brands: {', '.join(available_brands.keys())}")
    print(f"Saved templates: {template_count} (rest use programmatic generation)")

    # Create output directories
    create_output_dirs(output_dir, config["output"]["phishing_subdir"], config["output"]["legitimate_subdir"])

    # Generate phishing
    phishing_count = config["sizes"]["phishing"]
    print(f"\nGenerating {phishing_count} phishing pages...")
    phishing_meta = generate_phishing_dataset(
        config, output_dir, available_brands, saved_templates, template_dir, brands_meta
    )

    # Generate legitimate and balance raster-overlay structure.
    legitimate_count = config["sizes"]["legitimate"]
    phishing_screenshot_overlay_count = sum(
        1
        for row in phishing_meta
        if row.get("phishing_strategy") == "screenshot_overlay"
    )

    print(f"\nGenerating {legitimate_count} legitimate pages...")
    print(
        "  Legitimate screenshot-overlay controls: "
        f"{min(phishing_screenshot_overlay_count, legitimate_count)}"
    )

    legitimate_meta = generate_legitimate_dataset(
        config,
        output_dir,
        available_brands,
        screenshot_overlay_count=phishing_screenshot_overlay_count,
    )
    # Write CSV
    all_metadata = phishing_meta + legitimate_meta
    csv_path = os.path.join(output_dir, config["output"]["metadata_file"])
    write_metadata_csv(all_metadata, csv_path)
    print(f"\nMetadata written to: {csv_path}")

    # Summary
    print_summary(phishing_meta, legitimate_meta)
    elapsed = time.time() - start_time
    print(f"Output directory: {output_dir}")
    print(f"Generation time: {elapsed:.1f}s")
    print("Done.")


if __name__ == "__main__":
    main()
