#!/usr/bin/env python3
"""
Phishing Dataset Generator for ML-based Detection Research.

Loads real brand login page HTML templates and generates phishing pages
(hosted on 3rd-party trusted services) and legitimate pages by replacing
form action URLs and hidden fields.

Usage:
    python generate_dataset.py                         # default config
    python generate_dataset.py --config my_config.yaml # custom config
    python generate_dataset.py --phishing 200 --legitimate 200
    python generate_dataset.py --seed 123
"""

import argparse
import csv
import hashlib
import os
import random
import sys
from collections import Counter
from pathlib import Path

import yaml

from generators.template_loader import load_brands_meta
from generators.phishing_page import generate_phishing_page
from generators.legitimate_page import generate_legitimate_page


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


def generate_phishing_dataset(config: dict, template_dir: str,
                               brands_meta: dict, output_dir: str) -> list[dict]:
    """Generate all phishing pages. Returns list of metadata dicts."""
    size = config["sizes"]["phishing"]
    platforms = config["platforms"]
    brands = config["brands"]
    hidden_field_range = config["generation"]["hidden_fields_phishing"]
    dirs = config["output"]

    all_metadata = []

    for i in range(size):
        # Select platform (weighted)
        platform = weighted_choice(platforms)
        platform_name = platform["name"]
        platform_domain = platform["domain"]

        # Select brand
        brand_key = random.choice(brands)
        brand_meta = brands_meta.get(brand_key)
        if not brand_meta:
            print(f"  WARNING: Brand '{brand_key}' not found in brands_meta.yaml, skipping.", file=sys.stderr)
            continue

        # Random hidden field count
        hidden_count = random.randint(hidden_field_range[0], hidden_field_range[1])

        # Generate page
        page_html, metadata = generate_phishing_page(
            template_dir=template_dir,
            brand_meta=brand_meta,
            platform_name=platform_name,
            platform_domain=platform_domain,
            hidden_field_count=hidden_count,
            index=i,
        )

        # Filename
        brand_slug = brand_key.lower().replace(" ", "_")
        filename = f"{platform_name}_{brand_slug}_{i:04d}.html"
        filepath = os.path.join(output_dir, dirs["phishing_subdir"], filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(page_html)

        metadata["filename"] = filename
        metadata["content_hash"] = compute_content_hash(page_html)
        metadata["file_size_bytes"] = len(page_html.encode("utf-8"))
        all_metadata.append(metadata)

        if (i + 1) % 50 == 0 or i == 0:
            print(f"  [phishing] Generated {i + 1}/{size} pages...", flush=True)

    return all_metadata


def generate_legitimate_dataset(config: dict, template_dir: str,
                                 brands_meta: dict, output_dir: str) -> list[dict]:
    """Generate all legitimate pages. Returns list of metadata dicts."""
    size = config["sizes"]["legitimate"]
    platforms = config["platforms"]
    brands = config["brands"]
    dirs = config["output"]

    all_metadata = []

    for i in range(size):
        platform = weighted_choice(platforms)
        platform_name = platform["name"]
        platform_domain = platform["domain"]

        brand_key = random.choice(brands)
        brand_meta = brands_meta.get(brand_key)
        if not brand_meta:
            print(f"  WARNING: Brand '{brand_key}' not found in brands_meta.yaml, skipping.", file=sys.stderr)
            continue

        page_html, metadata = generate_legitimate_page(
            template_dir=template_dir,
            brand_meta=brand_meta,
            platform_name=platform_name,
            platform_domain=platform_domain,
            index=i,
        )

        brand_slug = brand_key.lower().replace(" ", "_")
        filename = f"{platform_name}_{brand_slug}_{i:04d}.html"
        filepath = os.path.join(output_dir, dirs["legitimate_subdir"], filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(page_html)

        metadata["filename"] = filename
        metadata["content_hash"] = compute_content_hash(page_html)
        metadata["file_size_bytes"] = len(page_html.encode("utf-8"))
        all_metadata.append(metadata)

        if (i + 1) % 50 == 0 or i == 0:
            print(f"  [legitimate] Generated {i + 1}/{size} pages...", flush=True)

    return all_metadata


def write_metadata_csv(all_metadata: list[dict], output_path: str):
    if not all_metadata:
        return
    fieldnames = []
    seen = set()
    for meta in all_metadata:
        for key in meta.keys():
            if key not in seen:
                fieldnames.append(key)
                seen.add(key)
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

    platform_counts = Counter(m["platform"] for m in phishing_meta + legitimate_meta)
    print("  Platform Distribution:")
    for platform, count in platform_counts.most_common():
        print(f"    {platform:20s} {count:5d} ({count/total*100:.1f}%)")
    print()

    brand_counts = Counter(m["brand"] for m in phishing_meta)
    print("  Brand Distribution (phishing):")
    for brand, count in brand_counts.most_common():
        print(f"    {brand:20s} {count:5d}")
    print()

    mismatch = sum(1 for m in phishing_meta if m.get("has_domain_mismatch"))
    print(f"  Domain mismatches: {mismatch}/{len(phishing_meta)} phishing pages")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic phishing dataset using brand HTML templates."
    )
    parser.add_argument("--config", "-c", default="dataset_config.yaml")
    parser.add_argument("--seed", "-s", type=int, default=None)
    parser.add_argument("--phishing", "-p", type=int, default=None)
    parser.add_argument("--legitimate", "-l", type=int, default=None)
    parser.add_argument("--output", "-o", default=None)
    args = parser.parse_args()

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

    # Load brand templates metadata
    if not os.path.exists(brands_meta_path):
        print(f"Error: brands_meta.yaml not found at {brands_meta_path}", file=sys.stderr)
        print("Create it from templates/brands_meta.yaml. See templates/brands/README.md", file=sys.stderr)
        sys.exit(1)
    brands_meta = load_brands_meta(brands_meta_path)

    # Check which brand templates actually exist
    available_brands = []
    missing_brands = []
    for brand_key in config["brands"]:
        meta = brands_meta.get(brand_key)
        if not meta:
            missing_brands.append(brand_key)
            continue
        tpl_path = os.path.join(template_dir, meta["html_file"])
        if os.path.exists(tpl_path):
            available_brands.append(brand_key)
        else:
            missing_brands.append(brand_key)

    if missing_brands:
        print(f"WARNING: Missing templates for: {', '.join(missing_brands)}")
        print(f"  Add HTML files to {template_dir}/ and update brands_meta.yaml")

    if not available_brands:
        print("Error: No brand templates found. Add HTML files to templates/brands/", file=sys.stderr)
        print("See templates/brands/README.md for instructions.", file=sys.stderr)
        sys.exit(1)

    # Filter config to only available brands
    config["brands"] = available_brands
    print(f"Available brands: {', '.join(available_brands)}")

    # Create output directories
    create_output_dirs(output_dir, config["output"]["phishing_subdir"], config["output"]["legitimate_subdir"])

    # Generate phishing
    phishing_count = config["sizes"]["phishing"]
    print(f"\nGenerating {phishing_count} phishing pages...")
    phishing_meta = generate_phishing_dataset(config, template_dir, brands_meta, output_dir)

    # Generate legitimate
    legitimate_count = config["sizes"]["legitimate"]
    print(f"\nGenerating {legitimate_count} legitimate pages...")
    legitimate_meta = generate_legitimate_dataset(config, template_dir, brands_meta, output_dir)

    # Write CSV
    all_metadata = phishing_meta + legitimate_meta
    csv_path = os.path.join(output_dir, config["output"]["metadata_file"])
    write_metadata_csv(all_metadata, csv_path)
    print(f"\nMetadata written to: {csv_path}")

    # Summary
    print_summary(phishing_meta, legitimate_meta)
    print(f"Output directory: {output_dir}")
    print("Done.")


if __name__ == "__main__":
    main()
