# Phishing Dataset Generator

Synthetic dataset generator for ML-based phishing detection research.
Targets phishing hosted on **3rd-party trusted services**:

| Platform | Domain |
|---|---|
| GitHub Pages | `github.io` |
| Netlify | `netlify.app` |
| Vercel | `vercel.app` |
| Firebase Hosting | `firebaseapp.com` |
| Cloudflare Pages | `pages.dev` |

## What It Generates

- **Phishing pages** — credential-harvesting pages impersonating major brands
- **Legitimate pages** — benign documentation, blogs, portfolios, project sites
- **Metadata CSV** — ground-truth labels + per-page feature annotations

The generator produces pages that exercise each level of a multi-level detection system:

### Level 2 Coverage

| Detection Axis | Configurable Variations |
|---|---|
| Urgency keywords | `none`, `low`, `medium`, `high` |
| Authority spoofing | Injected authority phrases ("Account Protection Team") |
| Domain mismatches | Link text shows brand domain, href points elsewhere |
| Suspicious redirects | URL shorteners, base64, hex-encoded, data: URIs |
| Branding mimicry | `none`, `name_only`, `partial`, `close_copy` |
| HTML quality | `clean`, `slightly_broken`, `heavily_broken` |
| Form elements | `none`, `contact`, `email_password`, `full_credential`, `with_2fa` |
| GitHub-specific | Login in README, low commit count, embedded iframes |

### Level 3 Coverage

| Detection Axis | Configurable Variations |
|---|---|
| Sentiment/tone | `neutral`, `friendly`, `urgency`, `fear`, `anger` |
| CTA-to-content ratio | `low`, `medium`, `high` |
| Form behavior | `same_origin`, `cross_origin_https`, `cross_origin_http`, `data_uri`, `javascript_void` |

## Quick Start

```bash
# Install dependency
pip install pyyaml

# Generate dataset with default config (500 phishing + 500 legitimate)
python generate_dataset.py

# Custom sizes
python generate_dataset.py --phishing 200 --legitimate 200

# Custom config file
python generate_dataset.py --config my_config.yaml

# Override seed for reproducibility
python generate_dataset.py --seed 123
```

## Output Structure

```
dataset/
├── phishing/
│   ├── github_io_google_0000.html
│   ├── netlify_app_paypal_0001.html
│   ├── vercel_app_microsoft_0002.html
│   └── ...
├── legitimate/
│   ├── github_io_datatools_0000.html
│   ├── netlify_app_docgen_0001.html
│   └── ...
└── dataset_meta.csv
```

## Configuration

Edit `dataset_config.yaml` to control:

- **Dataset size** — number of phishing and legitimate pages
- **Platform distribution** — weight of each hosting platform
- **Brand targets** — which brands to impersonate
- **Feature distributions** — probability of each variation level

### Example: Change Platform Weights

```yaml
platforms:
  - name: github_io
    domain: github.io
    weight: 0.50    # 50% of pages on GitHub Pages
  - name: netlify_app
    domain: netlify.app
    weight: 0.15
  # ...
```

### Example: Adjust Urgency Distribution

```yaml
level2:
  urgency:
    intensities: [none, low, medium, high]
    distribution: [0.10, 0.20, 0.30, 0.40]  # more high-urgency pages
```

## Metadata CSV Columns

| Column | Description |
|---|---|
| `filename` | HTML file name |
| `label` | `1` = phishing, `0` = legitimate |
| `platform` | Hosting platform name |
| `brand_impersonated` | Brand being impersonated (phishing) |
| `urgency_intensity` | Urgency level used |
| `form_type` | Form complexity level |
| `form_action_type` | Where form submits to |
| `link_obfuscation_level` | Link obfuscation technique level |
| `html_quality_level` | HTML quality degradation level |
| `branding_mimicry_level` | Brand impersonation fidelity |
| `sentiment_tone` | Emotional tone of content |
| `cta_intensity` | Call-to-action button aggressiveness |
| `cta_to_content_ratio` | Ratio of CTA to content |
| `has_iframe` | Whether page contains iframes |
| `domain_mismatch_count` | Number of mismatched links |
| `content_hash` | SHA-256 hash of page content |
| `github_stars` | Simulated star count (GitHub only) |
| `github_commits` | Simulated commit count (GitHub only) |
| `github_contributors` | Simulated contributor count (GitHub only) |
| `github_repo_age_days` | Simulated repo age (GitHub only) |

## Project Structure

```
phishing_dataset_generator/
├── generate_dataset.py          # Main entry point
├── dataset_config.yaml          # Configuration
├── generators/
│   ├── __init__.py
│   ├── phishing_page.py         # Phishing page assembler
│   ├── legitimate_page.py       # Legitimate page assembler
│   ├── forms.py                 # Form generation (Level 2)
│   ├── urgency_language.py      # Urgency keywords (Level 2)
│   ├── links.py                 # Link obfuscation (Level 2)
│   ├── branding.py              # Brand mimicry (Level 2)
│   ├── html_quality.py          # HTML quality degradation (Level 2)
│   ├── sentiment.py             # Sentiment/tone (Level 3)
│   └── third_party_specific.py  # Platform-specific templates
└── README.md
```

## Brands Covered

Google, Microsoft, PayPal, Apple, Facebook, Amazon, Instagram, LinkedIn, Netflix, Twitter/X — each with unique visual profiles (colors, logos, fonts) at varying mimicry levels.

## Research Context

This dataset is designed for research on detecting phishing pages hosted on trusted 3rd-party platforms, where traditional URL-based blacklists (PhishTank, etc.) are insufficient because:

1. The hosting domain (e.g., `github.io`) is inherently trusted
2. Phishing pages are often short-lived and unavailable by the time they're listed
3. The HTML content and page behavior are the primary signals, not the URL alone
