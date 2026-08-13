"""
Attacker-owned domain generator for phishing dataset creation.

Generates realistic typosquatting, combosquatting, phonetic, and
subdomain-spoofing domains that an attacker might register to host
phishing pages. These are distinct from third-party hosted phishing
(e.g., facebook.github.io) — attacker-owned domains are registered
on cheap TLDs (e.g., faceb00k.com, paypal-secure.xyz).

Domain strategies:
  - typosquat:    char substitution/deletion/insertion (faceb00k.com)
  - combosquat:   brand + trust keywords (paypal-secure.com)
  - phonetic:     sounds-like (fasebook.com)
  - subdomain:    brand as subdomain of attacker domain (paypal.evil-login.com)
  - tld_swap:     same name, different TLD (google.xyz, facebook.co)

Uses the domain strategies to generate and return full_domain (e.g. subdomain+domain+tld)
and metadata (e.g. contains url paths too)
"""

import random
import re
from .legit_phish_utility import FAKE_DOMAINS_PHRASES, URL_PATH_PHRASES, generate_random_combo, get_tld_risk, ATTACKER_TLD_NAMES, ATTACKER_TLD_WEIGHTS


# ── Typosquatting character transforms ─────────────────────────────────────────

# Common character substitutions used in typosquatting
CHAR_SUBS = {
    "a": ["4"],
    "e": ["3"],
    "i": ["1", "l"],
    "o": ["0"],
    "s": ["5"],
    "l": ["1"],
    "t": ["7"],
    "b": ["8"],
    "g": ["9"],
    "m": ["rn"]
}

# Character insertion/deletion positions
INSERT_CHARS = ["-", "x", "i"]


def _typosquat(brand: str) -> str:
    """Generate a typosquatting variant of a brand name."""
    method = random.choice(["substitute", "delete", "insert", "double", "transpose"])

    if method == "substitute" and len(brand) >= 4:
        # Replace 1-2 characters with similar-looking ones
        idx = random.sample(range(len(brand)), k=min(2, len(brand) // 2))
        chars = list(brand)
        for i in idx:
            if chars[i].lower() in CHAR_SUBS:
                chars[i] = random.choice(CHAR_SUBS[chars[i].lower()])
        return "".join(chars)

    if method == "delete" and len(brand) >= 5:
        # Delete one character
        idx = random.randint(0, len(brand) - 1)
        return brand[:idx] + brand[idx + 1:]

    if method == "insert":
        # Insert a character
        idx = random.randint(0, len(brand))
        char = random.choice(INSERT_CHARS)
        return brand[:idx] + char + brand[idx:]

    if method == "double" and len(brand) >= 4:
        # Double a character
        idx = random.randint(0, len(brand) - 1)
        return brand[:idx] + brand[idx] + brand[idx:]

    if method == "transpose" and len(brand) >= 4:
        # Swap two adjacent characters
        idx = random.randint(0, len(brand) - 2)
        chars = list(brand)
        chars[idx], chars[idx + 1] = chars[idx + 1], chars[idx]
        return "".join(chars)

    # Fallback: substitute
    return _typosquat(brand)


# ── Combosquatting keywords ────────────────────────────────────────────────────

COMBO_KEYWORDS = [
    "secure", "security", "login", "signin", "verify", "update",
    "account", "auth", "sso", "portal", "support", "help",
    "confirm", "restore", "recovery", "validate", "check",
    "online", "web", "app", "mobile", "id", "pass",
]


def _combosquat(brand: str) -> str:
    """Generate a combosquatting domain: brand + trust keyword."""
    keyword = random.choice(COMBO_KEYWORDS)
    pattern = random.choice([
        "{brand}-{keyword}",     # paypal-secure
        "{brand}{keyword}",      # paypalsecure
        "{keyword}-{brand}",     # secure-paypal
        "{keyword}{brand}",      # securepaypal
    ])
    return pattern.format(brand=brand, keyword=keyword)


# ── Phonetic variants ─────────────────────────────────────────────────────────

# Phonetic substitutions that sound similar
PHONETIC_SUBS = {
    "ph": ["f"],
    "f": ["ph"],
    "ck": ["k"],
    "x": ["ks"],
    "z": ["s"],
    "s": ["z"],
    "oo": ["u", "ew"],
    "ee": ["i", "ea"],
    "i": ["y"],
    "ou": ["u"],
    "c": ["k", "s"],
    "k": ["c", "ck"],
    "th": ["d", "t"],
}


def _phonetic(brand: str) -> str:
    """Generate a phonetically similar brand name variant."""
    for pattern, replacements in PHONETIC_SUBS.items():
        if pattern in brand:
            return brand.replace(pattern, random.choice(replacements), 1)

    # Fallback: apply a random substitution
    if len(brand) >= 4:
        idx = random.randint(0, len(brand) - 2)
        pair = brand[idx:idx + 2]
        if pair.lower() in [k.lower() for k in PHONETIC_SUBS]:
            for k, v in PHONETIC_SUBS.items():
                if k.lower() == pair.lower():
                    return brand[:idx] + random.choice(v) + brand[idx + 2:]

    return _typosquat(brand)  # ultimate fallback


def _pick_tld() -> str:
    """Pick a TLD weighted toward cheaper/riskier options."""
    return random.choices(ATTACKER_TLD_NAMES, weights=ATTACKER_TLD_WEIGHTS, k=1)[0]


# ── Subdomain spoofing ────────────────────────────────────────────────────────
def _subdomain_spoof(brand: str) -> str:
    """Generate a subdomain spoof: brand.fake-domain.tld"""
    base = generate_random_combo(FAKE_DOMAINS_PHRASES, "domain")
    return f"{brand}.{base}"


# ── Main generator ────────────────────────────────────────────────────────────

# Strategy weights
ATTACKER_STRATEGIES = {
    "typosquat": 0.30,
    "combosquat": 0.25,
    "subdomain": 0.20,
    "phonetic": 0.15,
    "tld_swap": 0.10,
}


def pick_attacker_strategy() -> str:
    """Pick a random attacker domain strategy."""
    names = list(ATTACKER_STRATEGIES.keys())
    weights = [ATTACKER_STRATEGIES[s] for s in names]
    return random.choices(names, weights=weights, k=1)[0]


def generate_attacker_domain(brand_key: str, strategy: str | None = None) -> tuple[str, dict]:
    """
    Generate an attacker-owned phishing domain.

    Args:
        brand_key: Brand key (e.g., "facebook", "paypal").
        strategy: Specific strategy. If None, picks randomly.

    Returns:
        (domain_string, metadata_dict)

    Examples:
        ("faceb00k.com", {...})
        ("paypal-secure.xyz", {...})
        ("fasebook.top", {...})
        ("facebook.secure-login.com", {...})
        ("google.co", {...})
    """
    if strategy is None:
        strategy = pick_attacker_strategy()

    brand = brand_key.lower().replace("_", "").replace(" ", "")
    tld = _pick_tld()

    if strategy == "typosquat":
        domain_label = _typosquat(brand)

    elif strategy == "combosquat":
        domain_label = _combosquat(brand)

    elif strategy == "phonetic":
        domain_label = _phonetic(brand)

    elif strategy == "subdomain":
        # Subdomain spoof: brand.attacker-domain.tld
        # The "attacker domain" part also uses a suspicious TLD
        inner = _subdomain_spoof(brand)
        domain_label = inner  # e.g., "facebook.secure-login"
        # Full domain becomes: facebook.secure-login.xyz

    elif strategy == "tld_swap":
        # Keep the brand name, swap to a suspicious TLD
        domain_label = brand
        # Prefer non-.com TLDs for this strategy
        risky_tlds = [t for t in ATTACKER_TLD_NAMES if t != "com"]
        tld = random.choice(risky_tlds)

    else:
        domain_label = _typosquat(brand)

    full_domain = f"{domain_label}.{tld}"

    # Generate a normalized plausible phishing URL path
    url_path = generate_random_combo(URL_PATH_PHRASES)

    metadata = {
        "attacker_domain": full_domain,     # subdomain+domain+tld
        "attacker_domain_label": domain_label,  # subdomain+domain
        "attacker_tld": tld,
        "attacker_strategy": strategy,
        "tld_risk_score": get_tld_risk(tld),
        "url_path": url_path
    }

    return full_domain, metadata
