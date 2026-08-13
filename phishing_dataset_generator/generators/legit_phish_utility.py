import random
import re
import csv

from urllib.parse import urlsplit, urljoin


# ── TLD options ────────────────────────────────────────────────────────────────

"""
TLD Weights are basically phishing domain score which is 
the total phishing domains per 10k domains
"""
TLD_STATS_FILE = "dataset/Phishing-TLDstats-Feb2026-Apr2026.csv"

def load_tld_weights(csv_path: str):
    tld_names = []
    tld_weights = []

    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            try:
                tld = row["TLD"].strip().lower()
                score = float(row["Phishing Domain Score"])
            except (KeyError, ValueError, TypeError):
                continue

            if tld and score > 0:
                tld_names.append(tld)
                tld_weights.append(score)

    # Normalize TLD phishing domain score from to 0–1
    max_score = max(tld_weights, default=0)

    if max_score > 0:
        tld_weights = [round(score / max_score, 3) for score in tld_weights]

    return tld_names, tld_weights

ATTACKER_TLD_NAMES, ATTACKER_TLD_WEIGHTS = load_tld_weights(TLD_STATS_FILE)

# default TLD risk for unknown TLDs
MAX_TLD_RISK = max(ATTACKER_TLD_WEIGHTS)
TLD_RISK = dict(zip(ATTACKER_TLD_NAMES, ATTACKER_TLD_WEIGHTS))

def get_tld_risk(tld: str) -> float:
    """Get the normalized phishing risk score for a TLD."""
    return TLD_RISK.get(
        tld.lower().lstrip("."),
        MAX_TLD_RISK
    )


# Fake "legitimate-looking" base domains
FAKE_DOMAINS_PHRASES = [
    "secure", "login", "account", "verify", "auth", "portal", "identity", "check",
    "security", "hub", "center", "access", "sso", "service", "now", "safe"
]

# url path phrases to be used to generate URL Path
URL_PATH_PHRASES = [
    "", "signin", "login", "verify", "auth", "account",
    "sso", "identity", "session", "new", "security", "authorize"
]

def normalize_url_path(path: str) -> str:
    """
    Normalize a URL path without modifying the URL scheme.

    Examples:
        "//account///verify/"   -> "/account/verify"
        "security"              -> "/security"
        ""                      -> "/"
    """
    path = path.strip()

    # Collapse repeated slashes in the path only.
    path = re.sub(r"/+", "/", path)

    # Ensure exactly one leading slash.
    path = "/" + path.lstrip("/")

    # Remove the trailing slash unless this is the root path.
    if len(path) > 1:
        path = path.rstrip("/")

    return path


""" Generates fake base domains with 1 to 4 different phrases
 e.g. secure or secure-login or securelogin or secure-accountlogin
"""
def generate_random_combo(
    array: list[str],
    combo_type: str | None = None,
) -> str:
    if combo_type == "domain":
        count = random.randint(1, min(4, len(array)))
        words = random.sample(array, count)
        separator = random.choice(["-", ""])
        return separator.join(words)

    # Explicitly allow a root path.
    if "" in array and random.random() < 0.05:
        return "/"

    # Combos For path
    non_empty = [word for word in array if word]
    count = random.randint(1, min(4, len(non_empty)))
    words = random.sample(non_empty, count)
    separator = random.choice(["-", "", "/"])

    return normalize_url_path(separator.join(words))


def generate_platform_url(platform_domain: str) -> str:
    subdomain = generate_random_combo(FAKE_DOMAINS_PHRASES, "domain")
    url_path = generate_random_combo(URL_PATH_PHRASES)
    return f"https://{subdomain}.{platform_domain}{url_path}"


def hostname(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def belongs_to_domain(hostname: str, domain: str | None) -> bool:
    if not domain:
        return False

    domain = domain.lower().lstrip(".")
    return hostname == domain or hostname.endswith("." + domain)


def classify_form_action(
    page_url: str,
    form_action_url: str,
    platform_domain: str | None,
    resolved_real_domain: str | None
) -> str:
    """
        Classify a form action relative to the final page URL.
    """
    if not form_action_url or not form_action_url.strip():
        return "empty"

    normalized = form_action_url.strip().lower()

    if normalized == "about:blank":
        return "about_blank"
    if normalized.startswith("javascript:"):
        return "javascript"
    if normalized.startswith("mailto:"):
        return "mailto"

    parsed_action = urlsplit(form_action_url)

    if not parsed_action.hostname:
        return "relative"

    page = urlsplit(page_url)
    action = parsed_action

    page_origin = (
        page.scheme.lower(),
        (page.hostname or "").lower(),
        page.port,
    )
    action_origin = (
        action.scheme.lower(),
        (action.hostname or "").lower(),
        action.port,
    )

    if page_origin == action_origin:
        return "same_origin"

    page_host = (page.hostname or "").lower()
    action_host = (action.hostname or "").lower()

    if (
        belongs_to_domain(page_host, platform_domain)
        and belongs_to_domain(action_host, platform_domain)
    ):
        return "same_platform_cross_origin"

    # Brand-dependent classification is only possible when
    # the official domain was successfully resolved.
    if resolved_real_domain is not None:
        if belongs_to_domain(action_host, resolved_real_domain):
            return "official_brand_cross_origin"

        return "external_cross_origin"

    return "unknown_brand_cross_origin"


def resolve_form_action(page_url: str, form_action_url: str | None) -> str:
    """Resolve a normal/relative form action against the page URL.

    Special non-HTTP targets are returned unchanged.
    """
    if not form_action_url or not form_action_url.strip():
        return ""

    value = form_action_url.strip()
    lower = value.lower()

    if (
        lower == "about:blank"
        or lower.startswith("javascript:")
        or lower.startswith("mailto:")
    ):
        return value

    return urljoin(page_url, value)
