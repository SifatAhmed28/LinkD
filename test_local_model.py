import json
import re
import numpy as np
import onnxruntime as ort


# ============================================================
# CONFIG
# ============================================================
MODEL_PATH = "phishing_model.onnx"
METADATA_PATH = "metadata.json"


# ============================================================
# LOAD MODEL + METADATA
# ============================================================
with open(METADATA_PATH) as f:
    metadata = json.load(f)

feature_columns = metadata["features"]
THRESHOLD = metadata.get("threshold", 0.5)

# Create a fast lookup: feature name → column index
feature_index = {name: i for i, name in enumerate(feature_columns)}
n_features = len(feature_columns)

session = ort.InferenceSession(
    MODEL_PATH,
    providers=["CPUExecutionProvider"]
)
input_name = session.get_inputs()[0].name


# ============================================================
# HELPERS
# ============================================================
def text_stats(text: str):
    """Return length, digit_count, special_count, space_count"""
    if text is None:
        text = ""
    text = str(text)
    length = len(text)
    digit = sum(c.isdigit() for c in text)
    space = sum(c.isspace() for c in text)
    special = length - sum(c.isalnum() or c.isspace() for c in text)
    return length, digit, special, space


# Columns that were turned into text statistics during training
TEXT_COLUMNS = [
    "url", "form_action", "visible_text", "parsed_forms",
    "body_visible_text", "document_title", "url_path"
]


def prepare_one_sample(raw: dict) -> np.ndarray:
    """
    Convert a single raw dictionary (same keys as your original CSV)
    into a float32 vector of shape (1, n_features)
    """
    vec = np.zeros(n_features, dtype=np.float32)

    # ---------- 1. Numeric / boolean columns (already numbers) ----------
    numeric_like = [
        "brand_domain_known", "form_action_brand_domain_mismatch",
        "hidden_fields_count", "tld_risk_score", "urgency_score",
        "fear_score", "credential_keyword_score", "url_entropy",
        "url_digit_ratio", "url_letter_ratio", "url_num_dots",
        "url_num_slashes", "url_num_hyphens", "url_num_equals",
        "url_num_question", "url_num_ampersand", "url_num_percent",
        "url_num_double_slash", "url_num_sensitive_words",
        "url_has_at_symbol", "html_num_eval_calls",
        "html_num_unescape_calls", "html_has_right_click_disabled",
        "html_has_favicon", "html_num_hidden_inputs",
        "authority_score", "reward_score",
    ]

    for col in numeric_like:
        if col in raw and col in feature_index:
            try:
                vec[feature_index[col]] = float(raw[col] or 0)
            except (TypeError, ValueError):
                vec[feature_index[col]] = 0.0

    # ---------- 2. Text feature extraction ----------
    for col in TEXT_COLUMNS:
        if col not in raw:
            continue
        length, digit, special, space = text_stats(raw[col])

        for suffix, value in [
            ("_length", length),
            ("_digit_count", digit),
            ("_special_count", special),
            ("_space_count", space),
        ]:
            name = col + suffix
            if name in feature_index:
                vec[feature_index[name]] = value

    # ---------- 3. Categorical one-hot (exact match to training) ----------
    # These were the original categorical columns
    cat_cols = [
        "hosting_mode", "platform", "platform_domain",
        "brand", "resolved_real_domain"
    ]

    for col in cat_cols:
        if col not in raw:
            continue
        value = str(raw[col]).strip() if raw[col] is not None else ""
        # pandas get_dummies creates names like "platform_github"
        onehot_name = f"{col}_{value}"
        if onehot_name in feature_index:
            vec[feature_index[onehot_name]] = 1.0

    return vec.reshape(1, -1)


# ============================================================
# PREDICTION
# ============================================================
def predict(raw_samples: list[dict]):
    """
    raw_samples: list of dictionaries (each dict = one row)
    Returns: (probabilities of class 1, binary predictions)
    """
    features = np.vstack([prepare_one_sample(s) for s in raw_samples])

    outputs = session.run(None, {input_name: features})

    # outputs[1] is a list of dicts: [{0: p0, 1: p1}, {0: p0, 1: p1}, ...]
    proba = np.array([d[1] for d in outputs[1]], dtype=np.float32)

    preds = (proba >= THRESHOLD).astype(int)
    return proba, preds


# ============================================================
# EXAMPLE
# ============================================================
if __name__ == "__main__":
    sample = {
        "url": "https://secure-login.bank-verify.com/account",
        "hosting_mode": "first_party",
        "platform": "",
        "platform_domain": "bank-verify.com",
        "brand": "paypal",
        "resolved_real_domain": "paypal.com",
        "form_action": "https://evil.com/collect",
        "brand_domain_known": 0,
        "form_action_brand_domain_mismatch": 1,
        "hidden_fields_count": 3,
        "tld_risk_score": 0.8,
        "urgency_score": 0.9,
        "fear_score": 0.7,
        "credential_keyword_score": 0.95,
        "visible_text": "Urgent! Your account will be locked. Enter password now.",
        "parsed_forms": "password email",
        "url_entropy": 4.1,
        "url_digit_ratio": 0.12,
        "url_letter_ratio": 0.7,
        "url_num_dots": 3,
        "url_num_slashes": 3,
        "url_num_hyphens": 2,
        "url_num_equals": 0,
        "url_num_question": 0,
        "url_num_ampersand": 0,
        "url_num_percent": 0,
        "url_num_double_slash": 1,
        "url_num_sensitive_words": 2,
        "url_has_at_symbol": 0,
        "html_num_eval_calls": 0,
        "html_num_unescape_calls": 0,
        "html_has_right_click_disabled": 1,
        "html_has_favicon": 0,
        "html_num_hidden_inputs": 2,
        "authority_score": 0.1,
        "reward_score": 0.0,
        "url_path": "/account",
    }

    proba, pred = predict([sample])
    print(f"Phishing probability: {proba[0]:.4f}")
    print(f"Prediction (1=phishing): {pred[0]}")