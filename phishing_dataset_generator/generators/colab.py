# ============================================================
# PHISHING DETECTION ML PIPELINE - SINGLE CELL
# Trains models, evaluates, and SAVES a ready-to-use inference bundle
# ============================================================

!pip install -q xgboost catboost lightgbm joblib

import pandas as pd
import numpy as np
import warnings
import re
import joblib
from pathlib import Path

warnings.filterwarnings("ignore")

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import (
    roc_auc_score,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)

from xgboost import XGBClassifier
from catboost import CatBoostClassifier
from lightgbm import LGBMClassifier


# ============================================================
# LOAD DATA
# ============================================================

PATH = "/content/dataset_meta.csv"
df = pd.read_csv(PATH)
print("Original dataset shape:", df.shape)


# ============================================================
# KEEP ONLY REQUESTED COLUMNS
# ============================================================

KEEP_COLUMNS = [
    "label",
    "url",
    "hosting_mode",
    "platform",
    "platform_domain",
    "brand",
    "resolved_real_domain",
    "form_action",
    "brand_domain_known",
    "form_action_brand_domain_mismatch",
    "hidden_fields_count",
    "tld_risk_score",
    "urgency_score",
    "fear_score",
    "credential_keyword_score",
    "visible_text",
    "parsed_forms",
    "url_entropy",
    "url_digit_ratio",
    "url_letter_ratio",
    "url_num_dots",
    "url_num_slashes",
    "url_num_hyphens",
    "url_num_equals",
    "url_num_question",
    "url_num_ampersand",
    "url_num_percent",
    "url_num_double_slash",
    "url_num_sensitive_words",
    "url_has_at_symbol",
    "html_num_eval_calls",
    "html_num_unescape_calls",
    "html_has_right_click_disabled",
    "html_has_favicon",
    "html_num_hidden_inputs",
    "authority_score",
    "body_visible_text",
    "document_title",
    "document_upload_score",
    "html_embedded_raster_bytes",
    "html_empty_submit_button_count",
    "html_has_full_viewport_image",
    "html_has_fullscreen_form_layer",
    "html_has_object_fit_cover_or_fill",
    "html_has_raster_form_overlay_pattern",
    "html_has_transparent_form_controls",
    "html_max_z_index",
    "html_num_absolute_position_rules",
    "html_num_canvas",
    "html_num_embedded_raster_images",
    "html_num_fixed_position_rules",
    "html_num_forms",
    "html_num_images",
    "html_num_svg",
    "reward_score",
    "url_path",
]

missing_columns = [col for col in KEEP_COLUMNS if col not in df.columns]
if missing_columns:
    print("\nWARNING - requested columns missing from CSV:")
    for col in missing_columns:
        print("  -", col)

existing_keep_columns = [col for col in KEEP_COLUMNS if col in df.columns]
df = df[existing_keep_columns].copy()
print("\nDataset after whitelist:", df.shape)


# ============================================================
# SANITY CHECK LABEL
# ============================================================

if "label" not in df.columns:
    raise ValueError("The dataset does not contain the required 'label' column.")

df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df[df["label"].isin([0, 1])].copy()
df["label"] = df["label"].astype(int)
print("\nLabel distribution:")
print(df["label"].value_counts().sort_index())


# ============================================================
# SPLIT X / Y
# ============================================================

X = df.drop(columns=["label"]).copy()
y = df["label"].copy()


# ============================================================
# NORMALIZE BOOLEAN-LIKE COLUMNS
# ============================================================

BOOLEAN_COLUMNS = [
    "page_brand_domain_mismatch",
    "form_action_brand_domain_mismatch",
    "has_password_field",
    "url_has_at_symbol",
    "html_has_right_click_disabled",
    "html_has_favicon",
    "html_has_full_viewport_image",
    "html_has_fullscreen_form_layer",
    "html_has_object_fit_cover_or_fill",
    "html_has_raster_form_overlay_pattern",
    "html_has_transparent_form_controls",
    "brand_domain_known",
]

for col in BOOLEAN_COLUMNS:
    if col not in X.columns:
        continue
    X[col] = (
        X[col].astype(str).str.strip().str.lower()
        .map({"true": 1, "false": 0, "1": 1, "0": 0})
    )


# ============================================================
# REMOVE COMPLETELY UNUSABLE FEATURES
# ============================================================

remove = []
for col in X.columns:
    if X[col].isna().all() or X[col].nunique(dropna=False) <= 1:
        remove.append(col)

if remove:
    X = X.drop(columns=remove)
print("\nRemoved unusable/constant features:", len(remove))
if remove:
    print(remove)


# ============================================================
# HANDLE HIGH-CARDINALITY RAW TEXT
# ============================================================

HIGH_CARDINALITY_TEXT = [
    "url", "form_action", "visible_text", "parsed_forms",
    "body_visible_text", "document_title", "url_path",
]

for col in HIGH_CARDINALITY_TEXT:
    if col not in X.columns:
        continue
    values = X[col].fillna("").astype(str)
    X[f"{col}_length"] = values.str.len()
    X[f"{col}_digit_count"] = values.str.count(r"\d")
    X[f"{col}_special_char_count"] = values.str.count(r"[^A-Za-z0-9\s]")
    X[f"{col}_space_count"] = values.str.count(r"\s")
    X = X.drop(columns=[col])


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)


# ============================================================
# FILL MISSING VALUES (store medians for inference)
# ============================================================

numeric_medians = {}
for col in X_train.columns:
    if X_train[col].dtype == "object":
        X_train[col] = X_train[col].fillna("unknown")
        X_test[col] = X_test[col].fillna("unknown")
    else:
        median_value = pd.to_numeric(X_train[col], errors="coerce").median()
        if pd.isna(median_value):
            median_value = 0.0
        numeric_medians[col] = float(median_value)
        X_train[col] = pd.to_numeric(X_train[col], errors="coerce").fillna(median_value)
        X_test[col] = pd.to_numeric(X_test[col], errors="coerce").fillna(median_value)


# ============================================================
# ENCODE CATEGORICAL FEATURES
# ============================================================

cat_cols = X_train.select_dtypes(include=["object", "category"]).columns.tolist()
print("\nCategorical features:", cat_cols)

combined = pd.concat([X_train, X_test], axis=0)
combined = pd.get_dummies(combined, columns=cat_cols, drop_first=True, dtype=np.uint8)

X_train = combined.loc[X_train.index].copy()
X_test = combined.loc[X_test.index].copy()


# ============================================================
# CLEAN FEATURE NAMES
# ============================================================

def clean_feature_name(name):
    name = str(name)
    name = re.sub(r"[\[\]<>]", "_", name)
    name = re.sub(r"[^A-Za-z0-9_]+", "_", name)
    name = re.sub(r"_+", "_", name)
    return name.strip("_")

X_train.columns = [clean_feature_name(c) for c in X_train.columns]
X_test.columns = [clean_feature_name(c) for c in X_test.columns]


# ============================================================
# REMOVE DUPLICATE FEATURE NAMES
# ============================================================

before = X_train.shape[1]
keep_mask = ~X_train.columns.duplicated()
X_train = X_train.loc[:, keep_mask]
X_test = X_test.loc[:, keep_mask]
print("\nDuplicate columns removed:", before - X_train.shape[1])


# ============================================================
# FORCE NUMERIC TYPES
# ============================================================

for col in X_train.columns:
    X_train[col] = pd.to_numeric(X_train[col], errors="coerce").fillna(0)
    X_test[col] = pd.to_numeric(X_test[col], errors="coerce").fillna(0)

bool_cols = X_train.select_dtypes(include=["bool"]).columns
for col in bool_cols:
    X_train[col] = X_train[col].astype(np.uint8)
    X_test[col] = X_test[col].astype(np.uint8)

print("\nFinal ML feature matrices:")
print("Train:", X_train.shape)
print("Test: ", X_test.shape)

feature_columns = list(X_train.columns)


# ============================================================
# MODELS
# ============================================================

MODELS = {
    "Random Forest": RandomForestClassifier(
        n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1
    ),
    "Extra Trees": ExtraTreesClassifier(
        n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1
    ),
    "XGBoost": XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05,
        eval_metric="logloss", random_state=42, n_jobs=-1
    ),
    "CatBoost": CatBoostClassifier(
        iterations=300, learning_rate=0.05, verbose=0, random_state=42
    ),
    "LightGBM": LGBMClassifier(
        n_estimators=300, learning_rate=0.05, random_state=42,
        verbosity=-1, n_jobs=-1
    ),
    "Logistic Regression": LogisticRegression(
        max_iter=3000, class_weight="balanced", random_state=42
    ),
    "SVM": SVC(
        probability=True, class_weight="balanced", random_state=42
    ),
}


# ============================================================
# TRAIN + EVALUATE
# ============================================================

trained_models = {}
results = []

for name, model in MODELS.items():
    print("\n==============================")
    print("Training:", name)
    print("==============================")

    model.fit(X_train, y_train)
    trained_models[name] = model

    prob = model.predict_proba(X_test)[:, 1]
    pred = (prob >= 0.5).astype(int)

    results.append({
        "Model": name,
        "ROC_AUC": roc_auc_score(y_test, prob),
        "Accuracy": accuracy_score(y_test, pred),
        "Precision": precision_score(y_test, pred, zero_division=0),
        "Recall": recall_score(y_test, pred, zero_division=0),
        "F1": f1_score(y_test, pred, zero_division=0),
    })


# ============================================================
# MODEL RESULTS
# ============================================================

results_df = (
    pd.DataFrame(results)
    .sort_values("ROC_AUC", ascending=False)
    .reset_index(drop=True)
)

print("\n==============================")
print("MODEL RESULTS")
print("==============================")
display(results_df.style.format({
    "ROC_AUC": "{:.4f}",
    "Accuracy": "{:.4f}",
    "Precision": "{:.4f}",
    "Recall": "{:.4f}",
    "F1": "{:.4f}",
}))

best_name = results_df.iloc[0]["Model"]
best_model = trained_models[best_name]
print("\nBest model:", best_name)


# ============================================================
# SAVE TRAINED INFERENCE BUNDLE
# ============================================================

MODEL_BUNDLE_PATH = "/content/phishing_model_bundle.joblib"

inference_bundle = {
    "model": best_model,
    "model_name": best_name,
    "feature_columns": feature_columns,
    "numeric_medians": numeric_medians,
    "categorical_columns": cat_cols,
    "boolean_columns": BOOLEAN_COLUMNS,
    "high_cardinality_text": HIGH_CARDINALITY_TEXT,
    "keep_columns": [c for c in KEEP_COLUMNS if c != "label"],
    "results": results_df.to_dict(orient="records"),
}

joblib.dump(inference_bundle, MODEL_BUNDLE_PATH)
print(f"\nSaved inference bundle → {MODEL_BUNDLE_PATH}")


# ============================================================
# INFERENCE HELPER (ready to use later)
# ============================================================

def predict_phishing_confidence(raw_row: dict, bundle_path: str = MODEL_BUNDLE_PATH) -> float:
    """
    Take a dict of raw feature values (same columns as the dataset)
    and return phishing confidence in [0, 1].

    Example:
        confidence = predict_phishing_confidence({
            "url": "https://evil.com/login",
            "hosting_mode": "first_party",
            "tld_risk_score": 0.4,
            ...
        })
    """
    bundle = joblib.load(bundle_path)
    model = bundle["model"]
    feature_columns = bundle["feature_columns"]
    numeric_medians = bundle["numeric_medians"]
    cat_cols = bundle["categorical_columns"]
    boolean_columns = bundle["boolean_columns"]
    high_card = bundle["high_cardinality_text"]

    # Build single-row DataFrame from raw input
    row = {c: raw_row.get(c, np.nan) for c in bundle["keep_columns"]}
    X = pd.DataFrame([row])

    # Boolean normalization
    for col in boolean_columns:
        if col not in X.columns:
            continue
        X[col] = (
            X[col].astype(str).str.strip().str.lower()
            .map({"true": 1, "false": 0, "1": 1, "0": 0})
        )

    # High-cardinality text → numeric stats
    for col in high_card:
        if col not in X.columns:
            continue
        values = X[col].fillna("").astype(str)
        X[f"{col}_length"] = values.str.len()
        X[f"{col}_digit_count"] = values.str.count(r"\d")
        X[f"{col}_special_char_count"] = values.str.count(r"[^A-Za-z0-9\s]")
        X[f"{col}_space_count"] = values.str.count(r"\s")
        X = X.drop(columns=[col])

    # Fill missing
    for col in X.columns:
        if col in numeric_medians:
            X[col] = pd.to_numeric(X[col], errors="coerce").fillna(numeric_medians[col])
        elif X[col].dtype == "object":
            X[col] = X[col].fillna("unknown")
        else:
            X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)

    # One-hot (align to training columns)
    existing_cats = [c for c in cat_cols if c in X.columns]
    if existing_cats:
        X = pd.get_dummies(X, columns=existing_cats, drop_first=True, dtype=np.uint8)

    # Clean names
    X.columns = [clean_feature_name(c) for c in X.columns]

    # Align to training feature set
    for col in feature_columns:
        if col not in X.columns:
            X[col] = 0
    X = X[feature_columns]

    # Force numeric
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors="coerce").fillna(0)

    proba = model.predict_proba(X)[0][1]
    return float(proba)


# ============================================================
# QUICK SMOKE-TEST ON ONE TEST SAMPLE
# ============================================================

sample_idx = X_test.index[0]
# Reconstruct a minimal raw-like dict from original df for demo
raw_demo = df.loc[sample_idx].drop(labels=["label"], errors="ignore").to_dict()
conf = predict_phishing_confidence(raw_demo)
print("\nSmoke-test sample actual label:", int(y_test.loc[sample_idx]))
print("Predicted phishing confidence:", round(conf, 4))


# ============================================================
# SUMMARY
# ============================================================

print("\n==============================")
print("FINISHED SUCCESSFULLY")
print("==============================")
print("Rows used:", len(df))
print("Final encoded ML features:", X_train.shape[1])
print("Best model:", best_name)
print("Best ROC AUC:", round(float(results_df.iloc[0]["ROC_AUC"]), 4))
print("Model bundle saved at:", MODEL_BUNDLE_PATH)
print("\nUse later with:")
print("  confidence = predict_phishing_confidence(raw_feature_dict)")