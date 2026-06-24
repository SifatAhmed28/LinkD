"""
ML Score Aggregator — Final Fusion

Combines all Level 3 ML scores (fear, form, OCR, visual) with the
Level 2 heuristic score into a final weighted verdict.

Design principles:
- L2 score provides a strong prior for the ML fusion
- Visual spoofing is given highest weight (most definitive signal)
- Configurable weights via environment variables
- Output is normalized to [0, 1] with explicit verdict thresholds
"""

import logging
import os
from typing import Any, Dict

logger = logging.getLogger("linkd.aggregator")

# Configurable weights (must sum to ~1.0 for L3 components)
WEIGHT_FEAR   = float(os.getenv("WEIGHT_FEAR",   "0.25"))
WEIGHT_FORM   = float(os.getenv("WEIGHT_FORM",   "0.30"))
WEIGHT_OCR    = float(os.getenv("WEIGHT_OCR",    "0.20"))
WEIGHT_VISUAL = float(os.getenv("WEIGHT_VISUAL", "0.25"))

# L2 score influence on final result
L2_INFLUENCE = 0.3  # 30% weight to L2 prior, 70% to L3

# Final verdict thresholds
VERDICT_SAFE_THRESHOLD      = float(os.getenv("VERDICT_SAFE_THRESHOLD",      "0.30"))
VERDICT_MALICIOUS_THRESHOLD = float(os.getenv("VERDICT_MALICIOUS_THRESHOLD", "0.70"))


def aggregate_ml_scores(
    fear_score: float,
    form_score: float,
    ocr_score: float,
    visual_score: float,
    l2_score: float = 0.0,
) -> Dict[str, Any]:
    """
    Fuse Level 3 ML scores into a final threat verdict.

    Args:
        fear_score: Sentiment-based fear/urgency score [0, 1]
        form_score: Form behavior analysis score [0, 1]
        ocr_score: OCR-based text pattern score [0, 1]
        visual_score: Visual brand similarity spoofing score [0, 1]
        l2_score: Level 2 heuristic score (passed from gateway) [0, 1]

    Returns:
        Dict with verdict, final_score, confidence, fusion_detail
    """
    # ── Level 3 Weighted Sum ──────────────────────────────────────────────
    # Normalize weights to handle any floating-point imprecision
    total_weight = WEIGHT_FEAR + WEIGHT_FORM + WEIGHT_OCR + WEIGHT_VISUAL
    l3_score = (
        (WEIGHT_FEAR   * fear_score) +
        (WEIGHT_FORM   * form_score) +
        (WEIGHT_OCR    * ocr_score)  +
        (WEIGHT_VISUAL * visual_score)
    ) / total_weight

    # ── Combine L2 Prior with L3 ──────────────────────────────────────────
    # When all L3 components are 0 (page unreachable, ML models failed, no screenshot),
    # dynamically raise L2 influence to 0.85 so the heuristic score dominates
    # instead of being diluted to 30% by a zero L3.
    all_l3_zero = (fear_score == 0.0 and form_score == 0.0
                   and ocr_score == 0.0 and visual_score == 0.0)
    effective_l2_influence = 0.85 if all_l3_zero else L2_INFLUENCE

    final_score = (effective_l2_influence * l2_score) + ((1 - effective_l2_influence) * l3_score)
    final_score = round(min(max(final_score, 0.0), 1.0), 4)

    # ── Verdict Assignment ─────────────────────────────────────────────────
    if final_score < VERDICT_SAFE_THRESHOLD:
        verdict = "SAFE"
    elif final_score >= VERDICT_MALICIOUS_THRESHOLD:
        verdict = "MALICIOUS"
    else:
        verdict = "SUSPICIOUS"

    # ── Confidence Estimation ─────────────────────────────────────────────
    # Base: distance from midpoint of verdict thresholds.
    # The further the score is from the ambiguous middle, the higher the base.
    mid = (VERDICT_SAFE_THRESHOLD + VERDICT_MALICIOUS_THRESHOLD) / 2
    distance_from_mid = abs(final_score - mid)
    base_confidence = 0.5 + distance_from_mid

    # L3 coverage: fraction of ML signals that actually fired (non-zero).
    # When screenshot fails or models can't load, all 4 scores stay 0.0 —
    # in that case we need to penalise confidence — but HOW MUCH depends on verdict.
    l3_signals_fired = sum([
        1 if fear_score   > 0.0 else 0,
        1 if form_score   > 0.0 else 0,
        1 if ocr_score    > 0.0 else 0,
        1 if visual_score > 0.0 else 0,
    ])
    l3_coverage = l3_signals_fired / 4  # 0.0 (none fired) → 1.0 (all fired)

    # Max confidence is verdict-aware:
    #
    #   SAFE verdict:
    #     L2 heuristics alone can reliably rule out threats when score is clearly low.
    #     Missing L3 only lowers the ceiling a little.
    #     → cap range: 0.75 (no L3) → 0.97 (full L3)
    #
    #   SUSPICIOUS / MALICIOUS verdict:
    #     We need ML confirmation before claiming high certainty.
    #     Missing L3 means we're basically guessing — hard cap at 0.45.
    #     → cap range: 0.45 (no L3) → 0.97 (full L3)
    if verdict == "SAFE":
        max_confidence = 0.75 + (l3_coverage * 0.22)
    else:
        max_confidence = 0.45 + (l3_coverage * 0.52)

    confidence = round(min(base_confidence, max_confidence), 4)

    # ── Override: visual spoofing is near-certain malicious ───────────────
    if visual_score >= 0.82:
        verdict = "MALICIOUS"
        confidence = round(min(confidence + 0.15, 1.0), 4)
        logger.warning(f"Visual spoofing override applied: visual_score={visual_score:.3f}")

    fusion_detail = {
        "l2_score": round(l2_score, 4),
        "l3_score": round(l3_score, 4),
        "l3_components": {
            "fear":   round(fear_score,   4),
            "form":   round(form_score,   4),
            "ocr":    round(ocr_score,    4),
            "visual": round(visual_score, 4),
        },
        "l3_coverage": round(l3_coverage, 4),
        "l3_signals_fired": l3_signals_fired,
        "weights": {
            "fear":   WEIGHT_FEAR,
            "form":   WEIGHT_FORM,
            "ocr":    WEIGHT_OCR,
            "visual": WEIGHT_VISUAL,
        },
        "l2_influence": round(effective_l2_influence, 4),
        "thresholds": {
            "safe":      VERDICT_SAFE_THRESHOLD,
            "malicious": VERDICT_MALICIOUS_THRESHOLD,
        },
    }

    logger.info(
        f"Score fusion: L2={l2_score:.3f}, L3={l3_score:.3f} "
        f"→ final={final_score:.3f}, verdict={verdict}, confidence={confidence:.3f}"
    )

    return {
        "verdict": verdict,
        "final_score": final_score,
        "confidence": confidence,
        "fusion_detail": fusion_detail,
    }
