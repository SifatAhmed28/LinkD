"""
Level 3 Inference Router

POST /analyze — accepts extracted page data from the Node.js gateway
and returns a final ML-based verdict.
"""

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl, field_validator

from app.level3.form_behavior import analyze_form_behavior
from app.utils.screenshot import capture_screenshot
from app.utils.aggregator import aggregate_ml_scores

logger = logging.getLogger("linkd.inference")

router = APIRouter(prefix="", tags=["inference"])


# ── Request / Response Models ─────────────────────────────────────────────────

class FormInput(BaseModel):
    type: str = "text"
    name: str = ""
    id: str = ""


class FormData(BaseModel):
    action: str = ""
    method: str = "get"
    inputs: List[FormInput] = []


class AnalyzeRequest(BaseModel):
    url: str
    html: Optional[str] = ""
    visible_text: Optional[str] = ""
    forms: Optional[List[FormData]] = []
    l2_score: Optional[float] = 0.0
    l2_breakdown: Optional[Dict[str, Any]] = {}
    l2_features: Optional[Dict[str, Any]] = {}  # Structured L2 feature vector (Phase 1)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v



class AnalyzeResponse(BaseModel):
    url: str
    verdict: str
    final_score: float
    confidence: float
    breakdown: Dict[str, Any]
    screenshot_url: Optional[str] = None
    ocr_text: Optional[str] = None


# ── Main Inference Endpoint ───────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    logger.info(f"L3 analysis started for: {request.url}")

    breakdown = {}

    # Store the L2 structured feature vector in breakdown for logging / future fusion use
    if request.l2_features:
        breakdown["l2_features"] = request.l2_features
        logger.info(f"L2 feature vector received: {len(request.l2_features)} features")

    # ── 1. Screenshot Capture ─────────────────────────────────────────────
    screenshot_path = None
    screenshot_url = None
    try:
        screenshot_path = await capture_screenshot(request.url)
        if screenshot_path:
            # Expose as a relative URL the dashboard can fetch
            filename = os.path.basename(screenshot_path)
            screenshot_url = f"/screenshots/{filename}"
            logger.info(f"Screenshot captured: {screenshot_path}")
    except Exception as e:
        logger.warning(f"Screenshot failed: {e}")

    # ── 2. Sentiment / Fear Analysis ─────────────────────────────────────
    fear_score = 0.0
    sentiment_detail = {}
    try:
        from app.level3.sentiment import SentimentAnalyzer
        analyzer = SentimentAnalyzer.get_instance()
        sentiment_result = analyzer.analyze(request.visible_text or "")
        fear_score = sentiment_result.get("fear_score", 0.0)
        sentiment_detail = sentiment_result
        breakdown["sentiment"] = sentiment_detail
        logger.info(f"Sentiment fear_score: {fear_score:.3f}")
    except Exception as e:
        logger.error(f"Sentiment analysis failed: {e}")
        breakdown["sentiment"] = {"error": str(e)}

    # ── 3. Form Behavior Analysis ─────────────────────────────────────────
    form_score = 0.0
    form_detail = {}
    try:
        forms_dict = [f.model_dump() for f in (request.forms or [])]
        form_result = analyze_form_behavior(request.url, forms_dict, request.html or "")
        form_score = form_result.get("form_score", 0.0)
        form_detail = form_result
        breakdown["form_behavior"] = form_detail
        logger.info(f"Form behavior score: {form_score:.3f}")
    except Exception as e:
        logger.error(f"Form analysis failed: {e}")
        breakdown["form_behavior"] = {"error": str(e)}

    # ── 4. Visual OCR Analysis ────────────────────────────────────────────
    ocr_score = 0.0
    ocr_text = ""
    ocr_detail = {}
    if screenshot_path:
        try:
            from app.level3.visual_ocr import VisualOCRAnalyzer
            ocr_analyzer = VisualOCRAnalyzer.get_instance()
            ocr_result = ocr_analyzer.analyze(screenshot_path)
            ocr_score = ocr_result.get("ocr_score", 0.0)
            ocr_text = ocr_result.get("extracted_text", "")
            ocr_detail = ocr_result
            breakdown["ocr"] = ocr_detail
            logger.info(f"OCR score: {ocr_score:.3f}, text length: {len(ocr_text)}")
        except Exception as e:
            logger.error(f"OCR analysis failed: {e}")
            breakdown["ocr"] = {"error": str(e)}

    # ── 5. Visual Similarity Analysis ────────────────────────────────────
    visual_score = 0.0
    visual_detail = {}
    if screenshot_path:
        try:
            from app.level3.visual_similarity import VisualSimilarityAnalyzer
            visual_analyzer = VisualSimilarityAnalyzer.get_instance()
            visual_result = visual_analyzer.analyze(screenshot_path, request.url)
            visual_score = visual_result.get("visual_score", 0.0)
            visual_detail = visual_result
            breakdown["visual_similarity"] = visual_detail
            logger.info(f"Visual similarity score: {visual_score:.3f}")
        except Exception as e:
            logger.error(f"Visual similarity failed: {e}")
            breakdown["visual_similarity"] = {"error": str(e)}

    # ── 6. Final Score Fusion ─────────────────────────────────────────────
    result = aggregate_ml_scores(
        fear_score=fear_score,
        form_score=form_score,
        ocr_score=ocr_score,
        visual_score=visual_score,
        l2_score=request.l2_score or 0.0,
    )

    breakdown["score_fusion"] = result["fusion_detail"]

    logger.info(
        f"L3 final: verdict={result['verdict']}, "
        f"score={result['final_score']:.3f}, "
        f"confidence={result['confidence']:.3f}"
    )

    return AnalyzeResponse(
        url=request.url,
        verdict=result["verdict"],
        final_score=result["final_score"],
        confidence=result["confidence"],
        breakdown=breakdown,
        screenshot_url=screenshot_url,
        ocr_text=ocr_text[:2000] if ocr_text else None,
    )
