"""
Sentiment & Emotion Analysis — Level 3

Uses cardiffnlp/twitter-roberta-base-emotion (HuggingFace) to quantify
emotional vectors in page text, specifically targeting "fear" and "anger"
which are primary social engineering mechanisms in phishing attacks.

Implements a singleton pattern with lazy loading for memory efficiency.
"""

import logging
import os
from typing import Dict, Any, Optional

logger = logging.getLogger("linkd.sentiment")

# HuggingFace model for emotion classification
MODEL_NAME = "cardiffnlp/twitter-roberta-base-emotion"

# Emotion labels for this model (in order)
EMOTION_LABELS = ["anger", "joy", "optimism", "sadness"]

# Extended fear/urgency lexicon for supplement scoring
FEAR_LEXICON = [
    "suspended", "locked", "compromised", "unauthorized", "illegal",
    "hacked", "breached", "stolen", "expired", "blocked", "terminated",
    "arrest", "legal action", "fraud", "penalty", "violation",
    "immediately", "urgent", "alert", "warning", "critical", "danger",
]

URGENCY_LEXICON = [
    "verify now", "act now", "action required", "expires", "last chance",
    "limited time", "24 hours", "within", "deadline", "must", "required",
    "immediately", "asap", "right now",
]


class SentimentAnalyzer:
    """Singleton sentiment analyzer using RoBERTa emotion model."""

    _instance: Optional["SentimentAnalyzer"] = None

    def __init__(self):
        self._pipeline = None
        self._model_loaded = False

    @classmethod
    def get_instance(cls) -> "SentimentAnalyzer":
        if cls._instance is None:
            cls._instance = cls()
        if not cls._instance._model_loaded:
            cls._instance._load_model()
        return cls._instance

    def _load_model(self):
        """Lazy-load the HuggingFace emotion classification pipeline."""
        try:
            from transformers import pipeline
            logger.info(f"Loading sentiment model: {MODEL_NAME}")
            self._pipeline = pipeline(
                "text-classification",
                model=MODEL_NAME,
                top_k=None,         # Return all emotion scores
                truncation=True,
                max_length=512,
            )
            self._model_loaded = True
            logger.info("✅ Sentiment model loaded.")
        except Exception as e:
            logger.error(f"Failed to load sentiment model: {e}")
            self._model_loaded = False
            raise

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Analyze text for emotional content, focusing on fear/urgency signals.

        Args:
            text: Visible page text (truncated to ~512 tokens internally)

        Returns:
            Dictionary with fear_score, emotion_scores, lexicon_score
        """
        if not text or len(text.strip()) < 10:
            return {"fear_score": 0.0, "emotion_scores": {}, "lexicon_score": 0.0}

        emotion_scores: Dict[str, float] = {}
        model_fear_score = 0.0

        # ── Transformer-Based Emotion Scoring ────────────────────────────
        if self._pipeline:
            try:
                # Truncate text to avoid token overflow
                truncated = text[:2000]
                results = self._pipeline(truncated)

                for item in results[0]:
                    label = item["label"].lower()
                    score = float(item["score"])
                    emotion_scores[label] = round(score, 4)

                # "anger" is the closest to fear in this model's label set
                # We treat high anger + low joy as a fear/urgency proxy
                anger = emotion_scores.get("anger", 0.0)
                joy = emotion_scores.get("joy", 0.0)
                sadness = emotion_scores.get("sadness", 0.0)

                # Fear proxy: high anger + sadness, low joy
                model_fear_score = min((anger * 0.6 + sadness * 0.3) * (1 - joy * 0.5), 1.0)

            except Exception as e:
                logger.warning(f"Transformer inference error: {e}")

        # ── Lexicon-Based Supplement ──────────────────────────────────────
        text_lower = text.lower()
        fear_hits = sum(1 for word in FEAR_LEXICON if word in text_lower)
        urgency_hits = sum(1 for phrase in URGENCY_LEXICON if phrase in text_lower)

        # Normalize lexicon contributions
        lexicon_score = min((fear_hits * 0.08) + (urgency_hits * 0.1), 1.0)

        # ── Combine Scores ────────────────────────────────────────────────
        # Weighted: transformer is primary, lexicon supplements
        fear_threshold = float(os.getenv("FEAR_SCORE_THRESHOLD", "0.6"))
        combined_fear = round(model_fear_score * 0.7 + lexicon_score * 0.3, 4)

        return {
            "fear_score": combined_fear,
            "emotion_scores": emotion_scores,
            "lexicon_score": round(lexicon_score, 4),
            "model_fear_score": round(model_fear_score, 4),
            "fear_threshold": fear_threshold,
            "exceeds_threshold": combined_fear >= fear_threshold,
        }
