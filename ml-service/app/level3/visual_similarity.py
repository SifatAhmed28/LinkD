"""
Visual Similarity Analysis — Level 3

Uses ResNet-50 (pretrained on ImageNet) as a feature extractor to compute
visual embeddings of page screenshots, then compares them against a database
of known brand login portal layouts using cosine similarity.

Architecture:
  Screenshot → ResNet-50 (strip FC layer) → 2048-dim embedding
  → cosine_similarity(embedding, brand_db_embeddings)
  → if similarity > threshold AND domain ≠ brand domain → SPOOFING

This catches visual clones that may bypass text-based detection.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import numpy as np

logger = logging.getLogger("linkd.visual_similarity")

SIMILARITY_THRESHOLD = float(os.getenv("VISUAL_SIMILARITY_THRESHOLD", "0.82"))
BRAND_DB_PATH = Path(__file__).parent.parent / "models" / "brand_db.json"

# Brand canonical domains for mismatch checking
BRAND_DOMAINS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "github": "github.com",
    "linkedin": "linkedin.com",
    "twitter": "twitter.com",
    "netflix": "netflix.com",
    "dropbox": "dropbox.com",
}


class VisualSimilarityAnalyzer:
    """Singleton CNN-based visual similarity analyzer."""

    _instance: Optional["VisualSimilarityAnalyzer"] = None

    def __init__(self):
        self._model = None
        self._transform = None
        self._brand_db: List[Dict] = []
        self._loaded = False

    @classmethod
    def get_instance(cls) -> "VisualSimilarityAnalyzer":
        if cls._instance is None:
            cls._instance = cls()
        if not cls._instance._loaded:
            cls._instance._load_model()
        return cls._instance

    def _load_model(self):
        """Load ResNet-50 feature extractor and brand embedding database."""
        try:
            import torch
            import torchvision.models as models
            import torchvision.transforms as transforms

            logger.info("Loading ResNet-50 feature extractor...")

            # Load pretrained ResNet-50 and strip the final classification head
            resnet = models.resnet50(weights=models.ResNet50_Weights.IMAGENET1K_V2)
            # Use all layers except the final FC layer
            self._model = torch.nn.Sequential(*list(resnet.children())[:-1])
            self._model.eval()

            # Standard ImageNet normalization
            self._transform = transforms.Compose([
                transforms.Resize((224, 224)),
                transforms.ToTensor(),
                transforms.Normalize(
                    mean=[0.485, 0.456, 0.406],
                    std=[0.229, 0.224, 0.225]
                ),
            ])

            # Load brand embedding database
            self._load_brand_db()

            self._loaded = True
            logger.info(f"✅ ResNet-50 loaded. Brand DB: {len(self._brand_db)} entries.")

        except Exception as e:
            logger.error(f"Failed to load visual similarity model: {e}")
            self._loaded = False
            raise

    def _load_brand_db(self):
        """Load pre-computed brand layout embeddings from JSON."""
        if BRAND_DB_PATH.exists():
            try:
                with open(BRAND_DB_PATH, "r") as f:
                    data = json.load(f)
                # Support both formats: a plain list OR {"entries": [...], ...}
                if isinstance(data, list):
                    self._brand_db = data
                elif isinstance(data, dict):
                    self._brand_db = data.get("entries", [])
                else:
                    self._brand_db = []
                logger.info(f"Brand DB loaded: {len(self._brand_db)} brand layouts")
            except Exception as e:
                logger.warning(f"Brand DB load error: {e}")
                self._brand_db = []
        else:
            logger.warning(f"Brand DB not found at {BRAND_DB_PATH}. Visual similarity disabled.")
            self._brand_db = []

    def _extract_embedding(self, image_path: str) -> Optional["np.ndarray"]:
        """Extract 2048-dim embedding vector from a screenshot."""
        try:
            import numpy as np
            import torch
            from PIL import Image

            img = Image.open(image_path).convert("RGB")
            tensor = self._transform(img).unsqueeze(0)

            with torch.no_grad():
                embedding = self._model(tensor)

            # Flatten to 1D and L2-normalize
            vec = embedding.squeeze().numpy()
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec = vec / norm
            return vec

        except Exception as e:
            logger.error(f"Embedding extraction error: {e}")
            return None

    def analyze(self, screenshot_path: str, page_url: str) -> Dict[str, Any]:
        """
        Compare a page screenshot against the brand embedding database.

        Args:
            screenshot_path: Path to the captured screenshot
            page_url: The scanned URL (for domain mismatch check)

        Returns:
            Dictionary with visual_score, matched_brand, similarity, flags
        """
        if not os.path.exists(screenshot_path):
            return {"visual_score": 0.0, "error": "Screenshot not found"}

        if not self._brand_db:
            return {
                "visual_score": 0.0,
                "info": "Brand DB empty — visual similarity skipped",
            }

        # Extract embedding for current page
        page_embedding = self._extract_embedding(screenshot_path)
        if page_embedding is None:
            return {"visual_score": 0.0, "error": "Embedding extraction failed"}

        # Get page domain for mismatch check
        page_domain = ""
        try:
            parsed = urlparse(page_url)
            page_domain = parsed.hostname or ""
        except Exception:
            pass

        # ── Compare Against Brand DB ──────────────────────────────────────
        best_similarity = 0.0
        best_brand = None
        similarities = []

        for entry in self._brand_db:
            brand_name = entry.get("brand", "unknown")
            stored_embedding = np.array(entry.get("embedding", []))

            if stored_embedding.size == 0:
                continue

            # Cosine similarity (both vectors are already L2-normalized)
            sim = float(np.dot(page_embedding, stored_embedding))
            similarities.append({"brand": brand_name, "similarity": round(sim, 4)})

            if sim > best_similarity:
                best_similarity = sim
                best_brand = brand_name

        # Sort by similarity descending
        similarities.sort(key=lambda x: x["similarity"], reverse=True)
        top_matches = similarities[:3]

        flags = []
        visual_score = 0.0

        if best_similarity >= SIMILARITY_THRESHOLD and best_brand:
            # Check if the page domain matches the brand's expected domain
            expected_domain = BRAND_DOMAINS.get(best_brand, "")
            is_legitimate_domain = (
                expected_domain and
                (page_domain == expected_domain or page_domain.endswith(f".{expected_domain}"))
            )

            if not is_legitimate_domain:
                # High visual similarity to a brand, but wrong domain = SPOOFING
                flags.append(f"visual_spoofing_{best_brand}")
                visual_score = best_similarity  # Use raw similarity as score
                logger.warning(
                    f"Visual spoofing detected! Page looks like {best_brand} "
                    f"(similarity={best_similarity:.3f}) but domain is {page_domain}"
                )
            else:
                # Looks like the brand AND is on the right domain — legitimate
                visual_score = 0.0
                flags.append(f"legitimate_{best_brand}_page")

        return {
            "visual_score": round(visual_score, 4),
            "best_similarity": round(best_similarity, 4),
            "matched_brand": best_brand,
            "similarity_threshold": SIMILARITY_THRESHOLD,
            "top_matches": top_matches,
            "flags": flags,
            "page_domain": page_domain,
        }
