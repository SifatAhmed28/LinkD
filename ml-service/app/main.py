"""
LinkD ML Service — FastAPI entry point

Runs Level 3 deep ML analysis:
  - RoBERTa sentiment/emotion analysis (fear/urgency)
  - Form behavior cross-origin analysis
  - EasyOCR visual text extraction
  - ResNet-50 visual brand similarity
"""

import os
import logging
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.routers.inference import router as inference_router

load_dotenv()

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("linkd.ml-service")

# ── Screenshot directory ─────────────────────────────────────────────────────
os.makedirs(os.getenv("SCREENSHOT_DIR", "./screenshots"), exist_ok=True)


# ── Lifespan: optional eager model loading ───────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    strategy = os.getenv("MODEL_LOAD_STRATEGY", "lazy")
    if strategy == "eager":
        logger.info("Eager model loading — pre-loading all Level 3 models...")
        from app.level3.sentiment import SentimentAnalyzer
        from app.level3.visual_similarity import VisualSimilarityAnalyzer
        # Initialize singletons (this loads model weights into memory)
        SentimentAnalyzer.get_instance()
        VisualSimilarityAnalyzer.get_instance()
        logger.info("✅ All models loaded and ready.")
    else:
        logger.info("Lazy model loading — models will load on first request.")
    yield
    logger.info("ML Service shutting down.")


# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="LinkD ML Service",
    description="Level 3 ML inference for phishing detection",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(inference_router)

# ── Static files: serve captured screenshots ─────────────────────────────────
_screenshot_dir = os.getenv("SCREENSHOT_DIR", "./screenshots")
os.makedirs(_screenshot_dir, exist_ok=True)
app.mount("/screenshots", StaticFiles(directory=_screenshot_dir), name="screenshots")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "linkd-ml-service"}


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal ML service error", "detail": str(exc)},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("NODE_ENV") != "production",
        log_level="info",
    )
