# LinkD — ML-Based Phishing Detection on Trusted Platforms

**LinkD** is a three-level machine learning system that detects phishing attacks hosted on legitimate third-party platforms such as GitHub Pages, Notion, Google Sites, and Netlify — where traditional domain-blacklist approaches fail.

---

## Architecture

```
Client Request
      │
      ▼
┌──────────────────────────────────────┐
│  Node.js / Express Gateway  :3000    │
│                                      │
│  Level 1: Caching & Verification     │
│   ├─ Static Whitelist (in-memory)    │
│   ├─ Redis LRU Cache + TTL           │
│   └─ SHA-256 Content Hash Guard      │
│                                      │
│  Level 2: Heuristics Engine          │
│   ├─ Urgency/Fear Pattern Regex      │
│   ├─ Anchor Text ↔ Href Mismatch     │
│   ├─ URL Obfuscation Detection       │
│   └─ GitHub REST API Context         │
└──────────────────┬───────────────────┘
                   │ Score 0.2–0.85 (SUSPICIOUS)
                   ▼
┌──────────────────────────────────────┐
│  Python / FastAPI ML Service  :8000  │
│                                      │
│  Level 3: Deep ML Inference          │
│   ├─ RoBERTa Emotion Analysis        │
│   ├─ Form Cross-Origin Detection     │
│   ├─ Playwright Screenshot           │
│   ├─ EasyOCR Text Extraction         │
│   └─ ResNet-50 Visual Similarity     │
└──────────────────────────────────────┘
                   │
                   ▼
       React Dashboard :5173
```

---

## Project Structure

```
LinkD/
├── gateway/           # Node.js/Express — Level 1 & 2
│   ├── src/
│   │   ├── server.js
│   │   ├── routes/scan.js
│   │   ├── level1/          # Whitelist, Redis cache, content hash
│   │   ├── level2/          # Pattern detection, GitHub API, obfuscation
│   │   └── utils/           # URL parser, score aggregator, logger
│   └── config/whitelist.json
│
├── ml-service/        # Python/FastAPI — Level 3
│   ├── app/
│   │   ├── main.py
│   │   ├── routers/inference.py
│   │   ├── level3/          # Sentiment, form, OCR, visual similarity
│   │   └── utils/           # Screenshot, aggregator
│   ├── scripts/
│   │   └── generate_brand_db.py
│   └── requirements.txt
│
├── dashboard/         # React/Vite — UI
│   └── src/
│       ├── App.jsx
│       ├── components/
│       │   ├── ScanInput.jsx
│       │   ├── ResultCard.jsx
│       │   ├── ThreatTimeline.jsx
│       │   ├── VisualPreview.jsx
│       │   └── StatsBanner.jsx
│       └── api/scanApi.js
│
└── docker-compose.yml
```

---

## Quick Start

### Option A: Docker Compose (Recommended)

```bash
# 1. Copy and configure environment
cp gateway/.env.example gateway/.env
cp ml-service/.env.example ml-service/.env
cp dashboard/.env.example dashboard/.env

# 2. (Optional) Add your GitHub token to gateway/.env
echo "GITHUB_TOKEN=ghp_your_token_here" >> gateway/.env

# 3. Start all services
docker compose up --build

# Dashboard → http://localhost:5173
# Gateway   → http://localhost:3000
# ML Service → http://localhost:8000
```

### Option B: Manual Development Setup

**Step 1 — Start Redis**
```bash
# With Docker
docker run -d -p 6379:6379 redis:7-alpine

# Or install locally: https://redis.io/download
```

**Step 2 — Start the ML Service**
```bash
cd ml-service

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Install Playwright browser
playwright install chromium

# Copy environment
copy .env.example .env

# (Optional) Pre-generate brand embedding database
python scripts/generate_brand_db.py

# Start server
python -m uvicorn app.main:app --reload --port 8000
```

**Step 3 — Start the Gateway**
```bash
cd gateway

# Install dependencies
npm install

# Copy environment
copy .env.example .env
# Edit .env: set GITHUB_TOKEN if desired

# Start development server
npm run dev
```

**Step 4 — Start the Dashboard**
```bash
cd dashboard

# Install dependencies
npm install

# Copy environment
copy .env.example .env

# Start Vite dev server
npm run dev
# → http://localhost:5173
```

---

## API Reference

### `POST /api/scan`

Scan a URL for phishing indicators.

**Request**
```json
{
  "url": "https://google-verify.github.io/account-recovery/"
}
```

**Response**
```json
{
  "url": "https://google-verify.github.io/account-recovery/",
  "verdict": "MALICIOUS",
  "score": 0.91,
  "confidence": 0.87,
  "level_caught": "L3_ML",
  "breakdown": {
    "urgencyKeyword": 0.25,
    "domainMismatch": 0.3,
    "githubFlags": ["repo_very_new", "password_input_on_github"],
    "ml": {
      "sentiment": { "fear_score": 0.72, "exceeds_threshold": true },
      "form_behavior": { "form_score": 0.65, "flags": ["cross_origin_form_action"] },
      "visual_similarity": { "matched_brand": "google", "best_similarity": 0.91, "flags": ["visual_spoofing_google"] }
    }
  },
  "cached": false,
  "response_ms": 4231,
  "screenshot_url": "/screenshots/abc123.png",
  "timestamp": "2026-06-23T12:00:00.000Z"
}
```

**Verdict Values**
| Verdict | Score Range | Meaning |
|---|---|---|
| `SAFE` | < 0.2 (L2) / < 0.3 (L3) | No threat indicators |
| `SUSPICIOUS` | Between thresholds | Some indicators — manual review recommended |
| `MALICIOUS` | > 0.85 (L2) / > 0.7 (L3) | Phishing confirmed |

---

## Detection Logic

### Level 1: Cache & Verification
- **Static whitelist**: 40+ trusted domains checked in O(1)
- **Redis LRU**: 24h TTL for SAFE, 72h for MALICIOUS
- **Content hash guard**: SHA-256 of page body — detects live content swapping (cache poisoning evasion)

### Level 2: Heuristics (Score Thresholds: 0.0–1.0)
| Signal | Weight | Description |
|---|---|---|
| `urgencyKeyword` | 0.25 | Social engineering language detection |
| `domainMismatch` | 0.30 | Anchor text brand ≠ href destination |
| `urlObfuscation` | 0.20 | Shorteners, IP URLs, IDN homographs |
| `formPasswordField` | 0.35 | Password input on unusual platform |
| `crossOriginForm` | 0.30 | Form POSTs to different origin |
| `githubNewRepo` | 0.40 | Repo created < 7 days ago |
| `githubPasswordInReadme` | 0.80 | Password field in GitHub Pages (critical) |

### Level 3: ML Inference
| Component | Model | Detects |
|---|---|---|
| Sentiment | `cardiffnlp/twitter-roberta-base-emotion` | Fear/urgency in text |
| Form Analysis | Rule-based | Cross-origin POSTs, HTTPS downgrades |
| OCR | EasyOCR | Text hidden in images |
| Visual Similarity | ResNet-50 (2048-dim embeddings) | Brand layout cloning |

---

## GitHub API Setup

The GitHub context analyzer uses the GitHub REST API. Without a token, the limit is **60 requests/hour**.

1. Create a [Personal Access Token](https://github.com/settings/tokens) (no scopes needed for public repo data)
2. Add to `gateway/.env`:
   ```
   GITHUB_TOKEN=ghp_your_token_here
   ```
3. This raises the limit to **5,000 requests/hour**

---

## Generating the Brand Embedding Database

The visual similarity model requires pre-computed embeddings of legitimate brand login pages:

```bash
cd ml-service
python scripts/generate_brand_db.py
```

This will:
1. Use Playwright to screenshot 11 major brand login pages
2. Pass each screenshot through ResNet-50 to extract 2048-dim embeddings
3. L2-normalize and save to `app/models/brand_db.json`

**Brands covered**: Google, Microsoft, Apple, PayPal, Amazon, Facebook, GitHub, LinkedIn, Twitter, Netflix, Dropbox

---

## Configuration

All thresholds and weights are configurable via environment variables:

| Variable | Default | Description |
|---|---|---|
| `SCORE_SAFE_THRESHOLD` | `0.2` | L2 score below this → SAFE |
| `SCORE_MALICIOUS_THRESHOLD` | `0.85` | L2 score above this → MALICIOUS |
| `VISUAL_SIMILARITY_THRESHOLD` | `0.82` | Cosine similarity for brand match |
| `FEAR_SCORE_THRESHOLD` | `0.6` | RoBERTa fear score trigger |
| `MODEL_LOAD_STRATEGY` | `lazy` | `lazy` or `eager` model loading |
| `WEIGHT_FEAR` | `0.25` | L3 fear score weight |
| `WEIGHT_FORM` | `0.30` | L3 form behavior weight |
| `WEIGHT_OCR` | `0.20` | L3 OCR weight |
| `WEIGHT_VISUAL` | `0.25` | L3 visual similarity weight |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Gateway | Node.js 20, Express.js, ioredis, Cheerio, Octokit, tldts |
| Cache | Redis 7 (LRU eviction) / in-memory LRU fallback |
| ML Service | Python 3.11, FastAPI, PyTorch, Transformers, EasyOCR, Playwright |
| Vision | ResNet-50 (torchvision), cosine similarity |
| NLP | `cardiffnlp/twitter-roberta-base-emotion` |
| OCR | EasyOCR |
| Dashboard | React 18, Vite 5, Axios |
| Orchestration | Docker Compose |

---

## License

MIT — see LICENSE for details.
