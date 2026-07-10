FROM python:3.11-slim AS base

# System dependencies for Playwright and EasyOCR
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget gnupg ca-certificates \
    libglib2.0-0 libnss3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2 libpangocairo-1.0-0 \
    fonts-liberation fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium browser
RUN playwright install chromium --with-deps

# Copy application
COPY . .

# Create directories
RUN mkdir -p screenshots app/models/weights scripts/brand_screenshots

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
