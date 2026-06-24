"""
Playwright Headless Screenshot Capture

Captures a full-page screenshot of a URL using a headless Chromium browser.
Includes timeout management, error handling, and file management.
"""

import logging
import os
import uuid
from pathlib import Path
from typing import Optional

logger = logging.getLogger("linkd.screenshot")

SCREENSHOT_DIR = Path(os.getenv("SCREENSHOT_DIR", "./screenshots"))
PLAYWRIGHT_TIMEOUT = int(os.getenv("PLAYWRIGHT_TIMEOUT", "15000"))
PLAYWRIGHT_HEADLESS = os.getenv("PLAYWRIGHT_HEADLESS", "true").lower() == "true"


async def capture_screenshot(url: str) -> Optional[str]:
    """
    Capture a full-page screenshot of the given URL using Playwright.

    Args:
        url: The URL to screenshot

    Returns:
        Absolute path to the saved screenshot PNG, or None on failure
    """
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{uuid.uuid4().hex}.png"
    output_path = SCREENSHOT_DIR / filename

    try:
        from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=PLAYWRIGHT_HEADLESS,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-web-security",
                    "--disable-features=VizDisplayCompositor",
                ],
            )

            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )

            page = await context.new_page()

            # Block heavy resources for faster loading
            await page.route(
                "**/*.{woff,woff2,ttf,eot}",
                lambda route: route.abort()
            )

            try:
                await page.goto(
                    url,
                    timeout=PLAYWRIGHT_TIMEOUT,
                    wait_until="networkidle",
                )
            except PlaywrightTimeout:
                logger.warning(f"Page load timeout — taking screenshot anyway: {url}")
            except Exception as e:
                logger.warning(f"Page navigation error: {e} — attempting screenshot")

            # Dismiss cookie banners / popups if present
            try:
                await page.keyboard.press("Escape")
            except Exception:
                pass

            await page.screenshot(
                path=str(output_path),
                full_page=False,       # Viewport screenshot (not full page scroll)
                type="png",
                clip={"x": 0, "y": 0, "width": 1280, "height": 800},
            )

            await browser.close()

        logger.info(f"Screenshot saved: {output_path}")
        return str(output_path)

    except ImportError:
        logger.error("Playwright not installed. Run: pip install playwright && playwright install chromium")
        return None
    except Exception as e:
        logger.error(f"Screenshot capture failed for {url}: {e}")
        return None


async def cleanup_old_screenshots(max_files: int = 500):
    """Remove oldest screenshots when directory exceeds max_files."""
    try:
        screenshots = sorted(
            SCREENSHOT_DIR.glob("*.png"),
            key=lambda f: f.stat().st_mtime,
        )
        if len(screenshots) > max_files:
            for old_file in screenshots[: len(screenshots) - max_files]:
                old_file.unlink(missing_ok=True)
                logger.debug(f"Cleaned up old screenshot: {old_file}")
    except Exception as e:
        logger.warning(f"Screenshot cleanup error: {e}")
