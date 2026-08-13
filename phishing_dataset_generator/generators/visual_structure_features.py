"""
Static visual-structure features for generated phishing pages.

This module deliberately does NOT perform OCR or browser rendering. It extracts
HTML/CSS signals that indicate image-heavy and overlay-based page construction.
OCR belongs in a later preprocessing or inference stage.
"""

from __future__ import annotations

import base64
import re
from html.parser import HTMLParser
from pathlib import Path


_DATA_IMAGE_RE = re.compile(
    r"data:image/(?P<fmt>png|jpe?g|webp);base64,(?P<data>[A-Za-z0-9+/=\s]+)",
    re.IGNORECASE,
)


class _StructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.images = 0
        self.data_uri_images = 0
        self.password_inputs = 0
        self.forms = 0
        self.empty_submit_buttons = 0
        self._button_stack: list[dict] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attr = {str(k).lower(): (v or "") for k, v in attrs}
        tag = tag.lower()

        if tag == "img":
            self.images += 1
            if attr.get("src", "").lower().startswith("data:image/"):
                self.data_uri_images += 1
        elif tag == "form":
            self.forms += 1
        elif tag == "input" and attr.get("type", "text").lower() == "password":
            self.password_inputs += 1
        elif tag == "button":
            self._button_stack.append({
                "is_submit": attr.get("type", "submit").lower() == "submit",
                "has_text": False,
            })

    def handle_data(self, data: str) -> None:
        if self._button_stack and data.strip():
            self._button_stack[-1]["has_text"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "button" and self._button_stack:
            button = self._button_stack.pop()
            if button["is_submit"] and not button["has_text"]:
                self.empty_submit_buttons += 1


def _max_z_index(html: str) -> int:
    values = []
    for raw in re.findall(r"z-index\s*:\s*(-?\d+)", html, flags=re.IGNORECASE):
        try:
            values.append(int(raw))
        except ValueError:
            continue
    return max(values, default=0)


def extract_visual_structure_features(html: str) -> dict:
    """Extract image/overlay features without rendering or OCR."""
    parser = _StructureParser()
    parser.feed(html)
    lower = html.lower()

    embedded_bytes = 0
    for match in _DATA_IMAGE_RE.finditer(html):
        try:
            embedded_bytes += len(base64.b64decode(re.sub(r"\s+", "", match.group("data"))))
        except Exception:
            pass

    return {
        "html_num_images": parser.images,
        "html_num_embedded_raster_images": parser.data_uri_images,
        "html_embedded_raster_bytes": embedded_bytes,
        "html_num_forms": parser.forms,
        "html_num_password_inputs": parser.password_inputs,
        "html_num_canvas": len(re.findall(r"<canvas\b", lower)),
        "html_num_svg": len(re.findall(r"<svg\b", lower)),
        "html_empty_submit_button_count": parser.empty_submit_buttons,
        "html_max_z_index": _max_z_index(html),
        "html_num_absolute_position_rules": len(re.findall(r"position\s*:\s*absolute", lower)),
        "html_num_fixed_position_rules": len(re.findall(r"position\s*:\s*fixed", lower)),
        "html_has_full_viewport_image": bool(
            re.search(r"<img\b", lower)
            and re.search(r"width\s*:\s*100vw", lower)
            and re.search(r"height\s*:\s*100vh", lower)
        ),
        "html_has_object_fit_cover_or_fill": bool(
            re.search(r"object-fit\s*:\s*(?:cover|fill)", lower)
        ),
        "html_has_transparent_form_controls": bool(
            re.search(r"background\s*:\s*transparent", lower)
            and re.search(r"<(?:input|button)\b", lower)
        ),
        "html_has_fullscreen_form_layer": bool(
            re.search(r"<form\b", lower)
            and re.search(r"inset\s*:\s*0", lower)
            and re.search(r"z-index\s*:\s*(?:[1-9]\d*)", lower)
        ),
        "html_has_raster_form_overlay_pattern": bool(
            parser.images > 0
            and parser.forms > 0
            and parser.password_inputs > 0
            and re.search(r"position\s*:\s*(?:fixed|absolute)", lower)
            and re.search(r"background\s*:\s*transparent", lower)
        ),
    }


def export_embedded_raster_assets(html: str, output_dir: str | Path, sample_id: str) -> list[str]:
    """
    Decode embedded PNG/JPEG/WebP assets to files without performing OCR.

    This is useful when the training dataset should store image files separately
    from HTML while keeping generation and OCR as independent stages.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    for index, match in enumerate(_DATA_IMAGE_RE.finditer(html)):
        fmt = match.group("fmt").lower()
        extension = "jpg" if fmt in {"jpg", "jpeg"} else fmt
        raw = base64.b64decode(re.sub(r"\s+", "", match.group("data")))
        path = out / f"{sample_id}_embedded_{index:02d}.{extension}"
        path.write_bytes(raw)
        written.append(str(path))

    return written
