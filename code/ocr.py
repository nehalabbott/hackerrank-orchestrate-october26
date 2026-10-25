"""Deterministic local OCR for evidence screenshots, cached by file content.

RapidOCR (ONNX runtime, CPU) is slow on full-size screenshots (~30 s each),
so results are cached as JSON under <repo>/.cache/ocr/<sha256>.json. The cache
key is the image's content hash, so a changed image is always re-read.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE_DIR = REPO_ROOT / ".cache" / "ocr"
CACHE_VERSION = 1

_engine = None


@dataclass(frozen=True)
class OcrBox:
    text: str
    x0: float
    y0: float
    x1: float
    y1: float
    confidence: float

    @property
    def y_center(self) -> float:
        return (self.y0 + self.y1) / 2


def _get_engine():
    global _engine
    if _engine is None:
        try:
            from rapidocr_onnxruntime import RapidOCR
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise RuntimeError(
                "rapidocr_onnxruntime is required to read image evidence; "
                "install it with: pip install -r requirements.txt") from exc
        _engine = RapidOCR()
    return _engine


def ocr_image(path: Path | str, cache_dir: Path | str | None = DEFAULT_CACHE_DIR) -> list[OcrBox]:
    path = Path(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    cache_file = Path(cache_dir) / f"{digest}.json" if cache_dir else None
    if cache_file and cache_file.is_file():
        cached = json.loads(cache_file.read_text(encoding="utf-8"))
        if cached.get("version") == CACHE_VERSION:
            return [OcrBox(**box) for box in cached["boxes"]]

    result, _ = _get_engine()(str(path))
    boxes = []
    for points, text, confidence in result or ():
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        boxes.append(OcrBox(text, float(min(xs)), float(min(ys)), float(max(xs)),
                            float(max(ys)), float(confidence)))
    boxes.sort(key=lambda b: (round(b.y_center), b.x0))

    if cache_file:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": CACHE_VERSION, "source": path.name,
                   "boxes": [box.__dict__ for box in boxes]}
        cache_file.write_text(json.dumps(payload, ensure_ascii=False, indent=0),
                              encoding="utf-8")
    return boxes


if __name__ == "__main__":
    # Warm the cache: python code/ocr.py dataset/evidence/images/*.png
    for arg in sys.argv[1:]:
        print(arg, len(ocr_image(arg)), flush=True)
