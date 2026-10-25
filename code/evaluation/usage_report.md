# Usage Report — final full-dataset run

The final run that produced `output.csv` (`python code/main.py`, 518 requests) makes **no language-
model or other remote API calls**. Every decision is computed by deterministic local code:
rule-based intent classification, identity resolution, evidence parsing (SQLite, JSON, logs, PDF via
PyMuPDF, screenshots via local RapidOCR on CPU), policy application and planning.

## Model usage

| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Est. cost |
|---|---|---|---|---|---|---|
| — (none) | — | 0 | 0 | 0 | 0 | $0.00 |
| **Overall** | | **0** | **0** | **0** | **0** | **$0.00** |

- Average tokens per request: 0 (0 / 518).
- Estimated cost per request: $0.00.
- No API keys or credentials are read or required.

## Local compute (measured on the development machine: Windows 11, 8 logical CPUs, Python 3.13.15)

| Stage | Time |
|---|---|
| OCR of the 11 evidence screenshots into an empty cache (RapidOCR 1.2.3, CPU) | 95 s total in the final check; an earlier run on the same machine took about 35 s per image. Results are cached in `.cache/ocr/` keyed by image SHA-256 |
| Full 518-request run with the OCR cache warm | 2.0 s |

The fresh OCR pass reproduced the cached results exactly for all 11 screenshots, so the run is
deterministic with or without a warm cache.

## Notes

- The solution was developed with an AI coding assistant (Claude Code, model `claude-opus-5-5`).
  That usage is part of development, not of the submitted pipeline, and its token counts were not
  measured by this project; the session transcript is submitted separately (`log.txt` and the
  agent trace).
