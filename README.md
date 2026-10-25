# Ghost Data Still Exists — Deletion Audit Agent

HackerRank Orchestrate (October 2026). For every request in `dataset/deletion_requests.csv` the
agent decides whether deletion was actually requested, reconstructs the subject's current and
historical identifiers, establishes the state of every linked record at `audit_at` from the supplied
evidence, applies `deletion_rules.csv`, and writes `COMPLETE`, `INCOMPLETE` or `NOT_APPLICABLE` with
the ordered findings, remediation and verification steps to `output.csv`.

The full challenge contract is in `problem_statement.md` and `AGENTS.md` in the challenge repository.

## Setup

Python 3.11 or newer (developed and tested on 3.13.15). From the repository root:

```bash
python -m pip install -r code/requirements.txt
```

| Dependency | Why |
|---|---|
| `pymupdf` | text extraction from PDF evidence |
| `rapidocr_onnxruntime` | local CPU OCR for PNG screenshots — no network, no API key. **Required to reproduce the submitted `output.csv`**: without it the 11 screenshots are reported as unsupported and 10 eval cases change |
| `pytest` | test suite |

No API keys, environment variables or network access are used.

## Run

The dataset must be at `dataset/` (it is not part of `code.zip`).

```bash
python code/main.py                 # 518 requests -> ./output.csv
python code/validate_output.py      # contract check of ./output.csv
python code/main.py --sample        # 32 public samples -> ./sample_predictions.csv
python code/evaluation/main.py      # score samples vs dataset/sample_output.csv (--failures for details)
python -m pytest code/tests         # 111 tests
python code/data_loader.py          # dataset schema / id / timestamp validation report
```

The first run OCRs the screenshots (measured 95 s total; earlier runs took up to about 35 s per image)
and caches the results in `.cache/ocr/`, keyed by image hash. Later runs take about 2 s. Output is
deterministic: repeated runs are byte-identical, and a fresh OCR pass reproduced the cache exactly.

`main.py` prints to stderr any `COMPLETE` case that rests on missing rather than positive evidence
(see Limitations).

## Results

On the 32 public samples (`code/evaluation/evaluation_report.md` has full definitions and history):

| Status accuracy | Step precision | Step recall | Step F1 | Exact sequence | Order consistency |
|---|---|---|---|---|---|
| 1.000 | 1.000 | 0.824 | 0.903 | 0.312 | 1.000 |

Full run: 518 rows (INCOMPLETE 354, COMPLETE 154, NOT_APPLICABLE 10), validator OK.
No model calls are made (`code/evaluation/usage_report.md`).

## Architecture (`code/`)

| Module | Role |
|---|---|
| `data_loader.py` | loads and validates every CSV (required columns, ids, UTC timestamps, enums, JSON) |
| `identity.py` | replays `user_audit_log.csv` into validity periods per identifier; time-aware email resolution |
| `evidence.py` | extracts observations from SQL (in-memory SQLite, replica tables), recursive JSON, six log layouts (trace-joined), PDF, text and OCR rows; builds an index with exact normalized identifier matching and audit-time filtering |
| `ocr.py` | cached local OCR |
| `intent.py` | rule-based deletion vs non-deletion classification (EN, ES, PT, FR, JA, KO) |
| `engine.py` | discovery, per-resource state assessment, policy decisions |
| `planner.py` | builds and validates `steps_json` (allowed triples, ordering, citations, de-duplication) |
| `main.py`, `validate_output.py`, `evaluation/main.py` | entry point, output validator, sample scorer |

## Key design decisions

- **Claims are not proof.** `reported_status` and `system_activity` results never establish state.
  Activity is used only for explicit data-catalog identity links.
- **Audit-time discipline.** An observation is usable only if its file was captured, and the record
  observed, at or before `audit_at`. Resources are linked only through evidence observed after
  `requested_at`. Citations are always manifest file ids.
- **Grounded ownership only.** A resource belongs to the subject only through a subject identifier
  in the record, an explicit `*resource_id` reference from such a record, or a data-catalog link
  (including exact aliases such as a statement number or file name). Links are rejected when the
  resource's own evidence shows another person. Ownership is never inferred from timing.
- **Replicas.** Any location still holding the record keeps it PRESENT. A later snapshot listing
  that omits it proves absence only when there is no positive sighting.
- **Policy.** `deletion_rules.csv` maps categories to DELETE / REDACT / ANONYMIZE / RETAIN.
  Redaction may keep the stable `user_id`; anonymization may not. Enabled flows and restorable or
  unblocked identifiable backups are recreation risks. A visible identifier outranks any status
  label.
- **Planner.** Steps are ordered by the operation table, then `system_id`, then `resource_id`, which
  places DISABLE_DATA_FLOW and BLOCK_RESTORE before record changes. A COMPLETE case keeps only cited
  verifications, and every row is validated before writing.

## Limitations

- Sample recall is 0.824. The 34 missing sample steps involve resources that appear only in
  activity or nowhere (16), records with no subject identifier (10), or links that exist only in
  post-audit files (8). None can be grounded without violating the rules.
- Four eval cases (case_63, case_517, case_519, case_521) are `COMPLETE` with `[]` because no evidence
  available at `audit_at` mentions the subject. The contract has no "unresolved" status, so this is
  the only valid row; they are listed on stderr.
- Intent, record-category and screenshot-state rules are deterministic heuristics over explicit cues;
  phrasings or screens outside them may be missed.

## Packaging

```bash
zip -r code.zip README.md code -x "*/__pycache__/*" "*/.pytest_cache/*"
```

Submit `code.zip`, the root `output.csv`, `log.txt` (chat transcript) and `agent-trace.zip`
(see `agent_trace_instructions.md`).
