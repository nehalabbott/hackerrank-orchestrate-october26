# Evaluation Report — Ghost Data Still Exists

All numbers below were produced by the commands shown, on the final code, against the 32 public
sample requests (`dataset/sample_deletion_requests.csv` scored against `dataset/sample_output.csv`).
No organizer-only data was used.

```bash
python code/main.py --sample            # writes sample_predictions.csv
python code/evaluation/main.py --failures
python code/validate_output.py sample_predictions.csv --requests sample
```

## 1. Metrics (final run)

| Metric | Value | Definition |
|---|---|---|
| Case-level status accuracy | **1.000** (32/32) | `deletion_status` equals the reference |
| Step precision | **1.000** (159/159) | predicted steps that exactly match a reference step on phase, system_id, resource_id, operation, state, evidence_id |
| Step recall | **0.824** (159/193) | reference steps that were predicted |
| Step F1 | **0.903** | harmonic mean of the two |
| Field accuracy (position-aligned) | phase 0.824, system_id 0.611, resource_id 0.611, operation 0.663, state 0.663, evidence_id 0.824 | per-field agreement when the i-th predicted step is compared with the i-th reference step (a missing early step shifts every later position, so this is a strict lower bound) |
| Sequence accuracy (row exact match) | **0.312** (10/32) | status and the whole `steps_json` array identical to the reference |
| Order consistency | **1.000** | for every pair of steps present in both prediction and reference, their relative order agrees |

Status confusion (reference → predicted): COMPLETE→COMPLETE 10, INCOMPLETE→INCOMPLETE 22.
The public samples contain no NOT_APPLICABLE case, so intent classification is evaluated by the
custom cases in §3 instead.

**Interpretation.** Every step the system emits is correct and correctly ordered; the gap is
entirely missing steps (recall). Sequence accuracy is low only because a case with any missing step
cannot match exactly.

**Ambiguity flagged.** The README asks for "case, row, field, and sequence accuracy" without
defining them. "Row" is reported here two ways: step-level (each step object = a row of
`steps_json`) as precision/recall/F1, and output-row exact match as sequence accuracy.

## 2. Full-dataset run (518 requests)

`python code/main.py` → `output.csv`; `python code/validate_output.py` → **OK**.

- 518 rows, sorted by case_id, exact header; every row passes the step-contract validator
  (allowed phase/operation/state triples, consecutive step_no, phase and operation order, evidence
  rules, no duplicates); every cited id is a manifest file_id captured at or before that case's
  `audit_at`.
- Statuses: INCOMPLETE 354, COMPLETE 154, NOT_APPLICABLE 10. 2,652 steps, 1,021 with citations.
- Deterministic: two consecutive runs produce byte-identical files
  (sha256 `9abe05dbb0efa25087da93753d987ade31f2a80c494efb3caec8c20bbe954eb1`).
- An independent audit (development script) confirmed every emitted step's resource is linked to
  the subject by evidence available at `audit_at` and observed after `requested_at`
  (2,803 by subject identifier, 1 by explicit `source_resource_id`, 7 by non-conflicting catalog
  links) and that no step depends on timing or post-audit evidence.

## 3. Custom evaluation cases

These were written by us as synthetic fixtures (no real or organizer data) and run in
`code/tests/` (`python -m pytest code/tests` → **111 passed**). The end-to-end cases build a
complete mini-dataset (identities, audit log, rules, requests, activity, SQL/JSON/log/text
evidence) and run the real engine.

| # | Case (fixture) | What it checks | Expected result | Outcome |
|---|---|---|---|---|
| 1 | `case_1` — request with an old email in different case | historical identity; failover replica still holds the profile while the primary listing is empty; tombstone with email left; connector selected by the old email still enabled; restorable backup; retained audit record; support message keeping only `user_id`; post-audit `NOT_FOUND` claim; look-alike email of another user | INCOMPLETE, 14 steps in exact order (restore/flow stopped before record changes) | pass |
| 2 | `case_2` | profile 404 and retained audit record from a trace-joined log; a pre-request search sighting must be ignored | COMPLETE with 2 cited verifications | pass |
| 3 | `case_3` | "send me a copy … do not delete anything" | NOT_APPLICABLE, `[]` | pass |
| 4 | `case_4` | an account deleted by the workflow just before the report, with no identity link | COMPLETE `[]`, flagged as unverified (timing alone never attributes) | pass |
| 5 | `case_5` | `source_resource_id` reference; catalog link to a blocked backup; decoys: another person's search entry, catalog link contradicted by the record, catalog link after audit, catalog link before request | INCOMPLETE; only grounded resources appear | pass |
| 6 | `case_6` | catalog aliases (`export_6 (NST-6)`, `object_6 (receipt_6.pdf)`, `tombstone_6 (user_6)`); near-miss tokens `NST-60`, `receipt_60.pdf`; alias listed only after audit | INCOMPLETE; export flagged from the statement, no state claimed from decoys | pass |
| 7 | `case_7` | tombstone alias whose line still shows the email despite a "Retained reference" label; alias found only in another person's document | INCOMPLETE: exposed tombstone; conflicting export not used | pass |
| 8 | `case_8` | backup holding the subject's email with no block; explicitly blocked backup; identity-free catalog-linked backup | INCOMPLETE: one restore risk; the others verification only | pass |
| 9 | intent cases (20 texts) | deletion in EN/ES/PT/FR/JA/KO and non-deletion (export, correction, marketing opt-out, login help, negated deletion) | correct classification | pass |
| 10 | planner contract cases | ordering, duplicate merge, evidence rules, rejection of invalid operations/states/sequences | as specified | pass |

The suite also contains format tests (SQL replicas and coverage, recursive JSON, six log layouts with
trace joins and malformed lines, PDF, text, OCR row grouping), identity tests (changed/reused
identifiers, missing history, unrelated users) and loader tests (missing files, malformed rows,
duplicate ids, timestamps).

## 4. Failures found and improvements made

Sample metrics at each milestone (status / precision / recall / F1 / sequence):

| Step | Change | Result |
|---|---|---|
| First engine | evidence-linked discovery, latest-state assessment, rules from `deletion_rules.csv` | 0.875 / 0.852 / 0.746 / 0.796 / 0.406 |
| Fixes from failure analysis | redaction keeps the stable `user_id` (support messages were wrongly reported as exposed); a snapshot listing never overrides a positive sighting in another location (failover-replica drift was hidden); support tickets vs attachments; discovery only from evidence after the request (old decoy lookups) | 1.000 / 1.000 / 0.870 / 0.931 / 0.469 |
| Correctness review | **removed** an account-attribution heuristic that used activity timing near `reported_at` — it inferred ownership from timing alone | 1.000 / 1.000 / 0.819 / 0.900 / 0.281 |
| Grounded links | explicit `source_resource_id` references; data-catalog identity links (within request–audit window, rejected on ownership conflict); explicit status words on screenshots | 1.000 / 1.000 / 0.824 / 0.903 / 0.312 |
| Eval-only fixes | catalog aliases resolved to exact evidence tokens with per-file conflict rejection; `decision=deny` and `available=true/false` states; date-in-filename resource-id false positive; visible identifiers outrank status labels | samples unchanged; 6 eval verdicts corrected |
| Final review | an identifiable backup with no restore block is a restore risk (rule_14 + §6.5) instead of an unproven COMPLETE | samples unchanged; 1 eval verdict corrected |

Other defects caught by tests during development: integrity-seal digests read as email hashes;
resource ids with trailing letters (`search_12x`); pipe-row raw text hiding lookup subjects; empty but
valid SQL listings reported as errors; Windows CRLF handling in fixtures.

## 5. Remaining failures (34 missing sample steps)

Every missing step was traced through raw files, OCR text and PDF text. None can be grounded in
evidence available at `audit_at` without breaking the rules, so they are left unresolved:

| Missing steps | Root cause |
|---|---|
| 16 | the resource appears in no participant evidence except `system_activity` (13) or nowhere (3); attributing it would need timing alone |
| 10 | the record is in pre-audit evidence but holds no subject identifier (404 profile lookups without a lookup key; anonymized analytics records with all identifiers null) |
| 8 | the subject link exists only in files captured after `audit_at` (`evidence_02`, `evidence_06`) |

## 6. Known limitations

- Four eval cases (case_63, case_517, case_519, case_521) are COMPLETE with `[]` because no
  evidence available at `audit_at` mentions the subject (case_63's only link is a catalog entry
  contradicted by the record). The contract has no "unresolved" status: NOT_APPLICABLE would
  contradict an authorized deletion and INCOMPLETE requires evidence-backed findings, so this is
  the only valid row. `python code/main.py` lists such cases on stderr.
- Intent classification is rule-based (English, Spanish, Portuguese, French, Japanese, Korean
  deletion vocabulary plus explicit non-deletion cues). Unseen phrasings could be misread.
- Record categories (e.g. support message vs attachment) and screenshot states use field names and
  explicit status words; a screen that shows no status yields no state claim.
- Reproducing `output.csv` requires the OCR engine (see `README.md`); without it 10 eval cases differ.
