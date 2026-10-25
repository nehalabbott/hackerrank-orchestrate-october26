"""Validate a predictions file against the submission contract.

    python code/validate_output.py [output.csv] [--requests sample]

Checks: exact header; one row per request, no extras, sorted by case_id;
steps_json parses and satisfies planner.validate_steps for its status; every
cited evidence_id is a participant-visible file_id, activity_id or audit_id
whose capture time is at or before that case's audit_at.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from data_loader import DEFAULT_DATASET_DIR, REPO_ROOT, load_dataset  # noqa: E402
from identity import _natural_key  # noqa: E402
from planner import OUTPUT_HEADER, PlanError, validate_steps  # noqa: E402


def validate(path: Path, dataset_dir: Path = DEFAULT_DATASET_DIR, table: str = "requests") -> list[str]:
    dataset = load_dataset(dataset_dir, names=(table, "evidence", "activity", "audit_log"))
    requests = dataset[table].by_id()
    cited_times = {r["file_id"]: r["captured_at"] for r in dataset["evidence"].rows}
    cited_times.update({r["activity_id"]: r["event_time"] for r in dataset["activity"].rows})
    cited_times.update({r["audit_id"]: r["event_time"] for r in dataset["audit_log"].rows})

    errors: list[str] = []
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader, None)
        if header != list(OUTPUT_HEADER):
            errors.append(f"header {header} != {list(OUTPUT_HEADER)}")
        rows = list(reader)

    case_ids = [row[0] for row in rows if row]
    if case_ids != sorted(case_ids, key=_natural_key):
        errors.append("rows are not sorted by case_id")
    if len(case_ids) != len(set(case_ids)):
        errors.append("duplicate case_id rows")
    missing, extra = set(requests) - set(case_ids), set(case_ids) - set(requests)
    if missing:
        errors.append(f"{len(missing)} requests have no row, e.g. {sorted(missing)[:3]}")
    if extra:
        errors.append(f"{len(extra)} rows are not requests, e.g. {sorted(extra)[:3]}")

    for row in rows:
        if len(row) != 3:
            errors.append(f"row {row[:1]} has {len(row)} fields")
            continue
        case_id, status, steps_json = row
        try:
            steps = json.loads(steps_json)
            if not isinstance(steps, list):
                raise PlanError("steps_json is not an array")
            validate_steps(status, steps)
        except (json.JSONDecodeError, PlanError, KeyError, TypeError) as exc:
            errors.append(f"{case_id}: {exc}")
            continue
        audit_at = requests[case_id]["audit_at"] if case_id in requests else None
        for step in steps:
            evidence_id = step["evidence_id"]
            if not evidence_id:
                continue
            if evidence_id not in cited_times:
                errors.append(f"{case_id} step {step['step_no']}: unknown evidence {evidence_id}")
            elif audit_at and cited_times[evidence_id] > audit_at:
                errors.append(f"{case_id} step {step['step_no']}: {evidence_id} captured after audit_at")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", nargs="?", type=Path, default=REPO_ROOT / "output.csv")
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_DIR)
    parser.add_argument("--requests", choices=("eval", "sample"), default="eval")
    args = parser.parse_args(argv)
    table = "sample_requests" if args.requests == "sample" else "requests"
    errors = validate(args.path, args.dataset, table)
    for error in errors:
        print(error)
    print(f"{args.path}: {'OK' if not errors else f'{len(errors)} problems'}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
