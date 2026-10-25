"""Load and validate the participant-facing CSV files under dataset/.

Fatal problems (missing file, missing required columns) raise DatasetError.
Row-level problems (wrong field count, blank or duplicate IDs, unparseable
timestamps, unknown enum values, invalid JSON) are collected as Issue
records; the offending row is skipped and loading continues.

Run directly to print a validation report:

    python code/data_loader.py [dataset_dir]
"""

from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATASET_DIR = REPO_ROOT / "dataset"


class DatasetError(Exception):
    """A problem that prevents a table from being loaded at all."""


@dataclass(frozen=True)
class TableSpec:
    name: str
    filename: str
    columns: tuple[str, ...]
    id_column: str | None = None
    timestamp_columns: tuple[str, ...] = ()
    enums: dict[str, frozenset[str]] = field(default_factory=dict)
    json_columns: tuple[str, ...] = ()


@dataclass(frozen=True)
class Issue:
    table: str
    line: int  # 1-based physical line of the row in the CSV (header is line 1)
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"{self.table}:{self.line} [{self.kind}] {self.detail}"


@dataclass
class Table:
    spec: TableSpec
    rows: list[dict]
    issues: list[Issue]

    def by_id(self) -> dict[str, dict]:
        if self.spec.id_column is None:
            raise TypeError(f"{self.spec.name} has no id column")
        return {row[self.spec.id_column]: row for row in self.rows}


REQUEST_COLUMNS = (
    "case_id", "email", "requested_at", "reported_status",
    "reported_at", "audit_at", "request_text",
)
REQUEST_TIMESTAMPS = ("requested_at", "reported_at", "audit_at")
REPORTED_STATUSES = frozenset({"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"})
DELETION_STATUSES = frozenset({"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})
OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")

SPECS: dict[str, TableSpec] = {
    spec.name: spec
    for spec in (
        TableSpec(
            "requests", "deletion_requests.csv", REQUEST_COLUMNS,
            id_column="case_id", timestamp_columns=REQUEST_TIMESTAMPS,
            enums={"reported_status": REPORTED_STATUSES},
        ),
        TableSpec(
            "sample_requests", "sample_deletion_requests.csv", REQUEST_COLUMNS,
            id_column="case_id", timestamp_columns=REQUEST_TIMESTAMPS,
            enums={"reported_status": REPORTED_STATUSES},
        ),
        TableSpec(
            "sample_output", "sample_output.csv", OUTPUT_COLUMNS,
            id_column="case_id",
            enums={"deletion_status": DELETION_STATUSES},
            json_columns=("steps_json",),
        ),
        TableSpec(
            "identities", "user_identities.csv",
            ("user_id", "name", "email", "phone", "email_hash", "updated_at"),
            id_column="user_id", timestamp_columns=("updated_at",),
        ),
        TableSpec(
            "audit_log", "user_audit_log.csv",
            ("audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"),
            id_column="audit_id", timestamp_columns=("event_time",),
            enums={"field_name": frozenset({"email", "email_hash", "phone", "name"})},
        ),
        TableSpec(
            "activity", "system_activity.csv",
            ("activity_id", "event_time", "event_type", "source_system",
             "target_system", "resource_id", "reported_result", "details"),
            id_column="activity_id", timestamp_columns=("event_time",),
            enums={"reported_result": frozenset({"SUCCESS", "FAILED", "PARTIAL"})},
        ),
        TableSpec(
            "rules", "deletion_rules.csv",
            ("rule_id", "data_category", "condition", "required_action"),
            id_column="rule_id",
            enums={"required_action": frozenset(
                {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"})},
        ),
        TableSpec(
            "evidence", "evidence_files.csv",
            ("file_id", "file_path", "origin", "captured_at"),
            id_column="file_id", timestamp_columns=("captured_at",),
        ),
        TableSpec("output_template", "output.csv", OUTPUT_COLUMNS),
    )
}


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into an aware UTC datetime.

    Offsets are required so that every comparison against audit_at is
    unambiguous; naive timestamps raise ValueError.
    """
    text = value.strip()
    if not text:
        raise ValueError("empty timestamp")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp has no UTC offset: {value!r}")
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_table(spec: TableSpec, dataset_dir: Path | str = DEFAULT_DATASET_DIR) -> Table:
    path = Path(dataset_dir) / spec.filename
    if not path.is_file():
        raise DatasetError(f"{spec.name}: missing file {path}")

    rows: list[dict] = []
    issues: list[Issue] = []
    seen_ids: dict[str, int] = {}

    # utf-8-sig tolerates a BOM from spreadsheet tools; newline="" keeps
    # quoted multi-line fields intact.
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            raise DatasetError(f"{spec.name}: {path} is empty") from None
        header = [col.strip() for col in header]
        missing = [col for col in spec.columns if col not in header]
        if missing:
            raise DatasetError(f"{spec.name}: missing required columns {missing}")
        duplicated = sorted({col for col in header if header.count(col) > 1})
        if duplicated:
            raise DatasetError(f"{spec.name}: duplicate columns {duplicated}")

        for values in reader:
            line = reader.line_num
            if not values or all(not v.strip() for v in values):
                continue
            if len(values) != len(header):
                issues.append(Issue(spec.name, line, "field_count",
                                    f"expected {len(header)} fields, got {len(values)}"))
                continue
            row = dict(zip(header, values))
            row_issues = _validate_row(spec, row, line)
            if row_issues:
                issues.extend(row_issues)
                continue
            if spec.id_column is not None:
                row_id = row[spec.id_column]
                if row_id in seen_ids:
                    issues.append(Issue(spec.name, line, "duplicate_id",
                                        f"{spec.id_column}={row_id} first seen on line {seen_ids[row_id]}"))
                    continue
                seen_ids[row_id] = line
            rows.append(row)

    return Table(spec, rows, issues)


def _validate_row(spec: TableSpec, row: dict, line: int) -> list[Issue]:
    issues: list[Issue] = []
    if spec.id_column is not None:
        row[spec.id_column] = row[spec.id_column].strip()
        if not row[spec.id_column]:
            issues.append(Issue(spec.name, line, "missing_id", f"blank {spec.id_column}"))
    for col in spec.timestamp_columns:
        try:
            row[col] = parse_timestamp(row[col])
        except ValueError as exc:
            issues.append(Issue(spec.name, line, "bad_timestamp", f"{col}: {exc}"))
    for col, allowed in spec.enums.items():
        if row[col] not in allowed:
            issues.append(Issue(spec.name, line, "bad_enum", f"{col}={row[col]!r}"))
    for col in spec.json_columns:
        try:
            row[col] = json.loads(row[col])
        except json.JSONDecodeError as exc:
            issues.append(Issue(spec.name, line, "bad_json", f"{col}: {exc}"))
    return issues


@dataclass
class Dataset:
    root: Path
    tables: dict[str, Table]
    issues: list[Issue]

    def __getitem__(self, name: str) -> Table:
        return self.tables[name]


def load_dataset(dataset_dir: Path | str = DEFAULT_DATASET_DIR,
                 names: tuple[str, ...] | None = None) -> Dataset:
    """Load every table (or the named subset) and run cross-table ID checks."""
    root = Path(dataset_dir)
    selected = names or tuple(SPECS)
    tables = {name: load_table(SPECS[name], root) for name in selected}
    issues = [issue for table in tables.values() for issue in table.issues]
    issues.extend(_check_references(root, tables))
    return Dataset(root, tables, issues)


def _check_references(root: Path, tables: dict[str, Table]) -> list[Issue]:
    issues: list[Issue] = []

    if "audit_log" in tables and "identities" in tables:
        users = tables["identities"].by_id()
        for row in tables["audit_log"].rows:
            if row["user_id"] not in users:
                issues.append(Issue("audit_log", 0, "unknown_user_id",
                                    f"{row['audit_id']} references {row['user_id']}"))

    if "sample_output" in tables and "sample_requests" in tables:
        requested = set(tables["sample_requests"].by_id())
        answered = set(tables["sample_output"].by_id())
        for case_id in sorted(requested - answered):
            issues.append(Issue("sample_output", 0, "missing_case", case_id))
        for case_id in sorted(answered - requested):
            issues.append(Issue("sample_output", 0, "unknown_case", case_id))

    if "requests" in tables and "sample_requests" in tables:
        overlap = set(tables["requests"].by_id()) & set(tables["sample_requests"].by_id())
        for case_id in sorted(overlap):
            issues.append(Issue("requests", 0, "case_id_in_samples", case_id))

    if "evidence" in tables:
        listed = set()
        for row in tables["evidence"].rows:
            rel = row["file_path"].replace("\\", "/")
            listed.add(rel)
            if not (root / rel).is_file():
                issues.append(Issue("evidence", 0, "missing_evidence_file",
                                    f"{row['file_id']} -> {rel}"))
        evidence_dir = root / "evidence"
        if evidence_dir.is_dir():
            for path in sorted(evidence_dir.rglob("*")):
                rel = path.relative_to(root).as_posix()
                if path.is_file() and rel not in listed:
                    issues.append(Issue("evidence", 0, "unlisted_evidence_file", rel))

    return issues


def summarize(dataset: Dataset) -> str:
    lines = [f"dataset: {dataset.root}"]
    for name, table in dataset.tables.items():
        lines.append(f"  {name:<16} {table.spec.filename:<32} rows={len(table.rows)}")
    lines.append(f"issues: {len(dataset.issues)}")
    lines.extend(f"  {issue}" for issue in dataset.issues)
    return "\n".join(lines)


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DATASET_DIR
    try:
        loaded = load_dataset(target)
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    print(summarize(loaded))
    sys.exit(1 if loaded.issues else 0)
