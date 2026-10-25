from datetime import datetime, timezone

import pytest

from data_loader import (
    DEFAULT_DATASET_DIR,
    SPECS,
    DatasetError,
    format_timestamp,
    load_dataset,
    load_table,
    parse_timestamp,
)

REQUEST_HEADER = "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n"
GOOD_REQUEST = ("case_1,a@example.com,2026-01-01T00:00:00Z,COMPLETE,"
                "2026-01-02T00:00:00Z,2026-01-03T00:00:00Z,Please delete my account\n")


def write(tmp_path, filename, text):
    (tmp_path / filename).write_text(text, encoding="utf-8", newline="")


def kinds(table):
    return [issue.kind for issue in table.issues]


def test_parse_timestamp_normalizes_to_utc():
    assert parse_timestamp("2026-07-16T08:00:00Z") == datetime(2026, 7, 16, 8, tzinfo=timezone.utc)
    assert parse_timestamp("2026-07-16T10:00:00+02:00") == datetime(2026, 7, 16, 8, tzinfo=timezone.utc)
    assert format_timestamp(parse_timestamp("2026-07-16T10:00:00+02:00")) == "2026-07-16T08:00:00Z"


@pytest.mark.parametrize("value", ["", "2026-07-16", "2026-07-16T08:00:00", "yesterday"])
def test_parse_timestamp_rejects_naive_or_garbage(value):
    with pytest.raises(ValueError):
        parse_timestamp(value)


def test_missing_file_raises(tmp_path):
    with pytest.raises(DatasetError, match="missing file"):
        load_table(SPECS["requests"], tmp_path)


def test_empty_file_raises(tmp_path):
    write(tmp_path, "deletion_requests.csv", "")
    with pytest.raises(DatasetError, match="empty"):
        load_table(SPECS["requests"], tmp_path)


def test_missing_required_column_raises(tmp_path):
    write(tmp_path, "deletion_requests.csv", "case_id,email\ncase_1,a@example.com\n")
    with pytest.raises(DatasetError, match="audit_at"):
        load_table(SPECS["requests"], tmp_path)


def test_duplicate_column_raises(tmp_path):
    write(tmp_path, "deletion_rules.csv",
          "rule_id,data_category,condition,required_action,rule_id\n")
    with pytest.raises(DatasetError, match="duplicate columns"):
        load_table(SPECS["rules"], tmp_path)


def test_bom_header_and_quoted_multiline_text_are_accepted(tmp_path):
    body = ('﻿' + REQUEST_HEADER +
            'case_1,a@example.com,2026-01-01T00:00:00Z,COMPLETE,2026-01-02T00:00:00Z,'
            '2026-01-03T00:00:00Z,"Bitte löschen,\nmein Konto"\n')
    write(tmp_path, "deletion_requests.csv", body)
    table = load_table(SPECS["requests"], tmp_path)
    assert table.issues == []
    assert table.rows[0]["request_text"] == "Bitte löschen,\nmein Konto"
    assert table.rows[0]["audit_at"] == datetime(2026, 1, 3, tzinfo=timezone.utc)


def test_malformed_rows_are_skipped_and_reported(tmp_path):
    body = (REQUEST_HEADER + GOOD_REQUEST
            + "case_2,b@example.com,2026-01-01T00:00:00Z\n"                    # too few fields
            + GOOD_REQUEST.replace("case_1", "case_3").rstrip("\n") + ",extra\n"  # too many
            + GOOD_REQUEST.replace("case_1", "case_4").replace("2026-01-03T00:00:00Z", "not-a-date")
            + GOOD_REQUEST.replace("case_1", "case_5").replace("COMPLETE", "DONE")
            + GOOD_REQUEST.replace("case_1", " ")
            + "\n")                                                               # blank line ignored
    write(tmp_path, "deletion_requests.csv", body)
    table = load_table(SPECS["requests"], tmp_path)
    assert [row["case_id"] for row in table.rows] == ["case_1"]
    assert kinds(table) == ["field_count", "field_count", "bad_timestamp", "bad_enum", "missing_id"]
    assert [issue.line for issue in table.issues] == [3, 4, 5, 6, 7]


def test_duplicate_ids_keep_first_row(tmp_path):
    write(tmp_path, "deletion_requests.csv",
          REQUEST_HEADER + GOOD_REQUEST + GOOD_REQUEST.replace("a@example.com", "b@example.com"))
    table = load_table(SPECS["requests"], tmp_path)
    assert [row["email"] for row in table.rows] == ["a@example.com"]
    assert kinds(table) == ["duplicate_id"]
    assert "first seen on line 2" in table.issues[0].detail


def test_invalid_steps_json_is_reported(tmp_path):
    write(tmp_path, "sample_output.csv",
          'case_id,deletion_status,steps_json\ncase_1,NOT_APPLICABLE,[]\ncase_2,COMPLETE,"[{bad"\n')
    table = load_table(SPECS["sample_output"], tmp_path)
    assert table.rows[0]["steps_json"] == []
    assert kinds(table) == ["bad_json"]


def test_cross_table_reference_checks(tmp_path):
    write(tmp_path, "user_identities.csv",
          "user_id,name,email,phone,email_hash,updated_at\n"
          "user_1,A,a@example.com,+1,h,2026-01-01T00:00:00Z\n")
    write(tmp_path, "user_audit_log.csv",
          "audit_id,user_id,event_time,field_name,old_value,new_value\n"
          "audit_1,user_1,2026-01-01T00:00:00Z,email,old@example.com,a@example.com\n"
          "audit_2,user_9,2026-01-01T00:00:00Z,phone,+1,+2\n")
    (tmp_path / "evidence" / "logs").mkdir(parents=True)
    (tmp_path / "evidence" / "logs" / "listed.log").write_text("x")
    (tmp_path / "evidence" / "logs" / "stray.log").write_text("x")
    write(tmp_path, "evidence_files.csv",
          "file_id,file_path,origin,captured_at\n"
          "evidence_01,evidence/logs/listed.log,ops,2026-01-01T00:00:00Z\n"
          "evidence_02,evidence/logs/gone.log,ops,2026-01-01T00:00:00Z\n")
    dataset = load_dataset(tmp_path, names=("identities", "audit_log", "evidence"))
    found = sorted((issue.kind, issue.detail) for issue in dataset.issues)
    assert found == [
        ("missing_evidence_file", "evidence_02 -> evidence/logs/gone.log"),
        ("unknown_user_id", "audit_2 references user_9"),
        ("unlisted_evidence_file", "evidence/logs/stray.log"),
    ]


@pytest.mark.skipif(not (DEFAULT_DATASET_DIR / "deletion_requests.csv").is_file(),
                    reason="participant dataset not present")
def test_real_dataset_loads_cleanly():
    dataset = load_dataset()
    assert [str(issue) for issue in dataset.issues] == []
    counts = {name: len(table.rows) for name, table in dataset.tables.items()}
    assert counts == {
        "requests": 518, "sample_requests": 32, "sample_output": 32,
        "identities": 850, "audit_log": 306, "activity": 4011,
        "rules": 15, "evidence": 94, "output_template": 0,
    }
