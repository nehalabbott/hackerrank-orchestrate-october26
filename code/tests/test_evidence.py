import json
from datetime import datetime, timezone

import pytest

import evidence
from data_loader import DEFAULT_DATASET_DIR, load_dataset
from evidence import (
    EvidenceFile,
    build_evidence_index,
    extract_json,
    extract_log,
    extract_pdf,
    extract_sql,
    extract_text,
    identifiers_in_text,
    identifiers_in_value,
    infer_state,
    ocr_rows,
    parse_log_line,
)
from ocr import OcrBox

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)


def ts(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def ef_for(tmp_path, name, content, captured="2026-09-30T00:00:00Z", file_id="evidence_01"):
    path = tmp_path / name
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8", newline="")
    return EvidenceFile(file_id, path, "test", ts(captured))


def by_resource(observations):
    out = {}
    for obs in observations:
        out.setdefault(obs.resource_id, []).append(obs)
    return out


# -- identifier extraction and decoys ----------------------------------------

def test_identifier_boundaries_reject_near_misses():
    found = identifiers_in_text("ref user_33, mail Nadia.Ionescu@Yahoo.com; tel +40 723-481 638")
    assert ("user", "user_33") in found and ("user", "user_3") not in found
    assert ("email", "nadia.ionescu@yahoo.com") in found
    assert ("phone", "+40723481638") in found
    assert ("email", "nadia.popescu@yahoo.com") not in identifiers_in_text("nadia.ionescu@yahoo.com")
    assert identifiers_in_text("account_8741 customer_user_9") == set()


def test_digests_are_not_email_hashes():
    seal = "sha256:" + "0" * 61 + "e99"
    assert identifiers_in_value({"integrity_seal": seal}) == set()
    assert identifiers_in_text(seal) == set()
    real = "a" * 64
    assert identifiers_in_value({"email_hash": real.upper()}) == {("email_hash", real)}


def test_resource_ids_tolerate_ocr_row_numbers_but_not_word_prefixes():
    assert evidence.resource_ids_in("4backup_9286 and search_12x") == ["backup_9286"]
    assert evidence.resource_ids_in("customer_export_7364.zip") == ["export_7364"]
    assert evidence.resource_ids_in("account_service account_1") == ["account_1"]
    # a date after the number is a file name, not a resource id
    assert evidence.resource_ids_in("customer_export_2026-02-10.zip export_77-") == ["export_77"]


@pytest.mark.parametrize("attrs,state", [
    ({"enabled": "1"}, "ACTIVE"),
    ({"enabled": False}, "DISABLED"),
    ({"restore_allowed": "0"}, "BLOCKED"),
    ({"result": "NOT_FOUND"}, "ABSENT"),
    ({"result": "IDENTIFIABLE"}, "PRESENT"),
    ({"http_status": "404", "rows": "0"}, "ABSENT"),
    ({"status_code": 200}, "PRESENT"),
    ({"hits": {"total": 0}}, "ABSENT"),
    ({"rows": "2"}, "PRESENT"),
    ({"note": "x"}, None),
    ({"event": "restore_authorization_completed", "decision": "deny"}, "BLOCKED"),
    ({"decision": "approved"}, "ACTIVE"),
    ({"decision": "pending"}, None),
    ({"event": "export_download_check_completed", "available": "true"}, "PRESENT"),
    ({"available": "false"}, "ABSENT"),
])
def test_infer_state(attrs, state):
    assert infer_state(attrs) == state


# -- SQL ---------------------------------------------------------------------

SQL = """-- Captured at: 2026-09-02T23:00:00Z
-- Database topology: failover_replica
BEGIN TRANSACTION;
CREATE TABLE customer_data_primary (resource_id TEXT PRIMARY KEY, origin_system TEXT NOT NULL,
  collection_name TEXT NOT NULL, record_json TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE customer_data_failover_replica (resource_id TEXT PRIMARY KEY, origin_system TEXT NOT NULL,
  collection_name TEXT NOT NULL, record_json TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE connector_subscriptions (resource_id TEXT PRIMARY KEY, customer_reference TEXT,
  customer_email TEXT, enabled INTEGER NOT NULL);
INSERT INTO customer_data_failover_replica VALUES ('account_5', 'account_service', 'customer_profiles',
  '{"resource_id":"account_5","customer_reference":"user_5","email":"a@x.com"}', '2026-09-02T22:00:00Z');
INSERT INTO connector_subscriptions VALUES ('data_flow_1', NULL, 'a@x.com', 1);
COMMIT;
"""


def test_sql_rows_replicas_and_coverage(tmp_path):
    obs, cov = extract_sql(ef_for(tmp_path, "db.sql", SQL))
    rows = by_resource(obs)
    replica = rows["account_5"][0]
    assert replica.location == "customer_data_failover_replica/customer_profiles"
    assert replica.system_id == "account_service" and replica.state == "PRESENT"
    assert replica.observed_at == ts("2026-09-02T23:00:00Z")
    assert {("user", "user_5"), ("email", "a@x.com")} <= replica.identifiers
    assert replica.attributes["topology"] == "failover_replica"
    assert rows["data_flow_1"][0].state == "ACTIVE"
    listed = {c.location: c.resource_ids for c in cov}
    assert listed["customer_data_failover_replica"] == {"account_5"}
    assert listed["connector_subscriptions"] == {"data_flow_1"}


def test_sql_empty_scoped_table_still_yields_coverage(tmp_path):
    script = ("CREATE TABLE snapshot_scope (origin_system TEXT, captured_at TEXT);"
              "CREATE TABLE customer_profiles (resource_id TEXT PRIMARY KEY, email TEXT);"
              "CREATE TABLE support_records (resource_id TEXT PRIMARY KEY);"
              "INSERT INTO snapshot_scope VALUES ('account_service', '2026-09-05T07:18:01Z');")
    obs, cov = extract_sql(ef_for(tmp_path, "inv.sql", script))
    assert obs == []
    assert [(c.location, c.system_id, c.resource_ids) for c in cov] == [
        ("customer_profiles", "account_service", frozenset())]


# -- JSON --------------------------------------------------------------------

def test_json_recursive_records_lookups_and_claims(tmp_path):
    data = {
        "exported_at": "2026-09-17T12:00:00Z",
        "snapshots": [{"captured_at": "2026-09-15T12:00:00Z", "data_store": "support_platform",
                       "collection": "support_conversations",
                       "records": [{"resource_id": "support_9", "subject_reference": "user_2",
                                    "message_text": "Send it to b@y.org please"}]}],
        "service_exports": {"search_service": {"index_queries": [
            {"observed_at": "2026-09-16T08:00:00Z", "query": "b@y.org", "resource_id": "search_4",
             "hits": {"total": 1, "documents": [{"resource_id": "search_4", "email": "b@y.org"}]}},
            {"observed_at": "2026-09-16T09:00:00Z", "query": "c@y.org", "resource_id": "search_5",
             "hits": {"total": 0, "documents": []}}]},
            "account_service": {"profile_lookups": [
                {"observed_at": "2026-09-16T10:00:00Z", "profile": None, "resource_id": "account_7",
                 "status_code": 404}]}},
        "records": [{"recorded_at": "2026-09-10T00:00:00Z", "system": "export_service",
                     "resource_id": "export_3", "record_type": "USER_EXPORT", "result": "FOUND",
                     "subject_reference": "B@Y.ORG"}],
    }
    obs, cov = extract_json(ef_for(tmp_path, "bundle.json", json.dumps(data)))
    rows = by_resource(obs)
    support = rows["support_9"][0]
    assert support.kind == "record" and support.state == "PRESENT"
    assert support.observed_at == ts("2026-09-15T12:00:00Z")
    assert {("user", "user_2"), ("email", "b@y.org")} <= support.identifiers
    query, document = sorted(rows["search_4"], key=lambda o: o.location)
    assert query.kind == "lookup" and query.state == "PRESENT"
    assert query.context_identifiers == {("email", "b@y.org")} and not query.identifiers
    assert document.identifiers == {("email", "b@y.org")}
    assert rows["search_5"][0].state == "ABSENT"
    assert rows["account_7"][0].state == "ABSENT"
    claim = rows["export_3"][0]
    assert claim.kind == "claim" and claim.state == "PRESENT"
    assert claim.context_identifiers == {("email", "b@y.org")} and not claim.identifiers
    assert [(c.location, c.resource_ids) for c in cov] == [
        ("support_platform/support_conversations", frozenset({"support_9"}))]


def test_json_record_time_never_exceeds_file_capture(tmp_path):
    data = {"records": [{"resource_id": "account_1", "observed_at": "2026-12-01T00:00:00Z"}]}
    obs, _ = extract_json(ef_for(tmp_path, "r.json", json.dumps(data),
                                 captured="2026-09-01T00:00:00Z"))
    assert obs[0].observed_at == T0


# -- logs --------------------------------------------------------------------

LOG = "\n".join([
    '2026-09-15T08:51:45Z level=DEBUG service=search_service trace_id=tr-1 event=index_query_started match_key="g.silva76.jr@gmail.com"',
    '2026-09-15T08:51:57Z level=INFO service=search_service trace_id=tr-1 resource_id=search_1874 event=index_query_completed result=hit',
    '2026-07-28T05:51:21Z [INFO] [account_service] [tr-2] profile_lookup_completed: resource_id="account_7947" rows="0" http_status="404" correlation_key="l.n@gmail.com"',
    '2026-07-03T07:51:59Z | INFO | analytics_platform | tr-3 | analytics_profile_read | resource_id="analytics_257" email="null" phone="null"',
    '2026-03-25T08:51:23Z <12>1 node-1 support_platform tr-4 - - level=WARN resource_id="support_9464" event="message_pii_scan" matched_value="silva.mariana@icloud.com"',
    '2026-04-19T06:51:21Z {"severity":"INFO","service":"search_service","trace_id":"tr-5","resource_id":"search_9365","event":"index_query_completed","result":"hit"}',
    '2026-09-30T11:51:03Z requestId=tr-6 level=DEBUG function=profile_service message="resource_id=\\"account_66777\\" event=\\"profile_lookup_completed\\" http_status=\\"200\\" correlation_key=\\"a.w@yahoo.com\\""',
    '2026-09-17T22:00:05Z level=INFO trace_id=tr-7 event=contact_query_started lookup_key=decoy@yahoo.com',
    '2026-09-17T22:00:06Z level=INFO trace_id=tr-7 event=contact_query_completed resource_id=support_1',
    '2026-09-17T22:00:07Z level=INFO trace_id=tr-7 event=contact_query_completed resource_id=support_2',
    'garbage line without timestamp resource_id=account_999',
    '2026-13-45T99:00:00Z level=INFO resource_id=account_998',
])


def test_log_formats_trace_join_and_malformed_lines(tmp_path):
    obs, _ = extract_log(ef_for(tmp_path, "svc.log", LOG + "\n"))
    rows = by_resource(obs)
    assert "account_999" not in rows and "account_998" not in rows
    search = rows["search_1874"][0]
    assert search.state == "PRESENT" and search.location == "line 2"
    assert search.context_identifiers == {("email", "g.silva76.jr@gmail.com")}
    account = rows["account_7947"][0]
    assert account.state == "ABSENT" and account.attributes["service"] == "account_service"
    assert account.context_identifiers == {("email", "l.n@gmail.com")}
    assert rows["analytics_257"][0].identifiers == frozenset()
    pii = rows["support_9464"][0]
    assert pii.identifiers == {("email", "silva.mariana@icloud.com")}
    assert pii.attributes["service"] == "support_platform"
    assert rows["search_9365"][0].state == "PRESENT"
    nested = rows["account_66777"][0]
    assert nested.state == "PRESENT" and nested.attributes["service"] == "profile_service"
    assert nested.context_identifiers == {("email", "a.w@yahoo.com")}
    # tr-7 touches two resources, so its lookup key must not be attached to either.
    assert not rows["support_1"][0].all_identifiers and not rows["support_2"][0].all_identifiers


def test_parse_log_line_rejects_bad_timestamp():
    assert parse_log_line("2026-02-30T00:00:00Z level=INFO resource_id=account_1", 1) is None
    assert parse_log_line("not a log line", 1) is None


# -- documents ---------------------------------------------------------------

def test_text_pipe_rows_become_claims(tmp_path):
    text = ("SHIFT HANDOVER\nSnapshot: 2026-10-01T12:00:00Z\n"
            "- 2026-10-01T12:00:00Z | account_service | account_146 | USER_PROFILE | NOT_FOUND | E.L@yahoo.com\n"
            "- 2026-10-01T12:00:00Z | backup_service | backup_706 | BACKUP_ARCHIVE | BLOCKED | user_39\n")
    obs, _ = extract_text(ef_for(tmp_path, "handover.txt", text, captured="2026-10-01T12:00:00Z"))
    rows = by_resource(obs)
    account = rows["account_146"][0]
    assert (account.kind, account.state, account.system_id) == ("claim", "ABSENT", "account_service")
    assert account.context_identifiers == {("email", "e.l@yahoo.com")}
    assert rows["backup_706"][0].state == "BLOCKED"


def test_pdf_text_links_single_resource_document(tmp_path):
    pymupdf = pytest.importorskip("pymupdf")
    path = tmp_path / "extract.pdf"
    doc = pymupdf.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Event reference audit_record_003")
    page.insert_text((72, 96), "subject reference user_03")
    page.insert_text((72, 120), "ORD-1 | user_08 | Card dispute | Retain until 04 May 2033")
    doc.save(path)
    doc.close()
    obs, _ = extract_pdf(EvidenceFile("evidence_07", path, "test", T0))
    doc_level = [o for o in obs if o.location == "document"]
    assert doc_level[0].resource_id == "audit_record_003"
    assert ("user", "user_03") in doc_level[0].identifiers
    row = [o for o in obs if "ORD-1" in o.attributes.get("raw_row", "")][0]
    assert row.resource_id is None and ("user", "user_08") in row.all_identifiers
    # resource-less lines are kept (unlinked) so explicit aliases can be resolved later
    line = [o for o in obs if o.attributes.get("text") == "subject reference user_03"][0]
    assert line.resource_id is None and line.location.startswith("page 1 line")
    assert all(o.evidence_id == "evidence_07" and o.observed_at == T0 for o in obs)


def test_ocr_rows_link_identifiers_to_resource_on_same_row(tmp_path, monkeypatch):
    boxes = [
        OcrBox("backup_9291", 257, 405, 340, 425, 0.9),
        OcrBox("bluepeakco@outlook.com", 452, 404, 600, 424, 0.9),
        OcrBox("2 backup_9288", 257, 447, 345, 467, 0.9),
        OcrBox("miller.logistics@company.com", 451, 445, 640, 465, 0.9),
    ]
    assert [[b.text for b in row] for row in ocr_rows(boxes)] == [
        ["backup_9291", "bluepeakco@outlook.com"], ["2 backup_9288", "miller.logistics@company.com"]]
    monkeypatch.setattr("ocr.ocr_image", lambda path, cache_dir=None: boxes)
    obs, _ = evidence.extract_image(ef_for(tmp_path, "console.png", b"png"))
    rows = by_resource(obs)
    assert rows["backup_9291"][0].identifiers == {("email", "bluepeakco@outlook.com")}
    assert rows["backup_9288"][0].identifiers == {("email", "miller.logistics@company.com")}


@pytest.mark.parametrize("resource_id,text,state", [
    ("data_flow_1121", "data_flow_1121 | warehouse | a@x.com | Continuous | 1,284 | 07:59", "ACTIVE"),
    ("data_flow_2", "data_flow_2 | warehouse | Paused", "DISABLED"),
    ("data_flow_3", "data_flow_3 | Active | Paused", None),          # contradictory -> unknown
    ("data_flow_4", "data_flow_4 | warehouse | 07:59", None),         # no status word
    ("backup_9287", "backup_9287 | a@x.com | eu-west-1 | AES-256 | Archive", None),
    ("backup_7", "backup_7 | a@x.com | Restore blocked", "BLOCKED"),
    ("search_1", "search_1 | Continuous", None),                      # not a flow
    ("tombstone_17", "user_17 Retained reference Customer key", "REDACTED"),
    ("tombstone_18", "user_18 Customer key", None),
    (None, "Continuous", None),
])
def test_screen_row_state_uses_explicit_status_words_only(resource_id, text, state):
    assert evidence.screen_row_state(resource_id, text) == state


def test_image_rows_carry_screen_state(tmp_path, monkeypatch):
    boxes = [OcrBox("data_flow_1121", 257, 405, 340, 425, 0.9),
             OcrBox("jain.aditi@gmail.com", 452, 404, 600, 424, 0.9),
             OcrBox("Continuous", 700, 404, 780, 424, 0.9)]
    monkeypatch.setattr("ocr.ocr_image", lambda path, cache_dir=None: boxes)
    obs, _ = evidence.extract_image(ef_for(tmp_path, "connectors.png", b"png"))
    row = [o for o in obs if o.location.startswith("row")][0]
    assert (row.resource_id, row.state) == ("data_flow_1121", "ACTIVE")


# -- index -------------------------------------------------------------------

def make_dataset(tmp_path, files):
    (tmp_path / "evidence").mkdir()
    lines = ["file_id,file_path,origin,captured_at"]
    for file_id, name, captured, content in files:
        (tmp_path / "evidence" / name).write_text(content, encoding="utf-8", newline="")
        lines.append(f"{file_id},evidence/{name},test,{captured}")
    (tmp_path / "evidence_files.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return load_dataset(tmp_path, names=("evidence",))


def test_index_audit_time_filtering_decoys_and_malformed_files(tmp_path, monkeypatch):
    early = {"records": [{"resource_id": "account_1", "email": "ana@x.com", "observed_at": "2026-08-01T00:00:00Z"}]}
    late = {"records": [{"resource_id": "account_1", "result": "NOT_FOUND", "record_type": "USER_PROFILE",
                         "subject_reference": "ana@x.com", "recorded_at": "2026-09-20T00:00:00Z"}]}
    decoy = {"records": [{"resource_id": "account_2", "email": "ana.x@x.com"}]}
    dataset = make_dataset(tmp_path, [
        ("evidence_01", "early.json", "2026-08-02T00:00:00Z", json.dumps(early)),
        ("evidence_02", "late.json", "2026-09-21T00:00:00Z", json.dumps(late)),
        ("evidence_03", "decoy.json", "2026-08-02T00:00:00Z", json.dumps(decoy)),
        ("evidence_04", "broken.json", "2026-08-02T00:00:00Z", "{not json"),
        ("evidence_05", "shot.png", "2026-08-02T00:00:00Z", "png"),
    ])

    def no_engine(path, cache_dir=None):
        raise RuntimeError("rapidocr_onnxruntime is required")
    monkeypatch.setattr("ocr.ocr_image", no_engine)

    index = build_evidence_index(dataset, include_activity=False)
    assert index.issues == ["evidence_04: JSONDecodeError: Expecting property name enclosed in "
                            "double quotes: line 1 column 2 (char 1)"]
    assert index.unsupported == ["evidence_05: rapidocr_onnxruntime is required"]
    keys = {("email", "ana@x.com")}
    assert index.resources_for(keys) == {"account_1"}
    assert [o.evidence_id for o in index.matching(keys, ts("2026-09-01T00:00:00Z"))] == ["evidence_01"]
    assert index.latest("account_1", ts("2026-09-01T00:00:00Z")).state == "PRESENT"
    assert index.latest("account_1").state == "ABSENT"
    assert index.matching({("name", "ana")}) == []


@pytest.mark.skipif(not (DEFAULT_DATASET_DIR / "evidence_files.csv").is_file(),
                    reason="participant dataset not present")
def test_real_corpus_builds_without_errors(monkeypatch):
    def no_engine(path, cache_dir=None):
        raise RuntimeError("OCR disabled for this test")
    monkeypatch.setattr("ocr.ocr_image", no_engine)
    dataset = load_dataset(names=("evidence", "activity"))
    index = build_evidence_index(dataset)
    assert index.issues == []
    assert all(entry.endswith("OCR disabled for this test") for entry in index.unsupported)
    assert len(index.unsupported) == sum(r["file_path"].endswith(".png")
                                         for r in dataset["evidence"].rows)
    assert all(o.observed_at <= o.captured_at for o in index.observations)
    assert all(o.system_id for o in index.observations if o.resource_id)
