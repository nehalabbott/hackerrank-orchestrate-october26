import json

import pytest

from data_loader import DEFAULT_DATASET_DIR, load_dataset
from engine import DeletionEngine
from planner import validate_steps

H_OLD, H_NEW, H_OTHER = "a" * 64, "b" * 64, "c" * 64

IDENTITIES = f"""user_id,name,email,phone,email_hash,updated_at
user_1,Ana Silva,ana@x.com,+1 555 0101,{H_NEW},2026-05-01T00:00:00Z
user_2,Ana Xu,ana.x@x.com,+1 555 0202,{H_OTHER},2026-05-01T00:00:00Z
user_3,Ben Ode,ben@x.com,+1 555 0303,{"d" * 64},2026-05-01T00:00:00Z
user_4,Cy Lam,cy@x.com,+1 555 0404,{"e" * 64},2026-05-01T00:00:00Z
user_5,Dee Roe,dee@x.com,+1 555 0505,{"f" * 64},2026-05-01T00:00:00Z
user_6,Eve Ito,eve@x.com,+1 555 0606,{"9" * 64},2026-05-01T00:00:00Z
user_7,Fay Oh,fay@x.com,+1 555 0707,{"8" * 64},2026-05-01T00:00:00Z
user_8,Gil Abe,gil@x.com,+1 555 0808,{"7" * 64},2026-05-01T00:00:00Z
"""
AUDIT = f"""audit_id,user_id,event_time,field_name,old_value,new_value
audit_1,user_1,2026-03-01T00:00:00Z,email,ana.old@x.com,ana@x.com
audit_2,user_1,2026-03-01T00:00:00Z,email_hash,{H_OLD},{H_NEW}
"""
RULES = """rule_id,data_category,condition,required_action
rule_01,USER_PROFILE,Always,DELETE
rule_05,SUPPORT_MESSAGE,Shared context,REDACT
rule_07,ANALYTICS_PROFILE,Attributable,ANONYMIZE
rule_12,SECURITY_AUDIT_LOG,Within retention,RETAIN
rule_14,BACKUP_ARCHIVE,Restore access can be blocked,RETAIN
rule_15,ACCOUNT_TOMBSTONE,Stable user_id only,REDACT
"""
REQUESTS = """case_id,email,requested_at,reported_status,reported_at,audit_at,request_text
case_1,ANA.OLD@x.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-02T12:00:00Z,2026-09-10T00:00:00Z,Please delete my account.
case_2,ben@x.com,2026-09-01T00:00:00Z,NOT_STARTED,2026-09-03T12:00:00Z,2026-09-10T00:00:00Z,Please erase my account and personal data.
case_3,ana@x.com,2026-09-01T00:00:00Z,NOT_STARTED,2026-09-03T12:00:00Z,2026-09-10T00:00:00Z,Please send me a copy of my data. Do not delete anything.
case_4,cy@x.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-04T12:00:00Z,2026-09-10T00:00:00Z,I want my account permanently deleted.
case_5,dee@x.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-02T12:00:00Z,2026-09-10T00:00:00Z,Please delete my account.
case_6,eve@x.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-02T12:00:00Z,2026-09-10T00:00:00Z,Please delete my account.
case_7,fay@x.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-02T12:00:00Z,2026-09-10T00:00:00Z,Please delete my account.
case_8,gil@x.com,2026-09-01T00:00:00Z,COMPLETE,2026-09-02T12:00:00Z,2026-09-10T00:00:00Z,Please delete my account.
"""
ACTIVITY = """activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details
activity_1,2026-09-02T11:00:00Z,DELETE_RECORD,deletion_worker,account_service,account_1,SUCCESS,Submitted account_1.
activity_2,2026-09-04T11:00:00Z,DELETE_RECORD,deletion_worker,account_service,account_4,SUCCESS,Submitted account_4.
activity_3,2026-09-03T11:00:00Z,DELETE_RECORD,deletion_worker,account_service,account_3,FAILED,Submitted account_3.
activity_4,2026-09-05T06:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,backup_service,backup_5,SUCCESS,Data catalog linked backup_5 to dee@x.com and user_5.
activity_5,2026-09-05T06:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,marketing_platform,marketing_7,SUCCESS,Data catalog linked marketing_7 to dee@x.com and user_5.
activity_6,2026-09-15T06:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,integration_service,data_flow_7,SUCCESS,Data catalog linked data_flow_7 to dee@x.com and user_5.
activity_7,2026-08-01T06:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,export_service,export_7,SUCCESS,Data catalog linked export_7 to dee@x.com and user_5.
activity_8,2026-09-05T06:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,export_service,export_6,SUCCESS,Data catalog linked export_6 (NST-6) to eve@x.com and user_6.
activity_9,2026-09-05T06:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,object_storage,object_6,SUCCESS,Attachment catalog confirmed object_6 (receipt_6.pdf) belongs only to eve@x.com and user_6.
activity_10,2026-09-05T06:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,identity_service,tombstone_6,SUCCESS,Data catalog linked tombstone_6 (user_6) to eve@x.com and user_6.
activity_11,2026-09-05T06:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,identity_service,tombstone_7,SUCCESS,Data catalog linked tombstone_7 (user_7) to fay@x.com and user_7.
activity_12,2026-09-05T06:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,export_service,export_8,SUCCESS,Data catalog linked export_8 (NST-8) to fay@x.com and user_7.
activity_13,2026-09-05T06:00:00Z,LINK_RESOURCE_IDENTITY,data_catalog,backup_service,backup_81,SUCCESS,Data catalog linked backup_81 (backup_81) to gil@x.com and user_8.
"""
# A recovery-console listing: backup_80 visibly holds gil's email with no block
# shown; backup_81 is catalog-linked but the listing shows no identifier or state.
GIL_CONSOLE = "backup_80  gil@x.com  eu-west-1  84.7 GB  Archive\nbackup_81  eu-west-1  91.4 GB  Archive\n"
GIL_JSON = {"records": [{"resource_id": "backup_82", "customer_email": "gil@x.com",
                         "restore_allowed": False, "observed_at": "2026-09-05T00:00:00Z"}]}
# Statement NST-6 carries eve's email: a sighting of export_6. NST-60 and
# receipt_60.pdf are near-miss decoys; receipt_6.pdf is only listed after audit_at.
EVE_TEXT = "Customer statement NST-6\nEmail eve@x.com\nAlso see statement NST-60\nreceipt_60.pdf 10 KB\n"
EVE_LATE = "receipt_6.pdf 12 KB Standard\n"
REGISTRY_TEXT = "user_6 Retained reference Customer key\nuser_7 Retained reference fay@x.com\n"
FAY_TEXT = "Customer statement NST-8\nEmail someone.else@x.com\n"
DEE_SQL = """-- Captured at: 2026-09-05T00:00:00Z
CREATE TABLE search_documents_primary (resource_id TEXT PRIMARY KEY, display_name TEXT, email TEXT, source_resource_id TEXT, indexed_at TEXT);
CREATE TABLE backup_restore_entries (resource_id TEXT PRIMARY KEY, customer_reference TEXT, customer_email TEXT, archive_key TEXT, restore_allowed INTEGER);
INSERT INTO search_documents_primary VALUES ('search_9', 'Dee Roe', 'dee@x.com', 'account_9', '2026-09-04T00:00:00Z');
INSERT INTO search_documents_primary VALUES ('search_8', 'Dee Roeland', 'dee.roeland@x.com', 'account_8', '2026-09-04T00:00:00Z');
INSERT INTO backup_restore_entries VALUES ('backup_5', NULL, NULL, 'archive/backup_5.tar.zst', 0);
"""
DEE_JSON = {"records": [
    {"resource_id": "marketing_7", "email": "someone.else@x.com", "observed_at": "2026-09-05T00:00:00Z"},
    {"resource_id": "data_flow_7", "enabled": True, "observed_at": "2026-09-05T00:00:00Z"},
    {"resource_id": "export_7", "owner_email": None, "observed_at": "2026-09-05T00:00:00Z"},
]}
REPLICA_SQL = """-- Captured at: 2026-09-05T00:00:00Z
CREATE TABLE customer_data_primary (resource_id TEXT PRIMARY KEY, origin_system TEXT, collection_name TEXT, record_json TEXT, updated_at TEXT);
CREATE TABLE customer_data_failover_replica (resource_id TEXT PRIMARY KEY, origin_system TEXT, collection_name TEXT, record_json TEXT, updated_at TEXT);
INSERT INTO customer_data_failover_replica VALUES ('account_1', 'account_service', 'customer_profiles',
 '{"resource_id":"account_1","customer_reference":"user_1","email":"ana@x.com"}', '2026-09-05T00:00:00Z');
"""
INVENTORY_SQL = """-- Captured at: 2026-09-06T00:00:00Z
CREATE TABLE customer_profiles (resource_id TEXT PRIMARY KEY, email TEXT);
"""


def bundle():
    def snap(store, collection, records):
        return {"captured_at": "2026-09-06T00:00:00Z", "data_store": store,
                "collection": collection, "records": records}
    return {"exported_at": "2026-09-06T00:00:00Z", "snapshots": [
        snap("security_service", "security_audit_events",
             [{"resource_id": "audit_record_1", "subject_reference": "user_1"}]),
        snap("identity_service", "deleted_customer_references",
             [{"resource_id": "tombstone_1", "subject_reference": "user_1", "name": None,
               "email": "ana@x.com", "phone": None, "email_hash": None}]),
        snap("integration_service", "connector_configurations",
             [{"resource_id": "data_flow_1", "subject_selector": "ana.old@x.com", "enabled": True}]),
        snap("backup_service", "backup_catalog",
             [{"resource_id": "backup_1", "subject_reference": "user_1", "restore_allowed": True}]),
        snap("support_platform", "support_conversations",
             [{"resource_id": "support_1", "subject_reference": "user_1",
               "message_text": "Order delayed; shared with courier."}]),
        snap("analytics_platform", "customer_analytics_reports",
             [{"resource_id": "analytics_2", "user_id": "user_2", "email": "ana.x@x.com"}]),
    ]}


LATE = {"records": [{"recorded_at": "2026-09-20T00:00:00Z", "system": "account_service",
                     "resource_id": "account_1", "record_type": "USER_PROFILE",
                     "result": "NOT_FOUND", "subject_reference": "ana@x.com"}]}
BEN_LOG = "\n".join([
    "2026-09-05T08:00:00Z level=DEBUG service=account_service trace_id=rb-1 event=profile_lookup_started resource_id=account_3 lookup_key=ben@x.com",
    "2026-09-05T08:00:00Z level=INFO service=account_service trace_id=rb-1 event=profile_lookup_completed resource_id=account_3 rows=0 http_status=404",
    "2026-09-05T08:01:00Z level=DEBUG service=security_service trace_id=rb-2 event=audit_record_read_started resource_id=audit_record_3 lookup_key=user_3",
    "2026-09-05T08:01:00Z level=INFO service=security_service trace_id=rb-2 event=audit_record_read_completed resource_id=audit_record_3 rows=1 subject_reference=user_3",
    "2026-08-01T08:00:00Z level=INFO service=search_service trace_id=rb-3 event=index_query_completed resource_id=search_3 result=hit email=ben@x.com",
]) + "\n"


@pytest.fixture
def engine(tmp_path):
    files = {
        "user_identities.csv": IDENTITIES, "user_audit_log.csv": AUDIT,
        "deletion_rules.csv": RULES, "deletion_requests.csv": REQUESTS,
        "system_activity.csv": ACTIVITY,
    }
    evidence = [
        ("evidence_01", "replica.sql", "2026-09-05T00:00:00Z", REPLICA_SQL),
        ("evidence_02", "bundle.json", "2026-09-06T00:00:00Z", json.dumps(bundle())),
        ("evidence_03", "late.json", "2026-09-20T00:00:00Z", json.dumps(LATE)),
        ("evidence_04", "ben.log", "2026-09-05T09:00:00Z", BEN_LOG),
        ("evidence_05", "inventory.sql", "2026-09-06T00:00:00Z", INVENTORY_SQL),
        ("evidence_06", "dee.sql", "2026-09-05T00:00:00Z", DEE_SQL),
        ("evidence_07", "dee.json", "2026-09-05T00:00:00Z", json.dumps(DEE_JSON)),
        ("evidence_08", "eve.txt", "2026-09-05T00:00:00Z", EVE_TEXT),
        ("evidence_09", "eve_late.txt", "2026-09-20T00:00:00Z", EVE_LATE),
        ("evidence_10", "registry.txt", "2026-09-06T00:00:00Z", REGISTRY_TEXT),
        ("evidence_11", "fay.txt", "2026-09-06T00:00:00Z", FAY_TEXT),
        ("evidence_12", "gil_console.txt", "2026-09-05T00:00:00Z", GIL_CONSOLE),
        ("evidence_13", "gil.json", "2026-09-05T00:00:00Z", json.dumps(GIL_JSON)),
    ]
    (tmp_path / "evidence").mkdir()
    manifest = ["file_id,file_path,origin,captured_at"]
    for file_id, name, captured, content in evidence:
        (tmp_path / "evidence" / name).write_text(content, encoding="utf-8", newline="")
        manifest.append(f"{file_id},evidence/{name},test,{captured}")
    files["evidence_files.csv"] = "\n".join(manifest) + "\n"
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8", newline="")
    dataset = load_dataset(tmp_path, names=("requests", "identities", "audit_log", "activity",
                                            "rules", "evidence"))
    assert dataset.issues == []
    return DeletionEngine(dataset)


def decide(engine, case_id):
    request = engine.dataset["requests"].by_id()[case_id]
    result = engine.decide(request)
    validate_steps(result.deletion_status, result.steps)
    return result


def rows(result):
    return [(s["operation"], s["resource_id"], s["evidence_id"]) for s in result.steps]


def test_incomplete_case_covers_replicas_retention_tombstones_and_recreation(engine):
    result = decide(engine, "case_1")
    assert result.user_id == "user_1"  # resolved from the historical email, case-insensitively
    assert result.deletion_status == "INCOMPLETE"
    assert rows(result) == [
        # failover replica still holds the profile; the empty primary does not hide it
        ("REPORT_REMAINING_RECORD", "account_1", "evidence_01"),
        ("REPORT_EXPOSED_PII", "tombstone_1", "evidence_02"),
        ("REPORT_ACTIVE_DATA_FLOW", "data_flow_1", "evidence_02"),  # linked via old email
        ("REPORT_RESTORE_RISK", "backup_1", "evidence_02"),
        ("DISABLE_DATA_FLOW", "data_flow_1", ""),
        ("BLOCK_RESTORE", "backup_1", ""),
        ("DELETE_RECORD", "account_1", ""),
        ("REDACT_RECORD", "tombstone_1", ""),
        ("VERIFY_RECORD_ABSENT", "account_1", ""),
        ("VERIFY_RECORD_PRESENT", "audit_record_1", ""),
        ("VERIFY_RECORD_REDACTED", "tombstone_1", ""),
        ("VERIFY_RECORD_REDACTED", "support_1", ""),  # keeps only the stable user reference
        ("VERIFY_DATA_FLOW_DISABLED", "data_flow_1", ""),
        ("VERIFY_RESTORE_BLOCKED", "backup_1", ""),
    ]
    # evidence captured after audit_at (evidence_03 says NOT_FOUND) is ignored,
    # and another user's analytics record with a similar email is not included.
    assert all(s["resource_id"] != "analytics_2" for s in result.steps)


def test_complete_case_cites_evidence_and_ignores_pre_request_sightings(engine):
    result = decide(engine, "case_2")
    assert result.deletion_status == "COMPLETE"
    assert rows(result) == [
        ("VERIFY_RECORD_ABSENT", "account_3", "evidence_04"),
        ("VERIFY_RECORD_PRESENT", "audit_record_3", "evidence_04"),
    ]


def test_non_deletion_request_is_not_applicable(engine):
    result = decide(engine, "case_3")
    assert (result.deletion_status, result.steps) == ("NOT_APPLICABLE", [])


def test_timing_alone_never_attributes_a_resource(engine):
    # account_4 was deleted by the workflow an hour before case_4's report, but
    # no identifier, reference or catalog link ties it to user_4.
    result = decide(engine, "case_4")
    assert (result.deletion_status, result.steps) == ("COMPLETE", [])
    # ...and the verdict is flagged as resting on missing evidence, not proof.
    assert result.unverified == ["no subject-linked evidence citable at audit_at"]
    assert decide(engine, "case_2").unverified == []  # every check there is cited


def test_grounded_reference_and_catalog_links_with_decoys_and_time_bounds(engine):
    result = decide(engine, "case_5")
    assert result.deletion_status == "INCOMPLETE"
    assert rows(result) == [
        ("REPORT_REMAINING_RECORD", "search_9", "evidence_06"),
        ("DELETE_RECORD", "search_9", ""),
        # search_9 was built from account_9 (source_resource_id), so the
        # profile it names must be verified gone too.
        ("VERIFY_RECORD_ABSENT", "account_9", ""),
        ("VERIFY_RECORD_ABSENT", "search_9", ""),
        # catalog link + identity-free evidence showing restore is blocked
        ("VERIFY_RESTORE_BLOCKED", "backup_5", ""),
    ]
    found = {s["resource_id"] for s in result.steps}
    assert "account_8" not in found       # referenced only by another person's search entry
    assert "marketing_7" not in found     # catalog link contradicted by the record's own identifiers
    assert "data_flow_7" not in found     # catalog link made after audit_at
    assert "export_7" not in found        # catalog link made before the request


def test_catalog_aliases_resolve_to_exact_evidence_tokens(engine):
    result = decide(engine, "case_6")
    assert result.deletion_status == "INCOMPLETE"
    assert rows(result) == [
        # "export_6 (NST-6)": the statement naming NST-6 still holds eve's email
        ("REPORT_REMAINING_RECORD", "export_6", "evidence_08"),
        ("DELETE_RECORD", "export_6", ""),
        ("VERIFY_RECORD_ABSENT", "export_6", ""),
        # object_6 (receipt_6.pdf) is listed only after audit_at; NST-60 and
        # receipt_60.pdf are not exact alias matches, so no state is claimed
        ("VERIFY_RECORD_ABSENT", "object_6", ""),
        ("VERIFY_RECORD_REDACTED", "tombstone_6", ""),
    ]


def test_tombstone_alias_redacted_vs_exposed_and_conflicting_alias(engine):
    result = decide(engine, "case_7")
    # tombstone_7 (user_7): the registry line still shows fay's email -> exposed.
    # export_8 (NST-8): the only sighting holds someone else's email -> rejected.
    assert result.deletion_status == "INCOMPLETE"
    assert rows(result) == [
        ("REPORT_EXPOSED_PII", "tombstone_7", "evidence_10"),
        ("REDACT_RECORD", "tombstone_7", ""),
        ("VERIFY_RECORD_ABSENT", "export_8", ""),
        ("VERIFY_RECORD_REDACTED", "tombstone_7", ""),
    ]


def test_identifiable_backup_without_block_is_a_restore_risk(engine):
    result = decide(engine, "case_8")
    assert result.deletion_status == "INCOMPLETE"
    assert rows(result) == [
        # rule_14: retention requires restore access to be blocked; an archive
        # holding gil's email with no block in evidence is a restore path
        ("REPORT_RESTORE_RISK", "backup_80", "evidence_12"),
        ("BLOCK_RESTORE", "backup_80", ""),
        ("VERIFY_RESTORE_BLOCKED", "backup_80", ""),
        # identity-free listing with no state: no finding is claimed
        ("VERIFY_RESTORE_BLOCKED", "backup_81", ""),
        # explicit restore_allowed=false: already compliant
        ("VERIFY_RESTORE_BLOCKED", "backup_82", ""),
    ]


def test_tombstone_alias_with_retained_reference_proves_redaction(engine):
    request = dict(engine.dataset["requests"].by_id()["case_6"])
    # Same subject, but only the tombstone link: a COMPLETE verdict must cite the registry.
    engine.index.observations[:] = [o for o in engine.index.observations
                                    if not (o.kind == "activity" and o.resource_id in ("export_6", "object_6"))]
    engine.index.__post_init__()
    result = engine.decide(request)
    validate_steps(result.deletion_status, result.steps)
    assert (result.deletion_status, rows(result)) == (
        "COMPLETE", [("VERIFY_RECORD_REDACTED", "tombstone_6", "evidence_10")])


@pytest.mark.skipif(not (DEFAULT_DATASET_DIR / "sample_output.csv").is_file(),
                    reason="participant dataset not present")
def test_sample_regression():
    """Guards the calibrated behaviour on the public samples (statuses must all match)."""
    dataset = load_dataset()
    engine = DeletionEngine(dataset)
    gold = dataset["sample_output"].by_id()
    status_hits = 0
    predicted_steps = gold_steps = matched = 0
    for request in dataset["sample_requests"].rows:
        result = engine.decide(request)
        validate_steps(result.deletion_status, result.steps)
        expected = gold[request["case_id"]]
        status_hits += result.deletion_status == expected["deletion_status"]
        key = lambda s: tuple(sorted((k, v) for k, v in s.items() if k != "step_no"))  # noqa: E731
        mine, theirs = {key(s) for s in result.steps}, {key(s) for s in expected["steps_json"]}
        predicted_steps, gold_steps, matched = (predicted_steps + len(mine), gold_steps + len(theirs),
                                                matched + len(mine & theirs))
    assert status_hits == len(gold)
    assert matched == predicted_steps     # no unsupported steps on the samples
    assert matched / gold_steps >= 0.82
