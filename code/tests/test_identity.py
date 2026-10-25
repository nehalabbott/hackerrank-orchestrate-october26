from datetime import datetime, timezone

import pytest

from data_loader import DEFAULT_DATASET_DIR, load_dataset
from identity import build_identity_index, normalize

IDENTITY_HEADER = "user_id,name,email,phone,email_hash,updated_at\n"
AUDIT_HEADER = "audit_id,user_id,event_time,field_name,old_value,new_value\n"


def ts(text):
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def build(tmp_path, identities, audit=""):
    (tmp_path / "user_identities.csv").write_text(IDENTITY_HEADER + identities,
                                                  encoding="utf-8", newline="")
    (tmp_path / "user_audit_log.csv").write_text(AUDIT_HEADER + audit,
                                                 encoding="utf-8", newline="")
    return build_identity_index(load_dataset(tmp_path, names=("identities", "audit_log")))


def test_normalize():
    assert normalize("email", "  Ana.Silva@Example.COM ") == "ana.silva@example.com"
    assert normalize("phone", "+33 6 24-34.80 16") == "+33624348016"
    assert normalize("name", "  Mateo   Ríos ") == "mateo ríos"


def test_changed_email_yields_both_values_with_periods(tmp_path):
    index = build(
        tmp_path,
        "user_1,Ana Silva,ana.new@example.com,+1 555 0100,hnew,2026-05-01T00:00:00Z\n",
        "audit_1,user_1,2026-02-01T00:00:00Z,email,ana.old@example.com,ana.mid@example.com\n"
        "audit_2,user_1,2026-04-01T00:00:00Z,email,ana.mid@example.com,ana.new@example.com\n"
        "audit_3,user_1,2026-04-01T00:00:00Z,email_hash,hmid,hnew\n"
        "audit_4,user_1,2026-02-01T00:00:00Z,email_hash,hold,hmid\n",
    )
    user = index["user_1"]
    assert user.values("email") == ["ana.old@example.com", "ana.mid@example.com",
                                    "ana.new@example.com"]
    assert user.values("email_hash") == ["hold", "hmid", "hnew"]
    assert user.current("email") == "ana.new@example.com"
    emails = [p for p in user.periods if p.field == "email"]
    assert [(p.valid_from, p.valid_to) for p in emails] == [
        (None, ts("2026-02-01T00:00:00")),
        (ts("2026-02-01T00:00:00"), ts("2026-04-01T00:00:00")),
        (ts("2026-04-01T00:00:00"), None),
    ]
    assert [p.sources for p in emails] == [
        ("audit_1",), ("audit_1", "audit_2"), ("audit_2", "user_identities")]
    assert user.held_at("email", ts("2026-03-01T00:00:00")) == ["ana.mid@example.com"]
    # A request made with a historical email still resolves, case-insensitively.
    resolution = index.resolve("email", "ANA.OLD@example.com", ts("2026-06-01T00:00:00"))
    assert (resolution.user_id, resolution.reason) == ("user_1", "held_before")
    assert index.resolve("email", "ana.old@example.com").reason == "sole_holder"
    assert index.issues == []


def test_missing_history_uses_snapshot_only(tmp_path):
    index = build(tmp_path, "user_1,Li Wei,li@example.com,+86 138 0000 0000,h1,"
                            "2026-01-01T00:00:00Z\n")
    user = index["user_1"]
    assert {p.field: p.value for p in user.periods} == {
        "email": "li@example.com", "phone": "+86 138 0000 0000",
        "email_hash": "h1", "name": "Li Wei"}
    assert all(p.valid_from is None and p.valid_to is None for p in user.periods)
    assert all(p.sources == ("user_identities",) for p in user.periods)
    assert index.resolve("phone", "+86 13800000000").user_id == "user_1"


def test_reused_email_resolves_by_time(tmp_path):
    index = build(
        tmp_path,
        "user_1,Sam Lee,sam.new@example.com,+1 1,h1,2026-05-01T00:00:00Z\n"
        "user_2,Sam Lee,shared@example.com,+1 2,h2,2026-05-01T00:00:00Z\n",
        "audit_1,user_1,2026-02-01T00:00:00Z,email,shared@example.com,sam.new@example.com\n"
        "audit_2,user_2,2026-04-01T00:00:00Z,email,other@example.com,shared@example.com\n",
    )
    assert index.owners("email", "shared@example.com") == {"user_1", "user_2"}
    before = index.resolve("email", "shared@example.com", ts("2026-01-15T00:00:00"))
    gap = index.resolve("email", "shared@example.com", ts("2026-03-01T00:00:00"))
    after = index.resolve("email", "shared@example.com", ts("2026-06-01T00:00:00"))
    assert (before.user_id, before.reason) == ("user_1", "held_at")
    assert (gap.user_id, gap.reason) == ("user_1", "held_before")
    assert (after.user_id, after.reason) == ("user_2", "held_at")
    assert after.ambiguous
    undated = index.resolve("email", "shared@example.com")
    assert (undated.user_id, undated.reason) == (None, "ambiguous")
    # Shared names are indexed but cannot be used to resolve a subject.
    assert len(index.lookup("name", "sam lee")) == 2
    with pytest.raises(ValueError):
        index.resolve("name", "Sam Lee")


def test_unrelated_users_do_not_leak_identifiers(tmp_path):
    index = build(
        tmp_path,
        "user_1,Ana Silva,ana@example.com,+1 1,h1,2026-05-01T00:00:00Z\n"
        "user_2,Ben Okafor,ben@example.com,+1 2,h2,2026-05-01T00:00:00Z\n",
        "audit_1,user_2,2026-02-01T00:00:00Z,email,ben.old@example.com,ben@example.com\n",
    )
    assert index["user_1"].normalized_values() == {"ana@example.com", "+11", "h1", "ana silva"}
    assert "ben.old@example.com" not in index["user_1"].normalized_values()
    assert index.resolve("email", "ben.old@example.com").user_id == "user_2"
    decoy = index.resolve("email", "ana.silva@example.com")
    assert (decoy.user_id, decoy.candidates, decoy.reason) == (None, (), "no_match")


def test_inconsistent_history_is_kept_and_reported(tmp_path):
    index = build(
        tmp_path,
        "user_1,Ana Silva,ana.snapshot@example.com,+1 1,h1,2026-05-01T00:00:00Z\n",
        "audit_1,user_1,2026-02-01T00:00:00Z,email,a@example.com,b@example.com\n"
        "audit_2,user_1,2026-03-01T00:00:00Z,email,c@example.com,d@example.com\n",
    )
    assert set(index["user_1"].values("email")) == {
        "a@example.com", "b@example.com", "c@example.com", "d@example.com",
        "ana.snapshot@example.com"}
    assert index["user_1"].current("email") == "ana.snapshot@example.com"
    assert len(index.issues) == 2


@pytest.mark.skipif(not (DEFAULT_DATASET_DIR / "user_audit_log.csv").is_file(),
                    reason="participant dataset not present")
def test_real_dataset_resolves_every_request_email():
    dataset = load_dataset(names=("identities", "audit_log", "requests", "sample_requests"))
    index = build_identity_index(dataset)
    assert index.issues == []
    for table in ("requests", "sample_requests"):
        for row in dataset[table].rows:
            resolution = index.resolve("email", row["email"], row["requested_at"])
            assert resolution.user_id is not None, row["case_id"]
            assert not resolution.ambiguous, row["case_id"]
