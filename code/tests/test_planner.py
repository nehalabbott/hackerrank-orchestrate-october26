import json

import pytest

from planner import PlanError, ResourcePlan, build_steps, serialize_steps, validate_steps


def ops(steps):
    return [(s["step_no"], s["operation"], s["resource_id"], s["evidence_id"]) for s in steps]


def test_incomplete_plan_order_dependencies_and_citations():
    plans = [
        ResourcePlan("support_platform", "support_9", "VERIFY_RECORD_REDACTED",
                     "REPORT_EXPOSED_PII", "REDACT_RECORD", "evidence_02"),
        ResourcePlan("search_service", "search_1", "VERIFY_RECORD_ABSENT",
                     "REPORT_REMAINING_RECORD", "DELETE_RECORD", "evidence_01"),
        ResourcePlan("integration_service", "data_flow_1", "VERIFY_DATA_FLOW_DISABLED",
                     "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "evidence_01"),
        ResourcePlan("account_service", "account_1", "VERIFY_RECORD_ABSENT",
                     verification_evidence="evidence_03"),
        ResourcePlan("security_service", "audit_record_1", "VERIFY_RECORD_PRESENT"),
    ]
    status, steps = build_steps(plans)
    assert status == "INCOMPLETE"
    assert ops(steps) == [
        (1, "REPORT_REMAINING_RECORD", "search_1", "evidence_01"),
        (2, "REPORT_EXPOSED_PII", "support_9", "evidence_02"),
        (3, "REPORT_ACTIVE_DATA_FLOW", "data_flow_1", "evidence_01"),
        (4, "DISABLE_DATA_FLOW", "data_flow_1", ""),     # stop recreation before deleting
        (5, "DELETE_RECORD", "search_1", ""),
        (6, "REDACT_RECORD", "support_9", ""),
        (7, "VERIFY_RECORD_ABSENT", "account_1", ""),     # future checks carry no citation
        (8, "VERIFY_RECORD_ABSENT", "search_1", ""),
        (9, "VERIFY_RECORD_PRESENT", "audit_record_1", ""),
        (10, "VERIFY_RECORD_REDACTED", "support_9", ""),
        (11, "VERIFY_DATA_FLOW_DISABLED", "data_flow_1", ""),
    ]
    assert [s["state"] for s in steps][:4] == ["PRESENT", "PRESENT", "ACTIVE", "DISABLED"]


def test_same_operation_sorts_by_system_then_resource():
    plans = [ResourcePlan("search_service", rid, "VERIFY_RECORD_ABSENT", "REPORT_REMAINING_RECORD",
                          "DELETE_RECORD", "evidence_01")
             for rid in ("search_9", "search_10")]
    plans.append(ResourcePlan("account_service", "account_7", "VERIFY_RECORD_ABSENT",
                              "REPORT_REMAINING_RECORD", "DELETE_RECORD", "evidence_01"))
    _, steps = build_steps(plans)
    assert [s["resource_id"] for s in steps[:3]] == ["account_7", "search_10", "search_9"]


def test_complete_plan_keeps_only_cited_verifications():
    status, steps = build_steps([
        ResourcePlan("account_service", "account_1", "VERIFY_RECORD_ABSENT",
                     verification_evidence="evidence_54"),
        ResourcePlan("security_service", "audit_record_1", "VERIFY_RECORD_PRESENT"),
    ])
    assert status == "COMPLETE"
    assert ops(steps) == [(1, "VERIFY_RECORD_ABSENT", "account_1", "evidence_54")]


def test_duplicates_are_merged_preferring_cited_step():
    plan = ResourcePlan("search_service", "search_1", "VERIFY_RECORD_ABSENT",
                        verification_evidence="evidence_05")
    status, steps = build_steps([ResourcePlan("search_service", "search_1", "VERIFY_RECORD_ABSENT"),
                                 plan, plan])
    assert status == "COMPLETE" and ops(steps) == [(1, "VERIFY_RECORD_ABSENT", "search_1", "evidence_05")]


@pytest.mark.parametrize("plan,message", [
    (ResourcePlan("s", "r", "VERIFY_RECORD_ABSENT", "REPORT_REMAINING_RECORD", "DELETE_RECORD"),
     "no evidence"),
    (ResourcePlan("s", "r", "VERIFY_RECORD_ABSENT", "REPORT_REMAINING_RECORD", None, "e1"),
     "no remediation"),
    (ResourcePlan("s", "r", "VERIFY_RECORD_REDACTED", "REPORT_REMAINING_RECORD", "DELETE_RECORD", "e1"),
     "must be verified"),
    (ResourcePlan("s", "r", "DELETE_RECORD"), "not a verification"),
    (ResourcePlan("s", "r", "VERIFY_RECORD_ABSENT", "PURGE", "DELETE_RECORD", "e1"), "not a finding"),
])
def test_invalid_plans_are_rejected(plan, message):
    with pytest.raises(PlanError, match=message):
        build_steps([plan])


def step(no, phase, op, state, ev="", rid="r1"):
    return {"step_no": no, "phase": phase, "system_id": "s", "resource_id": rid,
            "operation": op, "state": state, "evidence_id": ev}


@pytest.mark.parametrize("status,steps,message", [
    ("NOT_APPLICABLE", [step(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", "e")], "no steps"),
    ("COMPLETE", [step(2, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", "e")], "step_no"),
    ("COMPLETE", [step(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "PRESENT", "e")], "allowed"),
    ("COMPLETE", [step(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT")], "evidence"),
    ("INCOMPLETE", [step(1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT")], "without evidence"),
    ("INCOMPLETE", [step(1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "e"),
                    step(2, "REMEDIATION", "DELETE_RECORD", "ABSENT", "e")], "must not cite"),
    ("INCOMPLETE", [step(1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "e"),
                    step(2, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "e")], "out of order"),
    ("INCOMPLETE", [step(1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT")], "at least one finding"),
    ("COMPLETE", [step(1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "e")], "only contain"),
])
def test_validate_steps_rejects_contract_violations(status, steps, message):
    with pytest.raises(PlanError, match=message):
        validate_steps(status, steps)


def test_serialization_is_deterministic_json():
    _, steps = build_steps([ResourcePlan("account_service", "account_1", "VERIFY_RECORD_ABSENT",
                                         verification_evidence="evidence_54")])
    text = serialize_steps(steps)
    assert json.loads(text) == steps
    assert text == serialize_steps(json.loads(text))
    assert text.startswith('[{"step_no":1,"phase":"VERIFICATION"')
