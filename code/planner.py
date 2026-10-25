"""Remediation planner: turns per-resource decisions into a contract-valid steps_json.

The planner owns the output contract from problem_statement.md:

* only the 15 allowed (phase, operation, state) triples;
* phases FINDING -> REMEDIATION -> VERIFICATION, and within a phase the
  operation order of the table, then system_id, then resource_id ascending;
  that table order already puts DISABLE_DATA_FLOW and BLOCK_RESTORE before
  any record change, which is the dependency rule (stop recreation first);
* step_no consecutive from 1;
* evidence_id required on findings and on verification of COMPLETE cases,
  and empty on remediation and on verification of INCOMPLETE cases;
* no duplicate (operation, system_id, resource_id) steps.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

# (phase, operation, state) in the exact order of the operations table.
ALLOWED_OPERATIONS = (
    ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
    ("FINDING", "REPORT_EXPOSED_PII", "PRESENT"),
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
    ("FINDING", "REPORT_RESTORE_RISK", "ACTIVE"),
    ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
    ("REMEDIATION", "BLOCK_RESTORE", "BLOCKED"),
    ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
    ("REMEDIATION", "REDACT_RECORD", "REDACTED"),
    ("REMEDIATION", "ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
    ("VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED"),
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED", "BLOCKED"),
)
OPERATION_INDEX = {op: i for i, (_, op, _) in enumerate(ALLOWED_OPERATIONS)}
OPERATION_PHASE = {op: phase for phase, op, _ in ALLOWED_OPERATIONS}
OPERATION_STATE = {op: state for _, op, state in ALLOWED_OPERATIONS}
PHASES = ("FINDING", "REMEDIATION", "VERIFICATION")
STEP_FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
OUTPUT_HEADER = ("case_id", "deletion_status", "steps_json")

# Finding -> its remediation and the verification that proves it worked.
REMEDIATION_FOR = {
    "REPORT_ACTIVE_DATA_FLOW": "DISABLE_DATA_FLOW",
    "REPORT_RESTORE_RISK": "BLOCK_RESTORE",
}
VERIFICATION_FOR = {
    "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
    "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
    "DELETE_RECORD": "VERIFY_RECORD_ABSENT",
    "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
    "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED",
}


class PlanError(ValueError):
    pass


@dataclass(frozen=True)
class PlannedStep:
    operation: str
    system_id: str
    resource_id: str
    evidence_id: str = ""

    @property
    def phase(self) -> str:
        return OPERATION_PHASE[self.operation]

    @property
    def state(self) -> str:
        return OPERATION_STATE[self.operation]

    def sort_key(self) -> tuple:
        return (OPERATION_INDEX[self.operation], self.system_id, self.resource_id)


@dataclass(frozen=True)
class ResourcePlan:
    """What the engine decided for one resource.

    finding: FINDING operation when the resource violates policy (else None).
    remediation: REMEDIATION operation that fixes it (required with a finding).
    verification: VERIFICATION operation for the required final state.
    finding_evidence / verification_evidence: citations from visible evidence.
    """
    system_id: str
    resource_id: str
    verification: str
    finding: str | None = None
    remediation: str | None = None
    finding_evidence: str = ""
    verification_evidence: str = ""


def build_steps(plans: list[ResourcePlan]) -> tuple[str, list[dict]]:
    """Return (deletion_status, steps) for a deletion-authorized case."""
    incomplete = any(p.finding for p in plans)
    planned: dict[tuple[str, str, str], PlannedStep] = {}

    def add(step: PlannedStep) -> None:
        if step.operation not in OPERATION_INDEX:
            raise PlanError(f"operation not allowed: {step.operation}")
        key = (step.operation, step.system_id, step.resource_id)
        existing = planned.get(key)
        # Duplicate prevention: keep one step, preferring the one with a citation.
        if existing is None or (not existing.evidence_id and step.evidence_id):
            planned[key] = step

    for plan in plans:
        if plan.finding:
            if OPERATION_PHASE.get(plan.finding) != "FINDING":
                raise PlanError(f"{plan.finding} is not a finding")
            if not plan.finding_evidence:
                raise PlanError(f"finding on {plan.resource_id} has no evidence")
            if OPERATION_PHASE.get(plan.remediation or "") != "REMEDIATION":
                raise PlanError(f"finding on {plan.resource_id} has no remediation")
            if VERIFICATION_FOR[plan.remediation] != plan.verification:
                raise PlanError(f"{plan.remediation} must be verified by "
                                f"{VERIFICATION_FOR[plan.remediation]}")
            add(PlannedStep(plan.finding, plan.system_id, plan.resource_id, plan.finding_evidence))
            add(PlannedStep(plan.remediation, plan.system_id, plan.resource_id))
        if OPERATION_PHASE.get(plan.verification) != "VERIFICATION":
            raise PlanError(f"{plan.verification} is not a verification")
        if incomplete:
            add(PlannedStep(plan.verification, plan.system_id, plan.resource_id))
        elif plan.verification_evidence:
            add(PlannedStep(plan.verification, plan.system_id, plan.resource_id,
                            plan.verification_evidence))
        # A COMPLETE case may only contain evidence-backed checks, so an
        # uncited verification is dropped rather than emitted without proof.

    ordered = sorted(planned.values(), key=PlannedStep.sort_key)
    steps = [
        {"step_no": i, "phase": s.phase, "system_id": s.system_id, "resource_id": s.resource_id,
         "operation": s.operation, "state": s.state, "evidence_id": s.evidence_id}
        for i, s in enumerate(ordered, start=1)
    ]
    status = "INCOMPLETE" if incomplete else "COMPLETE"
    validate_steps(status, steps)
    return status, steps


def validate_steps(status: str, steps: list[dict]) -> None:
    """Raise PlanError if `steps` violates the output contract for `status`."""
    if status == "NOT_APPLICABLE":
        if steps:
            raise PlanError("NOT_APPLICABLE cases must have no steps")
        return
    if status not in ("COMPLETE", "INCOMPLETE"):
        raise PlanError(f"unknown status {status}")
    seen = set()
    previous = None
    for i, step in enumerate(steps, start=1):
        if tuple(sorted(step)) != tuple(sorted(STEP_FIELDS)):
            raise PlanError(f"step {i} has fields {sorted(step)}")
        if step["step_no"] != i:
            raise PlanError(f"step_no {step['step_no']} at position {i}")
        triple = (step["phase"], step["operation"], step["state"])
        if triple not in ALLOWED_OPERATIONS:
            raise PlanError(f"step {i}: {triple} is not an allowed combination")
        key = (OPERATION_INDEX[step["operation"]], step["system_id"], step["resource_id"])
        if previous is not None and key <= previous:
            raise PlanError(f"step {i} is out of order or duplicated")
        previous = key
        ident = (step["operation"], step["system_id"], step["resource_id"])
        if ident in seen:
            raise PlanError(f"duplicate step {ident}")
        seen.add(ident)
        cited = bool(step["evidence_id"])
        if step["phase"] == "FINDING" and not cited:
            raise PlanError(f"step {i}: finding without evidence")
        if step["phase"] == "REMEDIATION" and cited:
            raise PlanError(f"step {i}: remediation must not cite evidence")
        if step["phase"] == "VERIFICATION" and cited != (status == "COMPLETE"):
            raise PlanError(f"step {i}: verification evidence does not match {status}")
    phases = {s["phase"] for s in steps}
    if status == "COMPLETE" and phases - {"VERIFICATION"}:
        raise PlanError("COMPLETE cases may only contain verification steps")
    if status == "INCOMPLETE" and "FINDING" not in phases:
        raise PlanError("INCOMPLETE cases need at least one finding")


def serialize_steps(steps: list[dict]) -> str:
    """Deterministic JSON for the steps_json column."""
    return json.dumps([{k: s[k] for k in STEP_FIELDS} for s in steps],
                      ensure_ascii=False, separators=(",", ":"))
