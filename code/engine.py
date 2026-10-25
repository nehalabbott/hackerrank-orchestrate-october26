"""Deletion decision engine.

For each request:
1. intent.classify_request decides whether deletion is authorized; if not,
   the case is NOT_APPLICABLE with no steps.
2. identity resolves the request email (current or historical) to a user and
   every identifier that user has held.
3. Resources are discovered from evidence that is citable at audit_at,
   observed after the request, and linked to those identifiers; from
   explicit references in such records (e.g. a search document's
   source_resource_id); and from data-catalog identity links
   (LINK_RESOURCE_IDENTITY) unless the resource's own evidence shows a
   different subject. Ownership is never inferred from timing alone.
4. Each resource is assessed from its latest evidence at audit_at: presence,
   exposed identifiers, flow / restore state. Replica copies count: any
   location still holding the record at the latest snapshot keeps it PRESENT;
   a later snapshot listing that omits it proves it ABSENT.
5. deletion_rules.csv maps the resource category to DELETE / REDACT /
   ANONYMIZE / RETAIN; data flows must be DISABLED and backups BLOCKED.
6. planner.build_steps orders, de-duplicates and validates the result.

Reported statuses and activity results are never used as proof of state.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime

from data_loader import Dataset
from evidence import (
    RAW_ROW_KEY,
    STRONG_KINDS,
    EvidenceIndex,
    Observation,
    build_evidence_index,
    identity_keys,
    screen_row_state,
    system_for_resource,
)
from identity import IdentityIndex, build_identity_index
from intent import classify_request
from planner import ResourcePlan, build_steps

CATEGORY_BY_PREFIX = {
    "account": "USER_PROFILE",
    "search": "SEARCH_INDEX_ENTRY",
    "cache": "CACHE_ENTRY",
    "analytics": "ANALYTICS_PROFILE",
    "telemetry": "PRODUCT_TELEMETRY",
    "export": "USER_EXPORT",
    "object": "USER_EXPORT",
    "marketing": "MARKETING_PROFILE",
    "email_delivery": "EMAIL_DELIVERY_LOG",
    "audit_record": "SECURITY_AUDIT_LOG",
    "legal_hold": "LEGAL_HOLD_RECORD",
    "backup": "BACKUP_ARCHIVE",
    "tombstone": "ACCOUNT_TOMBSTONE",
    "data_flow": "DATA_FLOW",
    "support": "SUPPORT_ATTACHMENT",
}
# Fallback treatment when deletion_rules.csv has no row for a category.
DEFAULT_ACTIONS = {
    "USER_PROFILE": "DELETE", "SECONDARY_IDENTIFIER": "DELETE", "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE", "SUPPORT_MESSAGE": "REDACT", "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE", "PRODUCT_TELEMETRY": "ANONYMIZE", "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE", "EMAIL_DELIVERY_LOG": "REDACT", "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN", "BACKUP_ARCHIVE": "RETAIN", "ACCOUNT_TOMBSTONE": "REDACT",
}
# Fields whose presence (even as null) shows a record carries identity slots,
# so a present record with all of them empty is redacted / anonymized.
IDENTITY_FIELDS = {
    "email", "phone", "email_hash", "full_name", "name", "display_name", "customer_reference",
    "user_id", "requester_email", "requester_name", "requester_phone", "owner_email",
    "owner_phone", "customer_email", "subject_reference", "subject_selector",
}
PRESENT_STATES = {"PRESENT", "ACTIVE", "DISABLED", "BLOCKED", "REDACTED", "ANONYMIZED"}
# Activity events that assert identity ownership (not state) of a resource.
IDENTITY_LINK_EVENTS = {"LINK_RESOURCE_IDENTITY"}


@dataclass
class Assessment:
    resource_id: str
    system_id: str
    category: str
    action: str
    present: bool | None = None
    exposed: bool | None = None
    flow_state: str | None = None
    evidence_id: str = ""
    absent_evidence: str = ""


@dataclass
class CaseResult:
    case_id: str
    deletion_status: str
    steps: list[dict]
    user_id: str | None = None
    notes: list[str] = field(default_factory=list)
    # Required final states that no evidence citable at audit_at proves. A
    # COMPLETE case with entries here is "not contradicted", not "proven".
    unverified: list[str] = field(default_factory=list)


def load_rules(dataset: Dataset) -> dict[str, str]:
    rules = dict(DEFAULT_ACTIONS)
    if "rules" in dataset.tables:
        for row in dataset["rules"].rows:
            rules[row["data_category"].strip()] = row["required_action"].strip()
    return rules


def categorize(resource_id: str, observations: list[Observation]) -> str:
    """Data category from claim record types, collections and field names."""
    for obs in reversed(observations):
        record_type = obs.attributes.get("record_type")
        if isinstance(record_type, str) and record_type.isupper() and record_type != "DATA_FLOW":
            return record_type
    prefix = resource_id.rsplit("_", 1)[0]
    category = CATEGORY_BY_PREFIX.get(prefix, "SECONDARY_IDENTIFIER")
    keys = {k for o in observations for k in o.attributes}
    texts = " ".join(str(o.attributes.get(k, "")) for o in observations
                     for k in ("collection", "event", "text", "catalog_details")).lower()
    if prefix in ("support", "object") and "belongs only to" in texts and "attachment" in texts:
        return "SUPPORT_ATTACHMENT"  # rule condition stated explicitly by the catalog
    if prefix == "support":
        if keys & {"file", "file_name", "attachment"} or "attachment" in texts:
            return "SUPPORT_ATTACHMENT"
        if (any("message" in k or k.startswith("requester_") for k in keys)
                or any(w in texts for w in ("message", "conversation", "ticket"))):
            return "SUPPORT_MESSAGE"
    if prefix == "analytics" and "email_opt_in" in keys:
        return "MARKETING_PROFILE"
    return category


def referenced_resources(obs: Observation) -> set[str]:
    """Resources a record names in an explicit reference field (e.g. source_resource_id)."""
    refs = set()
    for key, value in obs.attributes.items():
        if key != "resource_id" and key.endswith("resource_id") and isinstance(value, str):
            refs |= {r for r in obs.linked_resources if r == value.strip()}
    return refs


class DeletionEngine:
    # Link resources only through evidence observed after the request was
    # made; older sightings describe accounts as they were before deletion
    # was asked for. Their state is still read from the full history.
    discover_from_request = True

    def __init__(self, dataset: Dataset, identities: IdentityIndex | None = None,
                 index: EvidenceIndex | None = None):
        self.dataset = dataset
        self.identities = identities or build_identity_index(dataset)
        self.index = index or build_evidence_index(dataset)
        self.rules = load_rules(dataset)

    # -- discovery ---------------------------------------------------------

    def discover(self, keys: set, request: dict) -> dict[str, list[Observation]]:
        at = request["audit_at"]
        found: dict[str, list[Observation]] = defaultdict(list)
        catalog_links: dict[str, list[Observation]] = defaultdict(list)
        for obs in self.index.matching(keys, at):
            if not obs.resource_id:
                continue
            if self.discover_from_request and obs.observed_at < request["requested_at"]:
                continue
            if obs.kind == "activity":
                # Activity is never proof of state, but a data-catalog link is
                # an explicit identity assertion about who a resource belongs to.
                if obs.attributes.get("event_type") in IDENTITY_LINK_EVENTS:
                    catalog_links[obs.resource_id].append(obs)
                continue
            own_strong = {i for i in obs.identifiers if i[0] in STRONG_KINDS}
            # A record that holds someone else's identifiers and only matched
            # through its lookup context belongs to that other subject.
            if own_strong and not own_strong & keys:
                continue
            found[obs.resource_id].append(obs)
        # Explicit references from the subject's own records (a search entry
        # built from an account profile names that profile).
        for observations in list(found.values()):
            for obs in observations:
                for rid in referenced_resources(obs):
                    found.setdefault(rid, [])
        for rid in sorted(catalog_links):
            if self._owned_by_other(rid, keys, at):
                continue
            found.setdefault(rid, [])
            for link in catalog_links[rid]:
                found[rid].extend(self._alias_sightings(rid, link, keys, request))
        return found

    def _alias_sightings(self, resource_id: str, link: Observation, keys: set,
                         request: dict) -> list[Observation]:
        """Evidence that names a catalog link's external alias for the resource.

        "Data catalog linked export_1842 (NST-2026-0718-1842) to ..." says the
        resource is known elsewhere as NST-2026-0718-1842. Document lines and
        screenshots captured in [requested_at, audit_at] that contain that exact
        token are sightings of the resource. A sighting holding only another
        subject's identifiers is rejected as a conflict.
        """
        details = str(link.attributes.get("details", ""))
        match = re.search(re.escape(resource_id) + r"\s*\(([^)]+)\)", details)
        alias = match.group(1).strip() if match else ""
        if not alias or alias == resource_id:
            return []
        token = re.compile(r"(?<![\w.-])" + re.escape(alias) + r"(?![\w-])", re.IGNORECASE)
        at, floor = request["audit_at"], request["requested_at"]
        system = system_for_resource(resource_id) or link.system_id
        matches = []
        for obs in self.index.observations:
            if obs.kind != "document" or obs.resource_id not in (None, resource_id):
                continue
            if not obs.available_at(at) or (self.discover_from_request and obs.observed_at < floor):
                continue
            text = str(obs.attributes.get("text") or obs.attributes.get(RAW_ROW_KEY) or "")
            if token.search(text):
                matches.append((obs, text))
        # Ownership conflicts are judged per evidence file: if any part of a file
        # naming the alias shows only another subject, none of it is used.
        conflicted = {obs.evidence_id for obs, _ in matches
                      if (own := {i for i in obs.identifiers if i[0] in STRONG_KINDS})
                      and not own & keys}
        sightings = []
        for obs, text in matches:
            if obs.evidence_id in conflicted:
                continue
            sightings.append(replace(
                obs, resource_id=resource_id, system_id=system,
                location=f"alias {alias} @ {obs.location}",
                state=obs.state or screen_row_state(resource_id, text),
                attributes={**obs.attributes, "catalog_alias": alias, "catalog_details": details}))
        return sightings

    def _owned_by_other(self, resource_id: str, keys: set, at: datetime) -> bool:
        """True when citable evidence shows the resource holding only another subject's identifiers."""
        for obs in self.index.history(resource_id, at):
            if obs.kind == "activity":
                continue
            own_strong = {i for i in obs.identifiers if i[0] in STRONG_KINDS}
            if own_strong and not own_strong & keys:
                return True
        return False

    # -- assessment --------------------------------------------------------

    def assess(self, resource_id: str, keys: set, at: datetime,
               not_before: datetime | None = None,
               sightings: list[Observation] = ()) -> Assessment:
        history = [o for o in self.index.history(resource_id, at) if o.kind != "activity"]
        if sightings:
            history = sorted(history + [o for o in sightings if o.available_at(at)],
                             key=lambda o: (o.observed_at, o.evidence_id, o.location))
        system = system_for_resource(resource_id) or next(
            (o.system_id for o in history if o.system_id), "unknown")
        category = categorize(resource_id, history)
        action = self.rules.get(category, "DELETE")
        result = Assessment(resource_id, system, category, action)

        # Redaction keeps the stable internal reference (user_id); only direct
        # identifiers count as exposed. Anonymization must unlink user_id too.
        exposure_keys = {k for k in keys if not (action == "REDACT" and k[0] == "user")}
        informative = [o for o in history if self._informative(o)]
        if informative:
            latest_time = informative[-1].observed_at
            latest = [o for o in informative if o.observed_at == latest_time]
            present = [o for o in latest if self._present(o)]
            absent = [o for o in latest if o.state == "ABSENT"]
            if present:
                result.present = True
                exposed = [o for o in present if self._exposed(o, exposure_keys)]
                treated = [o for o in present if self._treated(o)]
                if exposed:
                    result.exposed, result.evidence_id = True, exposed[0].evidence_id
                elif treated:
                    result.exposed, result.evidence_id = False, treated[0].evidence_id
                else:
                    result.evidence_id = present[0].evidence_id
                flows = {o.state for o in present}
                result.flow_state = ("ACTIVE" if "ACTIVE" in flows else
                                     "DISABLED" if "DISABLED" in flows else
                                     "BLOCKED" if "BLOCKED" in flows else None)
                if result.flow_state:
                    result.evidence_id = next(o.evidence_id for o in present
                                              if o.state == result.flow_state)
            elif absent:
                result.present, result.evidence_id = False, absent[0].evidence_id
        else:
            latest_time = None

        # A later listing of the system that omits the record proves absence.
        # Only listings after the record was last seen (and after the request)
        # count, so an unrelated earlier snapshot never proves anything.
        floor = max(t for t in (latest_time, not_before) if t is not None) \
            if (latest_time or not_before) else None
        # A listing never overrides a positive sighting: snapshots cover one
        # table or collection, and a copy elsewhere (e.g. a failover replica)
        # is exactly the drift this audit must catch.
        listing = self._absent_listing(resource_id, system, at, floor) if floor else ""
        if listing and result.present is None:
            result.present = False
            result.evidence_id = result.absent_evidence = listing
        return result

    def _absent_listing(self, resource_id: str, system: str, at: datetime,
                        after: datetime) -> str:
        """Latest snapshot file (taken after `after`) whose listings omit the record."""
        by_file: dict[str, list] = defaultdict(list)
        for cov in self.index.listings(system, at):
            if cov.observed_at > after:
                by_file[cov.evidence_id].append(cov)
        best = None
        for evidence_id, listings in by_file.items():
            if any(resource_id in c.resource_ids for c in listings):
                continue
            when = max(c.observed_at for c in listings)
            if best is None or (when, evidence_id) > best:
                best = (when, evidence_id)
        return best[1] if best else ""

    @staticmethod
    def _informative(obs: Observation) -> bool:
        # A catalog-alias sighting is a direct listing of the resource itself.
        if "catalog_alias" in obs.attributes:
            return True
        return obs.state is not None or bool(obs.identifiers) or bool(
            IDENTITY_FIELDS & set(obs.attributes))

    @staticmethod
    def _present(obs: Observation) -> bool:
        if obs.state is not None:
            return obs.state in PRESENT_STATES
        return True  # informative without a state: the record was read back

    @staticmethod
    def _exposed(obs: Observation, keys: set) -> bool:
        # An identifier the record visibly holds outranks any status label.
        if {i for i in obs.identifiers if i[0] in STRONG_KINDS} & keys:
            return True
        if obs.state in ("REDACTED", "ANONYMIZED"):
            return False
        return str(obs.attributes.get("result", "")).upper() == "IDENTIFIABLE"

    @staticmethod
    def _treated(obs: Observation) -> bool:
        if obs.state in ("REDACTED", "ANONYMIZED"):
            return True
        slots = IDENTITY_FIELDS & set(obs.attributes)
        direct = str(obs.attributes.get("direct_identifiers", "")).strip()
        return direct == "0" or (bool(slots) and not any(
            obs.attributes.get(k) not in (None, "", "null") for k in slots
            if k not in ("subject_reference", "customer_reference", "user_id")))

    # -- planning ----------------------------------------------------------

    def plan(self, a: Assessment) -> ResourcePlan:
        cite = a.evidence_id
        base = dict(system_id=a.system_id, resource_id=a.resource_id)
        if a.category == "DATA_FLOW":
            if a.flow_state == "ACTIVE":
                return ResourcePlan(**base, finding="REPORT_ACTIVE_DATA_FLOW", finding_evidence=cite,
                                    remediation="DISABLE_DATA_FLOW",
                                    verification="VERIFY_DATA_FLOW_DISABLED")
            return ResourcePlan(**base, verification="VERIFY_DATA_FLOW_DISABLED",
                                verification_evidence=cite if a.flow_state == "DISABLED" else "")
        if a.category == "BACKUP_ARCHIVE":
            # rule_14 lets an archive be retained only with restore access
            # blocked. An archive that visibly holds the subject's identifiers
            # with no evidence of a block is itself a restore path.
            unblocked_copy = a.flow_state is None and a.present and a.exposed
            if a.flow_state == "ACTIVE" or unblocked_copy:
                return ResourcePlan(**base, finding="REPORT_RESTORE_RISK", finding_evidence=cite,
                                    remediation="BLOCK_RESTORE", verification="VERIFY_RESTORE_BLOCKED")
            return ResourcePlan(**base, verification="VERIFY_RESTORE_BLOCKED",
                                verification_evidence=cite if a.flow_state == "BLOCKED" else "")
        if a.action == "RETAIN":
            return ResourcePlan(**base, verification="VERIFY_RECORD_PRESENT",
                                verification_evidence=cite if a.present else "")
        if a.action in ("REDACT", "ANONYMIZE"):
            remediation = "REDACT_RECORD" if a.action == "REDACT" else "ANONYMIZE_RECORD"
            verification = "VERIFY_RECORD_REDACTED" if a.action == "REDACT" else "VERIFY_RECORD_ANONYMIZED"
            if a.present is False:
                return ResourcePlan(**base, verification="VERIFY_RECORD_ABSENT",
                                    verification_evidence=cite)
            if a.present and a.exposed:
                return ResourcePlan(**base, finding="REPORT_EXPOSED_PII", finding_evidence=cite,
                                    remediation=remediation, verification=verification)
            return ResourcePlan(**base, verification=verification,
                                verification_evidence=cite if a.present and a.exposed is False else "")
        # DELETE
        if a.present:
            return ResourcePlan(**base, finding="REPORT_REMAINING_RECORD", finding_evidence=cite,
                                remediation="DELETE_RECORD", verification="VERIFY_RECORD_ABSENT")
        return ResourcePlan(**base, verification="VERIFY_RECORD_ABSENT",
                            verification_evidence=cite if a.present is False else "")

    # -- entry point -------------------------------------------------------

    def decide(self, request: dict) -> CaseResult:
        case_id = request["case_id"]
        intent = classify_request(request["request_text"])
        if not intent.authorizes_deletion:
            return CaseResult(case_id, "NOT_APPLICABLE", [], notes=[intent.reason])
        resolution = self.identities.resolve("email", request["email"], request["requested_at"])
        if resolution.user_id is None:
            reason = f"no subject for {request['email']}: {resolution.reason}"
            return CaseResult(case_id, "COMPLETE", [], notes=[reason], unverified=[reason])
        keys = identity_keys(self.identities[resolution.user_id])
        resources = self.discover(keys, request)
        assessments = [self.assess(rid, keys, request["audit_at"], request["requested_at"],
                                   [o for o in resources[rid] if "catalog_alias" in o.attributes])
                       for rid in sorted(resources)]
        plans = [self.plan(a) for a in assessments]
        status, steps = build_steps(plans)
        notes = [f"{a.resource_id}: {a.category}/{a.action} present={a.present} "
                 f"exposed={a.exposed} state={a.flow_state} ev={a.evidence_id}" for a in assessments]
        unverified = [f"{p.resource_id}: {p.verification} has no citable evidence"
                      for p in plans if not p.finding and not p.verification_evidence]
        if not plans:
            unverified.append("no subject-linked evidence citable at audit_at")
        return CaseResult(case_id, status, steps, resolution.user_id, notes, unverified)
