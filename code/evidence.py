"""Evidence extraction and indexing for every format under dataset/evidence/.

Each evidence file is turned into Observations: one per resource sighting
(a table row, JSON record, log line, document row or screenshot row). An
observation keeps

* evidence_id   - the manifest file_id (or activity_id) that can be cited;
* captured_at   - when the evidence file was captured (manifest time), used
                  to decide whether a case may cite it at its audit_at;
* observed_at   - the most specific time the record itself carries
                  (record/line/snapshot time), used to order states;
* system_id / resource_id / location (table, collection, line, row);
* state         - PRESENT / ABSENT / ACTIVE / DISABLED / BLOCKED / REDACTED /
                  ANONYMIZED when the evidence supports one, else None;
* identifiers   - identifiers the record itself contains (exposed PII);
* context_identifiers - identifiers it was looked up by or joined through
                  (lookup keys, trace-correlated lines), which link a record
                  to a subject without meaning the record still holds them.

Coverage entries record which resources a snapshot table or collection
listed, so absence from a complete listing can be reasoned about later.

Identifier matching is exact on normalized tokens with strict boundaries
(user_3 never matches user_33); names are kept but are not strong keys.
"""

from __future__ import annotations

import json
import re
import sqlite3
from bisect import insort
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from data_loader import Dataset, parse_timestamp
from identity import Identity, normalize

STRONG_KINDS = ("email", "phone", "email_hash", "user")

# Resource-ID prefix -> owning system, as used in system_id of output steps.
RESOURCE_SYSTEMS = {
    "account": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "data_flow": "integration_service",
    "backup": "backup_service",
    "audit_record": "security_service",
    "tombstone": "identity_service",
    "legal_hold": "legal_service",
    "cache": "cache_service",
    "email_delivery": "email_delivery_service",
    "marketing": "marketing_platform",
    "telemetry": "analytics_platform",
    "object": "object_storage",
}
_PREFIXES = sorted(RESOURCE_SYSTEMS, key=len, reverse=True)
# The trailing guard also rejects dates in file names ("customer_export_2026-02-10.zip").
RESOURCE_RE = re.compile(r"(?<![A-Za-z])(" + "|".join(_PREFIXES) + r")_(\d+)(?![A-Za-z0-9]|-\d)")
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])")
USER_RE = re.compile(r"(?<![A-Za-z0-9_])user_\d+(?!\d)", re.IGNORECASE)
HASH_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")
PHONE_RE = re.compile(r"(?<![\w+])\+\d[\d ().-]{6,}\d(?!\d)")
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")

PHONE_KEYS = {"phone", "requester_phone", "owner_phone", "customer_phone"}
NAME_KEYS = {"name", "full_name", "display_name", "requester_name", "customer_name"}
HASH_KEYS = {"email_hash"}
# Integrity seals and checksums are hex digests of the record, not identifiers.
DIGEST_KEYS = {"integrity_seal", "checksum", "checksum_prefix", "short_fingerprint"}
# Raw source text kept for traceability; its parsed cells are scanned instead.
RAW_ROW_KEY = "raw_row"
# Keys whose value is what a lookup searched for, not data the record holds.
CONTEXT_KEYS = {
    "lookup_key", "lookup_value", "correlation_key", "subject_key", "match_key",
    "scan_key", "query", "subject_ref", "owner_key",
}
RECORD_TIME_KEYS = ("observed_at", "recorded_at")
CONTAINER_TIME_KEYS = ("captured_at", "exported_at")
NULL_TOKENS = {"", "null", "none", "nil"}

STATES = ("PRESENT", "ABSENT", "ACTIVE", "DISABLED", "BLOCKED", "REDACTED", "ANONYMIZED")
_RESULT_STATES = {
    "FOUND": "PRESENT", "IDENTIFIABLE": "PRESENT", "PRESENT": "PRESENT", "HIT": "PRESENT",
    "NOT_FOUND": "ABSENT", "ABSENT": "ABSENT", "MISS": "ABSENT", "DELETED": "ABSENT",
    "ACTIVE": "ACTIVE", "ENABLED": "ACTIVE",
    "DISABLED": "DISABLED", "STOPPED": "DISABLED",
    "BLOCKED": "BLOCKED", "REDACTED": "REDACTED", "ANONYMIZED": "ANONYMIZED",
}

Identifier = tuple[str, str]


def system_for_resource(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    match = RESOURCE_RE.fullmatch(resource_id)
    return RESOURCE_SYSTEMS[match.group(1)] if match else None


def resource_ids_in(text: str) -> list[str]:
    return [f"{m.group(1)}_{m.group(2)}" for m in RESOURCE_RE.finditer(text)]


def identifiers_in_text(text: str) -> set[Identifier]:
    found: set[Identifier] = set()
    for m in EMAIL_RE.finditer(text):
        found.add(("email", normalize("email", m.group(0))))
    for m in USER_RE.finditer(text):
        found.add(("user", m.group(0).lower()))
    for m in HASH_RE.finditer(text):
        if not text[max(0, m.start() - 7):m.start()].lower().endswith("sha256:"):
            found.add(("email_hash", m.group(0).lower()))
    for m in PHONE_RE.finditer(text):
        found.add(("phone", normalize("phone", m.group(0))))
    return found


def identifiers_in_value(value: Any, key: str | None = None) -> set[Identifier]:
    """Identifiers inside a (possibly nested) value, using the key as a type hint."""
    if value is None or isinstance(value, bool):
        return set()
    if isinstance(value, dict):
        out: set[Identifier] = set()
        for k, v in value.items():
            out |= identifiers_in_value(v, k)
        return out
    if isinstance(value, (list, tuple)):
        out = set()
        for v in value:
            out |= identifiers_in_value(v, key)
        return out
    text = str(value).strip()
    if text.lower() in NULL_TOKENS or key in DIGEST_KEYS or key == RAW_ROW_KEY:
        return set()
    found = identifiers_in_text(text)
    if key in PHONE_KEYS:
        found.add(("phone", normalize("phone", text)))
    elif key in NAME_KEYS:
        found.add(("name", normalize("name", text)))
    elif key in HASH_KEYS:
        found.add(("email_hash", text.lower()))
    return found


def identity_keys(identity: Identity, kinds: Iterable[str] = STRONG_KINDS) -> set[Identifier]:
    """Every (kind, normalized value) an identity has ever held, plus its user_id."""
    kinds = set(kinds)
    keys = {(p.field, p.normalized) for p in identity.periods if p.field in kinds}
    if "user" in kinds:
        keys.add(("user", identity.user_id.lower()))
    return keys


@dataclass
class Observation:
    evidence_id: str
    source_format: str
    captured_at: datetime
    observed_at: datetime
    system_id: str | None
    resource_id: str | None
    location: str
    kind: str  # record | lookup | claim | document | activity
    state: str | None
    attributes: dict[str, Any]
    identifiers: frozenset[Identifier] = frozenset()
    context_identifiers: frozenset[Identifier] = frozenset()
    linked_resources: frozenset[str] = frozenset()

    @property
    def all_identifiers(self) -> frozenset[Identifier]:
        return self.identifiers | self.context_identifiers

    def available_at(self, at: datetime) -> bool:
        return self.captured_at <= at and self.observed_at <= at


@dataclass(frozen=True)
class Coverage:
    """A snapshot listing: everything `location` held for `system_id` at `observed_at`."""
    evidence_id: str
    captured_at: datetime
    observed_at: datetime
    system_id: str | None
    location: str
    resource_ids: frozenset[str]

    def available_at(self, at: datetime) -> bool:
        return self.captured_at <= at and self.observed_at <= at


@dataclass
class EvidenceFile:
    file_id: str
    path: Path
    origin: str
    captured_at: datetime


# --------------------------------------------------------------------------
# State inference

def _flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "1", "yes"):
        return True
    if text in ("false", "0", "no"):
        return False
    return None


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def infer_state(attrs: dict[str, Any], default: str | None = None) -> str | None:
    """Best-supported state for a resource sighting, from its own fields."""
    if "enabled" in attrs and _flag(attrs["enabled"]) is not None:
        return "ACTIVE" if _flag(attrs["enabled"]) else "DISABLED"
    if "restore_allowed" in attrs and _flag(attrs["restore_allowed"]) is not None:
        return "ACTIVE" if _flag(attrs["restore_allowed"]) else "BLOCKED"
    if _flag(attrs.get("deletion_block")) is True:
        return "BLOCKED"
    decision = str(attrs.get("decision", "")).strip().lower()
    if decision in ("deny", "denied", "blocked", "rejected"):
        return "BLOCKED"
    if decision in ("allow", "allowed", "approved", "permit"):
        return "ACTIVE"
    if "available" in attrs and _flag(attrs["available"]) is not None:
        return "PRESENT" if _flag(attrs["available"]) else "ABSENT"
    if "eligible" in attrs and _flag(attrs["eligible"]) is not None:
        return "ACTIVE" if _flag(attrs["eligible"]) else "BLOCKED"
    for key in ("result", "status"):
        value = attrs.get(key)
        if isinstance(value, str) and value.strip().upper() in _RESULT_STATES:
            return _RESULT_STATES[value.strip().upper()]
    for key in ("http_status", "status_code"):
        code = _int(attrs.get(key))
        if code is not None:
            if code == 404 or code == 410:
                return "ABSENT"
            if 200 <= code < 300:
                return "PRESENT"
    hits = attrs.get("hits")
    total = _int(hits.get("total")) if isinstance(hits, dict) else _int(attrs.get("total_hits"))
    if total is not None:
        return "PRESENT" if total > 0 else "ABSENT"
    rows = _int(attrs.get("rows"))
    if rows is not None:
        return "PRESENT" if rows > 0 else "ABSENT"
    if "archive_present" in attrs and _flag(attrs["archive_present"]) is False:
        return "ABSENT"
    return default


# --------------------------------------------------------------------------
# Record helpers shared by structured formats

def _split_identifiers(record: dict[str, Any], claim: bool) -> tuple[set[Identifier], set[Identifier]]:
    own: set[Identifier] = set()
    context: set[Identifier] = set()
    for key, value in record.items():
        if key == "resource_id":
            continue
        is_context = key in CONTEXT_KEYS or (claim and key == "subject_reference")
        (context if is_context else own).update(identifiers_in_value(value, key))
    return own, context


def _linked(record: dict[str, Any], resource_id: str | None) -> frozenset[str]:
    text = json.dumps({k: v for k, v in record.items() if k != "resource_id"},
                      ensure_ascii=False, default=str)
    return frozenset(r for r in resource_ids_in(text) if r != resource_id)


def _is_claim(record: dict[str, Any]) -> bool:
    return "record_type" in record and "result" in record


def _make_observation(ef: EvidenceFile, fmt: str, record: dict[str, Any], *,
                      observed_at: datetime, location: str, kind: str,
                      system_hint: str | None = None, default_state: str | None = None,
                      extra_context: Iterable[Identifier] = ()) -> Observation:
    resource_id = record.get("resource_id")
    resource_id = str(resource_id).strip() if resource_id else None
    claim = _is_claim(record)
    own, context = _split_identifiers(record, claim)
    context |= set(extra_context)
    context -= own
    system = record.get("system") if isinstance(record.get("system"), str) else None
    system = system or system_for_resource(resource_id) or system_hint
    return Observation(
        evidence_id=ef.file_id, source_format=fmt, captured_at=ef.captured_at,
        observed_at=observed_at, system_id=system, resource_id=resource_id,
        location=location, kind="claim" if claim else kind,
        state=infer_state(record, default_state), attributes=dict(record),
        identifiers=frozenset(own), context_identifiers=frozenset(context),
        linked_resources=_linked(record, resource_id),
    )


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return parse_timestamp(value)
    except ValueError:
        return None


def _clamp(observed: datetime | None, ef: EvidenceFile) -> datetime:
    # A record cannot be observed after its file was captured; fall back to
    # the manifest time when a record carries no usable time of its own.
    if observed is None or observed > ef.captured_at:
        return ef.captured_at
    return observed


# --------------------------------------------------------------------------
# SQL snapshots

TABLE_SYSTEMS = {
    "customer_profiles": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "customer_search_documents": "search_service",
    "search_documents_primary": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}
_SQL_CAPTURED_RE = re.compile(r"^--\s*Captured at:\s*(\S+)", re.MULTILINE)
_SQL_TOPOLOGY_RE = re.compile(r"^--\s*Database topology:\s*(\S+)", re.MULTILINE)


def extract_sql(ef: EvidenceFile) -> tuple[list[Observation], list[Coverage]]:
    script = ef.path.read_text(encoding="utf-8")
    header_time = _time(m.group(1)) if (m := _SQL_CAPTURED_RE.search(script)) else None
    topology = m.group(1) if (m := _SQL_TOPOLOGY_RE.search(script)) else None

    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(script)
        conn.row_factory = sqlite3.Row
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        scope: dict[str, datetime] = {}
        if "snapshot_scope" in tables:
            for row in conn.execute("SELECT origin_system, captured_at FROM snapshot_scope"):
                if (t := _time(row[1])) is not None:
                    scope[row[0]] = t

        observations: list[Observation] = []
        listings: dict[tuple[str, str | None], set[str]] = defaultdict(set)
        for table in tables:
            columns = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
            if "resource_id" not in columns:
                continue
            table_system = TABLE_SYSTEMS.get(table)
            if table_system:
                listings[(table, table_system)]
            for row in conn.execute(f'SELECT * FROM "{table}" ORDER BY resource_id'):
                record = dict(row)
                system_hint = record.pop("origin_system", None) or table_system
                collection = record.pop("collection_name", None)
                if "record_json" in record:
                    payload = json.loads(record.pop("record_json"))
                    payload.setdefault("resource_id", record["resource_id"])
                    record = {**payload, **{k: v for k, v in record.items() if k not in payload}}
                system = system_for_resource(record["resource_id"]) or system_hint
                observed = header_time or scope.get(system)
                location = f"{table}/{collection}" if collection else table
                attrs = {**record, "table": table, "topology": topology}
                if collection:
                    attrs["collection"] = collection
                obs = _make_observation(ef, "sql", attrs, observed_at=_clamp(observed, ef),
                                        location=location, kind="record",
                                        system_hint=system, default_state="PRESENT")
                observations.append(obs)
                listings[(table, obs.system_id)].add(obs.resource_id)
    finally:
        conn.close()

    coverage = []
    for (table, system), ids in sorted(listings.items(), key=lambda kv: (kv[0][0], kv[0][1] or "")):
        observed = header_time or scope.get(system or "")
        if observed is None and not header_time and scope:
            continue  # table not in this dump's declared scope
        coverage.append(Coverage(ef.file_id, ef.captured_at, _clamp(observed, ef), system,
                                 table, frozenset(ids)))
    return observations, coverage


# --------------------------------------------------------------------------
# JSON records

def _contains_resource(value: Any) -> bool:
    if isinstance(value, dict):
        return "resource_id" in value or any(_contains_resource(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_resource(v) for v in value)
    return False


def extract_json(ef: EvidenceFile) -> tuple[list[Observation], list[Coverage]]:
    data = json.loads(ef.path.read_text(encoding="utf-8"))
    observations: list[Observation] = []
    coverage: list[Coverage] = []

    def walk(node: Any, path: str, when: datetime | None, system: str | None,
             lookup: bool) -> None:
        if isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]", when, system, lookup)
            return
        if not isinstance(node, dict):
            return
        for key in CONTAINER_TIME_KEYS:
            when = _time(node.get(key)) or when
        system = node.get("data_store") or system
        if "resource_id" in node:
            emit(node, path, when, system, lookup)
            return
        if "collection" in node and isinstance(node.get("records"), list):
            ids = {str(r["resource_id"]) for r in node["records"]
                   if isinstance(r, dict) and r.get("resource_id")}
            coverage.append(Coverage(ef.file_id, ef.captured_at, _clamp(when, ef), system,
                                     f"{system}/{node['collection']}" if system else node["collection"],
                                     frozenset(ids)))
        for key, value in node.items():
            child_system = key if key in _KNOWN_SYSTEMS else system
            walk(value, f"{path}.{key}" if path else key, when, child_system,
                 lookup or key == "service_exports")

    def emit(node: dict, path: str, when: datetime | None, system: str | None,
             lookup: bool) -> None:
        own = {k: v for k, v in node.items() if not _contains_resource(v)}
        record_time = next((t for k in RECORD_TIME_KEYS if (t := _time(node.get(k)))), None)
        # Nested resource records (e.g. search hits) are emitted on their own.
        for key, value in node.items():
            if _contains_resource(value):
                walk(value, f"{path}.{key}", record_time or when, system, lookup)
                if isinstance(value, dict) and isinstance(value.get("total"), (int, str)):
                    own["hits"] = {"total": value["total"]}
        location = _json_location(path)
        observations.append(_make_observation(
            ef, "json", own, observed_at=_clamp(record_time or when, ef), location=location,
            kind="lookup" if lookup else "record", system_hint=system,
            default_state=None if lookup else "PRESENT"))

    walk(data, "", ef.captured_at, None, False)
    return observations, coverage


_KNOWN_SYSTEMS = set(RESOURCE_SYSTEMS.values())


def _json_location(path: str) -> str:
    return re.sub(r"\[\d+\]", "[]", path)


# --------------------------------------------------------------------------
# Logs

_LOG_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(.*)$")
_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s"|]+)')
_BRACKET_RE = re.compile(r"^\[(\w+)\]\s+\[([\w.-]+)\]\s+\[([\w.-]+)\]\s+(\w+):\s*(.*)$")
_PIPE_RE = re.compile(r"^(\w+)\s+\|\s+([\w.-]+)\s+\|\s+([\w.-]+)\s+\|\s+(\w+)\s+\|\s*(.*)$")
_SYSLOG_RE = re.compile(r"^<\d+>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+-\s+-\s+(.*)$")


@dataclass
class LogLine:
    line_no: int
    time: datetime
    fields: dict[str, Any]

    @property
    def trace(self) -> str | None:
        return self.fields.get("trace_id") or self.fields.get("requestId")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return re.sub(r'\\(.)', r"\1", value[1:-1])
    return value


def parse_kv(text: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key, raw in _KV_RE.findall(text):
        value = _unquote(raw)
        if key == "message" and "=" in value:
            fields.update(parse_kv(value))
            continue
        fields[key] = None if value.lower() in NULL_TOKENS else value
    return fields


def parse_log_line(line: str, line_no: int) -> LogLine | None:
    m = _LOG_TS_RE.match(line.strip())
    if not m:
        return None
    try:
        when = parse_timestamp(m.group(1))
    except ValueError:
        return None
    rest = m.group(2)
    fields: dict[str, Any] = {}
    if rest.startswith("{"):
        try:
            fields = {k: (None if isinstance(v, str) and v.lower() in NULL_TOKENS else v)
                      for k, v in json.loads(rest).items()}
        except json.JSONDecodeError:
            fields = parse_kv(rest)
    elif bm := _BRACKET_RE.match(rest):
        fields = {"level": bm.group(1), "service": bm.group(2), "trace_id": bm.group(3),
                  "event": bm.group(4), **parse_kv(bm.group(5))}
    elif pm := _PIPE_RE.match(rest):
        fields = {"level": pm.group(1), "service": pm.group(2), "trace_id": pm.group(3),
                  "event": pm.group(4), **parse_kv(pm.group(5))}
    elif sm := _SYSLOG_RE.match(rest):
        fields = {"host": sm.group(1), "service": sm.group(2), "trace_id": sm.group(3),
                  **parse_kv(sm.group(4))}
    else:
        fields = parse_kv(rest)
    fields.setdefault("service", fields.get("function") or fields.get("logger"))
    return LogLine(line_no, when, fields)


def extract_log(ef: EvidenceFile) -> tuple[list[Observation], list[Coverage]]:
    lines: list[LogLine] = []
    with ef.path.open(encoding="utf-8") as handle:
        for i, raw in enumerate(handle, start=1):
            if parsed := parse_log_line(raw, i):
                lines.append(parsed)

    # Lines sharing a trace describe one operation: the lookup key usually
    # appears on the *_started line and the resource_id on the *_completed one.
    trace_keys: dict[str, set[Identifier]] = defaultdict(set)
    trace_resources: dict[str, set[str]] = defaultdict(set)
    for ln in lines:
        if ln.trace:
            trace_keys[ln.trace] |= identifiers_in_value(
                {k: v for k, v in ln.fields.items() if k != "resource_id"})
            if ln.fields.get("resource_id"):
                trace_resources[ln.trace].add(str(ln.fields["resource_id"]))

    observations = []
    for ln in lines:
        resource_id = ln.fields.get("resource_id")
        if not resource_id:
            continue
        extra: set[Identifier] = set()
        # Only join through a trace that concerns this single resource, so one
        # trace touching several resources cannot cross-link their subjects.
        if ln.trace and trace_resources[ln.trace] == {str(resource_id)}:
            extra = trace_keys[ln.trace]
        observations.append(_make_observation(
            ef, "log", ln.fields, observed_at=_clamp(ln.time, ef),
            location=f"line {ln.line_no}", kind="lookup", extra_context=extra))
    return observations, []


# --------------------------------------------------------------------------
# Documents: PDF, plain text and screenshots share line-oriented parsing

_SYSTEM_NAME_RE = re.compile(r"^[a-z]+(?:_[a-z]+)+$")
_UPPER_TOKEN_RE = re.compile(r"^[A-Z][A-Z_]+$")


def _pipe_row(cells: list[str]) -> dict[str, Any]:
    """Interpret a `a | b | c` row: timestamp, system, resource, type, result, subject."""
    record: dict[str, Any] = {}
    uppers = []
    for cell in cells:
        text = cell.strip()
        if "observed_at" not in record and TIMESTAMP_RE.fullmatch(text):
            record["observed_at"] = text
        elif "resource_id" not in record and RESOURCE_RE.fullmatch(text):
            record["resource_id"] = text
        elif "system" not in record and text in _KNOWN_SYSTEMS:
            record["system"] = text
        elif _UPPER_TOKEN_RE.fullmatch(text):
            uppers.append(text)
        elif text:
            if "subject_reference" in record:
                record.setdefault("details", []).append(text)
            else:
                record["subject_reference"] = text
    if len(uppers) >= 2:
        record["record_type"], record["result"] = uppers[0], uppers[1]
    elif len(uppers) == 1:
        record["result"] = uppers[0]
    return record


def _document_observations(ef: EvidenceFile, fmt: str, lines: list[tuple[str, str]],
                           doc_time: datetime | None) -> list[Observation]:
    """Turn (locator, text) lines into observations.

    Pipe-delimited rows become one observation each. Every other line that
    names resources becomes a row observation for each resource it names. If
    the remaining free text names exactly one resource, a document-level
    observation ties all of its identifiers to that resource; if it names
    none, a resource-less observation still records which identifiers the
    document exposes.
    """
    observations = []
    free_text: list[str] = []
    when = _clamp(doc_time, ef)
    for locator, text in lines:
        if text.count("|") >= 2:
            record = _pipe_row(text.split("|"))
            record[RAW_ROW_KEY] = text
            row_time = _time(record.get("observed_at"))
            observations.append(_make_observation(
                ef, fmt, record, observed_at=_clamp(row_time or doc_time, ef),
                location=locator, kind="document"))
            continue
        free_text.append(text)
        resources = list(dict.fromkeys(resource_ids_in(text)))
        if len(resources) == 1:
            observations.append(_make_observation(
                ef, fmt, {"resource_id": resources[0], "text": text}, observed_at=when,
                location=locator, kind="document"))
        elif not resources:
            # Kept so explicit external references (file names, statement
            # numbers) can be resolved to this line later; it links no resource.
            observations.append(_make_observation(
                ef, fmt, {"text": text}, observed_at=when, location=locator, kind="document"))
    full = "\n".join(free_text)
    resources = list(dict.fromkeys(resource_ids_in(full)))
    if len(resources) == 1:
        observations.append(_make_observation(
            ef, fmt, {"resource_id": resources[0], "text": full}, observed_at=when,
            location="document", kind="document"))
    elif not resources and identifiers_in_text(full):
        observations.append(_make_observation(
            ef, fmt, {"text": full}, observed_at=when, location="document", kind="document"))
    return observations


def extract_text(ef: EvidenceFile) -> tuple[list[Observation], list[Coverage]]:
    text = ef.path.read_text(encoding="utf-8")
    lines = [(f"line {i}", line.strip().lstrip("-* ").strip())
             for i, line in enumerate(text.splitlines(), start=1) if line.strip()]
    stamps = [t for line in lines for t in [_time(m) for m in TIMESTAMP_RE.findall(line[1])] if t]
    return _document_observations(ef, "text", lines, max(stamps) if stamps else None), []


def extract_pdf(ef: EvidenceFile) -> tuple[list[Observation], list[Coverage]]:
    import pymupdf

    lines = []
    with pymupdf.open(ef.path) as doc:
        for page_no, page in enumerate(doc, start=1):
            for i, line in enumerate(page.get_text().splitlines(), start=1):
                if line.strip():
                    lines.append((f"page {page_no} line {i}", line.strip()))
    return _document_observations(ef, "pdf", lines, None), []


def ocr_rows(boxes: list, tolerance: float = 0.45) -> list[list]:
    """Group OCR boxes into visual rows (by vertical centre), left to right."""
    rows: list[list] = []
    for box in sorted(boxes, key=lambda b: (b.y_center, b.x0)):
        height = max(box.y1 - box.y0, 1.0)
        for row in rows:
            ref = row[0]
            limit = tolerance * min(height, max(ref.y1 - ref.y0, 1.0))
            if abs(ref.y_center - box.y_center) <= limit:
                insort(row, box, key=lambda b: b.x0)
                break
        else:
            rows.append([box])
    return rows


class UnsupportedEvidence(Exception):
    """The file's format cannot be read in this environment (e.g. no OCR engine)."""


def extract_image(ef: EvidenceFile, cache_dir: Path | None = None) -> tuple[list[Observation], list[Coverage]]:
    from ocr import DEFAULT_CACHE_DIR, ocr_image

    try:
        boxes = ocr_image(ef.path, cache_dir or DEFAULT_CACHE_DIR)
    except RuntimeError as exc:
        raise UnsupportedEvidence(str(exc)) from exc
    lines = []
    for row in ocr_rows(boxes):
        text = "  ".join(b.text for b in row)
        lines.append((f"row y={round(row[0].y_center)}", text))
    observations = _document_observations(ef, "image", lines, None)
    for obs in observations:
        if obs.state is None and obs.location.startswith("row"):
            obs.state = screen_row_state(obs.resource_id, obs.attributes.get("text", ""))
    return observations, []


# Explicit status words shown on admin screens, per resource type. Only rows
# that state a status get one; anything else stays unknown.
_SCREEN_STATES = {
    "data_flow": (("ACTIVE", r"\b(?:continuous|active|enabled|running|streaming)\b"),
                  ("DISABLED", r"\b(?:paused|disabled|stopped|inactive)\b")),
    "backup": (("BLOCKED", r"\b(?:restore blocked|blocked|locked|restore disabled)\b"),),
    "tombstone": (("REDACTED", r"\b(?:retained reference|identifiers removed|redacted)\b"),),
}


def screen_row_state(resource_id: str | None, text: str) -> str | None:
    if not resource_id:
        return None
    prefix = RESOURCE_RE.fullmatch(resource_id).group(1)
    lowered = text.lower()
    found = [state for state, pattern in _SCREEN_STATES.get(prefix, ())
             if re.search(pattern, lowered)]
    return found[0] if len(found) == 1 else None


# --------------------------------------------------------------------------
# Index

EXTRACTORS = {
    ".sql": extract_sql,
    ".json": extract_json,
    ".log": extract_log,
    ".txt": extract_text,
    ".pdf": extract_pdf,
    ".png": extract_image,
    ".jpg": extract_image,
    ".jpeg": extract_image,
}


@dataclass
class EvidenceIndex:
    observations: list[Observation]
    coverage: list[Coverage]
    issues: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    by_resource: dict[str, list[Observation]] = field(default_factory=dict)
    by_identifier: dict[Identifier, list[Observation]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.observations.sort(key=lambda o: (o.observed_at, o.evidence_id, o.location,
                                              o.resource_id or ""))
        by_resource: dict[str, list[Observation]] = defaultdict(list)
        by_identifier: dict[Identifier, list[Observation]] = defaultdict(list)
        for obs in self.observations:
            if obs.resource_id:
                by_resource[obs.resource_id].append(obs)
            for ident in obs.all_identifiers:
                by_identifier[ident].append(obs)
        self.by_resource = dict(by_resource)
        self.by_identifier = dict(by_identifier)

    def matching(self, keys: Iterable[Identifier], at: datetime | None = None,
                 kinds: Iterable[str] = STRONG_KINDS) -> list[Observation]:
        """Observations linked to any of `keys`, optionally only those citable at `at`."""
        kinds = set(kinds)
        seen: dict[int, Observation] = {}
        for key in keys:
            if key[0] not in kinds:
                continue
            for obs in self.by_identifier.get(key, ()):
                if at is None or obs.available_at(at):
                    seen[id(obs)] = obs
        return sorted(seen.values(), key=lambda o: (o.observed_at, o.evidence_id, o.location))

    def resources_for(self, keys: Iterable[Identifier], at: datetime | None = None) -> set[str]:
        return {o.resource_id for o in self.matching(keys, at) if o.resource_id}

    def history(self, resource_id: str, at: datetime | None = None) -> list[Observation]:
        return [o for o in self.by_resource.get(resource_id, ())
                if at is None or o.available_at(at)]

    def latest(self, resource_id: str, at: datetime | None = None,
               with_state: bool = True) -> Observation | None:
        candidates = [o for o in self.history(resource_id, at)
                      if not with_state or o.state is not None]
        return candidates[-1] if candidates else None

    def listings(self, system_id: str, at: datetime | None = None) -> list[Coverage]:
        return [c for c in self.coverage
                if c.system_id == system_id and (at is None or c.available_at(at))]


def activity_observations(dataset: Dataset) -> list[Observation]:
    """system_activity rows as claim observations (citable by activity_id)."""
    out = []
    for row in dataset["activity"].rows:
        details = row["details"]
        resource_id = row["resource_id"]
        out.append(Observation(
            evidence_id=row["activity_id"], source_format="activity",
            captured_at=row["event_time"], observed_at=row["event_time"],
            system_id=system_for_resource(resource_id) or row["target_system"],
            resource_id=resource_id, location="system_activity", kind="activity",
            state=None,
            attributes={k: row[k] for k in ("event_type", "source_system", "target_system",
                                            "reported_result", "details")},
            identifiers=frozenset(), context_identifiers=frozenset(identifiers_in_text(details)),
            linked_resources=frozenset(r for r in resource_ids_in(details) if r != resource_id),
        ))
    return out


def load_evidence_files(dataset: Dataset) -> list[EvidenceFile]:
    return [EvidenceFile(row["file_id"], dataset.root / row["file_path"], row["origin"],
                         row["captured_at"]) for row in dataset["evidence"].rows]


def build_evidence_index(dataset: Dataset, include_activity: bool = True,
                         ocr_cache_dir: Path | None = None) -> EvidenceIndex:
    observations: list[Observation] = []
    coverage: list[Coverage] = []
    issues: list[str] = []
    unsupported: list[str] = []
    for ef in load_evidence_files(dataset):
        extractor = EXTRACTORS.get(ef.path.suffix.lower())
        if extractor is None:
            unsupported.append(f"{ef.file_id}: no extractor for {ef.path.suffix}")
            continue
        try:
            if extractor is extract_image and ocr_cache_dir is not None:
                obs, cov = extract_image(ef, ocr_cache_dir)
            else:
                obs, cov = extractor(ef)
        except UnsupportedEvidence as exc:
            unsupported.append(f"{ef.file_id}: {exc}")
            continue
        except Exception as exc:  # keep going; one bad file must not stop the audit
            issues.append(f"{ef.file_id}: {type(exc).__name__}: {exc}")
            continue
        if not obs and not cov:
            issues.append(f"{ef.file_id}: nothing extracted from {ef.path.name}")
        observations.extend(obs)
        coverage.extend(cov)
    if include_activity:
        observations.extend(activity_observations(dataset))
    return EvidenceIndex(observations, coverage, issues, unsupported)
