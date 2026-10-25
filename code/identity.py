"""Historical identity resolution from user_identities.csv and user_audit_log.csv.

For every user and identifier field the audit log is replayed into a list of
validity periods. A period is half-open, [valid_from, valid_to):

* the value before the first change has an unknown start (valid_from=None)
  and ends at that change;
* each changed-to value starts at its change and ends at the next one;
* the last value is open-ended (valid_to=None) and should equal the snapshot.

Users with no history get a single open period sourced from the snapshot.
Inconsistencies (broken chains, a snapshot that disagrees with the last audit
value) are kept as extra periods and reported, never silently dropped.

Names are indexed but are not unique across users, so they must never be used
on their own to resolve a subject.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from data_loader import Dataset, format_timestamp

IDENTIFIER_FIELDS = ("email", "phone", "email_hash", "name")
UNIQUE_FIELDS = ("email", "phone", "email_hash")
SNAPSHOT_SOURCE = "user_identities"


def normalize(field_name: str, value: str) -> str:
    """Canonical comparison form for an identifier value."""
    text = value.strip()
    if field_name in ("email", "email_hash"):
        return text.lower()
    if field_name == "phone":
        digits = re.sub(r"\D", "", text)
        return f"+{digits}" if text.startswith("+") else digits
    return " ".join(text.casefold().split())


@dataclass(frozen=True)
class IdentifierPeriod:
    user_id: str
    field: str
    value: str
    valid_from: datetime | None
    valid_to: datetime | None
    # audit_ids (or "user_identities") that establish this period
    sources: tuple[str, ...]

    @property
    def normalized(self) -> str:
        return normalize(self.field, self.value)

    @property
    def is_current(self) -> bool:
        return self.valid_to is None

    def contains(self, at: datetime) -> bool:
        started = self.valid_from is None or self.valid_from <= at
        return started and (self.valid_to is None or at < self.valid_to)

    def __str__(self) -> str:
        start = format_timestamp(self.valid_from) if self.valid_from else "-inf"
        end = format_timestamp(self.valid_to) if self.valid_to else "now"
        return f"{self.user_id}.{self.field}={self.value} [{start}, {end})"


@dataclass
class Identity:
    user_id: str
    periods: list[IdentifierPeriod]

    def values(self, field_name: str) -> list[str]:
        """Distinct values ever held for a field, oldest first."""
        seen: dict[str, None] = {}
        for period in self.periods:
            if period.field == field_name:
                seen.setdefault(period.value)
        return list(seen)

    def normalized_values(self, fields: tuple[str, ...] = IDENTIFIER_FIELDS) -> set[str]:
        return {p.normalized for p in self.periods if p.field in fields}

    def current(self, field_name: str) -> str | None:
        for period in self.periods:
            if period.field == field_name and period.is_current:
                return period.value
        return None

    def held_at(self, field_name: str, at: datetime) -> list[str]:
        return [p.value for p in self.periods if p.field == field_name and p.contains(at)]


@dataclass(frozen=True)
class Resolution:
    query: str
    user_id: str | None
    period: IdentifierPeriod | None
    candidates: tuple[str, ...]
    reason: str

    @property
    def ambiguous(self) -> bool:
        return len(self.candidates) > 1


@dataclass
class IdentityIndex:
    identities: dict[str, Identity]
    issues: list[str] = field(default_factory=list)
    _by_value: dict[tuple[str, str], list[IdentifierPeriod]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        index: dict[tuple[str, str], list[IdentifierPeriod]] = defaultdict(list)
        for identity in self.identities.values():
            for period in identity.periods:
                index[(period.field, period.normalized)].append(period)
        self._by_value = dict(index)

    def __getitem__(self, user_id: str) -> Identity:
        return self.identities[user_id]

    def lookup(self, field_name: str, value: str) -> list[IdentifierPeriod]:
        return list(self._by_value.get((field_name, normalize(field_name, value)), ()))

    def owners(self, field_name: str, value: str) -> set[str]:
        return {p.user_id for p in self.lookup(field_name, value)}

    def resolve(self, field_name: str, value: str, at: datetime | None = None) -> Resolution:
        """Resolve an identifier value to a single user.

        Preference: the user holding the value at `at`; otherwise the user who
        held it most recently before `at`; otherwise the sole holder ever.
        Anything else is returned unresolved with all candidates listed.
        """
        if field_name not in UNIQUE_FIELDS:
            raise ValueError(f"{field_name} is not a unique identifier field")
        periods = self.lookup(field_name, value)
        candidates = tuple(sorted({p.user_id for p in periods}))
        if not periods:
            return Resolution(value, None, None, (), "no_match")

        if at is not None:
            holding = [p for p in periods if p.contains(at)]
            if len({p.user_id for p in holding}) == 1:
                return Resolution(value, holding[0].user_id, holding[0], candidates, "held_at")
            if not holding:
                ended = [p for p in periods if p.valid_to is not None and p.valid_to <= at]
                if ended:
                    latest = max(p.valid_to for p in ended)
                    last = [p for p in ended if p.valid_to == latest]
                    if len({p.user_id for p in last}) == 1:
                        return Resolution(value, last[0].user_id, last[0], candidates,
                                          "held_before")

        if len(candidates) == 1:
            return Resolution(value, candidates[0], periods[-1], candidates, "sole_holder")
        return Resolution(value, None, None, candidates, "ambiguous")


def build_identity_index(dataset: Dataset) -> IdentityIndex:
    snapshot = dataset["identities"].by_id()
    events: dict[tuple[str, str], list[dict]] = defaultdict(list)
    issues: list[str] = []

    for row in dataset["audit_log"].rows:
        if row["user_id"] not in snapshot:
            issues.append(f"{row['audit_id']}: unknown user {row['user_id']}")
            continue
        events[(row["user_id"], row["field_name"])].append(row)

    identities: dict[str, Identity] = {}
    for user_id in sorted(snapshot, key=_natural_key):
        user = snapshot[user_id]
        periods: list[IdentifierPeriod] = []
        for field_name in IDENTIFIER_FIELDS:
            history = sorted(events.get((user_id, field_name), ()),
                             key=lambda r: (r["event_time"], _natural_key(r["audit_id"])))
            periods.extend(_replay(user_id, field_name, user, history, issues))
        identities[user_id] = Identity(user_id, periods)

    return IdentityIndex(identities, issues)


def _replay(user_id: str, field_name: str, user: dict, history: list[dict],
            issues: list[str]) -> list[IdentifierPeriod]:
    current_value = user[field_name]
    if not history:
        return [IdentifierPeriod(user_id, field_name, current_value, None, None,
                                 (SNAPSHOT_SOURCE,))]

    periods: list[IdentifierPeriod] = []
    first = history[0]
    periods.append(IdentifierPeriod(user_id, field_name, first["old_value"], None,
                                    first["event_time"], (first["audit_id"],)))
    for i, event in enumerate(history):
        following = history[i + 1] if i + 1 < len(history) else None
        if following is not None and normalize(field_name, following["old_value"]) != \
                normalize(field_name, event["new_value"]):
            issues.append(f"{user_id}.{field_name}: {following['audit_id']} changes from "
                          f"{following['old_value']!r} but {event['audit_id']} set "
                          f"{event['new_value']!r}")
            # The unexplained old value was held at some point before the
            # following change; keep it so evidence using it still matches.
            periods.append(IdentifierPeriod(user_id, field_name, following["old_value"],
                                            None, following["event_time"],
                                            (following["audit_id"],)))
        valid_to = following["event_time"] if following else None
        sources = (event["audit_id"], following["audit_id"] if following else SNAPSHOT_SOURCE)
        if following is None and normalize(field_name, event["new_value"]) != \
                normalize(field_name, current_value):
            issues.append(f"{user_id}.{field_name}: snapshot {current_value!r} disagrees with "
                          f"{event['audit_id']} new value {event['new_value']!r}")
            sources = (event["audit_id"],)
            periods.append(IdentifierPeriod(user_id, field_name, event["new_value"],
                                            event["event_time"], user["updated_at"], sources))
            periods.append(IdentifierPeriod(user_id, field_name, current_value,
                                            user["updated_at"], None, (SNAPSHOT_SOURCE,)))
            continue
        periods.append(IdentifierPeriod(user_id, field_name, event["new_value"],
                                        event["event_time"], valid_to, sources))
    return periods


def _natural_key(identifier: str) -> tuple:
    prefix, _, number = identifier.rpartition("_")
    return (prefix, int(number)) if number.isdigit() else (identifier, 0)
