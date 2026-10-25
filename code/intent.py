"""Decide whether a request_text authorizes deletion.

Deterministic, multilingual rules (no model calls). A request is treated as
non-deletion when it asks for another action (access, export, correction,
marketing opt-out, login help) or explicitly says the account must be kept;
those signals win over incidental deletion vocabulary such as "without
removing". Otherwise it is a deletion request when it contains deletion
vocabulary in any supported language.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_NEGATED_DELETION = (
    r"\b(?:not|n't|never|without|no)\b[\w\s,'-]{0,40}?"
    r"\b(?:delet\w*|eras\w*|remov\w*|clos\w*|cancel\w*)"
)
NON_DELETION_PATTERNS = [
    _NEGATED_DELETION,
    r"\bdo(?:n't| not)\s+(?:delete|erase|remove|close|change)\b",
    r"\bkeep (?:the|my) (?:account|profile)\b",
    r"\bleave (?:the|my) (?:account|profile)\b",
    r"\b(?:account|profile)\b[\w\s]{0,30}\b(?:active|in place|as it is)\b",
    r"\bcontinue using\b",
    r"\bstill (?:use|need|want)\b",
    r"\bmarketing (?:lists?|emails?)\s+only\b",
    r"\b(?:stop|unsubscribe)\b[\w\s]{0,20}\b(?:promotional|marketing|newsletter)",
    r"\b(?:send|give|need|want|get|provide)\b[\w\s]{0,12}\bcopy of\b",
    r"\bdownload my\b",
    r"\bportable format\b",
    r"\binformation request\b",
    r"\bwhat personal (?:information|data) you hold\b",
    r"\b(?:correct|update|replace|change)\b[\w\s]{0,25}\b(?:name|surname|email address|phone|mobile|number)\b",
    r"\bmisspelled\b",
    r"\breset(?:ting)? (?:the |my )?(?:login|password)\b",
]
DELETION_PATTERNS = [
    r"\bdelet\w*", r"\beras\w*", r"\bremov\w*", r"\bclose (?:my|this|the) account\b",
    r"\bclos\w* (?:my|this|the) account\b", r"\bpermanently\b",
    r"\b(?:account|profile|data) is gone\b", r"\bcannot identify me\b",
    r"\bl[öo]sch\w*", r"\bsuppression\b", r"\bsupprim\w*", r"\beffac\w*",
    r"\beliminaci[óo]n\b", r"\belimin\w*", r"\bborr\w*", r"\bexclus[ãa]o\b", r"\bexclu\w*",
    r"\bapag\w*", r"\bcancel\w*", r"\busu[ńn]\w*", r"\bverwijder\w*", r"\bcancell\w*",
    r"削除", r"删除", r"刪除", r"삭제", r"удал\w*", r"видал\w*",
]
_NON_DELETION = [re.compile(p, re.IGNORECASE) for p in NON_DELETION_PATTERNS]
_DELETION = [re.compile(p, re.IGNORECASE) for p in DELETION_PATTERNS]


@dataclass(frozen=True)
class Intent:
    authorizes_deletion: bool
    reason: str


def classify_request(text: str) -> Intent:
    normalized = text.replace("’", "'")
    for pattern in _NON_DELETION:
        if m := pattern.search(normalized):
            return Intent(False, f"non-deletion signal: {m.group(0)!r}")
    for pattern in _DELETION:
        if m := pattern.search(normalized):
            return Intent(True, f"deletion signal: {m.group(0)!r}")
    return Intent(False, "no deletion signal")
