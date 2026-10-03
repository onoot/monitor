"""Shared finding model. Kept separate so the static and semantic passes can
both use it without importing each other."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


def fingerprint(text: str) -> str:
    return hashlib.sha1(text.strip().encode("utf-8", "replace")).hexdigest()[:12]


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def snippet_of(text: str, radius: int = 220, limit: int = 500) -> str:
    return re.sub(r"\s+", " ", text.strip())[:limit]


@dataclass(frozen=True)
class Evidence:
    file: str
    line: int
    snippet: str
    fingerprint: str

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "fingerprint": self.fingerprint,
        }


@dataclass
class Finding:
    rule_id: str
    category: str
    title: str
    severity: str
    evidence: Evidence
    description: str = ""
    exploit: str = ""
    breaker: str = ""
    remediation: str = ""
    cwe: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    confidence: str = "medium"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "exploit": self.exploit,
            "breaker": self.breaker,
            "remediation": self.remediation,
            "cwe": list(self.cwe),
            "rule_sources": list(self.sources),
            "evidence": self.evidence.to_dict(),
        }