"""Core data models shared across the scanner."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Tuple


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Status(str, Enum):
    """Per-requirement verdict.

    FAIL   - at least one violation was detected.
    PASS   - control indicators were found and no violation was detected.
               (Static indicators, not proof of compliance.)
    GAP    - requirement applies and is statically checkable, but no indicator was found.
    MANUAL - requirement cannot be verified statically; needs human/process review.
    NA     - the relevant AI component (e.g. MCP, RAG, agents) is not present.
    """

    FAIL = "FAIL"
    PASS = "PASS"
    GAP = "GAP"
    MANUAL = "MANUAL"
    NA = "N/A"


@dataclass(frozen=True)
class Requirement:
    id: str  # e.g. "2.1.3"
    text: str  # without the leading "Verify that"
    level: int  # 1..3 (0 for retired)
    chapter: str  # "C2"
    chapter_title: str
    section: str  # "C2.1"
    section_title: str
    retired: bool = False

    @property
    def chapter_no(self) -> int:
        return int(self.id.split(".")[0])

    @property
    def sort_key(self) -> Tuple[int, int, int]:
        a, b, c = (int(x) for x in self.id.split("."))
        return (a, b, c)


@dataclass
class Location:
    file: str
    line: int = 0
    snippet: str = ""


@dataclass
class Finding:
    """A concrete violation detected in the scanned target."""

    rule_id: str
    title: str
    severity: Severity
    requirements: Tuple[str, ...]
    message: str
    location: Location
    remediation: str = ""
    confidence: str = "medium"  # low | medium | high

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["requirements"] = list(self.requirements)
        return d


@dataclass
class Evidence:
    """A positive control indicator (e.g. a guardrail library, a schema validator)."""

    rule_id: str
    title: str
    requirements: Tuple[str, ...]
    location: Location

    def to_dict(self) -> dict:
        d = asdict(self)
        d["requirements"] = list(self.requirements)
        return d


@dataclass
class RequirementResult:
    requirement: Requirement
    status: Status
    findings: List[Finding] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict:
        r = self.requirement
        return {
            "id": r.id,
            "level": r.level,
            "chapter": r.chapter,
            "section": r.section,
            "text": r.text,
            "status": self.status.value,
            "note": self.note,
            "findings": [f.to_dict() for f in self.findings],
            "evidence": [e.to_dict() for e in self.evidence[:10]],
        }


@dataclass
class ScanResult:
    target: str
    standard_version: str
    scanner_version: str
    started_at: str
    duration_s: float
    files_scanned: int
    features: Dict[str, List[str]]  # detected AI feature -> sample locations
    findings: List[Finding]
    results: List[RequirementResult]
    max_level: int = 3
    suppressed: int = 0
    warnings: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        c = {s.value: 0 for s in Status}
        for r in self.results:
            c[r.status.value] += 1
        return c

    def to_dict(self) -> dict:
        return {
            "tool": "aisvs-scanner",
            "scanner_version": self.scanner_version,
            "standard": {"name": "OWASP AISVS", "version": self.standard_version},
            "target": self.target,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_s, 3),
            "files_scanned": self.files_scanned,
            "max_level": self.max_level,
            "detected_features": self.features,
            "summary": self.counts(),
            "suppressed_findings": self.suppressed,
            "warnings": self.warnings,
            "findings": [f.to_dict() for f in self.findings],
            "requirements": [r.to_dict() for r in self.results],
        }
