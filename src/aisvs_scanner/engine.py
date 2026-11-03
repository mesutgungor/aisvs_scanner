"""Core audit and verification engine for AISVS."""
from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from . import catalog
from .analyzers import artifact as artifact_analyzer
from .analyzers import mcp_config as mcp_analyzer
from .analyzers import taint as taint_analyzer
from .models import Evidence, Finding, Location, Requirement, RequirementResult, ScanResult, Severity, Status
from .profile import detect as detect_features
from .rules import all_rules
from .rules.base import Rule
from .walker import FileCtx, walk

SCANNER_VERSION = "1.0.0"

_SUPPRESSION_RE = re.compile(
    r"(?:#|//|<!--)\s*(?:aisvs:ignore|aisvs-ignore|noqa|nosec)(?::|\s+)?([A-Za-z0-9_-]*)",
    re.I,
)

# Requirements that require purely organizational, legal, physical, or human verification
MANUAL_REQUIREMENTS: Set[str] = {
    "1.2.1",  # labeling platform access controls
    "3.4.1",  # AI runtime environment boundaries
    "4.2.1",  # GPU firmware version pinning/attestation
    "4.2.5",  # accelerator interconnect topology
    "6.2.1",  # organizational AI BOM publishing policy
    "9.2.5",  # self-modification boundaries (unless static code)
    "9.5.6",  # operational session re-evaluation
    "11.1.1", # base model alignment training verification
    "11.2.1", # sensitive attributes policy verification
    "12.4.1", # autonomous threat landscape assessment
}

# Mapping requirement IDs or prefixes to required feature tags
REQUIREMENT_FEATURE_GATES: Dict[str, Tuple[str, ...]] = {
    "C10": ("mcp_server", "mcp_client"),
    "C8": ("rag", "agent"),
    "C9": ("agent", "mcp_server", "mcp_client"),
    "1.1": ("training",),
    "1.2": ("training",),
    "1.3": ("training",),
    "3.5": ("training", "rlhf"),
    "4.2": ("training", "serving"),
    "4.3": ("edge",),
    "5.3": ("serving", "llm"),
    "7.4": ("rag", "media_generation"),
    "11.2.4": ("training",),
    "11.2.5": ("training", "model_loading"),
    "12.1.4": ("rag",),
    "12.5.1": ("training",),
    "12.5.2": ("training",),
}


@dataclass
class ScanConfig:
    target: Path
    level: int = 3
    version: str = catalog.DEFAULT_VERSION
    catalog_path: Optional[str] = None
    exclude_globs: Optional[List[str]] = None
    min_severity: Severity = Severity.LOW
    min_confidence: str = "low"  # low, medium, high
    rules_filter: Optional[List[str]] = None
    ignored_rules: Optional[List[str]] = None
    fail_on: Optional[Severity] = None


class Scanner:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.catalog = catalog.load(version=config.version, path=config.catalog_path)
        self.rules: List[Rule] = all_rules()
        if config.rules_filter:
            rf = set(config.rules_filter)
            self.rules = [r for r in self.rules if r.id in rf]
        if config.ignored_rules:
            ir = set(config.ignored_rules)
            self.rules = [r for r in self.rules if r.id not in ir]

    def scan(self) -> ScanResult:
        start_time = time.time()
        target_path = self.config.target.resolve()

        # Step 1: Collect files
        all_files: List[FileCtx] = list(
            walk(
                target_path,
                exclude_globs=self.config.exclude_globs,
                include_artifacts=True,
            )
        )

        # Step 2: Detect AI profile / component usage
        features = detect_features(all_files)

        # Step 3: Run rule engine, AST taint analyzer, MCP config analyzer, and artifact analyzer
        raw_findings: List[Finding] = []
        raw_evidence: List[Evidence] = []
        suppressed_count = 0

        feature_set = set(features.keys())

        for f in all_files:
            # Check for file-level or line-level suppressions
            file_suppressions = self._get_file_suppressions(f)

            # 3a. Declarative pattern & call rules
            for r in self.rules:
                if not r.applies_to(f, feature_set):
                    continue
                for line, detail in r.matches(f):
                    if self._is_suppressed(r.id, line, file_suppressions):
                        suppressed_count += 1
                        continue

                    if r.kind == "violation":
                        raw_findings.append(r.finding(f, line, detail))
                    elif r.kind == "evidence":
                        raw_evidence.append(r.evidence(f, line))

            # 3b. Specialized AST Taint Analyzer (Python)
            if f.lang in {"python", "notebook"}:
                taint_findings = taint_analyzer.analyze(f)
                for fnd in taint_findings:
                    if self._is_suppressed(fnd.rule_id, fnd.location.line, file_suppressions):
                        suppressed_count += 1
                        continue
                    raw_findings.append(fnd)

            # 3c. MCP Config Analyzer (JSON)
            if f.lang == "json":
                mcp_fnds, mcp_evs = mcp_analyzer.analyze(f)
                for fnd in mcp_fnds:
                    if self._is_suppressed(fnd.rule_id, fnd.location.line, file_suppressions):
                        suppressed_count += 1
                        continue
                    raw_findings.append(fnd)
                raw_evidence.extend(mcp_evs)

            # 3d. Artifact Binary Analyzer (Weights / Serialized Models)
            if f.lang == "artifact":
                art_fnds, art_evs = artifact_analyzer.analyze(f)
                for fnd in art_fnds:
                    raw_findings.append(fnd)
                raw_evidence.extend(art_evs)

        # Step 4: Filter findings by severity and confidence
        filtered_findings: List[Finding] = [
            f for f in raw_findings
            if f.severity.rank >= self.config.min_severity.rank
            and self._confidence_rank(f.confidence) >= self._confidence_rank(self.config.min_confidence)
        ]

        # Step 5: Map findings & evidence to AISVS requirements
        results = self._evaluate_requirements(filtered_findings, raw_evidence, feature_set)

        duration = time.time() - start_time

        return ScanResult(
            target=str(target_path),
            standard_version=self.catalog.version,
            scanner_version=SCANNER_VERSION,
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
            duration_s=duration,
            files_scanned=len(all_files),
            features=features,
            findings=filtered_findings,
            results=results,
            max_level=self.config.level,
            suppressed=suppressed_count,
        )

    def _confidence_rank(self, conf: str) -> int:
        return {"low": 1, "medium": 2, "high": 3}.get(conf.lower(), 1)

    def _get_file_suppressions(self, f: FileCtx) -> Dict[int, Set[str]]:
        suppressions: Dict[int, Set[str]] = defaultdict(set)
        for i, line in enumerate(f.lines, 1):
            for m in _SUPPRESSION_RE.finditer(line):
                target_rule = m.group(1).strip()
                suppressions[i].add(target_rule if target_rule else "*")
        return suppressions

    def _is_suppressed(self, rule_id: str, line: int, suppressions: Dict[int, Set[str]]) -> bool:
        if line in suppressions:
            rules = suppressions[line]
            return "*" in rules or rule_id in rules or rule_id.split("-")[0] in rules
        return False

    def _is_feature_applicable(self, req: Requirement, features: Set[str]) -> bool:
        # If no AI features detected in repository at all, general AI rules apply if scanned directly
        if not features:
            return True

        for prefix, required_feats in REQUIREMENT_FEATURE_GATES.items():
            if req.chapter == prefix or req.section.startswith(prefix) or req.id.startswith(prefix):
                if not any(rf in features for rf in required_feats):
                    return False
        return True

    def _evaluate_requirements(
        self,
        findings: List[Finding],
        evidences: List[Evidence],
        features: Set[str],
    ) -> List[RequirementResult]:
        req_findings: Dict[str, List[Finding]] = defaultdict(list)
        req_evidence: Dict[str, List[Evidence]] = defaultdict(list)

        for f in findings:
            for rid in f.requirements:
                req_findings[rid].append(f)

        for e in evidences:
            for rid in e.requirements:
                req_evidence[rid].append(e)

        results: List[RequirementResult] = []

        for req in self.catalog.all:
            # Skip requirements higher than configured level
            if req.retired or (req.level > self.config.level and req.level > 0):
                continue

            findings_for_req = req_findings.get(req.id, [])
            evidence_for_req = req_evidence.get(req.id, [])

            if not self._is_feature_applicable(req, features):
                results.append(
                    RequirementResult(
                        requirement=req,
                        status=Status.NA,
                        note="Feature not detected in codebase (e.g. MCP/RAG/Agents/Training)",
                    )
                )
                continue

            if findings_for_req:
                results.append(
                    RequirementResult(
                        requirement=req,
                        status=Status.FAIL,
                        findings=findings_for_req,
                        evidence=evidence_for_req,
                        note=f"{len(findings_for_req)} security weakness(es) identified",
                    )
                )
            elif evidence_for_req:
                results.append(
                    RequirementResult(
                        requirement=req,
                        status=Status.PASS,
                        evidence=evidence_for_req,
                        note=f"{len(evidence_for_req)} indicator(s) of defense control verified",
                    )
                )
            elif req.id in MANUAL_REQUIREMENTS:
                results.append(
                    RequirementResult(
                        requirement=req,
                        status=Status.MANUAL,
                        note="Manual process/architectural review required",
                    )
                )
            else:
                results.append(
                    RequirementResult(
                        requirement=req,
                        status=Status.GAP,
                        note="No verified automated control or indicator detected",
                    )
                )

        return results
