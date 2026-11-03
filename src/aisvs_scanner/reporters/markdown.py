"""Markdown audit report generator."""
from __future__ import annotations

from typing import Dict, TextIO

from ..models import ScanResult, Status


def render_markdown(result: ScanResult, out: TextIO):
    counts = result.counts()
    total_evaluated = sum(counts.values())

    out.write(f"# OWASP AISVS Security Verification Audit Report\n\n")
    out.write(f"- **Standard**: [OWASP Artificial Intelligence Security Verification Standard (AISVS) v{result.standard_version}](https://github.com/OWASP/AISVS)\n")
    out.write(f"- **Target**: `{result.target}`\n")
    out.write(f"- **Scanned Files**: {result.files_scanned}\n")
    out.write(f"- **Max Verification Level**: Level {result.max_level}\n")
    out.write(f"- **Timestamp**: {result.started_at}\n\n")

    out.write("## Executive Summary\n\n")
    out.write("| Verification Status | Count | Percentage |\n")
    out.write("| :--- | :---: | :---: |\n")
    for s in Status:
        cnt = counts[s.value]
        pct = (cnt / total_evaluated * 100) if total_evaluated else 0
        out.write(f"| **{s.value}** | {cnt} | {pct:.1f}% |\n")
    out.write("\n")

    # Detected features
    out.write("### Detected AI Profile\n\n")
    if result.features:
        for feat, samples in sorted(result.features.items()):
            out.write(f"- **{feat}**: `{', '.join(samples[:2])}`\n")
    else:
        out.write("No specialized AI frameworks detected in source files.\n")
    out.write("\n")

    # Security Violations
    out.write(f"## Security Findings ({len(result.findings)})\n\n")
    if not result.findings:
        out.write("No security violations detected against applicable static verification checks.\n\n")
    else:
        out.write("| Severity | Rule | Finding | Location | AISVS Controls |\n")
        out.write("| :---: | :--- | :--- | :--- | :---: |\n")
        for f in result.findings:
            reqs = ", ".join(f.requirements)
            out.write(f"| **{f.severity.value.upper()}** | `{f.rule_id}` | {f.title} | `{f.location.file}:{f.location.line}` | {reqs} |\n")
        out.write("\n")

        out.write("### Finding Details & Remediation Guidance\n\n")
        for i, f in enumerate(result.findings, 1):
            out.write(f"#### {i}. [{f.severity.value.upper()}] {f.title} (`{f.rule_id}`)\n\n")
            out.write(f"- **Location**: `{f.location.file}:{f.location.line}`\n")
            out.write(f"- **Relevant AISVS Requirements**: {', '.join(f.requirements)}\n")
            out.write(f"- **Description**: {f.message}\n")
            if f.location.snippet:
                out.write(f"```text\n{f.location.snippet}\n```\n")
            if f.remediation:
                out.write(f"- **Remediation**: {f.remediation}\n\n")

    # Requirements Matrix
    out.write("## Detailed Requirements Verification Matrix\n\n")
    out.write("| # | Level | Chapter | Requirement | Status | Details |\n")
    out.write("| :---: | :---: | :--- | :--- | :---: | :--- |\n")
    for r in result.results:
        req = r.requirement
        out.write(f"| **{req.id}** | L{req.level} | {req.chapter} | {req.text} | **{r.status.value}** | {r.note} |\n")
    out.write("\n")
