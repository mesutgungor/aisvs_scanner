"""ANSI color-formatted terminal reporter."""
from __future__ import annotations

import sys
from typing import Dict, List, TextIO

from ..models import Finding, RequirementResult, ScanResult, Severity, Status

# ANSI codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

SEV_COLORS = {
    Severity.CRITICAL: RED + BOLD,
    Severity.HIGH: RED,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: CYAN,
    Severity.INFO: DIM,
}

STATUS_COLORS = {
    Status.FAIL: RED + BOLD,
    Status.PASS: GREEN + BOLD,
    Status.GAP: YELLOW,
    Status.MANUAL: BLUE,
    Status.NA: DIM,
}


def render_terminal(result: ScanResult, out: TextIO = sys.stdout, verbose: bool = False):
    w = out.write

    w(f"\n{BOLD}{CYAN}=== OWASP AISVS AI Security Verification Standard Scanner ==={RESET}\n")
    w(f"{DIM}Standard: OWASP AISVS v{result.standard_version} (Level 1-{result.max_level}) | Scanner v{result.scanner_version}{RESET}\n")
    w(f"{DIM}Target: {result.target} | Scanned {result.files_scanned} files in {result.duration_s:.2f}s{RESET}\n\n")

    # Detected AI features
    if result.features:
        w(f"{BOLD}Detected AI Components:{RESET} ")
        tags = []
        for feat in sorted(result.features.keys()):
            tags.append(f"{GREEN}{feat}{RESET}")
        w(", ".join(tags) + "\n\n")
    else:
        w(f"{DIM}No specialized AI framework components detected (evaluated against baseline controls).{RESET}\n\n")

    # High-level summary counts
    counts = result.counts()
    w(f"{BOLD}Verification Summary:{RESET}\n")
    w(f"  {STATUS_COLORS[Status.PASS]}PASS:   {counts['PASS']:3d}{RESET} (Verified defense indicators present)\n")
    w(f"  {STATUS_COLORS[Status.FAIL]}FAIL:   {counts['FAIL']:3d}{RESET} (Actionable security violations detected)\n")
    w(f"  {STATUS_COLORS[Status.GAP]}GAP:    {counts['GAP']:3d}{RESET} (Applicable controls missing static indicators)\n")
    w(f"  {STATUS_COLORS[Status.MANUAL]}MANUAL: {counts['MANUAL']:3d}{RESET} (Human/operational verification required)\n")
    w(f"  {STATUS_COLORS[Status.NA]}N/A:    {counts['N/A']:3d}{RESET} (Features not present in target)\n\n")

    # Chapter breakdown
    chapter_counts: Dict[str, Dict[str, int]] = {}
    for r in result.results:
        c_id = r.requirement.chapter
        if c_id not in chapter_counts:
            chapter_counts[c_id] = {s.value: 0 for s in Status}
        chapter_counts[c_id][r.status.value] += 1

    w(f"{BOLD}Chapter Breakdown:{RESET}\n")
    w(f"  {'Chapter':<8} {'PASS':>6} {'FAIL':>6} {'GAP':>6} {'MANUAL':>8} {'N/A':>6}  Title\n")
    w(f"  {'-'*8} {'-'*6} {'-'*6} {'-'*6} {'-'*8} {'-'*6}  {'-'*30}\n")

    chap_titles = {
        "C1": "Training Data Integrity & Traceability",
        "C2": "Input Validation & Prompt Injection",
        "C3": "Model Lifecycle Management",
        "C4": "Infrastructure & Sandboxing",
        "C5": "Access Control & Identity",
        "C6": "Supply Chain & AI BOM",
        "C7": "Model Behavior & Output Safety",
        "C8": "Memory, Embeddings & Vector DB",
        "C9": "Orchestration & Agentic Action",
        "C10": "Model Context Protocol (MCP)",
        "C11": "Adversarial Robustness",
        "C12": "Monitoring & Logging",
    }

    for cid in sorted(chapter_counts.keys(), key=lambda x: int(x[1:])):
        c = chapter_counts[cid]
        title = chap_titles.get(cid, "")
        fail_str = f"{RED}{c['FAIL']:6d}{RESET}" if c['FAIL'] > 0 else f"{c['FAIL']:6d}"
        pass_str = f"{GREEN}{c['PASS']:6d}{RESET}" if c['PASS'] > 0 else f"{c['PASS']:6d}"
        w(f"  {cid:<8} {pass_str} {fail_str} {c['GAP']:6d} {c['MANUAL']:8d} {c['N/A']:6d}  {title}\n")
    w("\n")

    # Detailed Findings list
    if result.findings:
        w(f"{BOLD}{RED}Security Findings ({len(result.findings)}):{RESET}\n")
        w(f"{DIM}{'='*70}{RESET}\n")
        for i, f in enumerate(result.findings, 1):
            sev_col = SEV_COLORS.get(f.severity, WHITE)
            reqs_str = ", ".join(f"AISVS #{r}" for r in f.requirements)
            w(f"\n{BOLD}[{i}] {sev_col}[{f.severity.value.upper()}]{RESET} {BOLD}{f.title}{RESET} ({CYAN}{f.rule_id}{RESET})\n")
            w(f"    {DIM}Location:{RESET}    {f.location.file}:{f.location.line}\n")
            w(f"    {DIM}AISVS Reqs:{RESET}  {reqs_str}\n")
            w(f"    {DIM}Confidence:{RESET}  {f.confidence}\n")
            w(f"    {DIM}Details:{RESET}     {f.message}\n")
            if f.location.snippet:
                w(f"    {DIM}Snippet:{RESET}     {YELLOW}{f.location.snippet}{RESET}\n")
            if f.remediation:
                w(f"    {GREEN}Fix:{RESET}         {f.remediation}\n")
        w("\n")
    else:
        w(f"{GREEN}{BOLD}✓ No critical or high security violations detected!{RESET}\n\n")

    if result.suppressed > 0:
        w(f"{DIM}Note: {result.suppressed} finding(s) were suppressed via inline directives.{RESET}\n\n")
