"""Command-line interface for the OWASP AISVS scanner."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import catalog
from .engine import SCANNER_VERSION, ScanConfig, Scanner
from .models import Severity
from .reporters import (
    render_csv,
    render_html,
    render_json,
    render_markdown,
    render_sarif,
    render_terminal,
)
from .rules import all_rules


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aisvs-scan",
        description="OWASP Artificial Intelligence Security Verification Standard (AISVS) Scanner",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {SCANNER_VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # 1. scan command
    p_scan = subparsers.add_parser("scan", help="Scan repository, code or model configs against AISVS")
    p_scan.add_argument("target", nargs="?", default=".", help="Target directory or file to scan (default: current dir)")
    p_scan.add_argument("-l", "--level", type=int, choices=[1, 2, 3], default=3, help="Max AISVS assurance level (1, 2, or 3; default: 3)")
    p_scan.add_argument("-f", "--format", choices=["terminal", "json", "sarif", "markdown", "html", "csv"], default="terminal", help="Report format (default: terminal)")
    p_scan.add_argument("-o", "--output", help="Write report to file instead of stdout")
    p_scan.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], default="low", help="Minimum severity finding to report (default: low)")
    p_scan.add_argument("--min-confidence", choices=["low", "medium", "high"], default="low", help="Minimum confidence finding to report (default: low)")
    p_scan.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], help="Exit with non-zero status code if findings at or above this severity are found")
    p_scan.add_argument("-e", "--exclude", action="append", default=[], help="Exclude glob patterns (can be repeated)")
    p_scan.add_argument("--standard-version", choices=["1.01", "1.02-dev"], default=catalog.DEFAULT_VERSION, help=f"AISVS standard version to audit against (default: {catalog.DEFAULT_VERSION})")
    p_scan.add_argument("--catalog", help="Custom path to AISVS JSON catalog file")
    p_scan.add_argument("--rule", action="append", help="Filter by specific rule ID (can be repeated)")
    p_scan.add_argument("--ignore-rule", action="append", help="Ignore specific rule ID (can be repeated)")

    # 2. list-requirements command
    p_reqs = subparsers.add_parser("list-requirements", help="List all AISVS requirements from the official catalog")
    p_reqs.add_argument("-c", "--chapter", help="Filter by chapter (e.g. C2, C9, C10)")
    p_reqs.add_argument("-l", "--level", type=int, choices=[1, 2, 3], help="Filter by verification level")
    p_reqs.add_argument("--standard-version", choices=["1.01", "1.02-dev"], default=catalog.DEFAULT_VERSION)

    # 3. list-rules command
    p_rules = subparsers.add_parser("list-rules", help="List all built-in security detection rules and evidence indicators")
    p_rules.add_argument("--kind", choices=["violation", "evidence", "all"], default="all")

    # 4. sync command
    p_sync = subparsers.add_parser("sync", help="Sync latest AISVS definitions from GitHub (OWASP/AISVS)")
    p_sync.add_argument("--standard-version", choices=["1.01", "1.02-dev"], default="1.01")
    p_sync.add_argument("--ref", default="main", help="Git branch or tag (default: main)")

    args = parser.parse_args(argv)

    if not args.command:
        # Default action when invoked with no subcommand is to run scan
        return cmd_scan(parser.parse_args(["scan"] + (argv or [])))

    if args.command == "scan":
        return cmd_scan(args)
    elif args.command == "list-requirements":
        return cmd_list_requirements(args)
    elif args.command == "list-rules":
        return cmd_list_rules(args)
    elif args.command == "sync":
        return cmd_sync(args)

    return 0


def cmd_scan(args) -> int:
    target_path = Path(args.target)
    if not target_path.exists():
        sys.stderr.write(f"Error: Target path does not exist: {target_path}\n")
        return 2

    config = ScanConfig(
        target=target_path,
        level=args.level,
        version=args.standard_version,
        catalog_path=args.catalog,
        exclude_globs=args.exclude,
        min_severity=Severity(args.min_severity),
        min_confidence=args.min_confidence,
        rules_filter=args.rule,
        ignored_rules=args.ignore_rule,
        fail_on=Severity(args.fail_on) if args.fail_on else None,
    )

    scanner = Scanner(config)
    result = scanner.scan()

    # Output selection
    out_file = None
    if args.output:
        out_file = open(args.output, "w", encoding="utf-8")
        stream = out_file
    else:
        stream = sys.stdout

    try:
        fmt = args.format
        if fmt == "terminal":
            render_terminal(result, stream)
        elif fmt == "json":
            render_json(result, stream)
        elif fmt == "sarif":
            render_sarif(result, stream)
        elif fmt == "markdown":
            render_markdown(result, stream)
        elif fmt == "html":
            render_html(result, stream)
        elif fmt == "csv":
            render_csv(result, stream)
    finally:
        if out_file:
            out_file.close()

    # Fail on severity threshold
    if config.fail_on:
        threshold_rank = config.fail_on.rank
        violating = [f for f in result.findings if f.severity.rank >= threshold_rank]
        if violating:
            if not args.output:
                sys.stderr.write(
                    f"\n[!] Failure: {len(violating)} finding(s) met or exceeded --fail-on={config.fail_on.value}\n"
                )
            return 1

    return 0


def cmd_list_requirements(args) -> int:
    cat = catalog.load(version=args.standard_version)
    reqs = cat.active
    if args.chapter:
        ch = args.chapter.upper()
        if not ch.startswith("C"):
            ch = f"C{ch}"
        reqs = [r for r in reqs if r.chapter == ch]
    if args.level:
        reqs = [r for r in reqs if r.level == args.level]

    print(f"\nOWASP AISVS v{cat.version} Requirements ({len(reqs)} items):\n")
    print(f"{'#':<10} {'Level':<7} {'Chapter':<6} {'Description'}")
    print(f"{'-'*10} {'-'*7} {'-'*6} {'-'*70}")
    for r in reqs:
        desc = (r.text[:67] + "...") if len(r.text) > 70 else r.text
        print(f"{r.id:<10} L{r.level:<6} {r.chapter:<6} {desc}")
    print()
    return 0


def cmd_list_rules(args) -> int:
    rules = all_rules()
    if args.kind != "all":
        rules = [r for r in rules if r.kind == args.kind]

    print(f"\nAISVS Scanner Detection Rules ({len(rules)} items):\n")
    print(f"{'Rule ID':<20} {'Kind':<10} {'Severity':<10} {'AISVS Reqs':<20} {'Title'}")
    print(f"{'-'*20} {'-'*10} {'-'*10} {'-'*20} {'-'*40}")
    for r in sorted(rules, key=lambda x: x.id):
        reqs_str = ", ".join(r.reqs[:3])
        if len(r.reqs) > 3:
            reqs_str += "..."
        sev = r.severity.value if r.kind == "violation" else "-"
        print(f"{r.id:<20} {r.kind:<10} {sev:<10} {reqs_str:<20} {r.title}")
    print()
    return 0


def cmd_sync(args) -> int:
    print(f"Syncing OWASP AISVS v{args.standard_version} from GitHub ({catalog.REPO}@{args.ref})...")
    try:
        out = catalog.sync(args.standard_version, ref=args.ref)
        print(f"✓ Successfully synced catalog to {out}")
        return 0
    except Exception as e:
        sys.stderr.write(f"Error syncing catalog: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
