"""SARIF 2.1.0 reporter for GitHub Code Scanning and CI/CD integrations."""
from __future__ import annotations

import json
from typing import Any, Dict, List, TextIO

from ..models import Finding, ScanResult, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _sarif_level(sev: Severity) -> str:
    if sev in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if sev == Severity.MEDIUM:
        return "warning"
    return "note"


def render_sarif(result: ScanResult, out: TextIO):
    rules_dict: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for f in result.findings:
        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message},
                "help": {
                    "text": f"{f.message}\n\nRemediation:\n{f.remediation}\n\nOWASP AISVS: {', '.join(f.requirements)}"
                },
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
                "properties": {
                    "tags": ["security", "ai", "owasp-aisvs"] + [f"aisvs-{r}" for r in f.requirements]
                },
            }

        sarif_results.append({
            "ruleId": f.rule_id,
            "level": _sarif_level(f.severity),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location.file},
                        "region": {
                            "startLine": max(1, f.location.line),
                            "snippet": {"text": f.location.snippet} if f.location.snippet else None,
                        },
                    }
                }
            ],
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence,
                "requirements": list(f.requirements),
                "remediation": f.remediation,
            },
        })

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "aisvs-scanner",
                        "semanticVersion": result.scanner_version,
                        "informationUri": "https://github.com/OWASP/AISVS",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    json.dump(sarif_doc, out, indent=2, ensure_ascii=False)
    out.write("\n")
