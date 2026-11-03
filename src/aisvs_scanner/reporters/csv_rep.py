"""CSV exporter for AISVS compliance records and spreadsheets."""
from __future__ import annotations

import csv
from typing import TextIO

from ..models import ScanResult


def render_csv(result: ScanResult, out: TextIO):
    writer = csv.writer(out)
    writer.writerow([
        "Requirement ID",
        "Level",
        "Chapter",
        "Section",
        "Requirement Text",
        "Status",
        "Note",
        "Findings Count",
        "Evidence Count",
    ])

    for r in result.results:
        req = r.requirement
        writer.writerow([
            req.id,
            req.level,
            req.chapter,
            req.section,
            req.text,
            r.status.value,
            r.note,
            len(r.findings),
            len(r.evidence),
        ])
