"""JSON reporter for machine-readable output."""
from __future__ import annotations

import json
from typing import TextIO

from ..models import ScanResult


def render_json(result: ScanResult, out: TextIO, indent: int = 2):
    json.dump(result.to_dict(), out, indent=indent, ensure_ascii=False)
    out.write("\n")
