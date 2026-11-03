"""Declarative rule DSL.

Two kinds of rules:
  * violation  - a pattern/call that is a concrete weakness  -> Finding (requirement FAIL)
  * evidence   - a pattern that indicates a control exists   -> Evidence (requirement PASS)

Two matching modes:
  * pattern - regex over the full file text (multiline)
  * call    - regex for a callee; the balanced argument text is inspected for
              required (`missing_any`) or forbidden (`forbid`) arguments.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import FrozenSet, Iterable, Iterator, List, Optional, Pattern, Tuple

from ..models import Evidence, Finding, Location, Severity
from ..util import extract_calls
from ..walker import CODE_LANGS, FileCtx

CODE_AND_CONFIG = CODE_LANGS | {
    "yaml", "json", "toml", "config", "dockerfile", "shell", "terraform", "requirements", "gradle", "text",
}
CODE_ONLY = CODE_LANGS
CONFIG_ONLY = {"yaml", "json", "toml", "config", "dockerfile", "shell", "terraform", "gradle"}


_SPREAD_RE = re.compile(r"\*\*\s*\w+|\.\.\.\s*\w+")

FLAGS = re.I | re.M


def _c(p: Optional[str], flags: int = FLAGS) -> Optional[Pattern[str]]:
    return re.compile(p, flags) if p else None


@dataclass
class Rule:
    id: str
    title: str
    reqs: Tuple[str, ...]
    kind: str  # violation | evidence
    severity: Severity = Severity.MEDIUM
    pattern: Optional[str] = None
    callee: Optional[str] = None
    missing_any: Optional[str] = None  # call mode: violation if args match none of these
    forbid: Optional[str] = None  # call mode: violation if args match
    unless_file: Optional[str] = None  # suppress if this appears anywhere in the file
    unless_line: Optional[str] = None  # suppress if this appears on the matching line
    langs: FrozenSet[str] = frozenset(CODE_AND_CONFIG)
    path_globs: Tuple[str, ...] = ()
    requires: Tuple[str, ...] = ()  # run only when any of these features is present
    message: str = ""
    remediation: str = ""
    confidence: str = "medium"
    case_sensitive: bool = False
    include_comments: bool = False
    max_hits_per_file: int = 5
    _rx: dict = field(default_factory=dict, repr=False)

    def __post_init__(self):
        fl = re.M if self.case_sensitive else FLAGS
        self._rx = {
            "pattern": _c(self.pattern, fl | (re.S if self.pattern and "(?s)" in self.pattern else 0)),
            "callee": _c(self.callee, fl),
            "missing_any": _c(self.missing_any, fl),
            "forbid": _c(self.forbid, fl),
            "unless_file": _c(self.unless_file, fl),
            "unless_line": _c(self.unless_line, fl),
        }

    # -- applicability -----------------------------------------------------
    def applies_to(self, f: FileCtx, features: Iterable[str]) -> bool:
        if f.lang not in self.langs:
            return False
        if self.requires and not set(self.requires) & set(features):
            return False
        if self.path_globs:
            rel = f.rel.replace("\\", "/")
            if not any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(f.name, g) or fnmatch.fnmatch(rel, "*/" + g) for g in self.path_globs):
                return False
        return True

    # -- matching ----------------------------------------------------------
    def matches(self, f: FileCtx) -> Iterator[Tuple[int, str]]:
        """Yield (line, detail) for each match in a file."""
        text = f.text
        if not text:
            return
        if self._rx["unless_file"] and self._rx["unless_file"].search(text):
            return
        hits = 0
        if self._rx["callee"]:
            for off, callee, args in extract_calls(text, self._rx["callee"]):
                line = f.line_of(off)
                if self._is_comment(f, line):
                    continue
                bad = False
                if self._rx["forbid"] and self._rx["forbid"].search(args):
                    bad = True
                elif self._rx["missing_any"] and not self._rx["missing_any"].search(args) and not _SPREAD_RE.search(args):
                    bad = True
                if bad:
                    if self._rx["unless_line"] and self._rx["unless_line"].search(f.lines[line - 1] if line <= len(f.lines) else ""):
                        continue
                    yield line, callee.strip()
                    hits += 1
                    if hits >= self.max_hits_per_file:
                        return
            return
        rx = self._rx["pattern"]
        if rx is None:
            return
        for m in rx.finditer(text):
            line = f.line_of(m.start())
            if self._is_comment(f, line):
                continue
            src_line = f.lines[line - 1] if line <= len(f.lines) else ""
            if self._rx["unless_line"] and self._rx["unless_line"].search(src_line):
                continue
            yield line, m.group(0)[:80]
            hits += 1
            if hits >= self.max_hits_per_file:
                return

    def _is_comment(self, f: FileCtx, line: int) -> bool:
        if self.include_comments or line > len(f.lines):
            return False
        s = f.lines[line - 1].lstrip()
        if f.lang in {"python", "notebook", "yaml", "dockerfile", "shell", "config", "toml", "requirements", "ruby", "terraform"}:
            return s.startswith("#")
        if f.lang in CODE_LANGS:
            return s.startswith(("//", "*", "/*"))
        return False

    # -- result builders ---------------------------------------------------
    def finding(self, f: FileCtx, line: int, detail: str) -> Finding:
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            requirements=self.reqs,
            message=(self.message or self.title) + (f" (`{detail}`)" if detail else ""),
            location=Location(f.rel, line, f.snippet(line)),
            remediation=self.remediation,
            confidence=self.confidence,
        )

    def evidence(self, f: FileCtx, line: int) -> Evidence:
        return Evidence(self.id, self.title, self.reqs, Location(f.rel, line, f.snippet(line)))


S = Severity


def V(id, title, reqs, severity=S.MEDIUM, **kw) -> Rule:
    return Rule(id=id, title=title, reqs=tuple(reqs.split()) if isinstance(reqs, str) else tuple(reqs), kind="violation", severity=severity, **kw)


def E(id, title, reqs, **kw) -> Rule:
    return Rule(id=id, title=title, reqs=tuple(reqs.split()) if isinstance(reqs, str) else tuple(reqs), kind="evidence", severity=S.INFO, **kw)
