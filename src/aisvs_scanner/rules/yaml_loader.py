"""Zero-dependency YAML loader and serializer for AISVS declarative rules.

Supports loading rules from bundled `data/rules/*.yaml` files as well as custom
user-provided `.yaml` / `.yml` files or directories, without requiring PyYAML.
If PyYAML is installed, both parsers produce identical Rule objects.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple, Union

from ..models import Severity
from .base import CODE_AND_CONFIG, CODE_ONLY, CONFIG_ONLY, Rule

RULES_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "rules"

LANG_GROUPS: Dict[str, FrozenSet[str]] = {
    "all": frozenset(CODE_AND_CONFIG),
    "code_and_config": frozenset(CODE_AND_CONFIG),
    "code": frozenset(CODE_ONLY),
    "code_only": frozenset(CODE_ONLY),
    "config_only": frozenset(CONFIG_ONLY),
}


# ---------------------------------------------------------------------------
# Pure-Python minimal YAML parser for rule files (zero external dependencies)
# ---------------------------------------------------------------------------

def _unquote_scalar(val: str) -> Any:
    """Parse a single-line YAML scalar (string, int, bool, inline list)."""
    val = val.strip()
    if not val:
        return ""
    # Single-quoted YAML string: '' escapes a literal single quote, backslashes are literal
    if len(val) >= 2 and val.startswith("'") and val.endswith("'"):
        return val[1:-1].replace("''", "'")
    # Double-quoted YAML/JSON string
    if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
        try:
            return json.loads(val)
        except Exception:
            return val[1:-1]
    # Inline list: [a, b, c]
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_unquote_scalar(item) for item in _split_inline_list(inner)]
    low = val.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in {"null", "none", "~"}:
        return None
    if re.fullmatch(r"-?\d+", val):
        return int(val)
    # Strip trailing inline comment for unquoted scalars
    m = re.search(r"\s+#", val)
    if m:
        val = val[: m.start()].rstrip()
    return val


def _split_inline_list(text: str) -> List[str]:
    items: List[str] = []
    cur: List[str] = []
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            cur.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(text):
                i += 1
                cur.append(text[i])
            elif ch == quote:
                if quote == "'" and i + 1 < len(text) and text[i + 1] == "'":
                    i += 1
                    cur.append(text[i])
                else:
                    quote = ""
        else:
            if ch in ("'", '"'):
                quote = ch
                cur.append(ch)
            elif ch == ",":
                items.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
        i += 1
    if cur:
        items.append("".join(cur).strip())
    return items


def parse_yaml_PurePython(text: str) -> Dict[str, Any]:
    """Parse a YAML rule document into `{"rules": [dict, ...]}` using only stdlib."""
    lines = text.splitlines()
    n = len(lines)
    i = 0
    rules: List[Dict[str, Any]] = []
    current_rule: Optional[Dict[str, Any]] = None

    while i < n:
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped == "---":
            i += 1
            continue

        indent = len(raw) - len(raw.lstrip(" "))

        # Top-level `rules:` header (or metadata keys before `rules:`)
        if indent == 0 and stripped.startswith("rules:"):
            rest = stripped[len("rules:"):].strip()
            if rest == "[]":
                return {"rules": []}
            i += 1
            continue

        # Start of a new rule item: `- id: ...` or `-`
        m_item = re.match(r"^(\s*)-\s*(.*)$", raw)
        if m_item and (current_rule is None or len(m_item.group(1)) <= 4):
            item_indent = len(m_item.group(1))
            rest = m_item.group(2).strip()
            current_rule = {}
            rules.append(current_rule)
            if rest:
                i = _parse_key_val_into(rest, lines, i, item_indent + 2, current_rule)
            else:
                i += 1
            continue

        # Key-value inside current rule
        if current_rule is not None:
            i = _parse_key_val_into(stripped, lines, i, indent, current_rule)
            continue

        i += 1

    return {"rules": rules}


def _parse_key_val_into(
    line_content: str,
    lines: List[str],
    idx: int,
    key_indent: int,
    target: Dict[str, Any],
) -> int:
    m = re.match(r"^([A-Za-z0-9_]+)\s*:\s*(.*)$", line_content)
    if not m:
        return idx + 1
    key, val_str = m.group(1), m.group(2).strip()
    n = len(lines)

    # Block scalar: `|` or `|-` or `>` or `>-`
    if val_str in {"|", "|-", "|+", ">", ">-"}:
        fold = val_str.startswith(">")
        keep_trailing = val_str.endswith("+")
        block_lines: List[str] = []
        j = idx + 1
        block_indent: Optional[int] = None
        while j < n:
            b_raw = lines[j]
            if not b_raw.strip():
                block_lines.append("")
                j += 1
                continue
            cur_ind = len(b_raw) - len(b_raw.lstrip(" "))
            if cur_ind <= key_indent:
                break
            if block_indent is None:
                block_indent = cur_ind
            block_lines.append(b_raw[block_indent:] if len(b_raw) >= block_indent else b_raw.lstrip(" "))
            j += 1
        while block_lines and block_lines[-1] == "" and not keep_trailing:
            block_lines.pop()
        if fold:
            target[key] = " ".join(block_lines)
        else:
            target[key] = "\n".join(block_lines)
        return j

    # Empty value followed by block list (`- item`)
    if not val_str:
        items: List[Any] = []
        j = idx + 1
        while j < n:
            b_raw = lines[j]
            b_strip = b_raw.strip()
            if not b_strip or b_strip.startswith("#"):
                j += 1
                continue
            cur_ind = len(b_raw) - len(b_raw.lstrip(" "))
            if cur_ind < key_indent:
                break
            if cur_ind == key_indent and not b_strip.startswith("-"):
                break
            m_li = re.match(r"^\s*-\s+(.*)$", b_raw)
            if m_li:
                items.append(_unquote_scalar(m_li.group(1)))
                j += 1
            else:
                break
        target[key] = items
        return j

    target[key] = _unquote_scalar(val_str)
    return idx + 1


def load_yaml_text(text: str) -> Dict[str, Any]:
    """Parse YAML text using PyYAML if available, falling back to pure-Python parser."""
    try:
        import yaml  # type: ignore
        doc = yaml.safe_load(text)
        if isinstance(doc, list):
            return {"rules": doc}
        if isinstance(doc, dict):
            return doc
    except ImportError:
        pass
    return parse_yaml_PurePython(text)


# ---------------------------------------------------------------------------
# Rule Hydration & Validation
# ---------------------------------------------------------------------------

def _resolve_langs(raw_langs: Any) -> FrozenSet[str]:
    if not raw_langs:
        return frozenset(CODE_AND_CONFIG)
    if isinstance(raw_langs, str):
        raw_langs = [raw_langs]
    out: set[str] = set()
    for item in raw_langs:
        s = str(item).strip().lower()
        if s in LANG_GROUPS:
            out.update(LANG_GROUPS[s])
        else:
            out.add(s)
    return frozenset(out)


def _resolve_str_tuple(val: Any) -> Tuple[str, ...]:
    if not val:
        return ()
    if isinstance(val, str):
        return tuple(x for x in re.split(r"[\s,]+", val.strip()) if x)
    if isinstance(val, (list, tuple)):
        return tuple(str(x).strip() for x in val if str(x).strip())
    return ()


def rule_from_dict(d: Dict[str, Any], source: str = "<yaml>") -> Rule:
    """Validate a raw rule dictionary and construct a `Rule` instance."""
    if not isinstance(d, dict):
        raise ValueError(f"{source}: rule entry must be a mapping, got {type(d).__name__}")

    rid = str(d.get("id", "")).strip()
    if not rid:
        raise ValueError(f"{source}: rule is missing required 'id' field")

    title = str(d.get("title", "")).strip()
    if not title:
        raise ValueError(f"{source} ({rid}): rule is missing required 'title' field")

    reqs = _resolve_str_tuple(d.get("requirements") or d.get("reqs"))
    if not reqs:
        raise ValueError(f"{source} ({rid}): rule is missing required 'requirements' field")

    kind = str(d.get("kind", "violation")).strip().lower()
    if kind not in {"violation", "evidence"}:
        raise ValueError(f"{source} ({rid}): 'kind' must be 'violation' or 'evidence', got '{kind}'")

    default_sev = "info" if kind == "evidence" else "medium"
    sev_str = str(d.get("severity", default_sev)).strip().lower()
    try:
        severity = Severity(sev_str)
    except ValueError:
        raise ValueError(
            f"{source} ({rid}): invalid severity '{sev_str}' (must be info, low, medium, high, or critical)"
        )

    raw_pattern = d.get("pattern") if d.get("pattern") is not None else d.get("patterns")
    if isinstance(raw_pattern, (list, tuple)):
        pattern = "|".join(f"(?:{p})" for p in raw_pattern if p)
    elif raw_pattern is not None:
        pattern = str(raw_pattern)
    else:
        pattern = None
    callee = d.get("callee")
    if not pattern and not callee:
        raise ValueError(f"{source} ({rid}): rule must define either 'pattern'/'patterns' or 'callee'")

    conf = str(d.get("confidence", "medium")).strip().lower()
    if conf not in {"low", "medium", "high"}:
        raise ValueError(f"{source} ({rid}): invalid confidence '{conf}' (must be low, medium, or high)")

    try:
        return Rule(
            id=rid,
            title=title,
            reqs=reqs,
            kind=kind,
            severity=severity,
            pattern=str(pattern) if pattern is not None else None,
            callee=str(callee) if callee is not None else None,
            missing_any=str(d["missing_any"]) if d.get("missing_any") is not None else None,
            forbid=str(d["forbid"]) if d.get("forbid") is not None else None,
            unless_file=str(d["unless_file"]) if d.get("unless_file") is not None else None,
            unless_line=str(d["unless_line"]) if d.get("unless_line") is not None else None,
            langs=_resolve_langs(d.get("langs")),
            path_globs=_resolve_str_tuple(d.get("path_globs")),
            requires=_resolve_str_tuple(d.get("requires")),
            message=str(d.get("message", "")),
            remediation=str(d.get("remediation", "")),
            confidence=conf,
            case_sensitive=bool(d.get("case_sensitive", False)),
            include_comments=bool(d.get("include_comments", False)),
            max_hits_per_file=int(d.get("max_hits_per_file", 5)),
        )
    except re.error as exc:
        raise ValueError(f"{source} ({rid}): invalid regular expression: {exc}") from exc


def load_rules_from_file(path: Union[str, Path]) -> List[Rule]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    doc = load_yaml_text(text)
    raw_rules = doc.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ValueError(f"{p}: 'rules' must be a list")
    return [rule_from_dict(item, source=str(p)) for item in raw_rules]


def load_rules_from_path(path: Union[str, Path]) -> List[Rule]:
    """Load rules from a single YAML file or recursively from a directory of YAML files."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Rules path does not exist: {p}")
    if p.is_file():
        return load_rules_from_file(p)
    rules: List[Rule] = []
    files = sorted(list(p.glob("*.yaml")) + list(p.glob("*.yml")))
    for f in files:
        rules.extend(load_rules_from_file(f))
    return rules


# ---------------------------------------------------------------------------
# YAML Serializer (for exporting rules and generating bundled rule packs)
# ---------------------------------------------------------------------------

_SIMPLE_SCALAR_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
_YAML_KEYWORDS = {"true", "false", "null", "none", "yes", "no", "on", "off"}


def _yaml_quote(s: str) -> str:
    """Format a string as an unquoted identifier if safe, or a single-quoted YAML scalar."""
    if _SIMPLE_SCALAR_RE.match(s) and s.lower() not in _YAML_KEYWORDS:
        return s
    escaped = s.replace("'", "''")
    return f"'{escaped}'"


def _compact_langs(langs: FrozenSet[str]) -> Union[str, List[str]]:
    if langs == frozenset(CODE_AND_CONFIG):
        return "all"
    if langs == frozenset(CODE_ONLY):
        return "code"
    if langs == frozenset(CONFIG_ONLY):
        return "config_only"
    if langs > frozenset(CODE_ONLY) and len(langs - frozenset(CODE_ONLY)) <= 4:
        extra = sorted(langs - frozenset(CODE_ONLY))
        return ["code"] + extra
    return sorted(langs)


def rule_to_dict(r: Rule) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "id": r.id,
        "title": r.title,
        "kind": r.kind,
        "requirements": list(r.reqs),
    }
    if r.kind == "violation" or r.severity != Severity.INFO:
        d["severity"] = r.severity.value
    if r.confidence != "medium":
        d["confidence"] = r.confidence
    langs = _compact_langs(r.langs)
    if langs != "all":
        d["langs"] = langs
    if r.requires:
        d["requires"] = list(r.requires)
    if r.path_globs:
        d["path_globs"] = list(r.path_globs)
    if r.pattern is not None:
        d["pattern"] = r.pattern
    if r.callee is not None:
        d["callee"] = r.callee
    if r.missing_any is not None:
        d["missing_any"] = r.missing_any
    if r.forbid is not None:
        d["forbid"] = r.forbid
    if r.unless_file is not None:
        d["unless_file"] = r.unless_file
    if r.unless_line is not None:
        d["unless_line"] = r.unless_line
    if r.case_sensitive:
        d["case_sensitive"] = True
    if r.include_comments:
        d["include_comments"] = True
    if r.max_hits_per_file != 5:
        d["max_hits_per_file"] = r.max_hits_per_file
    if r.message:
        d["message"] = r.message
    if r.remediation:
        d["remediation"] = r.remediation
    return d


def dump_rules_yaml(rules: Iterable[Rule], header_comment: str = "", header: str = "") -> str:
    """Serialize a sequence of Rules to clean, deterministic YAML."""
    out: List[str] = []
    hdr = header_comment or header
    if hdr:
        for line in hdr.strip().splitlines():
            out.append(f"# {line}" if line else "#")
        out.append("")
    out.append("rules:")
    for r in rules:
        d = rule_to_dict(r)
        first = True
        for k, v in d.items():
            prefix = "  - " if first else "    "
            first = False
            if isinstance(v, bool):
                out.append(f"{prefix}{k}: {'true' if v else 'false'}")
            elif isinstance(v, int):
                out.append(f"{prefix}{k}: {v}")
            elif isinstance(v, list):
                items_str = ", ".join(_yaml_quote(str(x)) for x in v)
                out.append(f"{prefix}{k}: [{items_str}]")
            else:
                out.append(f"{prefix}{k}: {_yaml_quote(str(v))}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"
