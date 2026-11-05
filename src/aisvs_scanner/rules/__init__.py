"""Declarative rule registry backed by YAML rule packs."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

from .base import Rule
from .yaml_loader import load_rules_from_path

RULES_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "rules"

_BUILTIN_CACHE: Optional[List[Rule]] = None


def builtin_rules() -> List[Rule]:
    """Load and cache all built-in OWASP AISVS YAML rule packs (C1–C12)."""
    global _BUILTIN_CACHE
    if _BUILTIN_CACHE is None:
        rules = load_rules_from_path(RULES_DATA_DIR)
        ids = [r.id for r in rules]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise RuntimeError(f"Duplicate built-in rule IDs: {sorted(dupes)}")
        _BUILTIN_CACHE = rules
    return list(_BUILTIN_CACHE)


def all_rules(
    extra_paths: Optional[Iterable[Union[str, Path]]] = None,
    include_builtin: bool = True,
) -> List[Rule]:
    """Return built-in rules merged with any user-supplied YAML rule files/directories.

    If a custom rule shares an ``id`` with an existing rule, the custom rule
    overrides the built-in rule in-place.
    """
    rule_map: Dict[str, Rule] = {}
    if include_builtin:
        for r in builtin_rules():
            rule_map[r.id] = r

    if extra_paths:
        for ep in extra_paths:
            for r in load_rules_from_path(Path(ep)):
                rule_map[r.id] = r

    return list(rule_map.values())


def by_id(
    extra_paths: Optional[Iterable[Union[str, Path]]] = None,
    include_builtin: bool = True,
) -> Dict[str, Rule]:
    return {r.id: r for r in all_rules(extra_paths=extra_paths, include_builtin=include_builtin)}
