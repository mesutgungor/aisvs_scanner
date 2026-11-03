"""Rule registry."""
from typing import Dict, List

from .base import Rule
from . import r_model_infra, r_io_access, r_agents_mcp, r_rag_robust_monitor


def all_rules() -> List[Rule]:
    rules: List[Rule] = []
    for mod in (r_model_infra, r_io_access, r_agents_mcp, r_rag_robust_monitor):
        rules.extend(mod.RULES)
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuntimeError(f"duplicate rule ids: {sorted(dupes)}")
    return rules


def by_id() -> Dict[str, Rule]:
    return {r.id: r for r in all_rules()}
