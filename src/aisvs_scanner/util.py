"""Small parsing helpers used by rules and analyzers."""
from __future__ import annotations

import re
from typing import Iterator, List, Tuple


def extract_calls(text: str, callee_re: "re.Pattern[str]") -> Iterator[Tuple[int, str, str]]:
    """Yield (offset, callee_text, args_text) for each call matching callee_re.

    Handles nested parentheses and string literals so multi-line calls work for
    Python, JS/TS, Java, Go, C# and similar syntaxes.
    """
    for m in callee_re.finditer(text):
        i = m.end()
        # allow whitespace/generics between callee and "("
        while i < len(text) and text[i] in " \t":
            i += 1
        if i >= len(text) or text[i] != "(":
            continue
        depth, j, quote = 0, i, ""
        n = len(text)
        while j < n:
            ch = text[j]
            if quote:
                if ch == "\\":
                    j += 1
                elif ch == quote:
                    quote = ""
            else:
                if ch in "\"'`":
                    quote = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
            j += 1
            if j - i > 20000:
                break
        yield m.start(), m.group(0), text[i + 1 : j]


def strip_comments_py(text: str) -> str:
    return re.sub(r"(?m)^\s*#.*$", "", text)


def mask(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "…" + "*" * 4
