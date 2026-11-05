"""File discovery and per-file context."""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__", ".tox",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build", ".next", ".nuxt",
    "site-packages", "target", ".idea", ".gradle", "Pods", "vendor", ".terraform", "coverage",
}

LANG_BY_EXT = {
    ".py": "python", ".ipynb": "notebook",
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js",
    ".go": "go", ".java": "java", ".kt": "java", ".cs": "csharp", ".rb": "ruby", ".rs": "rust",
    ".php": "php", ".swift": "swift",
    ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".toml": "toml", ".tf": "terraform",
    ".md": "text", ".txt": "text", ".prompt": "text", ".jinja": "text", ".j2": "text",
    ".sh": "shell", ".bash": "shell", ".ini": "config", ".cfg": "config", ".env": "config",
    ".rego": "rego", ".gradle": "gradle",
}
CODE_LANGS = {"python", "js", "go", "java", "csharp", "ruby", "rust", "php", "swift", "notebook"}

ARTIFACT_EXTS = {
    ".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".bin", ".h5", ".hdf5", ".keras",
    ".onnx", ".safetensors", ".gguf", ".ggml", ".tflite", ".mlmodel", ".mlpackage", ".pte",
    ".npy", ".npz", ".pb", ".dill", ".cbm", ".model", ".engine", ".trt", ".mar",
}

MAX_TEXT_BYTES = 2_000_000
MAX_ARTIFACT_SCAN_BYTES = 2_000_000_000

_BUILTIN_RULES_DIR = (Path(__file__).resolve().parent / "data" / "rules").resolve()


@dataclass
class FileCtx:
    path: Path
    rel: str
    ext: str
    lang: str
    size: int
    _text: Optional[str] = field(default=None, repr=False)
    _lines: Optional[List[str]] = field(default=None, repr=False)

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def text(self) -> str:
        if self._text is None:
            try:
                raw = self.path.read_bytes()[:MAX_TEXT_BYTES]  # aisvs:ignore AIS-PROMPT-003
                self._text = raw.decode("utf-8", errors="replace")
            except OSError:
                self._text = ""
            if self.lang == "notebook":
                self._text = _notebook_to_source(self._text)
        return self._text

    @property
    def lines(self) -> List[str]:
        if self._lines is None:
            self._lines = self.text.splitlines()
        return self._lines

    def line_of(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1

    def snippet(self, line: int, width: int = 160) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].strip()[:width]
        return ""


def _notebook_to_source(raw: str) -> str:
    import json

    try:
        nb = json.loads(raw)
        cells = nb.get("cells", [])
        return "\n".join("".join(c.get("source", [])) for c in cells if c.get("cell_type") == "code")
    except Exception:
        return raw


def _is_text_candidate(p: Path, ext: str) -> bool:
    name = p.name.lower()
    if ext in LANG_BY_EXT:
        return True
    return name in {
        "dockerfile", "makefile", "requirements.txt", ".env", ".cursorrules", ".windsurfrules",
        "containerfile", "jenkinsfile",
    } or name.startswith(("dockerfile.", ".env", "requirements"))


def _lang_for(p: Path, ext: str) -> str:
    name = p.name.lower()
    if name.startswith(("dockerfile", "containerfile")):
        return "dockerfile"
    if name.startswith("requirements") and ext == ".txt":
        return "requirements"
    if name.startswith(".env"):
        return "config"
    return LANG_BY_EXT.get(ext, "text")


def walk(
    root: Path,
    exclude_globs: Optional[List[str]] = None,
    include_artifacts: bool = True,
    max_files: int = 100_000,
) -> Iterator[FileCtx]:
    root = root.resolve()
    exclude_globs = exclude_globs or []
    if root.is_file():
        files = [root]
        base = root.parent
    else:
        files = None
        base = root

    def excluded(rel: str) -> bool:
        return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(os.path.basename(rel), g) for g in exclude_globs)

    count = 0
    iterator = (
        ((str(base), [], [root.name]),) if files else os.walk(base, followlinks=False)
    )
    for dirpath, dirnames, filenames in iterator:
        if not files:
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in DEFAULT_EXCLUDE_DIRS and not excluded(os.path.relpath(os.path.join(dirpath, d), base))
            )
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if _BUILTIN_RULES_DIR in p.resolve().parents:
                continue
            rel = os.path.relpath(p, base)
            if excluded(rel) or p.is_symlink():
                continue
            ext = p.suffix.lower()
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if _is_text_candidate(p, ext):
                yield FileCtx(p, rel, ext, _lang_for(p, ext), size)
            elif include_artifacts and ext in ARTIFACT_EXTS:
                yield FileCtx(p, rel, ext, "artifact", size)
            else:
                continue
            count += 1
            if count >= max_files:
                return
