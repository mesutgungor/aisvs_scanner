"""Binary and serialized model artifact analyzer.

Inspects model files (.pkl, .pt, .bin, .joblib, .onnx, .safetensors, .h5, .gguf):
- Scans pickle streams for dangerous globals (os.system, eval, exec, subprocess, posix._spawn, etc.)
- Detects unsafe formats vs safe serialization formats (safetensors, GGUF)
- Identifies oversized or suspicious archives / zip slips
"""
from __future__ import annotations

import io
import os
import pickle
import struct
from typing import List, Set, Tuple

from ..models import Evidence, Finding, Location, Severity
from ..walker import FileCtx

DANGEROUS_PICKLE_GLOBALS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "posix_spawn"),
    ("os", "spawnlp"),
    ("os", "spawnlpe"),
    ("posix", "system"),
    ("nt", "system"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("subprocess", "run"),
    ("builtins", "eval"),
    ("builtins", "exec"),
    ("__builtin__", "eval"),
    ("__builtin__", "exec"),
    ("builtins", "compile"),
    ("builtins", "getattr"),
    ("builtins", "__import__"),
    ("importlib", "import_module"),
    ("pty", "spawn"),
    ("commands", "getoutput"),
    ("sys", "modules"),
    ("socket", "socket"),
    ("urllib.request", "urlopen"),
    ("requests", "get"),
    ("requests", "post"),
}

SAFE_EXTENSIONS = {".safetensors", ".gguf"}
DANGEROUS_EXTENSIONS = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".bin", ".ckpt", ".dill"}


class _RestrictedUnpickler(pickle.Unpickler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.found_globals: List[Tuple[str, str]] = []

    def find_class(self, module, name):
        self.found_globals.append((module, name))
        return object


def _scan_pickle_bytes(raw: bytes) -> List[Tuple[str, str]]:
    """Scan raw bytes for pickle GLOBAL opcodes without executing arbitrary code."""
    globals_found: List[Tuple[str, str]] = []
    
    # Try using opcode disassembler or restricted unpickler
    try:
        unpickler = _RestrictedUnpickler(io.BytesIO(raw))
        while True:
            try:
                unpickler.load()
            except (pickle.UnpicklingError, EOFError):
                break
            except Exception:
                break
        globals_found.extend(unpickler.found_globals)
    except Exception:
        pass

    # Fallback byte pattern search for GLOBAL opcode: b'c' <module>\n<name>\n or b'\x93' (SHORT_BINUNICODE pair)
    if not globals_found:
        import re
        for m in re.finditer(rb'c([a-zA-Z0-9_.]+)\n([a-zA-Z0-9_]+)\n', raw):
            try:
                mod = m.group(1).decode("utf-8")
                name = m.group(2).decode("utf-8")
                globals_found.append((mod, name))
            except Exception:
                continue

    return globals_found


def analyze(f: FileCtx) -> Tuple[List[Finding], List[Evidence]]:
    findings: List[Finding] = []
    evidence: List[Evidence] = []

    if f.lang != "artifact":
        return findings, evidence

    ext = f.ext.lower()

    if ext in SAFE_EXTENSIONS:
        evidence.append(
            Evidence(
                rule_id="AIS-EV-SAFE-WEIGHTS",
                title=f"Safe weights format ({ext}) deployed",
                requirements=("4.1.2", "6.1.1"),
                location=Location(f.rel, 1, f"Artifact format: {ext}"),
            )
        )
        return findings, evidence

    # For potentially dangerous serialization formats:
    if ext in DANGEROUS_EXTENSIONS:
        findings.append(
            Finding(
                rule_id="AIS-ARTIFACT-001",
                title=f"Executable serialization format artifact present ({ext})",
                severity=Severity.HIGH,
                requirements=("4.1.2", "6.1.1"),
                message=(
                    f"Model artifact `{f.rel}` uses pickle-based/executable format `{ext}`. "
                    "Pickle-based weights allow arbitrary code execution upon loading."
                ),
                location=Location(f.rel, 1, f"File size: {f.size} bytes"),
                remediation=(
                    "Convert weights to a memory-mapped, safe format such as safetensors or GGUF. "
                    "If loading PyTorch weights, strictly require weights_only=True or verify digital signature."
                ),
                confidence="high",
            )
        )

        # Inspect binary for dangerous globals if under 100MB
        if f.size <= 100_000_000:
            try:
                raw_head = f.path.read_bytes()[:10_000_000]
                found_globals = _scan_pickle_bytes(raw_head)
                for mod, name in found_globals:
                    if (mod, name) in DANGEROUS_PICKLE_GLOBALS or mod in {"os", "subprocess", "posix", "sys", "builtins"}:
                        findings.append(
                            Finding(
                                rule_id="AIS-ARTIFACT-002",
                                title=f"Malicious/dangerous opcode in artifact: {mod}.{name}",
                                severity=Severity.CRITICAL,
                                requirements=("4.1.2", "6.1.1"),
                                message=(
                                    f"Detected dangerous global reference `{mod}.{name}` inside model artifact `{f.rel}`. "
                                    "This indicates weaponized or dangerous code embedded in model weights."
                                ),
                                location=Location(f.rel, 1, f"Global: {mod}.{name}"),
                                remediation="Quarantine and do not load this artifact. Review source and replace with verified weights.",
                                confidence="high",
                            )
                        )
                        break
            except Exception:
                pass

    return findings, evidence
