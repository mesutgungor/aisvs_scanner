"""AISVS requirement catalog: parse the official markdown, load bundled JSON, sync from GitHub."""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

from .models import Requirement

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_VERSION = "1.01"
REPO = "OWASP/AISVS"

_CHAPTER_RE = re.compile(r"^#\s+C(\d+)\s+(.+?)\s*$")
_SECTION_RE = re.compile(r"^##\s+C(\d+\.\d+)\s+(.+?)\s*$")
_ROW_RE = re.compile(r"^\|\s*\*\*(\d+\.\d+\.\d+)\*\*\s*\|(.*)\|\s*([123]?)\s*\|\s*$")
_LEAD_RE = re.compile(r"^\*\*Verify that\*\*,?\s*", re.I)


def parse_markdown(text: str) -> List[Requirement]:
    """Parse one AISVS chapter file into requirements."""
    reqs: List[Requirement] = []
    chapter = chapter_title = section = section_title = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        m = _CHAPTER_RE.match(line)
        if m:
            chapter, chapter_title = f"C{m.group(1)}", m.group(2)
            continue
        m = _SECTION_RE.match(line)
        if m:
            section, section_title = f"C{m.group(1)}", m.group(2)
            continue
        m = _ROW_RE.match(line)
        if not m or not chapter:
            continue
        rid, body, level = m.group(1), m.group(2).strip(), m.group(3)
        retired = "requirement removed" in body.lower()
        body = _LEAD_RE.sub("", body)
        if retired:
            body = "Requirement removed."
        # "7.1.3 Verify that, when..." keeps the leading comma phrase intact
        reqs.append(
            Requirement(
                id=rid,
                text=body.strip(),
                level=int(level) if level else 0,
                chapter=chapter,
                chapter_title=chapter_title,
                section=section or f"C{rid.rsplit('.', 1)[0]}",
                section_title=section_title,
                retired=retired,
            )
        )
    return reqs


def parse_directory(path: Path) -> List[Requirement]:
    reqs: List[Requirement] = []
    for f in sorted(Path(path).glob("0x10-C*.md")):
        reqs.extend(parse_markdown(f.read_text(encoding="utf-8")))
    return _dedupe(reqs)


def _dedupe(reqs: List[Requirement]) -> List[Requirement]:
    seen: Dict[str, Requirement] = {}
    for r in reqs:
        if r.id in seen and not seen[r.id].retired:
            continue
        seen[r.id] = r
    return sorted(seen.values(), key=lambda r: r.sort_key)


def to_json(version: str, reqs: List[Requirement]) -> dict:
    return {
        "standard": "OWASP AISVS",
        "version": version,
        "source": f"https://github.com/{REPO}/tree/main/{version}/en",
        "requirements": [
            {
                "id": r.id,
                "text": r.text,
                "level": r.level,
                "chapter": r.chapter,
                "chapter_title": r.chapter_title,
                "section": r.section,
                "section_title": r.section_title,
                "retired": r.retired,
            }
            for r in reqs
        ],
    }


def _from_json(doc: dict) -> List[Requirement]:
    return [Requirement(**r) for r in doc["requirements"]]


def available_versions() -> List[str]:
    return sorted(p.stem.replace("aisvs-", "") for p in DATA_DIR.glob("aisvs-*.json"))


def load(version: Optional[str] = None, path: Optional[str] = None) -> "Catalog":
    if path:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    else:
        version = version or DEFAULT_VERSION
        f = DATA_DIR / f"aisvs-{version}.json"
        if not f.exists():
            raise FileNotFoundError(
                f"No bundled catalog for AISVS {version}. Available: {', '.join(available_versions())}. "
                f"Use `aisvs-scan sync --version {version}` to fetch it."
            )
        doc = json.loads(f.read_text(encoding="utf-8"))
    return Catalog(doc["version"], _from_json(doc))


class Catalog:
    def __init__(self, version: str, reqs: List[Requirement]):
        self.version = version
        self.all = reqs
        self.active = [r for r in reqs if not r.retired]
        self.by_id = {r.id: r for r in reqs}

    def get(self, rid: str) -> Optional[Requirement]:
        return self.by_id.get(rid)


def sync(version: str, out_dir: Path = DATA_DIR, ref: str = "main") -> Path:
    """Fetch chapter files from GitHub for `version` (e.g. '1.01', '1.02-dev') and write the catalog."""
    api = f"https://api.github.com/repos/{REPO}/contents/{version}/en?ref={ref}"
    req = urllib.request.Request(api, headers={"User-Agent": "aisvs-scanner"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        listing = json.load(resp)
    reqs: List[Requirement] = []
    for item in listing:
        name = item["name"]
        if name.startswith("0x10-C") and name.endswith(".md"):
            r = urllib.request.Request(item["download_url"], headers={"User-Agent": "aisvs-scanner"})
            with urllib.request.urlopen(r, timeout=30) as resp:
                reqs.extend(parse_markdown(resp.read().decode("utf-8")))
    reqs = _dedupe(reqs)
    if not reqs:
        raise RuntimeError(f"No requirements found for version {version}")
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"aisvs-{version}.json"
    out.write_text(json.dumps(to_json(version, reqs), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out
