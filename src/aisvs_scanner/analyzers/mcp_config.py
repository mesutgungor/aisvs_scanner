"""Analyzer for MCP client configuration files (mcp.json, claude_desktop_config.json, .cursor/mcp.json, ...)."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Tuple

from ..models import Evidence, Finding, Location, Severity
from ..walker import FileCtx

COVERS = {"10.1.1", "10.1.2", "10.1.3", "10.2.1", "10.3.1", "10.4.7", "10.4.8", "9.2.1", "5.1.2"}

MCP_FILE_NAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json", "mcp_config.json", "cline_mcp_settings.json",
                  "mcp_settings.json", "settings.json", "settings.local.json", "config.json"}
SECRET_KEY = re.compile(r"key|token|secret|password|passwd|auth|credential", re.I)
ENV_REF = re.compile(r"^\s*(?:\$\{?[\w:.-]+\}?|%[\w]+%|\{\{.*\}\}|<.*>|\$\(.*\)|input:[\w.-]+|\$\{input:[\w.-]+\})\s*$")
BROAD_PATHS = re.compile(r"^(?:/|~|~/|\$HOME|%USERPROFILE%|[A-Za-z]:\\?|/Users|/home|/etc|/var)/?$")
PLACEHOLDER = re.compile(r"your[_-]|xxx|example|placeholder|<.*>|changeme|\.\.\.", re.I)


def _strip_jsonc(text: str) -> str:
    text = re.sub(r"(?m)^\s*//.*$", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r",(\s*[}\]])", r"\1", text)


def _load(f: FileCtx):
    try:
        return json.loads(f.text)
    except Exception:
        try:
            return json.loads(_strip_jsonc(f.text))
        except Exception:
            return None


def _servers(doc: Any) -> Dict[str, dict]:
    out: Dict[str, dict] = {}

    def visit(node: Any):
        if isinstance(node, dict):
            for key in ("mcpServers", "mcp_servers", "servers", "context_servers"):
                v = node.get(key)
                if isinstance(v, dict):
                    for name, spec in v.items():
                        if isinstance(spec, dict) and any(k in spec for k in ("command", "url", "serverUrl", "httpUrl", "type", "args")):
                            out[name] = spec
            mcp = node.get("mcp")
            if isinstance(mcp, dict):
                visit(mcp)
            for v in node.values():
                if isinstance(v, (dict, list)) and v is not mcp:
                    visit(v)
        elif isinstance(node, list):
            for v in node:
                visit(v)

    visit(doc)
    return out


def _line_of(f: FileCtx, needle: str) -> int:
    for i, line in enumerate(f.lines, 1):
        if needle in line:
            return i
    return 1


def _unpinned_package(cmd: str, args: List[str]) -> str:
    base = cmd.split("/")[-1].lower()
    pkgs = [a for a in args if isinstance(a, str) and not a.startswith("-")]
    if base in {"npx", "bunx", "pnpx"} or (base in {"pnpm", "yarn", "bun"} and args[:1] in (["dlx"], ["x"])):
        for a in pkgs:
            if a in {"dlx", "x", "exec"}:
                continue
            at = a.rfind("@")
            if at <= 0 or a.endswith("@latest"):
                return a
            return ""
    if base in {"uvx", "pipx"}:
        for a in pkgs:
            if a == "run":
                continue
            if not re.search(r"==|@[\w.]|\.whl$|^git\+.*@", a):
                return a
            return ""
    if base in {"docker", "podman"} and "run" in args:
        imgs = [a for a in args[args.index("run") + 1 :] if not a.startswith("-")]
        # first positional after flags that aren't values is the image (heuristic)
        for a in imgs:
            if "/" in a or ":" in a or re.match(r"^[a-z0-9._-]+$", a):
                if "@sha256:" in a:
                    return ""
                if ":" not in a.split("/")[-1] or a.endswith(":latest"):
                    return a
                return ""
    return ""


def analyze(f: FileCtx) -> Tuple[List[Finding], List[Evidence]]:
    findings: List[Finding] = []
    evidence: List[Evidence] = []
    if f.lang != "json" or f.size > 1_000_000:
        return findings, evidence
    if f.name.lower() not in MCP_FILE_NAMES and "mcpServers" not in f.text and "mcp_servers" not in f.text and "context_servers" not in f.text:
        return findings, evidence
    doc = _load(f)
    if doc is None:
        return findings, evidence
    servers = _servers(doc)
    if not servers:
        return findings, evidence

    def add(rule, title, sev, reqs, msg, needle, fix, conf="high"):
        line = _line_of(f, needle)
        findings.append(Finding(rule, title, sev, tuple(reqs.split()), msg, Location(f.rel, line, f.snippet(line)), fix, conf))

    all_pinned = True
    for name, spec in servers.items():
        cmd = str(spec.get("command", ""))
        args = [str(a) for a in spec.get("args", []) if not isinstance(a, (dict, list))] if isinstance(spec.get("args"), list) else []
        url = str(spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl") or "")

        pkg = _unpinned_package(cmd, args) if cmd else ""
        if pkg:
            all_pinned = False
            add("AIS-MCPCFG-001", "Unpinned MCP server package", Severity.MEDIUM, "10.1.1",
                f"MCP server `{name}` runs `{cmd} {pkg}` without a pinned version/digest; a compromised release executes on next start",
                pkg, "Pin an exact version (or image digest), verify provenance/signature, and review before upgrading.")
        if cmd.split("/")[-1].lower() in {"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"} and any(a in {"-c", "/c", "-Command"} for a in args):
            joined = " ".join(args)
            sev = Severity.HIGH if re.search(r"curl|wget|\|\s*(?:ba)?sh|Invoke-WebRequest|iex", joined) else Severity.MEDIUM
            add("AIS-MCPCFG-002", "MCP server launched through a shell wrapper", sev, "10.1.1 10.1.3",
                f"MCP server `{name}` is started via `{cmd} -c ...`", cmd, "Launch the server binary directly with fixed arguments inside a sandbox.")
        if url:
            if url.startswith("http://") and not re.match(r"http://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal)", url):
                add("AIS-MCPCFG-003", "Remote MCP server over plaintext HTTP", Severity.HIGH, "10.3.1",
                    f"MCP server `{name}` connects to `{url}` without TLS", url, "Use https:// with authentication.")
            hdrs = spec.get("headers") if isinstance(spec.get("headers"), dict) else {}
            has_auth = False
            for hk, hv in hdrs.items():
                if SECRET_KEY.search(hk):
                    has_auth = True
                    if isinstance(hv, str) and not ENV_REF.match(re.sub(r"^(?:Bearer|Basic)\s+", "", hv, flags=re.I)) and not PLACEHOLDER.search(hv):
                        add("AIS-MCPCFG-004", "Hard-coded credential in MCP server headers", Severity.HIGH, "5.1.2 10.2.1",
                            f"MCP server `{name}` embeds a literal credential in header `{hk}`", hk,
                            "Reference an environment variable/secret store and use short-lived OAuth tokens.")
            if not has_auth and url.startswith("http") and not re.match(r"https?://(?:localhost|127\.0\.0\.1|\[::1\])", url) and not spec.get("auth") and not spec.get("oauth"):
                add("AIS-MCPCFG-005", "Remote MCP server configured without visible authentication", Severity.LOW, "10.2.1",
                    f"MCP server `{name}` ({url}) has no Authorization header/OAuth setting in this file", url,
                    "Require OAuth 2.1 bearer tokens validated by the server for every request (may be handled by client OAuth discovery).", "low")
        env = spec.get("env") if isinstance(spec.get("env"), dict) else {}
        for ek, ev in env.items():
            if SECRET_KEY.search(ek) and isinstance(ev, str) and ev and not ENV_REF.match(ev) and not PLACEHOLDER.search(ev) and len(ev) >= 8:
                add("AIS-MCPCFG-004", "Hard-coded credential in MCP server env", Severity.HIGH, "5.1.2",
                    f"MCP server `{name}` embeds a literal secret in env `{ek}`", ek,
                    "Reference an environment variable/secret store; rotate the exposed value.")
        for a in args:
            if BROAD_PATHS.match(a.strip()):
                add("AIS-MCPCFG-006", "MCP server granted overly broad file-system scope", Severity.MEDIUM, "10.1.3",
                    f"MCP server `{name}` is given `{a}` as an allowed path", a,
                    "Scope servers to the narrowest project directory and use read-only mounts/sandboxing.")
                break
        if cmd.split("/")[-1].lower() in {"docker", "podman"} and "run" in args:
            joined = " ".join(args)
            if not re.search(r"--read-only|--cap-drop|--network[ =]none|--security-opt", joined):
                add("AIS-MCPCFG-007", "Containerized MCP server without hardening flags", Severity.LOW, "10.1.3",
                    f"MCP server `{name}` runs in a container with no --read-only/--cap-drop/--network restrictions", cmd,
                    "Add --read-only, --cap-drop=ALL, --security-opt no-new-privileges and restrict network/mounts.", "medium")
        aa = spec.get("autoApprove") or spec.get("alwaysAllow") or spec.get("auto_approve")
        if aa:
            star = aa == ["*"] or aa is True or (isinstance(aa, list) and "*" in aa)
            add("AIS-MCPCFG-008", "MCP tools auto-approved without user confirmation", Severity.HIGH if star else Severity.MEDIUM, "9.2.1 10.4.7",
                f"MCP server `{name}` auto-approves {'all tools' if star else 'tools: ' + ', '.join(map(str, aa)) if isinstance(aa, list) else 'tools'}",
                "autoApprove" if "autoApprove" in f.text else "alwaysAllow",
                "Require explicit approval for tools with side effects; limit auto-approval to read-only tools.")
        if spec.get("trust") is True:
            add("AIS-MCPCFG-008", "MCP server marked fully trusted (approval bypass)", Severity.HIGH, "9.2.1 10.4.7",
                f"MCP server `{name}` has `trust: true`", '"trust"', "Remove trust flag; approve tool calls explicitly.")

    if servers and all_pinned:
        evidence.append(Evidence("AIS-EV-MCPCFG-PINNED", "All configured MCP servers are version-pinned", ("10.1.1",), Location(f.rel, 1, f.snippet(1))))
    if re.search(r"allowedMcpServers|enabledMcpjsonServers|allowlist|allowed_servers", f.text):
        evidence.append(Evidence("AIS-EV-MCPCFG-ALLOWLIST", "MCP server allow-list configured", ("10.1.2",), Location(f.rel, 1, "")))
    return findings, evidence
