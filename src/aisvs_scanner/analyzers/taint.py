"""Python AST analyzer: lightweight taint tracking for AI-specific flows.

Sources
  * results of LLM calls (model output is untrusted)
  * parameters of functions exposed as agent/MCP tools (model-controlled input)
Sinks
  * code / command execution, SQL, file system, outbound network, raw HTML, unsafe deserialization
Also detects unbounded `while True` agent loops.
"""
from __future__ import annotations

import ast
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from ..models import Finding, Location, Severity
from ..walker import FileCtx

COVERS = {"7.1.1", "9.3.1", "9.5.1", "4.1.1", "7.3.3", "7.3.4", "9.3.7", "4.1.2", "9.1.2", "9.1.1", "9.5.3"}

LLM_METHODS = {
    "create", "invoke", "ainvoke", "generate", "agenerate", "generate_content", "generate_content_async",
    "chat", "completion", "acompletion", "predict", "converse", "invoke_model", "complete", "run_sync",
    "stream", "astream", "get_response", "respond", "ask", "query_llm", "call_llm",
}
LLM_HINT = re.compile(
    r"openai|anthropic|client|llm|chat|model|completion|agent|chain|gemini|ollama|litellm|bedrock|genai|"
    r"mistral|cohere|groq|runnable|pipeline|assistant", re.I)
TOOL_DECORATOR = re.compile(
    r"(?:^|\.)(?:tool|function_tool|register_tool|kernel_function|tool_plain|llm_tool)(?:\(|$)|\.tool\(|mcp\.tool|server\.tool|\.prompt\(\)|@tool")
SANITIZER = re.compile(
    r"sanitiz|escape|quote|validate|model_validate|parse_obj|clean|safe_|is_allowed|allowlist|whitelist|check_|"
    r"resolve_safe|secure_filename|literal_eval|json\.loads$|json_loads|int$|float$|bool$|len$", re.I)

SHELL_SINKS = {
    "eval", "exec", "os.system", "os.popen", "os.execv", "os.execl", "os.spawnv", "subprocess.run", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
    "subprocess.getstatusoutput", "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec",
    "pty.spawn", "commands.getoutput", "runpy.run_path", "importlib.import_module",
}
SQL_ATTRS = {"execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "run_sql"}
FILE_SINKS = {
    "open", "os.remove", "os.unlink", "os.rename", "os.rmdir", "os.makedirs", "os.chmod", "shutil.rmtree",
    "shutil.copy", "shutil.copyfile", "shutil.move", "shutil.copytree",
}
FILE_ATTRS = {"write_text", "write_bytes", "unlink", "rmdir", "read_text", "read_bytes", "open"}
NET_PREFIXES = ("requests.", "httpx.", "urllib.request.", "aiohttp.", "urllib3.")
NET_FUNCS = {"urlopen", "urlretrieve"}
NET_ATTRS = {"get", "post", "put", "delete", "patch", "request", "head", "fetch"}
HTML_SINKS = {"Markup", "mark_safe", "render_template_string", "HTMLResponse", "flask.Markup"}
DESER_SINKS = {"pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load", "marshal.loads", "dill.loads", "cloudpickle.loads", "jsonpickle.decode"}

Sink = Tuple[str, Severity, Tuple[str, ...], Tuple[str, ...], str]
# class -> (title, severity, reqs for llm-source, reqs for tool-source)
SINK_CLASSES: Dict[str, Tuple[str, Severity, Tuple[str, ...], Tuple[str, ...]]] = {
    "exec": ("command/code execution", Severity.HIGH, ("7.1.1", "9.3.1", "4.1.1"), ("9.3.1", "9.5.1", "4.1.1")),
    "sql": ("SQL execution", Severity.HIGH, ("7.1.1", "9.5.3"), ("9.3.1", "9.5.1")),
    "file": ("file-system operation", Severity.MEDIUM, ("7.1.1", "9.3.1"), ("9.3.1", "9.5.1")),
    "net": ("outbound network request", Severity.MEDIUM, ("7.3.3", "9.3.7"), ("9.3.7", "9.3.1")),
    "html": ("raw HTML rendering", Severity.MEDIUM, ("7.3.3", "7.3.4"), ("7.3.3", "9.3.1")),
    "deser": ("unsafe deserialization", Severity.HIGH, ("4.1.2", "7.1.1"), ("4.1.2", "9.3.1")),
}


def _name(node: ast.AST) -> str:
    """Dotted name for Name/Attribute chains, '' otherwise."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = _name(node.func)
        if inner:
            parts.append(inner + "()")
    else:
        return ""
    return ".".join(reversed(parts))


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _is_llm_call(call: ast.Call) -> bool:
    f = call.func
    if isinstance(f, ast.Attribute) and f.attr in LLM_METHODS:
        return bool(LLM_HINT.search(_unparse(f.value)))
    return False


def _classify_sink(call: ast.Call) -> Optional[str]:
    name = _name(call.func)
    if not name:
        return None
    last = name.split(".")[-1]
    if name in SHELL_SINKS or name.split("(")[0] in {"eval", "exec"}:
        return "exec"
    if name in DESER_SINKS:
        return "deser"
    if name in FILE_SINKS:
        return "file"
    if last in HTML_SINKS or name in HTML_SINKS:
        return "html"
    if isinstance(call.func, ast.Attribute):
        if last in SQL_ATTRS:
            return "sql"
        if last in FILE_ATTRS and "Path" in _unparse(call.func.value):
            return "file"
        if name.startswith(NET_PREFIXES) and last in NET_ATTRS | NET_FUNCS:
            return "net"
        if last in NET_ATTRS and re.search(r"session|client|http", _unparse(call.func.value), re.I) and last != "get":
            return "net"
        if last == "get" and re.search(r"requests|httpx|aiohttp|session|http_client", _unparse(call.func.value), re.I):
            return "net"
    if last in NET_FUNCS:
        return "net"
    return None


class _Scope(ast.NodeVisitor):
    def __init__(self, ctx: "Analyzer", tainted: Dict[str, str]):
        self.ctx = ctx
        self.tainted: Dict[str, str] = dict(tainted)  # var -> origin ("llm" | "tool")

    # -- taint helpers ------------------------------------------------------
    def expr_taint(self, node: Optional[ast.AST]) -> Optional[str]:
        if node is None:
            return None
        if isinstance(node, ast.Call):
            if _is_llm_call(node):
                return "llm"
            fname = _name(node.func)
            if fname and SANITIZER.search(fname.split(".")[-1]) and "format" not in fname:
                return None
        if isinstance(node, ast.Name):
            return self.tainted.get(node.id)
        found = None
        for child in ast.iter_child_nodes(node):
            t = self.expr_taint(child)
            if t:
                found = t if found != "tool" else found
                if t == "tool":
                    found = "tool"
        return found

    def _assign_targets(self, target: ast.AST, origin: Optional[str]):
        if isinstance(target, ast.Name):
            if origin:
                self.tainted[target.id] = origin
            else:
                self.tainted.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t in target.elts:
                self._assign_targets(t, origin)
        elif isinstance(target, ast.Starred):
            self._assign_targets(target.value, origin)

    # -- visitors -----------------------------------------------------------
    def visit_Assign(self, node: ast.Assign):
        self.visit(node.value)
        o = self.expr_taint(node.value)
        for t in node.targets:
            self._assign_targets(t, o)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        if node.value:
            self.visit(node.value)
            self._assign_targets(node.target, self.expr_taint(node.value))

    def visit_AugAssign(self, node: ast.AugAssign):
        self.visit(node.value)
        o = self.expr_taint(node.value)
        if o:
            self._assign_targets(node.target, o)

    def visit_NamedExpr(self, node: ast.NamedExpr):
        self.visit(node.value)
        self._assign_targets(node.target, self.expr_taint(node.value))

    def visit_For(self, node: ast.For):
        self.visit(node.iter)
        self._assign_targets(node.target, self.expr_taint(node.iter))
        for s in node.body + node.orelse:
            self.visit(s)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._assign_targets(item.optional_vars, self.expr_taint(item.context_expr))
        for s in node.body:
            self.visit(s)

    visit_AsyncWith = visit_With

    def visit_FunctionDef(self, node):
        self.ctx.analyze_function(node, self.tainted)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef):
        for s in node.body:
            self.visit(s)

    def visit_Call(self, node: ast.Call):
        self.generic_visit(node)
        cls = _classify_sink(node)
        if not cls:
            return
        args: List[ast.AST] = list(node.args[:1])
        for kw in node.keywords:
            if kw.arg in {"url", "path", "file", "cmd", "command", "args", "sql", "query", "code", "source", "body", "html", "content"}:
                args.append(kw.value)
        if cls == "net":
            # only the URL/host is interesting, not request bodies
            args = list(node.args[:1]) + [kw.value for kw in node.keywords if kw.arg == "url"]
        origin = None
        for a in args:
            o = self.expr_taint(a)
            if o:
                origin = o if origin != "tool" else origin
                if o == "tool":
                    origin = "tool"
        if origin:
            self.ctx.report(node, cls, origin)


class Analyzer:
    def __init__(self, f: FileCtx, tree: ast.AST):
        self.f = f
        self.tree = tree
        self.findings: List[Finding] = []
        self._seen: Set[Tuple[int, str]] = set()

    def report(self, node: ast.AST, cls: str, origin: str):
        key = (node.lineno, cls)
        if key in self._seen:
            return
        self._seen.add(key)
        title, sev, llm_reqs, tool_reqs = SINK_CLASSES[cls]
        call_txt = _name(node.func) if isinstance(node, ast.Call) else ""
        if origin == "tool":
            rid, ttl = "AIS-TAINT-TOOL", f"Tool parameter flows into {title}"
            reqs = tool_reqs
            msg = f"Model-controlled tool argument reaches `{call_txt}` ({title}) without validation"
            fix = "Validate parameters against a strict schema/allow-list, bind them as data (never into shell/SQL/paths/URLs), run the tool in a least-privilege sandbox, and require approval for impactful operations."
        else:
            rid, ttl = "AIS-TAINT-LLM", f"LLM output flows into {title}"
            reqs = llm_reqs
            msg = f"Untrusted model output reaches `{call_txt}` ({title}) without validation"
            fix = "Treat model output as untrusted: validate against a schema/allow-list, use parameterized APIs, and isolate execution."
        self.findings.append(Finding(
            rule_id=f"{rid}-{cls.upper()}", title=ttl, severity=sev, requirements=reqs, message=msg,
            location=Location(self.f.rel, node.lineno, self.f.snippet(node.lineno)), remediation=fix, confidence="medium"))

    def analyze_function(self, fn, outer: Dict[str, str]):
        tainted = {k: v for k, v in outer.items() if v == "llm"}  # module-level LLM vars are visible; tool params are not
        if any(TOOL_DECORATOR.search("@" + _unparse(d).lstrip("@")) or TOOL_DECORATOR.search(_unparse(d)) for d in fn.decorator_list):
            args = fn.args
            names = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs]
            if args.vararg:
                names.append(args.vararg.arg)
            if args.kwarg:
                names.append(args.kwarg.arg)
            for n in names:
                if n not in {"self", "cls", "ctx", "context", "run_context", "state", "config", "runtime"}:
                    tainted[n] = "tool"
        self._check_loops(fn)
        sc = _Scope(self, tainted)
        for stmt in fn.body:
            sc.visit(stmt)

    def _check_loops(self, scope):
        for node in ast.walk(scope):
            if isinstance(node, ast.While) and _always_true(node.test):
                body_nodes = [n for s in node.body for n in ast.walk(s)]
                calls_llm = any(isinstance(n, ast.Call) and (_is_llm_call(n) or _looks_agent_step(n)) for n in body_nodes)
                exits = any(isinstance(n, (ast.Break, ast.Return, ast.Raise)) for n in body_nodes)
                limited = any(
                    isinstance(n, ast.Name) and re.search(r"max_|limit|budget|retries|attempts|remaining", n.id, re.I)
                    for n in body_nodes)
                if calls_llm and not exits and not limited:
                    self.findings.append(Finding(
                        rule_id="AIS-LOOP-001", title="Unbounded agent loop", severity=Severity.MEDIUM,
                        requirements=("9.1.2", "9.1.1"),
                        message="`while True` loop invokes the model/agent with no break, return, or budget check",
                        location=Location(self.f.rel, node.lineno, self.f.snippet(node.lineno)),
                        remediation="Enforce max iterations, token/spend budgets, timeouts and a circuit breaker in the runtime.",
                        confidence="medium"))


def _always_true(test: ast.AST) -> bool:
    return isinstance(test, ast.Constant) and bool(test.value) is True


def _looks_agent_step(call: ast.Call) -> bool:
    return isinstance(call.func, ast.Attribute) and call.func.attr in {"step", "run", "act", "plan", "execute_tool", "call_tool"} and bool(
        re.search(r"agent|llm|model|assistant", _unparse(call.func.value), re.I))


def analyze(f: FileCtx) -> List[Finding]:
    if f.lang not in {"python", "notebook"}:
        return []
    text = f.text
    if not re.search(r"\b(?:openai|anthropic|langchain|llm|litellm|ollama|gemini|genai|bedrock|mistral|cohere|agent|tool|mcp)\b", text, re.I):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    a = Analyzer(f, tree)
    module_scope = _Scope(a, {})
    for stmt in tree.body:
        module_scope.visit(stmt)
    return a.findings
