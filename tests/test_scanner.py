"""Unit tests for catalog, rules, analyzers, engine, and reporters."""
import json
import tempfile
from pathlib import Path
import unittest

from aisvs_scanner import catalog
from aisvs_scanner.analyzers import artifact, mcp_config, taint
from aisvs_scanner.engine import ScanConfig, Scanner
from aisvs_scanner.models import Location, Severity, Status
from aisvs_scanner.rules import RULES_DATA_DIR, all_rules
from aisvs_scanner.rules.yaml_loader import (
    dump_rules_yaml,
    load_rules_from_file,
    parse_yaml_PurePython,
    rule_from_dict,
)
from aisvs_scanner.walker import FileCtx


class TestAISVSCatalog(unittest.TestCase):
    def test_load_bundled_catalogs(self):
        cat_101 = catalog.load("1.01")
        self.assertEqual(cat_101.version, "1.01")
        self.assertGreaterEqual(len(cat_101.active), 200)

        # 10.2.6 is retired
        req_10_2_6 = cat_101.get("10.2.6")
        self.assertIsNotNone(req_10_2_6)
        self.assertTrue(req_10_2_6.retired)

        # 7.1.3 should exist and be active
        req_7_1_3 = cat_101.get("7.1.3")
        self.assertIsNotNone(req_7_1_3)
        self.assertFalse(req_7_1_3.retired)
        self.assertEqual(req_7_1_3.level, 2)


class TestRulesAndRegistry(unittest.TestCase):
    def test_unique_rule_ids(self):
        rules = all_rules()
        self.assertGreater(len(rules), 30)
        ids = [r.id for r in rules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_rule_mapping_to_valid_requirements(self):
        cat = catalog.load("1.01")
        all_req_ids = {r.id for r in cat.all}
        for r in all_rules():
            for req_id in r.reqs:
                self.assertIn(req_id, all_req_ids, f"Rule {r.id} references invalid requirement {req_id}")

    def test_yaml_rule_packs_pure_python_and_roundtrip(self):
        yaml_files = sorted(RULES_DATA_DIR.glob("*.yaml"))
        self.assertEqual(len(yaml_files), 12)
        total = 0
        for yf in yaml_files:
            raw = yf.read_text(encoding="utf-8")
            parsed_pure = parse_yaml_PurePython(raw)
            pure_rules = [rule_from_dict(d) for d in parsed_pure["rules"]]
            file_rules = load_rules_from_file(yf)
            self.assertEqual(pure_rules, file_rules)
            # Round-trip dump and re-parse
            dumped = dump_rules_yaml(file_rules, header="Test")
            rt_rules = [rule_from_dict(d) for d in parse_yaml_PurePython(dumped)["rules"]]
            self.assertEqual(rt_rules, file_rules)
            total += len(file_rules)
        self.assertEqual(total, 175)

    def test_custom_yaml_rule_override_and_execution(self):
        custom_yaml = """
rules:
  - id: CUSTOM-TEST-001
    kind: violation
    reqs: ["2.1.1"]
    title: "Forbidden internal prompt marker"
    severity: critical
    confidence: high
    langs: [python]
    patterns:
      - 'FORBIDDEN_PROMPT_MARKER'
    remediation: "Remove forbidden marker."
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            rule_file = td / "my_rules.yaml"
            rule_file.write_text(custom_yaml, encoding="utf-8")
            target_py = td / "service.py"
            target_py.write_text('x = "FORBIDDEN_PROMPT_MARKER"\n', encoding="utf-8")

            cfg = ScanConfig(
                target=td,
                custom_rules=[str(rule_file)],
                no_builtin_rules=True,
            )
            res = Scanner(cfg).scan()
            self.assertEqual(len(res.findings), 1)
            self.assertEqual(res.findings[0].rule_id, "CUSTOM-TEST-001")
            self.assertEqual(res.findings[0].severity, Severity.CRITICAL)


class TestASTTaintAnalyzer(unittest.TestCase):
    def test_taint_llm_to_shell_exec(self):
        code = """
import os
from openai import OpenAI

client = OpenAI()
res = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "run"}])
cmd = res.choices[0].message.content
os.system(cmd)
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            fpath = Path(f.name)

        ctx = FileCtx(fpath, fpath.name, ".py", "python", len(code))
        findings = taint.analyze(ctx)
        fpath.unlink()

        self.assertTrue(any(f.rule_id == "AIS-TAINT-LLM-EXEC" for f in findings))

    def test_unbounded_agent_loop(self):
        code = """
from openai import OpenAI
client = OpenAI()

def agent_step():
    while True:
        resp = client.chat.completions.create(model="gpt-4o", messages=[])
        print(resp)
"""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            fpath = Path(f.name)

        ctx = FileCtx(fpath, fpath.name, ".py", "python", len(code))
        findings = taint.analyze(ctx)
        fpath.unlink()

        self.assertTrue(any(f.rule_id == "AIS-LOOP-001" for f in findings))


class TestMCPConfigAnalyzer(unittest.TestCase):
    def test_mcp_config_violations(self):
        mcp_json = """{
  "mcpServers": {
    "sqlite": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-sqlite"],
      "autoApprove": ["*"]
    },
    "insecure-remote": {
      "url": "http://api.external.com/mcp",
      "headers": {
        "Authorization": "Bearer secret-hardcoded-token-12345"
      }
    }
  }
}"""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            f.write(mcp_json)
            f.flush()
            fpath = Path(f.name)

        ctx = FileCtx(fpath, "mcp.json", ".json", "json", len(mcp_json))
        findings, evidence = mcp_config.analyze(ctx)
        fpath.unlink()

        f_ids = {f.rule_id for f in findings}
        self.assertIn("AIS-MCPCFG-001", f_ids)  # unpinned npx
        self.assertIn("AIS-MCPCFG-003", f_ids)  # plaintext http
        self.assertIn("AIS-MCPCFG-004", f_ids)  # hardcoded secret
        self.assertIn("AIS-MCPCFG-008", f_ids)  # autoApprove *


class TestArtifactAnalyzer(unittest.TestCase):
    def test_malicious_pickle_opcode(self):
        import pickle
        # Payload referencing os.system
        payload = b"cos\nsystem\n(S'echo pwned'\ntR."
        with tempfile.NamedTemporaryFile("wb", suffix=".pkl", delete=False) as f:
            f.write(payload)
            f.flush()
            fpath = Path(f.name)

        ctx = FileCtx(fpath, "weights.pkl", ".pkl", "artifact", len(payload))
        findings, _ = artifact.analyze(ctx)
        fpath.unlink()

        self.assertTrue(any(f.rule_id == "AIS-ARTIFACT-002" for f in findings))


class TestScannerEndToEnd(unittest.TestCase):
    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            td = Path(tmpdir)
            # Create a Python file with vulnerable and positive patterns
            (td / "app.py").write_text("""
import tiktoken
from openai import OpenAI

# Input length control
enc = tiktoken.get_encoding("cl100k_base")

client = OpenAI()
# Vulnerable: Concatenating user prompt into developer message
user_req = "sample"
system_prompt = f"System prompt with {user_req}"
client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "system", "content": system_prompt}],
    max_tokens=500
)
""", encoding="utf-8")

            cfg = ScanConfig(target=td, level=2)
            scanner = Scanner(cfg)
            res = scanner.scan()

            self.assertGreaterEqual(res.files_scanned, 1)
            # Check prompt injection finding
            f_ids = {f.rule_id for f in res.findings}
            self.assertIn("AIS-PROMPT-001", f_ids)

            # Check that results contains AISVS requirement checks
            req_statuses = {r.requirement.id: r.status for r in res.results}
            self.assertIn("2.1.6", req_statuses)
            self.assertEqual(req_statuses["2.1.6"], Status.FAIL)


if __name__ == "__main__":
    unittest.main()
