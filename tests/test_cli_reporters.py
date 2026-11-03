"""Tests for CLI commands and output reporters."""
import io
import json
import tempfile
from pathlib import Path
import unittest

from aisvs_scanner.cli import main
from aisvs_scanner.engine import ScanConfig, Scanner
from aisvs_scanner.reporters import (
    render_csv,
    render_html,
    render_json,
    render_markdown,
    render_sarif,
    render_terminal,
)


class TestReporters(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.td = Path(self.tmpdir.name)
        (self.td / "sample.py").write_text("""
import os
from openai import OpenAI

client = OpenAI()
res = client.chat.completions.create(model="gpt-4o", messages=[])
code = res.choices[0].message.content
eval(code)
""", encoding="utf-8")

        cfg = ScanConfig(target=self.td, level=3)
        scanner = Scanner(cfg)
        self.result = scanner.scan()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_terminal_reporter(self):
        buf = io.StringIO()
        render_terminal(self.result, buf)
        out = buf.getvalue()
        self.assertIn("OWASP AISVS", out)
        self.assertIn("Verification Summary", out)
        self.assertIn("Chapter Breakdown", out)

    def test_json_reporter(self):
        buf = io.StringIO()
        render_json(self.result, buf)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["tool"], "aisvs-scanner")
        self.assertIn("findings", data)
        self.assertIn("requirements", data)

    def test_sarif_reporter(self):
        buf = io.StringIO()
        render_sarif(self.result, buf)
        sarif = json.loads(buf.getvalue())
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "aisvs-scanner")
        self.assertGreater(len(sarif["runs"][0]["results"]), 0)

    def test_markdown_reporter(self):
        buf = io.StringIO()
        render_markdown(self.result, buf)
        out = buf.getvalue()
        self.assertIn("# OWASP AISVS Security Verification Audit Report", out)
        self.assertIn("## Executive Summary", out)

    def test_csv_reporter(self):
        buf = io.StringIO()
        render_csv(self.result, buf)
        out = buf.getvalue()
        self.assertIn("Requirement ID,Level,Chapter,Section", out)

    def test_html_reporter(self):
        buf = io.StringIO()
        render_html(self.result, buf)
        out = buf.getvalue()
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("OWASP AISVS Verification Dashboard", out)


class TestCLI(unittest.TestCase):
    def test_cli_list_requirements(self):
        ret = main(["list-requirements", "-c", "C2", "-l", "1"])
        self.assertEqual(ret, 0)

    def test_cli_list_rules(self):
        ret = main(["list-rules"])
        self.assertEqual(ret, 0)

    def test_cli_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "test.py"
            p.write_text("import openai\n", encoding="utf-8")
            ret = main(["scan", tmpdir, "-l", "1", "-f", "json"])
            self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main()
