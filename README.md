<div align="center">

# 🛡️ OWASP AISVS Scanner (`aisvs-scan`)

**Enterprise-Grade Static Security Verification & Compliance Auditor for AI Systems, Autonomous Agents, and Model Context Protocol (MCP)**

[![OWASP AISVS](https://img.shields.io/badge/OWASP-AISVS%20v1.01%20%7C%20v1.02--dev-blue?style=for-the-badge&logo=owasp)](https://github.com/OWASP/AISVS)
[![Python Version](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-informational?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg?style=for-the-badge)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Python)-brightgreen?style=for-the-badge)](#)
[![SARIF 2.1.0](https://img.shields.io/badge/Format-SARIF%202.1.0%20Ready-purple?style=for-the-badge&logo=github)](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
[![Tests Passing](https://img.shields.io/badge/Tests-100%25%20Passing-success?style=for-the-badge)](#testing)

<p align="center">
  <a href="#key-capabilities">Key Capabilities</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#chapter-coverage">12 AISVS Chapters</a> •
  <a href="#interactive-html-dashboard">Interactive Dashboard</a> •
  <a href="#cli-reference">CLI Reference</a> •
  <a href="#cicd-integration">CI/CD Integration</a> •
  <a href="#case-study">Real-World Benchmark</a>
</p>

</div>

---

## Executive Overview

The **[OWASP Artificial Intelligence Security Verification Standard (AISVS)](https://github.com/OWASP/AISVS)** establishes a comprehensive, vendor-neutral baseline of security requirements for modern AI applications, machine learning systems, autonomous agent swarms, and foundation model integrations.

`aisvs-scan` is a static application security testing (SAST) and compliance verification engine purpose-built for the AI era. It inspects source code, prompt hierarchies, tool manifests, MCP client/server topologies, and serialized model artifacts directly against the official AISVS catalog, evaluating requirements across **Levels 1, 2, and 3**.

Unlike legacy SAST tools that only identify generic injection vulnerabilities, `aisvs-scan` understands **AI-native threat vectors**:
- Model Context Protocol (MCP) server impersonation, DNS rebinding, unpinned tool runners, and form-mode secret elicitation.
- Agent tool execution without process isolation, sandbox escapes, and auto-approval bypasses on destructive actions.
- Model output flow into dangerous command, SQL, file, or network execution sinks (AI Taint Tracking).
- System/developer prompt contamination and instruction hierarchy degradation.
- Weaponized serialization opcodes embedded within PyTorch, Pickle, and Joblib model weights.
- Unauthenticated vector databases, cross-tenant embedding collisions, and missing retrieval authorization filters in RAG pipelines.

> ⚡ **Zero Third-Party Dependencies:** Implemented strictly using the Python Standard Library (`ast`, `re`, `pickle`, `urllib`, `dataclasses`, `argparse`). Installs instantaneously and runs hermetically in air-gapped or restricted CI environments.

---

## Key Capabilities

```
┌────────────────────────────────────────────────────────────────────────┐
│                        OWASP AISVS SCANNER                             │
├───────────────────────────────┬────────────────────────────────────────┤
│ 🎯 214 AISVS Requirements     │ 100% coverage of official AISVS 1.01   │
│                               │ and 1.02-dev standard specifications.  │
├───────────────────────────────┼────────────────────────────────────────┤
│ 🔬 4 Specialized Engines      │ AST Taint Tracker, MCP Config Auditor, │
│                               │ Model Weights Disassembler, & Rules.   │
├───────────────────────────────┼────────────────────────────────────────┤
│ 🛡️ Multi-Verdict Auditing     │ PASS (verified defense), FAIL (flaw),  │
│                               │ GAP (missing), MANUAL, and N/A.        │
├───────────────────────────────┼────────────────────────────────────────┤
│ 🧩 Component Profiling        │ Automatic detection of LLMs, Agents,   │
│                               │ RAG, MCP, Fine-Tuning, & Edge AI.      │
├───────────────────────────────┼────────────────────────────────────────┤
│ 📊 6 Enterprise Reports       │ Interactive HTML, SARIF 2.1.0, JSON,   │
│                               │ Terminal ANSI, Markdown, & GRC CSV.    │
└───────────────────────────────┴────────────────────────────────────────┘
```

---

## Architecture & Detection Engines

`aisvs-scan` uses a hybrid analysis pipeline combining syntax parsing, abstract syntax tree (AST) data-flow tracking, configuration auditing, and binary serialization inspection.

```
                           Target Repository / AI Project
                                         │
                             [File Walker & Lang Router]
                                         │
       ┌──────────────────┬──────────────┴─────┬──────────────────┐
       ▼                  ▼                    ▼                  ▼
┌──────────────┐   ┌──────────────┐     ┌──────────────┐   ┌──────────────┐
│  AST Taint   │   │  MCP Config  │     │   Artifact   │   │ Declarative  │
│   Tracker    │   │   Auditor    │     │ Disassembler │   │ Rule Engine  │
│ (Python AST) │   │ (JSON/Configs│     │ (.pkl/.pt)   │   │ (175+ Rules) │
└──────┬───────┘   └──────┬───────┘     └──────┬───────┘   └──────┬───────┘
       │                  │                    │                  │
       └──────────────────┴──────────────┬─────┴──────────────────┘
                                         ▼
                     [AI Feature & Component Profiler]
                                         ▼
                   [AISVS Requirements Verification Engine]
               (Evaluates L1/L2/L3: PASS, FAIL, GAP, MANUAL, N/A)
                                         ▼
       ┌──────────────────┬──────────────┼──────────────────┬─────────────┐
       ▼                  ▼              ▼                  ▼             ▼
Terminal Output      SARIF 2.1.0     HTML Report         Markdown      GRC CSV
(Developer UX)     (GitHub Security) (Dynamic Dashboard) (PR Summary) (Auditor)
```

### 1. Python AST Taint Tracking Engine (`analyzers/taint.py`)
Traces untrusted AI outputs and tool parameters through the Abstract Syntax Tree into critical sinks without relying on heuristic string matching:
- **Taint Sources**: Return values of LLM completion methods (`client.chat.completions.create`, `messages.create`, `generate_content`, `litellm`, etc.) and arguments passed into functions decorated as tools (`@tool`, `@function_tool`, `@mcp.tool`).
- **Execution Sinks**: 
  - Host Command & Code Execution (`eval`, `exec`, `os.system`, `subprocess.run`, `pty.spawn`, `asyncio.create_subprocess_shell`).
  - SQL Execution (`cursor.execute`, `pd.read_sql`).
  - File System Write/Delete Operations (`Path.write_text`, `os.remove`, `shutil.rmtree`).
  - Arbitrary Outbound Network Requests (`requests.get`, `httpx.post`, `aiohttp`).
  - Unsanitized HTML Rendering (XSS/SSRF via `render_template_string`, `Markup`).
- **Unbounded Agent Loop Detection**: Detects `while True` agent reasoning loops lacking loop budgets, recursion depth limits, or break conditions.

### 2. MCP Security & Governance Engine (`analyzers/mcp_config.py`)
Inspects MCP server manifests, `mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`, and client configurations:
- **Unpinned Tool Runners**: Flags executions of unpinned packages (`npx -y @package@latest`, `uvx tool`, `docker run image:latest`) vulnerable to supply chain hijacking.
- **Insecure Transport**: Detects remote MCP servers communicating over unencrypted plaintext HTTP (`http://`).
- **Secret Leaks**: Discovers hard-coded API keys, bearer tokens, and credentials in MCP environment blocks and headers.
- **Permission Over-scoping**: Catches servers configured with broad filesystem access (`/`, `~`, `$HOME`).
- **Human Approval Bypasses**: Flags auto-approval configurations (`autoApprove: ["*"]` or `trust: true`) that bypass human oversight on privileged actions.

### 3. Model Weight & Serialization Inspector (`analyzers/artifact.py`)
Inspects binary model files (`.pkl`, `.pt`, `.pth`, `.bin`, `.joblib`, `.ckpt`):
- **Executable Format Detection**: Flags pickle-based formats that allow arbitrary Python code execution during deserialization (recommending memory-mapped formats like Safetensors or GGUF).
- **Opcode Disassembly**: Safely parses the pickle bytecode stream without loading arbitrary objects to detect dangerous globals (`os.system`, `subprocess.Popen`, `posix_spawn`, `eval`, `builtins.exec`).

### 4. Declarative Pattern & Call Engine (`rules/`)
Over 175 rules covering prompt injection, token length enforcement, system message isolation, rate limits, structured JSON schema validation, and GenAI telemetry.

---

## 12 AISVS Chapters: Standard Coverage

`aisvs-scan` audits against all **12 Chapters (214 requirements)** defined in the official OWASP standard across verification levels **L1, L2, and L3**:

| Chapter | Title | Focus Areas & Controls Checked |
| :---: | :--- | :--- |
| **C1** | **Training Data Integrity & Traceability** | Feature minimization (1.1.1), data provenance inventory (1.1.2), dataset integrity monitoring (1.1.4), annotation access controls (1.2.1), data poisoning defenses (1.3.1), bias evaluation (1.3.3), and content sanitization before training (1.3.4). |
| **C2** | **Input Validation & Prompt Injection** | Input normalization (2.1.1), encoding smuggling defenses (2.1.2), prompt injection classifiers (2.1.3), input length enforcement (2.1.4), character set allow-listing (2.1.5), instruction hierarchy enforcement (2.1.6), and special-token injection prevention (2.1.7). |
| **C3** | **Model Lifecycle Management** | Model registries (3.1.1), cryptographic artifact signing (3.1.2) and admission verification (3.1.3), safety evaluation test suites (3.2.1), post-quantization validation (3.2.2), pinned model versions (3.2.3), and automated rollback triggers (3.3.1). |
| **C4** | **Infrastructure & Sandboxing** | Isolated workload execution (4.1.1), safe deserialization format allow-lists (4.1.2), hardware/workload attestation (4.1.3), confidential inference (4.1.4), GPU memory isolation (4.2.4), and on-device secure enclaves (4.3.4). |
| **C5** | **Access Control & Identity** | Step-up auth for high-risk actions (5.1.1), short-lived agent tokens (5.1.2), endpoint access controls & CORS (5.2.1), retrieval authorization context propagation (5.2.2), post-inference filtering (5.2.4), and multi-tenant compute isolation (5.3.1). |
| **C6** | **Supply Chain & AI BOM** | Malicious model scanning (6.1.1), approved weight sources (6.1.2), artifact integrity digests (6.1.3), machine-readable AI BOM (CycloneDX/SPDX3) (6.2.1), signed AI BOMs (6.2.2), and dependency confusion protections (6.1.2). |
| **C7** | **Model Behavior & Output Safety** | Strict schema validation on outputs (7.1.1), length bounds and stop tokens (7.1.2), refusal handling before action (7.1.3), confidence estimation (7.2.1), prompt disclosure filtering (7.3.2), outbound request blocks (7.3.3), and RAG citation provenance (7.4.2). |
| **C8** | **Memory, Embeddings & Vector DB** | Cross-tenant namespace isolation (8.1.1), retrieval scope constraints (8.1.3), PII masking before embedding (8.2.1), vector anomaly quarantine (8.2.2), memory TTL & expiry (8.3.1), and memory revocation/reset mechanisms (8.3.2). |
| **C9** | **Orchestration & Agentic Action** | Per-tool quotas & timeouts (9.1.1), execution loop budgets (9.1.2), swarm kill-switches (9.1.3), human approval gates for high-impact actions (9.2.1), reversibility classification (9.2.3), tool sandbox isolation (9.3.1), tool manifests (9.3.3), and agent identity (9.4.1). |
| **C10** | **Model Context Protocol (MCP)** | Component source verification (10.1.1), local sandbox confinement (10.1.3), token claim validation (10.2.2), no token passthrough (10.2.7), streamable HTTPS transport (10.3.1), DNS rebinding defenses (10.3.3), schema bounds (10.4.13), and tool definition pinning (10.4.8). |
| **C11** | **Adversarial Robustness** | Alignment suites (11.1.2), adversarial red-teaming (11.1.3), rate-limiting sized to extraction threats (11.2.2), membership-inference mitigations (11.2.4), extraction query detection (11.3.1), and decoding parameter constraints (11.3.5). |
| **C12** | **Monitoring & Logging** | Session telemetry (12.1.1), safety filtering audit logs (12.1.2), structured GenAI telemetry schema (OTel `gen_ai`) (12.1.3), RAG retrieval logging (12.1.4), jailbreak alerting (12.2.1), token attribution (12.2.5), drift detection (12.3.1), and hallucination tracking (12.3.3). |

---

## Verification Verdicts

For every requirement evaluated, the engine produces one of five verdicts:

- **`PASS`**: Positive defense control or implementation indicator was statically verified (e.g. schema validator, token length bound, sandbox runner, signature verification).
- **`FAIL`**: Actionable security weakness or policy violation detected in code, prompt, configuration, or model artifact.
- **`GAP`**: Statically verifiable requirement that is applicable to the target but has no detected defense indicator.
- **`MANUAL`**: The requirement requires human, operational, legal, or physical review (e.g. legal data agreements, out-of-band reviews).
- **`N/A`**: The relevant AI component (e.g. MCP, RAG, Agent, Training, Edge) was not detected in the target project, eliminating irrelevant noise.

---

## Quickstart

### 1. Run Directly (No Installation Needed)
```bash
# Clone the scanner
git clone https://github.com/mesutgungor/aisvs_scanner.git
cd aisvs_scanner

# Run scan on any target
./bin/aisvs-scan scan /path/to/ai-project
```

### 2. Install as a CLI Tool
```bash
python3 -m pip install -e .
aisvs-scan --help
```

---

## CLI Reference

### `aisvs-scan scan [TARGET] [OPTIONS]`
Performs a security verification audit of a target directory, file, or repository.

| Flag | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `target` | Positional | `.` | Directory or file to scan. |
| `-l`, `--level` | `1 \| 2 \| 3` | `3` | Maximum AISVS assurance level to audit against. |
| `-f`, `--format` | Choice | `terminal` | Report format: `terminal`, `html`, `sarif`, `json`, `markdown`, `csv`. |
| `-o`, `--output` | Path | `stdout` | Write output to a file instead of standard output. |
| `--fail-on` | Severity | None | Exit with code `1` if findings at or above this severity are found (`info`, `low`, `medium`, `high`, `critical`). |
| `-e`, `--exclude` | Glob | None | Exclude paths matching glob pattern (can be specified multiple times). |
| `--min-severity` | Severity | `low` | Filter out findings below this severity threshold. |
| `--min-confidence` | Choice | `low` | Filter out findings below confidence level (`low`, `medium`, `high`). |
| `--standard-version` | Choice | `1.01` | AISVS catalog version (`1.01` or `1.02-dev`). |
| `--rule` | Rule ID | None | Run only specific rule IDs (can be repeated). |
| `--ignore-rule` | Rule ID | None | Ignore specific rule IDs (can be repeated). |

### `aisvs-scan list-requirements [OPTIONS]`
Browse the official AISVS requirements catalog.

```bash
# View all requirements for Chapter 10 (MCP Security)
aisvs-scan list-requirements -c C10

# View only foundational Level 1 requirements for Input Validation
aisvs-scan list-requirements -c C2 -l 1
```

### `aisvs-scan list-rules`
List all 175+ built-in detection rules and defense indicators, showing their mapped AISVS controls and severities.

### `aisvs-scan sync`
Fetch the latest AISVS requirements and descriptions directly from the official [OWASP/AISVS](https://github.com/OWASP/AISVS) repository:
```bash
aisvs-scan sync --standard-version 1.02-dev --ref main
```

---

## Interactive HTML Dashboard

`aisvs-scan` includes a standalone, zero-dependency interactive HTML dashboard (`-f html`):

```bash
aisvs-scan scan /path/to/project -f html -o aisvs-audit-report.html
```

### Dashboard Features:
- **Interactive KPI Status Cards**: Click `PASS`, `FAIL`, `GAP`, `MANUAL`, or `N/A` cards to immediately filter the requirements matrix.
- **Findings Live Search & Severity Filter**: Instant real-time filtering across Rule IDs, file paths, snippets, and severities.
- **Chapter Selectors & Quick Pills**: Toggle presets like `Critical & High`, `MCP Only (C10)`, or `Agents (C9)`.
- **Expandable Code Inspection Drawers**: Click any finding row to reveal the extracted source code snippet, confidence score, and remediation steps.
- **Requirement Verification Matrix**: Live full-text search with dynamic counter (`Showing X of 214 requirements`).
- **Global Reset**: Single click to restore all views and filters.

---

## Output Formats

| Format Flag | Output Type | Primary Use Case |
| :--- | :--- | :--- |
| `-f terminal` | Rich ANSI terminal | Interactive developer workflow and local scanning. |
| `-f html` | Standalone HTML | Executive audit presentations, stakeholder reviews, and security teams. |
| `-f sarif` | OASIS SARIF 2.1.0 | Native GitHub Code Scanning, GitLab SAST, and IDE problem matchers. |
| `-f markdown` | GitHub Flavored Markdown | Pull request comments, automated security summaries, and wikis. |
| `-f json` | Structured JSON | Automation pipelines, SIEM ingest, and security data lakes. |
| `-f csv` | Comma-Separated Values | Compliance matrices, GRC tracking, and Excel spreadsheets. |

---

## CI/CD Integration

### GitHub Actions Workflow (with SARIF Alerts & Build Failure)

Create `.github/workflows/aisvs-security.yml`:

```yaml
name: OWASP AISVS AI Security Verification

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  ai-security-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Checkout AISVS Scanner
        uses: actions/checkout@v4
        with:
          repository: 'mesutgungor/aisvs_scanner'
          path: './.aisvs_scanner'

      - name: Run AISVS Security Verification
        run: |
          python3 ./.aisvs_scanner/bin/aisvs-scan scan . \
            --level 2 \
            --format sarif \
            --output aisvs-results.sarif \
            --fail-on high \
            -e ".aisvs_scanner/*" -e "tests/*"

      - name: Upload Results to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: aisvs-results.sarif
```

---

## Real-World Benchmark Case Study

The scanner was benchmarked against [`assafelovic/gpt-researcher`](https://github.com/assafelovic/gpt-researcher) (30,000+ ⭐), a complex open-source autonomous agent framework containing multi-agent loops, vector retrieval, and MCP servers:

```text
=== OWASP AISVS AI Security Verification Standard Scanner ===
Standard: OWASP AISVS v1.01 (Level 1-2) | Target: gpt-researcher
Scanned: 708 files in 51.23s

Verification Summary:
  PASS:    70 (Verified defense indicators present)
  FAIL:    15 (Actionable security violations detected)
  GAP:     73 (Applicable controls missing static indicators)
  MANUAL:   7 (Human/operational verification required)
  N/A:      2 (Features not present in target)
```

### Key Real-World Findings Detected:
1. **Unpinned MCP Tool Execution (`AIS-MCPCFG-001` → AISVS #10.1.1)**:
   `.mcp.json` executed `uvx gpt-researcher` without an exact version pin or digest. A compromised package release would immediately execute arbitrary code upon client launch.
2. **Unsafe Pickle Deserialization in Browser Scraper (`AIS-DESER-001` → AISVS #4.1.2, #6.1.1)**:
   `gpt_researcher/scraper/browser/browser.py` used `pickle.load()` on browser cookies, allowing remote code execution via poisoned state files.
3. **Retrieval Queries Without Tenant Filters (`AIS-RAG-002` → AISVS #5.2.2, #8.1.3)**:
   Vector store queries in `backend/chat/chat.py` were invoked without metadata scoping, allowing potential cross-tenant document leakage in multi-user environments.
4. **Silent Input Truncation (`AIS-PROMPT-003` → AISVS #2.1.4)**:
   Input strings were silently sliced (`context[:max_len]`) instead of rejected, which can strip safety guardrails and developer instructions.
5. **MCP Server Bound to `0.0.0.0` Without Host Verification (`AIS-MCP-013` → AISVS #10.3.3)**:
   FastAPI MCP server bound to all interfaces without Origin/Host verification middleware, exposing it to local DNS rebinding attacks.

*(An interactive HTML report of this benchmark is included in `examples/reports/gpt_researcher_audit_report.html`)*.

---

## Suppressing Warnings

To suppress false positives or document accepted risks, use inline directives on the offending line:

```python
# Suppress a specific rule:
api_key = get_temporary_test_token()  # aisvs:ignore AIS-SECRET-001

# Suppress all rules on a line:
result = client.chat.completions.create(...)  # noqa

# Or use standard security suppression tags:
raw_input = req.get_data()  # nosec
```

---

## Testing

Run the comprehensive unit test suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

All unit tests execute hermetically in `< 0.05 seconds`.

---

## Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/new-aisvs-rule`).
3. Commit your changes (`git commit -m 'Add AISVS check for C10.4.8'`).
4. Ensure all unit tests pass (`python3 -m unittest discover -s tests`).
5. Open a Pull Request.

---

## License

Distributed under the **Apache License 2.0**. See [`LICENSE`](LICENSE) for details.

Aligned with the **[OWASP Artificial Intelligence Security Verification Standard](https://github.com/OWASP/AISVS)** project.
