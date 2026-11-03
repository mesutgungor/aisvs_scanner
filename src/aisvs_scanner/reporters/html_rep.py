"""Standalone interactive HTML compliance dashboard with comprehensive dynamic filters."""
from __future__ import annotations

import html
import json
from typing import Dict, TextIO

from ..models import Finding, RequirementResult, ScanResult, Severity, Status

CHAPTER_NAMES = {
    "C1": "Training Data Integrity & Traceability",
    "C2": "Input Validation & Prompt Injection",
    "C3": "Model Lifecycle Management",
    "C4": "Infrastructure & Sandboxing",
    "C5": "Access Control & Identity",
    "C6": "Supply Chain & AI BOM",
    "C7": "Model Behavior & Output Safety",
    "C8": "Memory, Embeddings & Vector DB",
    "C9": "Orchestration & Agentic Action",
    "C10": "Model Context Protocol (MCP)",
    "C11": "Adversarial Robustness",
    "C12": "Monitoring & Logging",
}


def render_html(result: ScanResult, out: TextIO):
    counts = result.counts()

    # Precompute chapter counts
    chapter_stats: Dict[str, Dict[str, int]] = {}
    for r in result.results:
        cid = r.requirement.chapter
        if cid not in chapter_stats:
            chapter_stats[cid] = {s.value: 0 for s in Status}
        chapter_stats[cid][r.status.value] += 1

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OWASP AISVS Verification Dashboard - {html.escape(result.target)}</title>
  <style>
    :root {{
      --bg: #0d1117;
      --card-bg: #161b22;
      --card-hover: #1f242c;
      --border: #30363d;
      --border-focus: #58a6ff;
      --text: #c9d1d9;
      --text-dim: #8b949e;
      --text-bright: #f0f6fc;
      --pass: #238636;
      --pass-badge: #3fb950;
      --pass-bg: rgba(35, 134, 54, 0.18);
      --fail: #da3633;
      --fail-badge: #f85149;
      --fail-bg: rgba(218, 54, 51, 0.18);
      --gap: #d29922;
      --gap-badge: #e3b341;
      --gap-bg: rgba(210, 153, 34, 0.18);
      --manual: #1f6feb;
      --manual-badge: #58a6ff;
      --manual-bg: rgba(31, 111, 235, 0.18);
      --na: #484f58;
      --na-badge: #8b949e;
      --na-bg: rgba(110, 118, 129, 0.18);
      --code-bg: rgba(110, 118, 129, 0.15);
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 24px;
      line-height: 1.5;
    }}
    .container {{ max-width: 1300px; margin: 0 auto; }}
    h1, h2, h3, h4 {{ color: var(--text-bright); }}
    
    .header {{
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 12px;
    }}
    .header h1 {{ font-size: 1.75rem; font-weight: 700; }}
    .meta {{ color: var(--text-dim); font-size: 0.9rem; margin-top: 6px; }}
    .tags {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px; }}
    .tag {{
      background: rgba(56, 139, 253, 0.15);
      color: #58a6ff;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
    }}

    /* KPI Clickable Cards */
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      text-align: center;
      cursor: pointer;
      user-select: none;
      transition: all 0.2s ease;
      position: relative;
    }}
    .card:hover {{
      background: var(--card-hover);
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }}
    .card.active {{
      border-color: var(--text-bright);
      box-shadow: 0 0 0 2px var(--border-focus);
    }}
    .card .label {{
      font-size: 0.85rem;
      font-weight: 600;
      letter-spacing: 0.05em;
      color: var(--text-dim);
    }}
    .card .val {{
      font-size: 2.2rem;
      font-weight: 800;
      margin: 8px 0 4px;
    }}
    .card.pass .val {{ color: var(--pass-badge); }}
    .card.fail .val {{ color: var(--fail-badge); }}
    .card.gap .val {{ color: var(--gap-badge); }}
    .card.manual .val {{ color: var(--manual-badge); }}
    .card.na .val {{ color: var(--na-badge); }}
    .card .hint {{
      font-size: 0.75rem;
      color: var(--text-dim);
    }}

    /* Section Titles & Counters */
    .section-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin: 32px 0 16px;
      flex-wrap: wrap;
      gap: 12px;
    }}
    .counter-badge {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--text-dim);
      padding: 3px 10px;
      border-radius: 20px;
      font-size: 0.85rem;
      font-weight: 600;
    }}

    /* Filter Controls Bar */
    .filter-bar {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 16px;
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
    }}
    .filter-bar input[type="text"] {{
      background: #0d1117;
      border: 1px solid var(--border);
      color: var(--text-bright);
      padding: 7px 12px;
      border-radius: 6px;
      font-size: 0.88rem;
      min-width: 220px;
      flex: 1;
    }}
    .filter-bar select {{
      background: #0d1117;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 7px 12px;
      border-radius: 6px;
      font-size: 0.88rem;
      cursor: pointer;
    }}
    .filter-bar input[type="text"]:focus, .filter-bar select:focus {{
      outline: none;
      border-color: var(--border-focus);
    }}
    .btn {{
      background: rgba(110, 118, 129, 0.2);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 0.82rem;
      cursor: pointer;
      transition: all 0.15s;
    }}
    .btn:hover {{ background: rgba(110, 118, 129, 0.35); color: var(--text-bright); }}
    .btn.active {{
      background: var(--border-focus);
      color: #ffffff;
      border-color: var(--border-focus);
      font-weight: 600;
    }}

    .pill-group {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      align-items: center;
    }}

    /* Tables */
    table {{
      width: 100%;
      border-collapse: separate;
      border-spacing: 0;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 24px;
      font-size: 0.88rem;
    }}
    th, td {{
      padding: 12px 14px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      background: #1c2128;
      color: var(--text-bright);
      font-weight: 600;
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tbody tr:hover {{ background: rgba(255, 255, 255, 0.025); }}
    
    /* Status & Severity Badges */
    .badge {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.02em;
      white-space: nowrap;
    }}
    .badge.critical {{ background: rgba(248, 81, 73, 0.25); color: #ff7b72; border: 1px solid rgba(248, 81, 73, 0.4); }}
    .badge.high {{ background: var(--fail-bg); color: var(--fail-badge); border: 1px solid rgba(248, 81, 73, 0.3); }}
    .badge.medium {{ background: var(--gap-bg); color: var(--gap-badge); border: 1px solid rgba(227, 179, 65, 0.3); }}
    .badge.low {{ background: rgba(56, 139, 253, 0.18); color: #58a6ff; border: 1px solid rgba(56, 139, 253, 0.3); }}
    .badge.info {{ background: var(--na-bg); color: var(--na-badge); }}

    .badge.pass {{ background: var(--pass-bg); color: var(--pass-badge); border: 1px solid rgba(63, 185, 80, 0.3); }}
    .badge.fail {{ background: var(--fail-bg); color: var(--fail-badge); border: 1px solid rgba(248, 81, 73, 0.3); }}
    .badge.gap {{ background: var(--gap-bg); color: var(--gap-badge); border: 1px solid rgba(227, 179, 65, 0.3); }}
    .badge.manual {{ background: var(--manual-bg); color: var(--manual-badge); border: 1px solid rgba(88, 166, 255, 0.3); }}
    .badge.na {{ background: var(--na-bg); color: var(--na-badge); }}

    code {{
      background: var(--code-bg);
      padding: 2px 5px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      font-size: 0.82rem;
      color: #ff7b72;
    }}
    .loc-code {{ color: #79c0ff; }}

    /* Expandable finding row */
    .finding-row {{ cursor: pointer; }}
    .finding-details {{
      display: none;
      background: #0d1117;
      border-bottom: 1px solid var(--border);
      padding: 14px 18px;
    }}
    .finding-details.show {{ display: table-row; }}
    .details-content {{
      padding: 10px 14px;
      background: #161b22;
      border-left: 3px solid var(--border-focus);
      border-radius: 0 6px 6px 0;
      margin: 4px 0;
    }}
    .snippet-box {{
      background: #0d1117;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 8px 12px;
      font-family: monospace;
      font-size: 0.8rem;
      color: #e3b341;
      overflow-x: auto;
      margin: 8px 0;
    }}
    .fix-box {{
      color: #3fb950;
      font-size: 0.85rem;
      margin-top: 6px;
    }}

    .empty-state {{
      text-align: center;
      padding: 32px;
      color: var(--text-dim);
      font-style: italic;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>OWASP AISVS Verification Dashboard</h1>
        <div class="meta">
          Standard: <strong>OWASP AISVS v{result.standard_version}</strong> (Max Level {result.max_level}) &nbsp;|&nbsp; 
          Target: <code>{html.escape(result.target)}</code> &nbsp;|&nbsp; 
          Scanned {result.files_scanned} files in {result.duration_s:.2f}s
        </div>
        <div class="tags">
"""
    if result.features:
        for feat in sorted(result.features.keys()):
            doc += f"""          <span class="tag">AI: {html.escape(feat)}</span>\n"""

    doc += f"""        </div>
      </div>
      <div>
        <button class="btn" onclick="resetAllFilters()">↺ Reset All Filters</button>
      </div>
    </div>

    <!-- Clickable Interactive KPI Summary Cards -->
    <div class="cards">
      <div class="card pass" id="kpi-pass" onclick="toggleStatusFilter('PASS')">
        <div class="label">PASS</div>
        <div class="val">{counts['PASS']}</div>
        <div class="hint">Verified defenses &bull; Click to filter</div>
      </div>
      <div class="card fail" id="kpi-fail" onclick="toggleStatusFilter('FAIL')">
        <div class="label">FAIL</div>
        <div class="val">{counts['FAIL']}</div>
        <div class="hint">Actionable violations &bull; Click to filter</div>
      </div>
      <div class="card gap" id="kpi-gap" onclick="toggleStatusFilter('GAP')">
        <div class="label">GAP</div>
        <div class="val">{counts['GAP']}</div>
        <div class="hint">Missing controls &bull; Click to filter</div>
      </div>
      <div class="card manual" id="kpi-manual" onclick="toggleStatusFilter('MANUAL')">
        <div class="label">MANUAL</div>
        <div class="val">{counts['MANUAL']}</div>
        <div class="hint">Requires human review &bull; Click to filter</div>
      </div>
      <div class="card na" id="kpi-na" onclick="toggleStatusFilter('N/A')">
        <div class="label">N/A</div>
        <div class="val">{counts['N/A']}</div>
        <div class="hint">Not applicable &bull; Click to filter</div>
      </div>
    </div>

    <!-- Section 1: Actionable Findings -->
    <div class="section-header">
      <h2>Actionable Findings</h2>
      <span class="counter-badge" id="findingsCounter">Showing {len(result.findings)} of {len(result.findings)}</span>
    </div>

    <!-- Dynamic Filter Bar for Findings -->
    <div class="filter-bar">
      <input type="text" id="findingSearch" placeholder="Filter findings by rule, title, code, file, or keyword..." oninput="filterFindings()">
      
      <select id="findingSeverityFilter" onchange="filterFindings()">
        <option value="">All Severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
        <option value="INFO">Info</option>
      </select>

      <select id="findingChapterFilter" onchange="filterFindings()">
        <option value="">All Chapters</option>
"""
    for cid in sorted(CHAPTER_NAMES.keys(), key=lambda x: int(x[1:])):
        doc += f"""        <option value="{cid}">{cid}: {CHAPTER_NAMES[cid]}</option>\n"""

    doc += """      </select>

      <div class="pill-group">
        <button class="btn active" id="f-pill-all" onclick="setFindingSeverityQuick('')">All</button>
        <button class="btn" id="f-pill-crit-high" onclick="setFindingSeverityQuick('HIGH_PLUS')">Critical & High</button>
        <button class="btn" id="f-pill-mcp" onclick="setFindingChapterQuick('C10')">MCP Only (C10)</button>
        <button class="btn" id="f-pill-agent" onclick="setFindingChapterQuick('C9')">Agents (C9)</button>
      </div>
    </div>

    <table id="findingsTable">
      <thead>
        <tr>
          <th style="width: 100px;">Severity</th>
          <th style="width: 160px;">Rule</th>
          <th>Title & Details (Click row to expand)</th>
          <th style="width: 250px;">Location</th>
          <th style="width: 120px;">AISVS Controls</th>
        </tr>
      </thead>
      <tbody>
"""
    if not result.findings:
        doc += """        <tr><td colspan="5" class="empty-state">No security violations detected against applicable static controls.</td></tr>\n"""
    else:
        for idx, f in enumerate(result.findings, 1):
            sev_val = f.severity.value.upper()
            sev_class = f.severity.value.lower()
            # Determine chapters this finding maps to
            chaps = {f"C{r.split('.')[0]}" for r in f.requirements}
            chap_attr = " ".join(chaps)
            reqs_text = ", ".join(f.requirements)

            search_blob = f"{f.rule_id} {f.title} {f.message} {f.location.file} {f.location.snippet} {reqs_text}".lower()

            doc += f"""        <tr class="finding-row" id="frow-{idx}" onclick="toggleFindingDetails({idx})"
            data-severity="{sev_val}"
            data-chapters="{html.escape(chap_attr)}"
            data-search="{html.escape(search_blob)}">
          <td><span class="badge {sev_class}">{sev_val}</span></td>
          <td><code>{html.escape(f.rule_id)}</code></td>
          <td>
            <strong>{html.escape(f.title)}</strong>
            <div style="color:var(--text-dim); font-size:0.82rem; margin-top:2px;">{html.escape(f.message)}</div>
          </td>
          <td><span class="loc-code"><code>{html.escape(f.location.file)}:{f.location.line}</code></span></td>
          <td><strong>{html.escape(reqs_text)}</strong></td>
        </tr>
        <tr class="finding-details" id="fdet-{idx}">
          <td colspan="5">
            <div class="details-content">
              <div><strong>Confidence:</strong> {f.confidence.capitalize()} &nbsp;|&nbsp; <strong>AISVS Requirements:</strong> {html.escape(reqs_text)}</div>
"""
            if f.location.snippet:
                doc += f"""              <div style="margin-top:6px; font-size:0.82rem; color:var(--text-dim);">Code Snippet:</div>
              <div class="snippet-box">{html.escape(f.location.snippet)}</div>\n"""
            if f.remediation:
                doc += f"""              <div class="fix-box"><strong>Remediation:</strong> {html.escape(f.remediation)}</div>\n"""
            doc += """            </div>
          </td>
        </tr>\n"""

    doc += """      </tbody>
    </table>

    <!-- Section 2: Requirements Matrix -->
    <div class="section-header">
      <h2>Requirements Verification Checklist</h2>
      <span class="counter-badge" id="reqsCounter">Showing 0 of 0</span>
    </div>

    <!-- Dynamic Filter Bar for Requirements -->
    <div class="filter-bar">
      <input type="text" id="reqSearch" placeholder="Search requirements text, ID, or control note..." oninput="filterRequirements()">
      
      <select id="reqStatusFilter" onchange="filterRequirements()">
        <option value="">All Statuses</option>
        <option value="FAIL">FAIL (Violations)</option>
        <option value="PASS">PASS (Verified)</option>
        <option value="GAP">GAP (Missing)</option>
        <option value="MANUAL">MANUAL (Human review)</option>
        <option value="N/A">N/A (Not Applicable)</option>
      </select>

      <select id="reqChapterFilter" onchange="filterRequirements()">
        <option value="">All Chapters</option>
"""
    for cid in sorted(CHAPTER_NAMES.keys(), key=lambda x: int(x[1:])):
        c_stats = chapter_stats.get(cid, {})
        fail_cnt = c_stats.get("FAIL", 0)
        fail_note = f" ({fail_cnt} FAIL)" if fail_cnt > 0 else ""
        doc += f"""        <option value="{cid}">{cid}: {CHAPTER_NAMES[cid]}{fail_note}</option>\n"""

    doc += """      </select>

      <select id="reqLevelFilter" onchange="filterRequirements()">
        <option value="">All Levels</option>
        <option value="1">Level 1 (Foundational)</option>
        <option value="2">Level 2 (Hardened)</option>
        <option value="3">Level 3 (Advanced)</option>
      </select>
    </div>

    <table id="reqsTable">
      <thead>
        <tr>
          <th style="width: 80px;">ID</th>
          <th style="width: 70px;">Level</th>
          <th style="width: 80px;">Chapter</th>
          <th>Requirement Description</th>
          <th style="width: 110px;">Status</th>
          <th style="width: 280px;">Verification Evidence / Note</th>
        </tr>
      </thead>
      <tbody>
"""
    for r in result.results:
        req = r.requirement
        st_val = r.status.value
        st_class = st_val.lower().replace("/", "")
        search_blob = f"{req.id} {req.chapter} {req.text} {r.note}".lower()

        doc += f"""        <tr class="req-row"
            data-status="{st_val}"
            data-chapter="{req.chapter}"
            data-level="{req.level}"
            data-search="{html.escape(search_blob)}">
          <td><strong>{html.escape(req.id)}</strong></td>
          <td><span style="color:var(--text-dim)">L{req.level}</span></td>
          <td><strong>{html.escape(req.chapter)}</strong></td>
          <td>{html.escape(req.text)}</td>
          <td><span class="badge {st_class}">{st_val}</span></td>
          <td><small style="color:var(--text-dim)">{html.escape(r.note)}</small></td>
        </tr>
"""

    doc += """      </tbody>
    </table>
  </div>

  <script>
    // --- State variables ---
    let activeKpiStatus = null;

    // --- Interactive Finding details toggle ---
    function toggleFindingDetails(idx) {
      const row = document.getElementById('fdet-' + idx);
      if (row) {
        row.classList.toggle('show');
      }
    }

    // --- KPI Card Click Handler ---
    function toggleStatusFilter(status) {
      if (activeKpiStatus === status) {
        activeKpiStatus = null;
        document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
        document.getElementById('reqStatusFilter').value = '';
      } else {
        activeKpiStatus = status;
        document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
        const kpiCard = document.getElementById('kpi-' + status.toLowerCase().replace('/', ''));
        if (kpiCard) kpiCard.classList.add('active');
        document.getElementById('reqStatusFilter').value = status;
      }
      filterRequirements();

      // Scroll smoothly to requirements section if filtered
      const reqHeader = document.querySelector('#reqsTable');
      if (reqHeader) {
        reqHeader.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }

    // --- Quick Pills for Findings ---
    function setFindingSeverityQuick(mode) {
      document.querySelectorAll('#f-pill-all, #f-pill-crit-high').forEach(b => b.classList.remove('active'));
      if (mode === '') {
        document.getElementById('f-pill-all').classList.add('active');
        document.getElementById('findingSeverityFilter').value = '';
      } else if (mode === 'HIGH_PLUS') {
        document.getElementById('f-pill-crit-high').classList.add('active');
        document.getElementById('findingSeverityFilter').value = 'HIGH';
      }
      filterFindings();
    }

    function setFindingChapterQuick(chap) {
      const select = document.getElementById('findingChapterFilter');
      if (select.value === chap) {
        select.value = '';
      } else {
        select.value = chap;
      }
      filterFindings();
    }

    // --- Filter Findings Table ---
    function filterFindings() {
      const search = document.getElementById('findingSearch').value.toLowerCase().trim();
      const sev = document.getElementById('findingSeverityFilter').value;
      const chap = document.getElementById('findingChapterFilter').value;

      const rows = document.querySelectorAll('#findingsTable tbody tr.finding-row');
      let visibleCount = 0;

      rows.forEach(r => {
        const rowSev = r.getAttribute('data-severity');
        const rowChaps = r.getAttribute('data-chapters').split(' ');
        const searchBlob = r.getAttribute('data-search');
        const idMatch = r.id.replace('frow-', '');
        const detailRow = document.getElementById('fdet-' + idMatch);

        let matchSev = true;
        if (sev === 'HIGH') {
          matchSev = (rowSev === 'HIGH' || rowSev === 'CRITICAL');
        } else if (sev) {
          matchSev = (rowSev === sev);
        }

        let matchChap = !chap || rowChaps.includes(chap);
        let matchSearch = !search || searchBlob.includes(search);

        if (matchSev && matchChap && matchSearch) {
          r.style.display = '';
          visibleCount++;
        } else {
          r.style.display = 'none';
          if (detailRow) detailRow.classList.remove('show');
        }
      });

      const total = rows.length;
      document.getElementById('findingsCounter').textContent = `Showing ${visibleCount} of ${total}`;
    }

    // --- Filter Requirements Table ---
    function filterRequirements() {
      const search = document.getElementById('reqSearch').value.toLowerCase().trim();
      const status = document.getElementById('reqStatusFilter').value;
      const chapter = document.getElementById('reqChapterFilter').value;
      const level = document.getElementById('reqLevelFilter').value;

      const rows = document.querySelectorAll('#reqsTable tbody tr.req-row');
      let visibleCount = 0;

      rows.forEach(r => {
        const rowStatus = r.getAttribute('data-status');
        const rowChap = r.getAttribute('data-chapter');
        const rowLevel = r.getAttribute('data-level');
        const searchBlob = r.getAttribute('data-search');

        const matchStatus = !status || rowStatus === status;
        const matchChap = !chapter || rowChap === chapter;
        const matchLevel = !level || rowLevel === level;
        const matchSearch = !search || searchBlob.includes(search);

        if (matchStatus && matchChap && matchLevel && matchSearch) {
          r.style.display = '';
          visibleCount++;
        } else {
          r.style.display = 'none';
        }
      });

      const total = rows.length;
      document.getElementById('reqsCounter').textContent = `Showing ${visibleCount} of ${total}`;
    }

    // --- Reset All Filters ---
    function resetAllFilters() {
      document.getElementById('findingSearch').value = '';
      document.getElementById('findingSeverityFilter').value = '';
      document.getElementById('findingChapterFilter').value = '';
      document.getElementById('reqSearch').value = '';
      document.getElementById('reqStatusFilter').value = '';
      document.getElementById('reqChapterFilter').value = '';
      document.getElementById('reqLevelFilter').value = '';

      activeKpiStatus = null;
      document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
      document.querySelectorAll('.btn').forEach(b => b.classList.remove('active'));
      document.getElementById('f-pill-all').classList.add('active');

      filterFindings();
      filterRequirements();
    }

    // Initial setup on load
    document.addEventListener('DOMContentLoaded', () => {
      filterFindings();
      filterRequirements();
    });
    // Trigger immediately in case DOM is already ready
    filterFindings();
    filterRequirements();
  </script>
</body>
</html>
"""
    out.write(doc)
