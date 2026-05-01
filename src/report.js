// src/report.js — Report generation (HTML + JSON)
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  /**
   * Generate a standalone HTML report from analysis results
   */
  JSA.generateHTMLReport = function (results, metadata) {
    const meta = metadata || {};
    const timestamp = new Date().toISOString();
    const totalFindings = Object.values(results).reduce((s, arr) => s + arr.length, 0);

    // Count by severity
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    Object.values(results).forEach(arr => {
      arr.forEach(item => {
        const sev = (item.severity || 'info').toLowerCase();
        if (severityCounts[sev] !== undefined) severityCounts[sev]++;
      });
    });

    let findingsHTML = '';
    for (const [category, items] of Object.entries(results)) {
      if (items.length === 0) continue;
      const catLabel = (JSA.CATEGORIES.find(c => c.id === category) || {}).label || category;
      findingsHTML += `<div class="category"><h3>${escHtml(catLabel)} (${items.length})</h3>`;
      findingsHTML += `<table><thead><tr><th>Value</th><th>Type</th><th>Severity</th><th>Source</th></tr></thead><tbody>`;
      items.forEach(item => {
        const sev = item.severity || 'info';
        findingsHTML += `<tr>
          <td class="val">${escHtml(item.value)}</td>
          <td>${escHtml(item.type)}</td>
          <td><span class="sev sev-${sev}">${sev.toUpperCase()}</span></td>
          <td>${escHtml(item.sourceFile || '-')}</td>
        </tr>`;
      });
      findingsHTML += `</tbody></table></div>`;
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JS Recon Report — ${escHtml(meta.fileName || 'Analysis')}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter','Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}
h1{font-size:1.75rem;margin-bottom:.5rem;background:linear-gradient(to right,#60a5fa,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.meta{color:#94a3b8;font-size:.875rem;margin-bottom:2rem}
.summary{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}
.scard{padding:1rem 1.5rem;border-radius:.75rem;border:1px solid rgba(148,163,184,.15);background:rgba(30,41,59,.7);min-width:120px}
.scard .num{font-size:1.75rem;font-weight:700}
.scard .lbl{color:#94a3b8;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
.num.critical{color:#ef4444}.num.high{color:#f97316}.num.medium{color:#f59e0b}.num.low{color:#3b82f6}.num.info{color:#6b7280}
.category{margin-bottom:2rem}
.category h3{font-size:1.125rem;margin-bottom:.75rem;padding-bottom:.5rem;border-bottom:1px solid rgba(148,163,184,.15)}
table{width:100%;border-collapse:collapse;font-size:.8125rem}
th{text-align:left;padding:.5rem .75rem;background:rgba(15,23,42,.6);color:#94a3b8;font-weight:600;text-transform:uppercase;font-size:.6875rem;letter-spacing:.05em}
td{padding:.5rem .75rem;border-bottom:1px solid rgba(148,163,184,.08);vertical-align:top}
td.val{color:#60a5fa;word-break:break-all;font-family:monospace;font-size:.8125rem}
.sev{display:inline-block;padding:.125rem .5rem;border-radius:9999px;font-size:.6875rem;font-weight:700}
.sev-critical{background:rgba(239,68,68,.2);color:#fca5a5}.sev-high{background:rgba(249,115,22,.2);color:#fdba74}
.sev-medium{background:rgba(245,158,11,.2);color:#fcd34d}.sev-low{background:rgba(59,130,246,.2);color:#93c5fd}
.sev-info{background:rgba(107,114,128,.2);color:#d1d5db}
tr:hover{background:rgba(51,65,85,.4)}
</style>
</head>
<body>
<h1>JS Recon Analyzer — Report</h1>
<div class="meta">
  <p>Generated: ${timestamp}</p>
  <p>Target: ${escHtml(meta.fileName || 'Unknown')}</p>
  <p>Total Findings: ${totalFindings}</p>
</div>

<div class="summary">
  <div class="scard"><div class="num critical">${severityCounts.critical}</div><div class="lbl">Critical</div></div>
  <div class="scard"><div class="num high">${severityCounts.high}</div><div class="lbl">High</div></div>
  <div class="scard"><div class="num medium">${severityCounts.medium}</div><div class="lbl">Medium</div></div>
  <div class="scard"><div class="num low">${severityCounts.low}</div><div class="lbl">Low</div></div>
  <div class="scard"><div class="num info">${severityCounts.info}</div><div class="lbl">Info</div></div>
</div>

${findingsHTML}

</body></html>`;
  };

  function escHtml(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

})();
