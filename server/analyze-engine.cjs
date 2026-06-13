// server/analyze-engine.cjs — Server-side analysis engine
// Loads client-side modules (patterns.js, ast-analyzer.js) in a sandboxed context
// so we maintain a single source of truth for detection rules.

const fs = require('fs');
const path = require('path');
const acorn = require('acorn');

/**
 * Run full static analysis on JS code server-side.
 * Mirrors client-side analyzeFileContent() but runs in Node.js.
 * @param {string} code - JavaScript source code
 * @param {string} fileName - Source filename for findings
 * @returns {{ secrets, endpoints, urls, ips, vulnerabilities, libraries }}
 */
function analyze(code, fileName) {
  // ─── Create sandboxed JSA context ───
  const JSA = {};
  const sandbox = { window: { JSA }, self: { JSA }, JSA, acorn };

  // Load patterns.js into sandbox
  try {
    const patternsCode = fs.readFileSync(path.join(__dirname, '..', 'src', 'patterns.js'), 'utf8');
    const patternsFn = new Function('window', 'self', 'JSA', patternsCode);
    patternsFn(sandbox.window, sandbox.self, JSA);
    Object.assign(JSA, sandbox.window.JSA);
  } catch (e) {
    console.error('[Engine] Failed to load patterns.js:', e.message);
  }

  // Load ast-analyzer.js into sandbox
  try {
    const astCode = fs.readFileSync(path.join(__dirname, '..', 'src', 'ast-analyzer.js'), 'utf8');
    const astFn = new Function('window', 'self', 'JSA', 'acorn', astCode);
    astFn(sandbox.window, sandbox.self, JSA, acorn);
    Object.assign(JSA, sandbox.window.JSA);
  } catch (e) {
    console.error('[Engine] Failed to load ast-analyzer.js:', e.message);
  }

  const results = {
    secrets: [],
    endpoints: [],
    'full-urls': [],
    ips: [],
    vulnerabilities: [],
    libraries: [],
    emails: []
  };

  // ─── 1. Regex-based pattern matching ───
  if (JSA.PATTERNS) {
    for (const [key, rule] of Object.entries(JSA.PATTERNS)) {
      if (!rule.enabled || !rule.regex) continue;
      const regex = new RegExp(rule.regex.source, rule.regex.flags);
      let match;
      while ((match = regex.exec(code)) !== null) {
        const value = match[1] || match[0];
        if (!value || value.length < 3) continue;

        // Determine category
        let category = rule.resultCategory || key;
        if (category === 'urls' || category === 'linkfinder') {
          category = /^https?:\/\//i.test(value) ? 'full-urls' : 'endpoints';
        }

        // Skip MIME types and HTTP headers for endpoints
        if (category === 'endpoints' || category === 'full-urls') {
          if (/^(?:text|application|image|audio|video|font|multipart)\//.test(value)) continue;
          if (/^(?:content-type|accept|authorization|cache-control|access-control|user-agent)$/i.test(value)) continue;
        }

        // Compute line number
        const lineNum = code.substring(0, match.index).split('\n').length;

        const finding = {
          value: value.substring(0, 500),
          type: rule.label,
          severity: rule.severity || 'info',
          confidence: rule.confidence || 'medium',
          line: lineNum,
          sourceFile: fileName
        };

        if (!results[category]) results[category] = [];
        results[category].push(finding);
      }
    }
  }

  // ─── 2. AST-based analysis ───
  if (JSA.analyzeAST) {
    try {
      const astFindings = JSA.analyzeAST(code, fileName);
      for (const f of astFindings) {
        const cat = f.category || 'vulnerabilities';
        if (!results[cat]) results[cat] = [];
        results[cat].push(f);
      }
    } catch (e) {
      console.error('[Engine] AST analysis error:', e.message);
    }
  }

  // ─── 3. Deduplicate findings ───
  for (const cat of Object.keys(results)) {
    const seen = new Set();
    results[cat] = results[cat].filter(f => {
      const key = f.value + '|' + f.type;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  // ─── 4. Summary stats ───
  const stats = {};
  let totalFindings = 0;
  for (const [cat, items] of Object.entries(results)) {
    stats[cat] = items.length;
    totalFindings += items.length;
  }

  return { results, stats, totalFindings, fileName };
}

module.exports = { analyze };
