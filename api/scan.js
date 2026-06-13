// api/scan.js — Vercel Serverless Function for AST Analysis
// Offloads heavy parsing from the client browser to the server

import fs from 'fs';
import path from 'path';
import * as acorn from 'acorn';

// We cache the loaded sandbox across warm invocations
let JSA = null;

function initEngine() {
  if (JSA) return;
  JSA = {};
  const sandbox = { window: { JSA }, self: { JSA }, JSA, acorn };

  try {
    const patternsCode = fs.readFileSync(path.join(process.cwd(), 'src', 'patterns.js'), 'utf8');
    const patternsFn = new Function('window', 'self', 'JSA', patternsCode);
    patternsFn(sandbox.window, sandbox.self, JSA);
    Object.assign(JSA, sandbox.window.JSA);
  } catch (e) {
    console.error('[Scan Engine] Failed to load patterns.js:', e.message);
  }

  try {
    const astCode = fs.readFileSync(path.join(process.cwd(), 'src', 'ast-analyzer.js'), 'utf8');
    const astFn = new Function('window', 'self', 'JSA', 'acorn', astCode);
    astFn(sandbox.window, sandbox.self, JSA, acorn);
    Object.assign(JSA, sandbox.window.JSA);
  } catch (e) {
    console.error('[Scan Engine] Failed to load ast-analyzer.js:', e.message);
  }
}

function analyze(code, fileName) {
  initEngine();

  const results = {
    secrets: [],
    endpoints: [],
    'full-urls': [],
    ips: [],
    vulnerabilities: [],
    libraries: [],
    emails: []
  };

  // 1. Regex-based pattern matching
  if (JSA.PATTERNS) {
    for (const [key, rule] of Object.entries(JSA.PATTERNS)) {
      if (!rule.enabled || !rule.regex) continue;
      const regex = new RegExp(rule.regex.source, rule.regex.flags);
      let match;
      while ((match = regex.exec(code)) !== null) {
        const value = match[1] || match[0];
        if (!value || value.length < 3) continue;

        let category = rule.resultCategory || key;
        if (category === 'urls' || category === 'linkfinder') {
          category = /^https?:\/\//i.test(value) ? 'full-urls' : 'endpoints';
        }

        if (category === 'endpoints' || category === 'full-urls') {
          if (/^(?:text|application|image|audio|video|font|multipart)\//.test(value)) continue;
          if (/^(?:content-type|accept|authorization|cache-control|access-control|user-agent)$/i.test(value)) continue;
        }

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

  // 2. AST-based analysis
  if (JSA.analyzeAST) {
    try {
      const astFindings = JSA.analyzeAST(code, fileName);
      for (const f of astFindings) {
        const cat = f.category || 'vulnerabilities';
        if (!results[cat]) results[cat] = [];
        results[cat].push(f);
      }
    } catch (e) {
      console.error('[Scan Engine] AST analysis error:', e.message);
    }
  }

  // 3. Deduplicate findings
  for (const cat of Object.keys(results)) {
    const seen = new Set();
    results[cat] = results[cat].filter(f => {
      const key = f.value + '|' + f.type;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  // 4. Summary stats
  const stats = {};
  let totalFindings = 0;
  for (const [cat, items] of Object.entries(results)) {
    stats[cat] = items.length;
    totalFindings += items.length;
  }

  return { results, stats, totalFindings, fileName };
}

const MAX_SCAN_SIZE = 10 * 1024 * 1024; // 10MB limit for Vercel Serverless

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const payload = req.body;
    
    if (!payload || !payload.code) {
      return res.status(400).json({ error: 'Missing "code" field in request body' });
    }

    const codeSize = payload.code.length;
    if (codeSize > MAX_SCAN_SIZE) {
      return res.status(413).json({ error: `Code exceeds ${MAX_SCAN_SIZE / 1024 / 1024}MB limit` });
    }

    const fileName = payload.fileName || 'unknown.js';
    console.log(`[SCAN] Analyzing ${fileName} (${(codeSize / 1024).toFixed(1)}KB)...`);
    
    const startTime = Date.now();
    const result = analyze(payload.code, fileName);
    const elapsed = Date.now() - startTime;
    
    console.log(`[SCAN] ← ${result.totalFindings} findings in ${elapsed}ms`);

    return res.status(200).json({
      ...result,
      analysisTime: elapsed,
      codeSize
    });

  } catch (err) {
    console.error(`[SCAN] Error:`, err.message);
    return res.status(500).json({ error: 'Analysis failed: ' + err.message });
  }
}
