// src/analyzer.worker.js — Web Worker for off-thread analysis
self.window = self;
self.JSA = self.JSA || {};

importScripts(
  'https://cdn.jsdelivr.net/npm/acorn@8.14.0/dist/acorn.js',
  'patterns.js',
  'ast-analyzer.js',
  'route-extractor.js',
  'vuln-scanner.js',
  'taint-analyzer.js',
  'chunkcrawler.js'
);

function calculateEntropy(str) {
  const len = str.length;
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  return Object.values(freq).reduce((s, f) => s - f / len * Math.log2(f / len), 0);
}

function isBase64(str) {
  if (str.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(str)) return false;
  try { return btoa(atob(str)) === str; } catch (e) { return false; }
}

function escapeHtml(unsafe) {
  return String(unsafe || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

self.onmessage = async function(e) {
  const { content, fileName, sourceBaseUrl, options } = e.data;
  
  const globalResults = {};
  const seenSets = {};
  const categories = Object.keys(JSA.PATTERNS).map(k => JSA.PATTERNS[k].resultCategory || k);
  categories.push('secrets', 'ast', 'routes', 'vuln-scanner', 'taint', 'files');
  categories.forEach(c => { globalResults[c] = []; seenSets[c] = new Set(); });
  globalResults['full-urls'] = []; seenSets['full-urls'] = new Set();
  globalResults['endpoints'] = []; seenSets['endpoints'] = new Set();

  const patterns = JSA.PATTERNS;
  const ruleIds = Object.keys(patterns);
  let processed = 0;

  function reportProgress() {
    self.postMessage({ type: 'progress', progress: processed / (ruleIds.length + 5) });
  }

  // 1) Regex-based scanning
  for (const [ruleId, rule] of Object.entries(patterns)) {
    if (!rule.enabled) { processed++; continue; }

    const regex = new RegExp(rule.regex);
    let match;

    while ((match = regex.exec(content)) !== null) {
      let matchText = match[2] || match[1] || match[0];
      matchText = matchText.replace(/^["']|["']$/g, '').trim();
      if (matchText.length < 4) continue;

      const entry = {
        value: matchText,
        type: rule.label,
        contextMatch: escapeHtml(matchText),
        sourceFile: fileName,
        severity: rule.severity || 'info',
        confidence: rule.confidence || 'medium',
        ruleId: ruleId,
        isBase64: ruleId.includes('secret') || rule.resultCategory === 'secrets' ? isBase64(matchText) : false
      };

      if (rule.hasExploitInfo) {
        const sinkName = rule.exploitKey || matchText.replace(/\s*\($/, '').toLowerCase().replace(/\./g, '');
        if (JSA.EXPLOIT_DB && JSA.EXPLOIT_DB[sinkName]) entry.exploitInfo = JSA.EXPLOIT_DB[sinkName];
      }

      if (ruleId === 'urls' || ruleId === 'linkfinder') {
        if (/node_modules|!\*{2,}|raw-loader|__webpack_|webpackJsonp|webpackChunk/.test(matchText)) continue;
        if (/\.(?:ts|tsx|jsx|scss|sass|css|html|json|map|svg|less|pug|styl)(?:["'\s]|$)/i.test(matchText)) continue;
        if (/^\.{1,2}\//.test(matchText)) continue;
        if (/\.(?:png|jpe?g|gif|ico|webp|bmp|woff2?|ttf|eot|otf|mp[34]|wav|ogg|webm|pdf)(?:\?.*)?$/i.test(matchText)) continue;
        if (/^data:|sourceMappingURL|sourcesContent/i.test(matchText)) continue;
        if (/^\/\*|\*\/$/.test(matchText.trim())) continue;
        if (/^\/?(?:src|dist|build|lib|app|components|modules|services|utils|helpers|guards?|interceptors?|shared|core|assets|styles|environments)\//.test(matchText)) continue;
        if (/^#/.test(matchText)) continue;
        
        const targetCat = /^https?:\/\//i.test(matchText) ? 'full-urls' : 'endpoints';
        entry.type = targetCat === 'full-urls' ? 'Full URL' : 'Endpoint';
        if (seenSets[targetCat].has(matchText)) continue;
        seenSets[targetCat].add(matchText);
        globalResults[targetCat].push(entry);
      } else {
        const targetCat = rule.resultCategory || ruleId;
        if (!globalResults[targetCat]) { globalResults[targetCat] = []; seenSets[targetCat] = new Set(); }
        if (seenSets[targetCat].has(matchText)) continue;
        seenSets[targetCat].add(matchText);
        globalResults[targetCat].push(entry);
      }
    }
    processed++;
    reportProgress();
  }

  // 2) High-entropy string detection
  const threshold = 4.5;
  const stringRegex = /["']([a-zA-Z0-9\-_=]{16,64})["']/g;
  let strMatch;
  while ((strMatch = stringRegex.exec(content)) !== null) {
    const val = strMatch[1];
    if (calculateEntropy(val) > threshold && !seenSets.secrets.has(val)) {
      seenSets.secrets.add(val);
      globalResults.secrets.push({
        value: val, type: 'High Entropy String', contextMatch: escapeHtml(val),
        sourceFile: fileName, severity: 'medium', confidence: 'low',
        ruleId: 'entropy', isBase64: isBase64(val)
      });
    }
  }
  processed++; reportProgress();

  // 3) AST-based analysis
  if (typeof JSA.analyzeAST === 'function') {
    try {
      const astFindings = JSA.analyzeAST(content, fileName);
      astFindings.forEach(f => {
        const cat = f.category;
        if (!globalResults[cat]) return;
        const key = f.value + '|' + cat;
        if (seenSets[cat].has(key)) return;
        seenSets[cat].add(key);
        globalResults[cat].push({
          value: f.value, type: f.type, contextMatch: escapeHtml(f.value),
          sourceFile: fileName, severity: f.severity || 'info',
          confidence: f.confidence || 'medium', ruleId: 'ast',
          line: f.line, isBase64: false,
          exploitInfo: f.exploitKey ? JSA.EXPLOIT_DB[f.exploitKey] : undefined
        });
      });
    } catch (e) {}
  }
  processed++; reportProgress();

  // 4) Route extraction
  if (typeof JSA.extractRoutes === 'function') {
    try {
      const routeFindings = JSA.extractRoutes(content, fileName);
      routeFindings.forEach(f => {
        const cat = f.category;
        if (!globalResults[cat]) { globalResults[cat] = []; seenSets[cat] = new Set(); }
        if (seenSets[cat].has(f.value)) return;
        if (seenSets.endpoints && seenSets.endpoints.has(f.value)) return;
        seenSets[cat].add(f.value);
        globalResults[cat].push({
          value: f.value, type: f.type, contextMatch: escapeHtml(f.value),
          sourceFile: fileName, severity: f.severity || 'info',
          confidence: f.confidence || 'medium', ruleId: 'route',
          line: f.line, isBase64: false
        });
      });
    } catch (e) {}
  }
  processed++; reportProgress();

  // 5) Vulnerable Dependency Scanning
  if (typeof JSA.scanVulnerableDependencies === 'function') {
    try {
      const vulnFindings = JSA.scanVulnerableDependencies(content, fileName);
      vulnFindings.forEach(f => {
        const cat = f.category || 'vuln-scanner';
        if (!globalResults[cat]) { globalResults[cat] = []; seenSets[cat] = new Set(); }
        if (seenSets[cat].has(f.value)) return;
        seenSets[cat].add(f.value);
        globalResults[cat].push({
          value: f.value, type: f.type, contextMatch: escapeHtml(f.value),
          sourceFile: fileName, severity: f.severity || 'info',
          confidence: f.confidence || 'high', ruleId: 'vuln-scanner',
          isBase64: false, exploitInfo: f.exploitInfo || undefined
        });
      });
    } catch (e) {}
  }
  processed++; reportProgress();

  // 6) Taint Analysis
  if (typeof JSA.analyzeTaint === 'function') {
    try {
      const taintFindings = JSA.analyzeTaint(content, fileName);
      taintFindings.forEach(f => {
        const cat = f.category || 'taint';
        if (!globalResults[cat]) { globalResults[cat] = []; seenSets[cat] = new Set(); }
        if (seenSets[cat].has(f.value)) return;
        seenSets[cat].add(f.value);
        globalResults[cat].push({
          value: f.value, type: f.type, contextMatch: escapeHtml(f.value),
          sourceFile: fileName, severity: f.severity || 'info',
          confidence: f.confidence || 'high', ruleId: 'taint',
          line: f.line, isBase64: false
        });
      });
    } catch (e) {}
  }
  processed++; reportProgress();

  // 7) Chunk Crawling
  if (typeof JSA.crawlChunks === 'function' && sourceBaseUrl) {
    try {
      const chunkFindings = await JSA.crawlChunks(sourceBaseUrl, content);
      chunkFindings.forEach(f => {
        const cat = f.category || 'files';
        if (!globalResults[cat]) { globalResults[cat] = []; seenSets[cat] = new Set(); }
        if (seenSets[cat].has(f.value)) return;
        seenSets[cat].add(f.value);
        globalResults[cat].push({
          value: f.value, type: f.type, contextMatch: escapeHtml(f.value),
          sourceFile: fileName, severity: f.severity || 'info',
          confidence: f.confidence || 'high', ruleId: 'chunk',
          isBase64: false
        });
      });
    } catch (e) {}
  }

  self.postMessage({ type: 'done', results: globalResults });
};
