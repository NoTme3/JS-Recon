// src/main.js — Core application logic for JS Analyzer
(function () {
  'use strict';

  // Shannon entropy for detecting high-entropy strings
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

  // ─── ANALYSIS ENGINE ───
  async function analyzeFileContent(content, fileName, globalResults, seenSets, onProgress) {
    const patterns = JSA.PATTERNS;
    const ruleIds = Object.keys(patterns);
    let processed = 0;

    // 1) Regex-based scanning
    for (const [ruleId, rule] of Object.entries(patterns)) {
      if (!rule.enabled) { processed++; continue; }

      const regex = new RegExp(rule.regex);
      let match;

      while ((match = regex.exec(content)) !== null) {
        // Capture group support
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

        // Exploit info
        if (rule.hasExploitInfo) {
          const sinkName = rule.exploitKey || matchText.replace(/\s*\($/, '').toLowerCase().replace(/\./g, '');
          if (JSA.EXPLOIT_DB[sinkName]) entry.exploitInfo = JSA.EXPLOIT_DB[sinkName];
        }

        // URL splitting: full-urls vs endpoints
        if (ruleId === 'urls') {
          // ─── Comprehensive noise filtering for webpack bundles ───
          // Skip webpack module paths and comment artifacts
          if (/node_modules|!\*{2,}|raw-loader|__webpack_|webpackJsonp|webpackChunk/.test(matchText)) continue;
          // Skip source file paths (.ts, .tsx, .jsx, .scss, .css, .html, .json, .map, .svg, .less)
          if (/\.(?:ts|tsx|jsx|scss|sass|css|html|json|map|svg|less|pug|styl)(?:["'\s]|$)/i.test(matchText)) continue;
          // Skip relative module paths (./src/, ../components/, etc.)
          if (/^\.{1,2}\//.test(matchText)) continue;
          // Skip image/font/media asset paths
          if (/\.(?:png|jpe?g|gif|ico|webp|bmp|woff2?|ttf|eot|otf|mp[34]|wav|ogg|webm|pdf)(?:\?.*)?$/i.test(matchText)) continue;
          // Skip CSS data URIs and sourceMappingURL
          if (/^data:|sourceMappingURL|sourcesContent/i.test(matchText)) continue;
          // Skip Angular/webpack comment blocks like /*! ./src/... */
          if (/^\/\*|\*\/$/.test(matchText.trim())) continue;
          // Skip paths that are clearly internal build artifacts
          if (/^\/?(?:src|dist|build|lib|app|components|modules|services|utils|helpers|guards?|interceptors?|shared|core|assets|styles|environments)\//.test(matchText)) continue;
          // Skip fragment-only hrefs (#pablo, #section, etc.)
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
      if (onProgress) onProgress(processed / (ruleIds.length + 2));
    }

    // 2) High-entropy string detection
    const threshold = JSA.entropyThreshold || 4.5;
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
    if (onProgress) onProgress((processed + 1) / (ruleIds.length + 2));

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
      } catch (e) { console.error('AST analysis error:', e); }
    }

    // 4) Route extraction (skip values already in endpoints)
    if (typeof JSA.extractRoutes === 'function') {
      try {
        const routeFindings = JSA.extractRoutes(content, fileName);
        routeFindings.forEach(f => {
          const cat = f.category;
          if (!globalResults[cat]) { globalResults[cat] = []; seenSets[cat] = new Set(); }
          if (seenSets[cat].has(f.value)) return;
          // Skip if already found as an endpoint — avoid duplicates
          if (seenSets.endpoints && seenSets.endpoints.has(f.value)) return;
          seenSets[cat].add(f.value);
          globalResults[cat].push({
            value: f.value, type: f.type, contextMatch: escapeHtml(f.value),
            sourceFile: fileName, severity: f.severity || 'info',
            confidence: f.confidence || 'medium', ruleId: 'route',
            line: f.line, isBase64: false
          });
        });
      } catch (e) { console.error('Route extraction error:', e); }
    }
    if (onProgress) onProgress(1);
  }

  // ─── DOM READY ───
  document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const resultsSection = document.getElementById('results-section');
    const fileNameDisplay = document.getElementById('file-name-display');
    const statsGrid = document.getElementById('stats-grid');
    const lineNumbersEl = document.getElementById('line-numbers');
    const terminalStatus = document.getElementById('terminal-status');
    const codeInput = document.getElementById('code-input');
    const analyzePasteBtn = document.getElementById('analyze-paste-btn');
    const tabsNav = document.getElementById('tabs-nav');
    const tabsContent = document.getElementById('tabs-content');
    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressLabel = document.getElementById('progress-label');
    const severityFilter = document.getElementById('severity-filter');

    let GLOBAL_RESULTS = null;
    let LAST_SEARCH_INDEX = {};

    // ─── Generate tabs from JSA.CATEGORIES ───
    function buildTabs() {
      tabsNav.innerHTML = '';
      tabsContent.innerHTML = '';
      JSA.CATEGORIES.forEach((cat, idx) => {
        const btn = document.createElement('button');
        btn.className = 'tab-btn' + (idx === 0 ? ' active' : '');
        btn.dataset.target = cat.id;
        btn.textContent = cat.label;
        tabsNav.appendChild(btn);

        const panel = document.createElement('div');
        panel.className = 'tab-content' + (idx === 0 ? ' active' : '');
        panel.id = cat.id;
        panel.innerHTML = '<div class="list-container" id="list-' + cat.id + '"></div>';
        tabsContent.appendChild(panel);
      });
    }
    buildTabs();

    // ─── Generate settings ───
    function buildSettings() {
      const container = document.getElementById('rules-settings');
      if (!container) return;
      container.innerHTML = '<h3>Detection Rules</h3>';
      for (const [ruleId, rule] of Object.entries(JSA.PATTERNS)) {
        const row = document.createElement('div');
        row.className = 'setting-row';
        const cat = rule.resultCategory || ruleId;
        row.innerHTML = `
          <div class="setting-info">
            <label for="rule-${ruleId}">${escapeHtml(rule.label)}</label>
            <span class="setting-cat">${escapeHtml(cat)}</span>
          </div>
          <label class="toggle">
            <input type="checkbox" id="rule-${ruleId}" data-rule="${ruleId}" ${rule.enabled ? 'checked' : ''}>
            <span class="toggle-slider"></span>
          </label>`;
        container.appendChild(row);
      }

      container.addEventListener('change', (e) => {
        if (e.target.dataset.rule) {
          JSA.PATTERNS[e.target.dataset.rule].enabled = e.target.checked;
          JSA.saveSettings();
        }
      });

      const entropySlider = document.getElementById('entropy-threshold');
      const entropyValue = document.getElementById('entropy-value');
      if (entropySlider) {
        entropySlider.value = JSA.entropyThreshold;
        entropyValue.textContent = JSA.entropyThreshold;
        entropySlider.addEventListener('input', (e) => {
          JSA.entropyThreshold = parseFloat(e.target.value);
          entropyValue.textContent = JSA.entropyThreshold;
          JSA.saveSettings();
        });
      }
    }
    buildSettings();

    // ─── View switching ───
    document.querySelectorAll('.nav-item').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        document.querySelectorAll('.nav-item').forEach(l => l.classList.remove('active'));
        link.classList.add('active');
        const view = link.dataset.view;
        document.getElementById('view-scanner').classList.toggle('hidden', view !== 'scanner');
        document.getElementById('view-settings').classList.toggle('hidden', view !== 'settings');
      });
    });

    // ─── Line numbers ───
    function updateLineNumbers() {
      const text = codeInput.value;
      const lineCount = text ? text.split('\n').length : 1;
      lineNumbersEl.textContent = Array.from({ length: lineCount }, (_, i) => i + 1).join('\n');
      if (terminalStatus) {
        terminalStatus.textContent = lineCount + ' lines · ' + text.length + ' chars';
      }
    }

    // ─── Progress ───
    function showProgress(label) {
      progressContainer.classList.remove('hidden');
      progressBar.style.width = '0%';
      progressLabel.textContent = label || 'Analyzing...';
    }
    function updateProgress(pct) {
      progressBar.style.width = Math.round(pct * 100) + '%';
    }
    function hideProgress() {
      progressContainer.classList.add('hidden');
    }

    // ─── Drag & Drop ───
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(ev => {
      dropZone.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); }, false);
    });
    ['dragenter', 'dragover'].forEach(ev => {
      dropZone.addEventListener(ev, () => dropZone.classList.add('drag-over'), false);
    });
    ['dragleave', 'drop'].forEach(ev => {
      dropZone.addEventListener(ev, () => dropZone.classList.remove('drag-over'), false);
    });
    dropZone.addEventListener('drop', e => handleFiles(Array.from(e.dataTransfer.files)));
    fileInput.addEventListener('change', e => handleFiles(Array.from(e.target.files)));

    // ─── CORS-safe fetch helper ───
    const FETCH_STRATEGIES = [
      u => u,
      u => `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(u)}`,
      u => `https://cors.eu.org/${u}`,
      u => `https://corsproxy.io/?${encodeURIComponent(u)}`,
      u => `https://api.allorigins.win/raw?url=${encodeURIComponent(u)}`
    ];

    async function fetchWithProxy(url) {
      let text = null, lastErr = null;
      for (const fn of FETCH_STRATEGIES) {
        try {
          const r = await fetch(fn(url));
          if (!r.ok) throw new Error('HTTP ' + r.status);
          text = await r.text();
          break;
        } catch (err) { lastErr = err; continue; }
      }
      if (text === null) throw lastErr;
      return text;
    }

    // ─── Fetch URL (single) ───
    const fetchUrlInput = document.getElementById('fetch-url-input');
    const fetchUrlBtn = document.getElementById('fetch-url-btn');
    if (fetchUrlBtn) {
      fetchUrlBtn.addEventListener('click', async () => {
        const url = fetchUrlInput.value.trim();
        if (!url) { alert('Please enter a valid JavaScript file URL.'); return; }
        const originalHTML = fetchUrlBtn.innerHTML;
        fetchUrlBtn.innerHTML = 'Fetching...';
        fetchUrlBtn.disabled = true;
        dropZone.classList.add('loading-pulse');
        try {
          const text = await fetchWithProxy(url);
          codeInput.value = text;
          updateLineNumbers();
          const shortName = url.split('/').pop().split('?')[0] || 'remote_file.js';
          fileNameDisplay.textContent = shortName;
          await runAnalysis(text, shortName);
        } catch (e) {
          console.error('Fetch error:', e);
          alert('Failed to fetch the URL.\n\nTry downloading the file manually and using drag & drop instead.');
        } finally {
          fetchUrlBtn.innerHTML = originalHTML;
          fetchUrlBtn.disabled = false;
          dropZone.classList.remove('loading-pulse');
        }
      });
    }


    // ─── Terminal editor events ───
    if (codeInput && lineNumbersEl) {
      codeInput.addEventListener('input', updateLineNumbers);
      codeInput.addEventListener('paste', () => setTimeout(updateLineNumbers, 0));
      codeInput.addEventListener('scroll', () => { lineNumbersEl.scrollTop = codeInput.scrollTop; });
    }

    // ─── Beautify ───
    const beautifyBtn = document.getElementById('beautify-btn');
    if (beautifyBtn) {
      beautifyBtn.addEventListener('click', () => {
        if (!codeInput.value.trim()) return;
        try {
          codeInput.value = js_beautify(codeInput.value, { indent_size: 2, preserve_newlines: true, max_preserve_newlines: 2 });
          updateLineNumbers();
          const orig = beautifyBtn.innerHTML;
          beautifyBtn.innerHTML = '✨ Done';
          setTimeout(() => beautifyBtn.innerHTML = orig, 2000);
        } catch (e) { console.error('Beautify failed:', e); }
      });
    }

    // ─── Analyze pasted code ───
    if (analyzePasteBtn) {
      analyzePasteBtn.addEventListener('click', async () => {
        const text = codeInput.value.trim();
        if (!text) { alert('Please paste some JavaScript code first.'); return; }
        fileNameDisplay.textContent = 'Pasted Code';
        await runAnalysis(text, 'pasted-code');
      });
    }

    // ─── Dynamic analysis ───
    const runDynamicBtn = document.getElementById('run-dynamic-btn');
    if (runDynamicBtn) {
      runDynamicBtn.addEventListener('click', async () => {
        const text = codeInput.value.trim();
        if (!text) { alert('Please paste or upload code first.'); return; }
        if (!JSA.runDynamic) { alert('Dynamic analysis module not loaded.'); return; }

        runDynamicBtn.disabled = true;
        runDynamicBtn.textContent = '⏳ Running...';
        showProgress('Running dynamic analysis in sandbox...');

        try {
          const raw = await JSA.runDynamic(text);
          const findings = JSA.processDynamicResults(raw, fileNameDisplay.textContent || 'unknown');

          // Merge into existing results or create new
          if (!GLOBAL_RESULTS) {
            GLOBAL_RESULTS = JSA.createEmptyResults();
          }
          const seen = new Set(GLOBAL_RESULTS.dynamic.map(f => f.value));
          findings.forEach(f => {
            if (!seen.has(f.value)) {
              GLOBAL_RESULTS.dynamic.push({
                value: f.value,
                type: f.type,
                contextMatch: escapeHtml(f.value),
                sourceFile: f.sourceFile,
                severity: f.severity,
                confidence: f.confidence,
                ruleId: 'dynamic',
                isBase64: false
              });
              seen.add(f.value);
            }
          });

          renderResults(GLOBAL_RESULTS);
          resultsSection.classList.remove('hidden');

          // Switch to Dynamic tab
          document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
          document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
          const dynTab = document.querySelector('[data-target="dynamic"]');
          if (dynTab) dynTab.classList.add('active');
          const dynContent = document.getElementById('dynamic');
          if (dynContent) dynContent.classList.add('active');

          const msg = raw.timedOut ? 'Timed out — partial results shown' : `Found ${findings.length} runtime behaviors`;
          alert(msg);
        } catch (e) {
          console.error('Dynamic analysis error:', e);
          alert('Dynamic analysis failed: ' + e.message);
        } finally {
          runDynamicBtn.disabled = false;
          runDynamicBtn.textContent = '⚡ Dynamic';
          hideProgress();
        }
      });
    }

    // ─── File handling ───
    async function handleFiles(files) {
      if (!files || files.length === 0) return;
      const valid = files.filter(f => f.name.endsWith('.js') || f.name.endsWith('.ts') || f.name.endsWith('.map') || f.type.includes('javascript'));
      if (valid.length === 0) { alert('Please upload JavaScript (.js) or Source Map (.map) files.'); return; }
      fileNameDisplay.textContent = valid.length === 1 ? valid[0].name : `${valid.length} files loaded`;

      showProgress('Analyzing ' + valid.length + ' file(s)...');
      GLOBAL_RESULTS = JSA.createEmptyResults();
      const seenSets = JSA.createEmptySeen();
      let allText = '';

      try {
        for (let i = 0; i < valid.length; i++) {
          const file = valid[i];
          const pathName = file.webkitRelativePath || file.name;
          const text = await readFileAsText(file);

          // ─── Source map handling ───
          if (file.name.endsWith('.map') && typeof JSA.parseSourceMap === 'function') {
            progressLabel.textContent = 'Parsing source map: ' + pathName + '...';
            const mapResult = JSA.parseSourceMap(text);

            // Analyze each extracted original source file
            if (mapResult.files.length > 0) {
              for (let j = 0; j < mapResult.files.length; j++) {
                const sf = mapResult.files[j];
                allText += (allText ? '\n\n// === ' + sf.path + ' (from ' + pathName + ') ===\n' : '') + sf.content;
                progressLabel.textContent = 'Analyzing ' + sf.path + '...';
                await analyzeFileContent(sf.content, sf.path, GLOBAL_RESULTS, seenSets, (p) => {
                  updateProgress((i + (j + p) / mapResult.files.length) / valid.length);
                });
              }
            }

            // Also add source paths as endpoints for recon value
            mapResult.sources.forEach(src => {
              if (src && !seenSets.endpoints.has(src)) {
                seenSets.endpoints.add(src);
                GLOBAL_RESULTS.endpoints.push({
                  value: src, type: 'Source Map Path', contextMatch: escapeHtml(src),
                  sourceFile: pathName, severity: 'info', confidence: 'high',
                  ruleId: 'sourcemap', isBase64: false
                });
              }
            });
            continue;
          }

          // ─── Check for inline source maps ───
          if (typeof JSA.extractInlineSourceMap === 'function') {
            const inlineMap = JSA.extractInlineSourceMap(text);
            if (inlineMap) {
              const mapResult = JSA.parseSourceMap(inlineMap);
              if (mapResult.files.length > 0) {
                for (const sf of mapResult.files) {
                  allText += '\n\n// === ' + sf.path + ' (inline map from ' + pathName + ') ===\n' + sf.content;
                  await analyzeFileContent(sf.content, sf.path, GLOBAL_RESULTS, seenSets, () => {});
                }
              }
            }
          }

          allText += (allText ? '\n\n// === ' + pathName + ' ===\n' : '') + text;
          progressLabel.textContent = 'Analyzing ' + pathName + '...';
          await analyzeFileContent(text, pathName, GLOBAL_RESULTS, seenSets, (p) => {
            updateProgress((i + p) / valid.length);
          });
        }
        codeInput.value = allText;
        updateLineNumbers();
        renderResults(GLOBAL_RESULTS);
        resultsSection.classList.remove('hidden');
        resultsSection.scrollIntoView({ behavior: 'smooth' });
      } catch (e) {
        console.error(e);
        alert('Error analyzing files.');
      } finally {
        hideProgress();
      }
    }

    // ─── Run analysis helper ───
    async function runAnalysis(text, fileName) {
      showProgress('Analyzing...');
      dropZone.classList.add('loading-pulse');
      GLOBAL_RESULTS = JSA.createEmptyResults();
      const seenSets = JSA.createEmptySeen();

      try {
        await new Promise(r => setTimeout(r, 50)); // Let UI update
        await analyzeFileContent(text, fileName, GLOBAL_RESULTS, seenSets, updateProgress);
        renderResults(GLOBAL_RESULTS);
        resultsSection.classList.remove('hidden');
        resultsSection.scrollIntoView({ behavior: 'smooth' });
      } catch (e) {
        console.error(e);
        alert('Error analyzing code.');
      } finally {
        dropZone.classList.remove('loading-pulse');
        hideProgress();
      }
    }

    function readFileAsText(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = e => resolve(e.target.result);
        reader.onerror = e => reject(e);
        reader.readAsText(file);
      });
    }

    // ─── RENDERING ───
    function renderResults(results) {
      // Stats grid - use JSA.CATEGORIES directly to ensure IDs match perfectly
      statsGrid.innerHTML = JSA.CATEGORIES.map((cat, idx) => {
        const count = (results[cat.id] || []).length;
        // Skip dynamically created empty categories if they aren't meant to be cards, 
        // but for now let's just show them all or handle them like tabs.
        return `<div class="stat-card cat-${cat.id}" data-cat="${cat.id}" style="animation-delay:${idx * 30}ms"><div class="stat-title">${cat.label}</div><div class="stat-value ${cat.id}">${count}</div></div>`;
      }).join('');

      // Click stat card → switch to matching tab
      statsGrid.querySelectorAll('.stat-card[data-cat]').forEach(card => {
        card.addEventListener('click', () => {
          const catId = card.dataset.cat;
          const tabBtn = tabsNav.querySelector(`.tab-btn[data-target="${catId}"]`);
          if (tabBtn) tabBtn.click();
          document.querySelector('.tabs-container')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
      });

      // Render each tab's list
      const activeSeverity = severityFilter ? severityFilter.value : 'all';
      JSA.CATEGORIES.forEach(cat => {
        const container = document.getElementById('list-' + cat.id);
        if (!container) return;
        let items = results[cat.id] || [];

        if (activeSeverity !== 'all') {
          items = items.filter(i => i.severity === activeSeverity);
        }

        // Cross-file deduplication: group items by value, show "found in N files" badge
        const deduped = [];
        const valueMap = new Map();
        items.forEach(item => {
          if (valueMap.has(item.value)) {
            const existing = valueMap.get(item.value);
            if (!existing._sources) existing._sources = [existing.sourceFile];
            if (!existing._sources.includes(item.sourceFile)) {
              existing._sources.push(item.sourceFile);
            }
          } else {
            const entry = Object.assign({}, item);
            valueMap.set(item.value, entry);
            deduped.push(entry);
          }
        });

        if (deduped.length === 0) {
          container.innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg><p>No matches found.</p></div>';
          return;
        }

        container.innerHTML = deduped.map((item, idx) => {
          const sevClass = item.severity || 'info';
          let actionBtns = `<button class="action-btn copy-btn" data-val="${item.contextMatch}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>Copy</button>`;

          if (item.isBase64) {
            actionBtns += `<button class="action-btn decode-btn" data-val="${item.contextMatch}">Decode</button>`;
          }
          if (cat.id === 'full-urls' || cat.id === 'endpoints' || cat.id === 'routes') {
            actionBtns += `<button class="action-btn test-btn" data-val="${item.contextMatch}">Test</button>`;
          }

          let exploitPanel = '';
          if (item.exploitInfo) {
            const rc = item.exploitInfo.risk.toLowerCase();
            exploitPanel = `<div class="exploit-info"><button class="exploit-toggle"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>How can this be exploited?<svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="6 9 12 15 18 9"></polyline></svg></button><div class="exploit-details collapsed"><div class="exploit-row"><span class="risk-badge risk-${rc}">${item.exploitInfo.risk}</span></div><div class="exploit-row"><span class="exploit-label">Description</span><p>${item.exploitInfo.description}</p></div><div class="exploit-row"><span class="exploit-label">Payload</span><code class="exploit-payload">${item.exploitInfo.exploit}</code></div><div class="exploit-row"><span class="exploit-label">Mitigation</span><p>${item.exploitInfo.mitigation}</p></div></div></div>`;
          }

          const lineBadge = item.line ? `<span class="match-line">L${item.line}</span>` : '';
          const multiSourceBadge = (item._sources && item._sources.length > 1)
            ? `<span class="multi-source-badge" title="${item._sources.map(s => escapeHtml(s)).join(', ')}">found in ${item._sources.length} files</span>`
            : '';

          return `<div class="match-item search-target" data-severity="${sevClass}" style="animation-delay: ${Math.min(idx * 30, 1000)}ms">
            <div class="match-header">
              <div class="match-info-group">
                <span class="severity-dot sev-${sevClass}" title="${sevClass}"></span>
                <span class="match-value raw-value">${item.contextMatch}</span>
                <span class="match-source">${escapeHtml(item.sourceFile)}</span>
                ${multiSourceBadge}
                ${lineBadge}
                <span class="match-type">${escapeHtml(item.type)}</span>
              </div>
              <div class="match-actions">${actionBtns}</div>
            </div>
            ${exploitPanel}
          </div>`;
        }).join('');
      });

      attachInlineActions();
    }

    // ─── Inline action handlers ───
    function attachInlineActions() {
      document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', e => {
          const val = e.currentTarget.getAttribute('data-val');
          navigator.clipboard.writeText(val);
          const orig = e.currentTarget.innerHTML;
          e.currentTarget.innerHTML = 'Copied!';
          setTimeout(() => e.currentTarget.innerHTML = orig, 1500);
        });
      });

      document.querySelectorAll('.decode-btn').forEach(btn => {
        btn.addEventListener('click', e => {
          const val = e.currentTarget.getAttribute('data-val');
          const span = e.currentTarget.closest('.match-header').querySelector('.raw-value');
          try {
            const decoded = atob(val);
            span.textContent = span.dataset.decoded ? val : decoded;
            span.dataset.decoded = !span.dataset.decoded;
            e.currentTarget.textContent = span.dataset.decoded ? 'Encode' : 'Decode';
          } catch (err) { alert('Failed to decode base64'); }
        });
      });

      document.querySelectorAll('.test-btn').forEach(btn => {
        btn.addEventListener('click', async e => {
          let val = e.currentTarget.getAttribute('data-val');
          if (val.startsWith('/')) {
            const base = prompt('Enter base URL (e.g. https://api.example.com):');
            if (!base) return;
            val = base + val;
          }
          const orig = e.currentTarget.innerHTML;
          e.currentTarget.innerHTML = 'Testing...';
          try {
            await fetch(val, { method: 'GET', mode: 'no-cors' });
            e.currentTarget.innerHTML = 'Live';
            e.currentTarget.style.color = 'var(--accent-success)';
          } catch (err) {
            e.currentTarget.innerHTML = 'Failed';
            e.currentTarget.style.color = 'var(--accent-danger)';
          }
          setTimeout(() => { e.currentTarget.innerHTML = orig; e.currentTarget.style.color = ''; }, 3000);
        });
      });

      document.querySelectorAll('.exploit-toggle').forEach(btn => {
        btn.addEventListener('click', e => {
          e.stopPropagation();
          btn.nextElementSibling.classList.toggle('collapsed');
          btn.querySelector('.chevron').classList.toggle('rotated');
        });
      });

      // Click to highlight in textarea
      document.querySelectorAll('.match-item').forEach(item => {
        item.addEventListener('click', e => {
          if (e.target.closest('.action-btn') || e.target.closest('.exploit-toggle') || e.target.closest('.exploit-details')) return;
          const raw = item.querySelector('.raw-value');
          if (raw) highlightInTextarea(raw.textContent);
        });
      });
    }

    function highlightInTextarea(value) {
      const content = codeInput.value;
      if (!content) return;
      const startFrom = (LAST_SEARCH_INDEX[value] !== undefined) ? LAST_SEARCH_INDEX[value] + 1 : 0;
      let idx = content.indexOf(value, startFrom);
      if (idx === -1) idx = content.indexOf(value, 0); // wrap around
      if (idx === -1) return;
      LAST_SEARCH_INDEX[value] = idx;
      
      // Calculate scroll position
      const linesBefore = content.substring(0, idx).split('\n').length;
      
      // Focus and select text immediately
      codeInput.focus();
      codeInput.setSelectionRange(idx, idx + value.length);
      
      const lineHeight = parseInt(getComputedStyle(codeInput).lineHeight) || 19;
      // Scroll smoothly within the textarea only
      codeInput.scrollTo({
        top: Math.max(0, (linesBefore - 3) * lineHeight),
        behavior: 'smooth'
      });
    }

    // ─── Search ───
    document.getElementById('search-input').addEventListener('input', e => {
      const q = e.target.value.toLowerCase();
      document.querySelectorAll('.search-target').forEach(item => {
        const val = item.querySelector('.raw-value').textContent.toLowerCase();
        const src = item.querySelector('.match-source').textContent.toLowerCase();
        item.style.display = (val.includes(q) || src.includes(q)) ? 'block' : 'none';
      });
    });

    // ─── Severity filter ───
    if (severityFilter) {
      severityFilter.addEventListener('change', () => {
        if (GLOBAL_RESULTS) renderResults(GLOBAL_RESULTS);
      });
    }

    // ─── Tab switching ───
    tabsNav.addEventListener('click', e => {
      if (e.target.classList.contains('tab-btn')) {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        e.target.classList.add('active');
        document.getElementById(e.target.dataset.target).classList.add('active');
      }
    });

    // ─── Exports ───
    document.getElementById('export-json').addEventListener('click', () => {
      if (!GLOBAL_RESULTS) return;
      downloadFile('js_recon_results.json', 'application/json', JSON.stringify(GLOBAL_RESULTS, null, 2));
    });

    document.getElementById('export-csv').addEventListener('click', () => {
      if (!GLOBAL_RESULTS) return;
      let csv = 'Category,Type,Severity,Value,Source File,Base64\n';
      Object.entries(GLOBAL_RESULTS).forEach(([cat, items]) => {
        items.forEach(item => {
          csv += `"${cat}","${item.type}","${item.severity || ''}","${item.value}","${item.sourceFile}","${item.isBase64}"\n`;
        });
      });
      downloadFile('js_recon_results.csv', 'text/csv', csv);
    });

    document.getElementById('export-html').addEventListener('click', () => {
      if (!GLOBAL_RESULTS || !JSA.generateHTMLReport) return;
      const html = JSA.generateHTMLReport(GLOBAL_RESULTS, { fileName: fileNameDisplay.textContent });
      downloadFile('js_recon_report.html', 'text/html', html);
    });

    function downloadFile(name, type, content) {
      const blob = new Blob([content], { type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    // ─── Detail modal ───
    const modal = document.getElementById('detail-modal');
    const modalClose = document.getElementById('modal-close');
    if (modalClose) {
      modalClose.addEventListener('click', () => modal.classList.add('hidden'));
      modal.addEventListener('click', e => { if (e.target === modal) modal.classList.add('hidden'); });
    }

  });
})();
