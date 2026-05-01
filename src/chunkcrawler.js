// src/chunkcrawler.js — Recursive Webpack/Vite chunk discovery
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  JSA.crawlChunks = async function(baseUrl, text, onProgress) {
    if (!baseUrl || !text) return [];
    
    const chunkUrls = new Set();
    const findings = [];

    // Try to find webpack chunk map
    // {1:"chunk-abc",2:"chunk-def"}[e] + ".js"
    const webpackMapRegex = /\{((?:\d+:["'][a-zA-Z0-9\-_]+["']\s*,?\s*)+)\}/g;
    let mapMatch;
    while ((mapMatch = webpackMapRegex.exec(text)) !== null) {
      try {
        const mapStr = '{' + mapMatch[1] + '}';
        // A simple parse to get all string values
        const strValues = mapStr.match(/["']([a-zA-Z0-9\-_]+)["']/g);
        if (strValues) {
          strValues.forEach(s => {
            const chunkName = s.replace(/["']/g, '');
            if (chunkName && chunkName !== 'undefined') {
              const baseDir = baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
              chunkUrls.add(baseDir + chunkName + '.js');
            }
          });
        }
      } catch (e) {}
    }

    // Try to find direct imports (Vite/Rollup)
    const importRegex = /import\s*\(\s*["']([^"']+\.js)["']\s*\)/g;
    let impMatch;
    while ((impMatch = importRegex.exec(text)) !== null) {
      if (!impMatch[1].startsWith('http')) {
        const baseDir = baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1);
        const resolved = new URL(impMatch[1], baseDir).href;
        chunkUrls.add(resolved);
      } else {
        chunkUrls.add(impMatch[1]);
      }
    }

    if (chunkUrls.size === 0) return [];
    if (onProgress) onProgress(`Found ${chunkUrls.size} potential chunks, crawling...`);

    let count = 0;
    for (const url of chunkUrls) {
      try {
        // Fetch chunk text (simple get, we don't recursive-crawl chunks right now)
        const resp = await fetch(url);
        if (resp.ok) {
          const chunkText = await resp.text();
          findings.push({
            value: url, type: 'JS Chunk',
            category: 'files', severity: 'info', confidence: 'high',
            sourceFile: 'chunk-crawler', isBase64: false,
            contentLength: chunkText.length
          });
        }
      } catch (e) {
        // Ignore fetch errors for chunks
      }
      count++;
      if (onProgress) onProgress(`Crawled chunk ${count}/${chunkUrls.size}`);
    }

    return findings;
  };
})();
