// server.cjs — Local dev server with CORS proxy, AI proxy, and server-side analysis
// Endpoints:
//   POST /api/analyze  — AI enrichment proxy (bypasses CORS for NVIDIA/OpenAI/Anthropic)
//   GET  /api/fetch    — CORS proxy for fetching remote JS files
//   POST /api/scan     — Server-side AST analysis for large files
//   GET  /*            — Static file server

const http = require('http');
const fs = require('fs');
const path = require('path');
const { analyze } = require('./server/analyze-engine.cjs');

const PORT = 8000;
const MAX_FETCH_SIZE = 50 * 1024 * 1024; // 50MB max for remote fetch
const MAX_SCAN_SIZE = 100 * 1024 * 1024; // 100MB max for scan

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

// ─── Helpers ───
function jsonResponse(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req, maxSize) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > maxSize) {
        reject(new Error(`Body exceeds ${(maxSize / 1024 / 1024).toFixed(0)}MB limit`));
        req.destroy();
        return;
      }
      body += chunk.toString();
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  console.log(`[${req.method}] ${url.pathname}`);

  // ─── CORS headers for all responses ───
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // ═══════════════════════════════════════════════════════════
  // /api/fetch — CORS proxy for fetching remote scripts
  // ═══════════════════════════════════════════════════════════
  if (req.method === 'GET' && url.pathname === '/api/fetch') {
    const targetUrl = url.searchParams.get('url');
    if (!targetUrl) {
      return jsonResponse(res, 400, { error: 'Missing ?url= parameter' });
    }

    // Validate URL
    try {
      const parsed = new URL(targetUrl);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return jsonResponse(res, 400, { error: 'Only http/https URLs are supported' });
      }
    } catch (e) {
      return jsonResponse(res, 400, { error: 'Invalid URL: ' + e.message });
    }

    console.log(`[FETCH] → ${targetUrl}`);

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30000); // 30s timeout

      const response = await fetch(targetUrl, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': '*/*',
          'Accept-Encoding': 'identity'
        },
        redirect: 'follow'
      });
      clearTimeout(timeout);

      if (!response.ok) {
        return jsonResponse(res, response.status, {
          error: `Remote server returned ${response.status} ${response.statusText}`
        });
      }

      // Check content length
      const contentLength = parseInt(response.headers.get('content-length') || '0', 10);
      if (contentLength > MAX_FETCH_SIZE) {
        return jsonResponse(res, 413, {
          error: `File too large: ${(contentLength / 1024 / 1024).toFixed(1)}MB (max ${MAX_FETCH_SIZE / 1024 / 1024}MB)`
        });
      }

      const text = await response.text();
      if (text.length > MAX_FETCH_SIZE) {
        return jsonResponse(res, 413, {
          error: `File too large: ${(text.length / 1024 / 1024).toFixed(1)}MB`
        });
      }

      console.log(`[FETCH] ← ${text.length} bytes from ${targetUrl}`);

      // Return the fetched content as JSON with metadata
      return jsonResponse(res, 200, {
        content: text,
        url: targetUrl,
        size: text.length,
        contentType: response.headers.get('content-type') || 'unknown'
      });

    } catch (err) {
      if (err.name === 'AbortError') {
        return jsonResponse(res, 504, { error: 'Remote server timed out (30s)' });
      }
      console.error(`[FETCH] Error:`, err.message);
      return jsonResponse(res, 502, { error: 'Failed to fetch: ' + err.message });
    }
  }

  // ═══════════════════════════════════════════════════════════
  // /api/scan — Server-side analysis for large files
  // ═══════════════════════════════════════════════════════════
  if (req.method === 'POST' && url.pathname === '/api/scan') {
    try {
      const body = await readBody(req, MAX_SCAN_SIZE);
      const payload = JSON.parse(body);

      if (!payload.code) {
        return jsonResponse(res, 400, { error: 'Missing "code" field in request body' });
      }

      const fileName = payload.fileName || 'unknown.js';
      const codeSize = payload.code.length;

      console.log(`[SCAN] Analyzing ${fileName} (${(codeSize / 1024).toFixed(1)}KB)...`);
      const startTime = Date.now();

      const result = analyze(payload.code, fileName);

      const elapsed = Date.now() - startTime;
      console.log(`[SCAN] ← ${result.totalFindings} findings in ${elapsed}ms`);

      return jsonResponse(res, 200, {
        ...result,
        analysisTime: elapsed,
        codeSize
      });

    } catch (err) {
      if (err.message.includes('limit')) {
        return jsonResponse(res, 413, { error: err.message });
      }
      console.error(`[SCAN] Error:`, err.message);
      return jsonResponse(res, 500, { error: 'Analysis failed: ' + err.message });
    }
  }

  // ═══════════════════════════════════════════════════════════
  // /api/analyze — AI Enrichment Proxy
  // ═══════════════════════════════════════════════════════════
  if (req.method === 'POST' && url.pathname === '/api/analyze') {
    try {
      const body = await readBody(req, 1024 * 1024); // 1MB max for AI requests
      const payload = JSON.parse(body);

      if (!payload.apiKey) {
        return jsonResponse(res, 400, { error: 'Missing apiKey in request body' });
      }
      if (!payload.prompt) {
        return jsonResponse(res, 400, { error: 'Missing prompt in request body' });
      }

      const apiUrl = payload.apiUrl || 'https://integrate.api.nvidia.com/v1/chat/completions';
      const model = payload.model || 'meta/llama-3.3-70b-instruct';

      console.log(`[AI] → ${apiUrl} (model: ${model})`);

      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + payload.apiKey
        },
        body: JSON.stringify({
          model: model,
          messages: [{ role: 'user', content: payload.prompt }],
          temperature: 0.3,
          max_tokens: 2000,
          stream: false
        })
      });

      const contentType = response.headers.get('content-type') || '';
      const responseText = await response.text();

      if (!response.ok) {
        console.error(`[AI] ← ${response.status} ${response.statusText}`);
        let errorMsg = `Upstream API returned ${response.status}`;
        if (contentType.includes('application/json')) {
          try {
            const errObj = JSON.parse(responseText);
            errorMsg = errObj.error?.message || errObj.detail || errorMsg;
          } catch (e) {}
        } else if (contentType.includes('text/html')) {
          const titleMatch = responseText.match(/<title>(.*?)<\/title>/i);
          const h1Match = responseText.match(/<h1>(.*?)<\/h1>/i);
          errorMsg = titleMatch?.[1] || h1Match?.[1] || `API returned HTML error page (${response.status})`;
        }
        return jsonResponse(res, response.status, { error: errorMsg });
      }

      if (contentType.includes('application/json')) {
        try {
          const data = JSON.parse(responseText);
          console.log(`[AI] ← 200 OK (${data.choices?.[0]?.message?.content?.length || 0} chars)`);
          return jsonResponse(res, 200, data);
        } catch (e) {
          return jsonResponse(res, 502, { error: 'Failed to parse upstream response' });
        }
      } else {
        return jsonResponse(res, 502, { error: 'Upstream returned non-JSON: ' + contentType });
      }

    } catch (err) {
      console.error('[AI] Error:', err.message);
      return jsonResponse(res, 500, { error: 'Proxy error: ' + err.message });
    }
  }

  // ═══════════════════════════════════════════════════════════
  // Static File Server
  // ═══════════════════════════════════════════════════════════
  let filePath = '.' + decodeURIComponent(url.pathname);
  if (filePath === './') filePath = './index.html';

  const extname = String(path.extname(filePath)).toLowerCase();
  const mimeType = MIME_TYPES[extname] || 'application/octet-stream';

  fs.readFile(filePath, (error, content) => {
    if (error) {
      if (error.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('File not found: ' + filePath);
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Server Error: ' + error.code);
      }
    } else {
      res.writeHead(200, { 'Content-Type': mimeType });
      res.end(content, 'utf-8');
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n╔══════════════════════════════════════════════╗`);
  console.log(`║  JS Recon Server v3.1                        ║`);
  console.log(`╠══════════════════════════════════════════════╣`);
  console.log(`║  http://localhost:${PORT}                       ║`);
  console.log(`║                                              ║`);
  console.log(`║  Endpoints:                                  ║`);
  console.log(`║  POST /api/analyze  — AI enrichment proxy    ║`);
  console.log(`║  GET  /api/fetch    — CORS proxy             ║`);
  console.log(`║  POST /api/scan     — Server-side analysis   ║`);
  console.log(`╚══════════════════════════════════════════════╝\n`);
});
