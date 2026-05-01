// server.js — Local dev server with AI proxy (zero dependencies)
// Fix #1: Handles HTML error responses from NVIDIA without crashing
// Fix #3: Runs on port 8000 to match user's existing setup
// Fix #7: Content-type checking before JSON parsing
// Fix #9: Supports NVIDIA + generic OpenAI-compatible proxy

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8000;

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

const server = http.createServer(async (req, res) => {
  console.log(`[${req.method}] ${req.url}`);

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

  // ─── API Proxy for AI Enrichment ───
  if (req.method === 'POST' && req.url === '/api/analyze') {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body);

        if (!payload.apiKey) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing apiKey in request body' }));
          return;
        }

        if (!payload.prompt) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Missing prompt in request body' }));
          return;
        }

        // Determine which upstream API to call
        const apiUrl = payload.apiUrl || 'https://integrate.api.nvidia.com/v1/chat/completions';
        const model = payload.model || 'meta/llama-3.3-70b-instruct';

        console.log(`[PROXY] → ${apiUrl} (model: ${model})`);

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

        // FIX #1 & #7: Check content-type before parsing as JSON
        const contentType = response.headers.get('content-type') || '';
        const responseText = await response.text();

        if (!response.ok) {
          console.error(`[PROXY] ← ${response.status} ${response.statusText}`);
          console.error(`[PROXY] Body: ${responseText.substring(0, 200)}`);

          // Try to extract a useful error message
          let errorMsg = `Upstream API returned ${response.status}`;
          if (contentType.includes('application/json')) {
            try {
              const errObj = JSON.parse(responseText);
              errorMsg = errObj.error?.message || errObj.detail || errorMsg;
            } catch (e) {}
          } else if (contentType.includes('text/html')) {
            // HTML error page — extract title or first heading
            const titleMatch = responseText.match(/<title>(.*?)<\/title>/i);
            const h1Match = responseText.match(/<h1>(.*?)<\/h1>/i);
            errorMsg = titleMatch?.[1] || h1Match?.[1] || `API returned HTML error page (${response.status})`;
          }

          res.writeHead(response.status, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: errorMsg }));
          return;
        }

        // Success — parse and forward JSON
        if (contentType.includes('application/json')) {
          try {
            const data = JSON.parse(responseText);
            console.log(`[PROXY] ← 200 OK (${data.choices?.[0]?.message?.content?.length || 0} chars)`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(data));
          } catch (e) {
            console.error('[PROXY] JSON parse error on success response:', e.message);
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Failed to parse upstream response as JSON' }));
          }
        } else {
          // Non-JSON success (shouldn't happen but handle gracefully)
          console.error(`[PROXY] Unexpected content-type: ${contentType}`);
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Upstream returned non-JSON content: ' + contentType }));
        }

      } catch (err) {
        console.error('[PROXY] Internal Error:', err.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Proxy error: ' + err.message }));
      }
    });
    return;
  }

  // ─── Static File Server ───
  let filePath = '.' + decodeURIComponent(req.url.split('?')[0]);
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
  console.log(`\nJS Recon Local Server running at http://localhost:${PORT}`);
  console.log(`AI Proxy enabled at /api/analyze (bypasses CORS for NVIDIA)`);
  console.log(`Accessible on LAN at http://0.0.0.0:${PORT}`);
  console.log(`Press Ctrl+C to stop\n`);
});
