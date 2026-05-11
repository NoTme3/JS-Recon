// api/analyze.js — Vercel Serverless Function for AI Proxy
// Mirrors the proxy logic from server.js for production deployment
// Accepts: { apiKey, prompt, model?, apiUrl? }

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const payload = req.body;

  if (!payload || !payload.apiKey) {
    return res.status(400).json({ error: 'Missing apiKey in request body' });
  }

  if (!payload.prompt) {
    return res.status(400).json({ error: 'Missing prompt in request body' });
  }

  // Determine upstream API
  const apiUrl = payload.apiUrl || 'https://integrate.api.nvidia.com/v1/chat/completions';
  const model = payload.model || 'meta/llama-3.3-70b-instruct';

  try {
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

      return res.status(response.status).json({ error: errorMsg });
    }

    // Success — parse and forward
    if (contentType.includes('application/json')) {
      try {
        const data = JSON.parse(responseText);
        return res.status(200).json(data);
      } catch (e) {
        return res.status(502).json({ error: 'Failed to parse upstream response as JSON' });
      }
    } else {
      return res.status(502).json({ error: 'Upstream returned non-JSON content: ' + contentType });
    }

  } catch (err) {
    return res.status(500).json({ error: 'Proxy error: ' + err.message });
  }
}
