// api/analyze.js — Vercel Edge Function for AI Proxy
// Mirrors the proxy logic from server.js for production deployment
// Accepts: { apiKey, prompt, model?, apiUrl? }

export const config = {
  runtime: 'edge'
};

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default async function handler(req) {
  // Handle preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { 
      status: 405, 
      headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
    });
  }

  let payload;
  try {
    payload = await req.json();
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), { 
      status: 400, 
      headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
    });
  }

  if (!payload || !payload.apiKey) {
    return new Response(JSON.stringify({ error: 'Missing apiKey in request body' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }});
  }

  if (!payload.prompt) {
    return new Response(JSON.stringify({ error: 'Missing prompt in request body' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }});
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

      return new Response(JSON.stringify({ error: errorMsg }), { status: response.status, headers: { ...corsHeaders, 'Content-Type': 'application/json' }});
    }

    // Success — parse and forward
    if (contentType.includes('application/json')) {
      try {
        const data = JSON.parse(responseText);
        return new Response(JSON.stringify(data), { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' }});
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Failed to parse upstream response as JSON' }), { status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' }});
      }
    } else {
      return new Response(JSON.stringify({ error: 'Upstream returned non-JSON content: ' + contentType }), { status: 502, headers: { ...corsHeaders, 'Content-Type': 'application/json' }});
    }

  } catch (err) {
    return new Response(JSON.stringify({ error: 'Proxy error: ' + err.message }), { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }});
  }
}
