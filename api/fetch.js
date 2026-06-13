// api/fetch.js — Vercel Edge Function for CORS proxy
// Fetches remote JS files on behalf of the browser to bypass CORS restrictions

export const config = {
  runtime: 'edge'
};

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const MAX_SIZE = 50 * 1024 * 1024; // 50MB

export default async function handler(req) {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  const { searchParams } = new URL(req.url);
  const targetUrl = searchParams.get('url');

  if (!targetUrl) {
    return new Response(JSON.stringify({ error: 'Missing ?url= parameter' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  // Validate URL
  try {
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return new Response(JSON.stringify({ error: 'Only http/https URLs supported' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Invalid URL' }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000); // 20s for Edge

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
      return new Response(JSON.stringify({
        error: `Remote server returned ${response.status} ${response.statusText}`
      }), {
        status: response.status,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const text = await response.text();
    if (text.length > MAX_SIZE) {
      return new Response(JSON.stringify({
        error: `File too large: ${(text.length / 1024 / 1024).toFixed(1)}MB`
      }), {
        status: 413,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({
      content: text,
      url: targetUrl,
      size: text.length,
      contentType: response.headers.get('content-type') || 'unknown'
    }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });

  } catch (err) {
    const status = err.name === 'AbortError' ? 504 : 502;
    const msg = err.name === 'AbortError' ? 'Remote server timed out' : err.message;
    return new Response(JSON.stringify({ error: 'Failed to fetch: ' + msg }), {
      status,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}
