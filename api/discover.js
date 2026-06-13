// api/discover.js — Vercel Edge Function for JS file discovery
// Crawls an HTML page and extracts all JavaScript file URLs

export const config = {
  runtime: 'edge'
};

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function jsonResp(status, data) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

export default async function handler(req) {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const { searchParams } = new URL(req.url);
  const targetUrl = searchParams.get('url');
  const fetchContent = searchParams.get('fetch') === 'true';

  if (!targetUrl) return jsonResp(400, { error: 'Missing ?url= parameter' });

  try {
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return jsonResp(400, { error: 'Only http/https URLs supported' });
    }
  } catch (e) {
    return jsonResp(400, { error: 'Invalid URL' });
  }

  try {
    // Fetch the page
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);

    const response = await fetch(targetUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*'
      },
      redirect: 'follow'
    });
    clearTimeout(timeout);

    if (!response.ok) {
      return jsonResp(response.status, { error: `Remote server returned ${response.status}` });
    }

    const html = await response.text();

    // Extract JS URLs
    const jsUrls = new Set();

    // <script src="...">
    const scriptSrcRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
    let m;
    while ((m = scriptSrcRegex.exec(html)) !== null) {
      const src = m[1].trim();
      if (!src || src.startsWith('data:')) continue;
      try { jsUrls.add(new URL(src, targetUrl).href); } catch (e) {}
    }

    // Inline JS references (webpack chunks, dynamic imports)
    const inlineChunkRegex = /["']((?:https?:)?\/\/[^"']+\.js(?:\?[^"']*)?|\/[^"'\s]+\.js(?:\?[^"']*)?)/gi;
    while ((m = inlineChunkRegex.exec(html)) !== null) {
      try { jsUrls.add(new URL(m[1].trim(), targetUrl).href); } catch (e) {}
    }

    // <link rel="preload/modulepreload" href="...js">
    const preloadRegex = /<link[^>]+rel=["'](?:preload|modulepreload)["'][^>]+href=["']([^"']+\.js[^"']*)["'][^>]*>/gi;
    while ((m = preloadRegex.exec(html)) !== null) {
      try { jsUrls.add(new URL(m[1].trim(), targetUrl).href); } catch (e) {}
    }

    const discovered = Array.from(jsUrls);
    let scripts = discovered.map(u => ({
      url: u,
      filename: u.split('/').pop().split('?')[0] || 'script.js'
    }));

    // Fetch content for each script if requested
    if (fetchContent && discovered.length > 0) {
      const results = await Promise.allSettled(
        discovered.map(async (jsUrl) => {
          const ctrl = new AbortController();
          const t = setTimeout(() => ctrl.abort(), 10000);
          try {
            const r = await fetch(jsUrl, {
              signal: ctrl.signal,
              headers: {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Accept': '*/*'
              }
            });
            clearTimeout(t);
            if (!r.ok) return { url: jsUrl, error: `HTTP ${r.status}` };
            const text = await r.text();
            return { url: jsUrl, content: text, size: text.length };
          } catch (e) {
            clearTimeout(t);
            return { url: jsUrl, error: e.message };
          }
        })
      );

      scripts = results.map((r, i) => {
        const base = { url: discovered[i], filename: discovered[i].split('/').pop().split('?')[0] || 'script.js' };
        if (r.status === 'fulfilled' && r.value.content) {
          return { ...base, content: r.value.content, size: r.value.size };
        }
        return { ...base, error: r.value?.error || r.reason?.message || 'Failed' };
      });
    }

    return jsonResp(200, { pageUrl: targetUrl, totalFound: discovered.length, scripts });

  } catch (err) {
    const msg = err.name === 'AbortError' ? 'Page timed out' : err.message;
    return jsonResp(502, { error: 'Crawl failed: ' + msg });
  }
}
