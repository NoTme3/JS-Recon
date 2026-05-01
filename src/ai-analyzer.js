// src/ai-analyzer.js — Provider-agnostic AI enrichment (client-side)
// Fix #2: Push original references, not copies (enrichments now persist)
// Fix #4: Clear stale localStorage on version change
// Fix #5: Use numeric IDs for reliable AI matching
// Fix #6: Better error body handling in fetchWithRetry
// Fix #8: No hardcoded API key (localStorage only)
// Fix #10: Better loading state feedback

(function () {
  'use strict';
  window.JSA = window.JSA || {};

  const AI_CONFIG_VERSION = 2; // Bump this to force localStorage refresh

  // Severity ordering for prioritisation
  JSA.SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  // ─── Default config (no hardcoded API key — Fix #8) ───
  JSA.aiConfig = {
    _v: AI_CONFIG_VERSION,
    enabled: false,
    provider: 'nvidia',
    apiKey: '',
    maxFindings: 15
  };

  // Fix #4: Clear stale config if version mismatches
  JSA.loadAIConfig = function () {
    try {
      const s = localStorage.getItem('jsa-ai-config');
      if (s) {
        const saved = JSON.parse(s);
        if (saved._v === AI_CONFIG_VERSION) {
          Object.assign(JSA.aiConfig, saved);
        } else {
          // Version mismatch — clear stale config, keep user's API key if present
          console.warn('[AI] Config version mismatch, resetting to defaults');
          if (saved.apiKey) JSA.aiConfig.apiKey = saved.apiKey;
          if (saved.provider) JSA.aiConfig.provider = saved.provider;
          if (saved.enabled !== undefined) JSA.aiConfig.enabled = saved.enabled;
          JSA.saveAIConfig(); // Save clean version
        }
      }
    } catch (e) {
      console.warn('[AI] Failed to load config:', e);
    }
  };

  JSA.saveAIConfig = function () {
    try {
      JSA.aiConfig._v = AI_CONFIG_VERSION;
      localStorage.setItem('jsa-ai-config', JSON.stringify(JSA.aiConfig));
    } catch (e) {}
  };

  // ─── Retry helper with exponential backoff (Fix #6: better error extraction) ───
  async function fetchWithRetry(url, options, maxRetries) {
    const retries = maxRetries || 3;
    for (let attempt = 0; attempt <= retries; attempt++) {
      let r;
      try {
        r = await fetch(url, options);
      } catch (networkErr) {
        // Network error (CORS block, DNS failure, etc.)
        if (attempt < retries) {
          const waitSec = Math.pow(2, attempt + 1);
          if (JSA._onAIStatus) JSA._onAIStatus(`Network error. Retrying in ${waitSec}s...`);
          await new Promise(resolve => setTimeout(resolve, waitSec * 1000));
          continue;
        }
        throw new Error('Network error: ' + networkErr.message + '. Make sure the local server is running (node server.js).');
      }

      if (r.ok) return r;

      if (r.status === 429 && attempt < retries) {
        const waitSec = Math.pow(2, attempt + 1) + Math.random();
        console.warn(`[AI] Rate limited (429). Retrying in ${waitSec.toFixed(1)}s... (attempt ${attempt + 1}/${retries})`);
        if (JSA._onAIStatus) JSA._onAIStatus(`Rate limited. Retrying in ${Math.ceil(waitSec)}s...`);
        await new Promise(resolve => setTimeout(resolve, waitSec * 1000));
        continue;
      }

      // Non-retryable error — extract message carefully (Fix #6)
      let errMsg = `API returned ${r.status}`;
      try {
        const text = await r.text();
        try {
          const errBody = JSON.parse(text);
          errMsg = errBody.error?.message || errBody.error || errBody.detail || errMsg;
        } catch (e) {
          // Not JSON — use first 200 chars of text
          if (text.length > 0) errMsg += ': ' + text.substring(0, 200);
        }
      } catch (e) {}
      throw new Error(errMsg);
    }
    throw new Error('Rate limited (429). Please wait a minute and try again.');
  }

  // ─── Build the prompt (Fix #5: use numeric IDs for reliable matching) ───
  function buildPrompt(batch) {
    const findingsText = batch.map((f) =>
      `- [${f.id}] ${f.type} | severity: ${f.severity} | confidence: ${f.confidence} | value: "${f.value}" | file: ${f.sourceFile}`
    ).join('\n');

    return `You are a security analyst reviewing JavaScript recon findings.
For each finding below, provide:
1. "severity": Your assessed severity (critical/high/medium/low/info)
2. "reasoning": A 1-2 sentence explanation of the security risk
3. "suggestedTest": A specific test or payload to verify the finding

Respond ONLY with a valid JSON array. Each object must have these exact fields: id, severity, reasoning, suggestedTest.
The "id" field MUST exactly match the finding ID in brackets (e.g., "${batch[0]?.id || 'finding-1'}").
Do NOT wrap the response in markdown code blocks. Output ONLY the JSON array.

Findings:
${findingsText}`;
  }

  // ─── Parse AI response ───
  function parseAIResponse(text) {
    if (!text) return [];
    let clean = text.trim();
    // Strip markdown code fences
    clean = clean.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '');

    try {
      let parsed = JSON.parse(clean);
      if (parsed.enrichments) return parsed.enrichments;
      if (Array.isArray(parsed)) return parsed;
      const values = Object.values(parsed);
      if (values.length === 1 && Array.isArray(values[0])) return values[0];
      return [parsed];
    } catch (e) {
      // Try finding a JSON array in the text
      const arrMatch = clean.match(/\[[\s\S]*\]/);
      if (arrMatch) {
        try { return JSON.parse(arrMatch[0]); } catch (e2) {}
      }
      console.warn('[AI] Could not parse AI response:', clean.substring(0, 200));
      return [];
    }
  }

  // ─── Provider calls ───

  // Proxy call via local Node.js server (for NVIDIA, Anthropic — CORS-blocked APIs)
  async function callViaProxy(apiKey, prompt, model, apiUrl) {
    const r = await fetchWithRetry('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        apiKey,
        prompt,
        model,
        apiUrl: apiUrl || 'https://integrate.api.nvidia.com/v1/chat/completions'
      })
    }, 3);
    const data = await r.json();

    // The proxy forwards the raw upstream response
    if (data.error) throw new Error(data.error);
    return parseAIResponse(data.choices?.[0]?.message?.content);
  }

  // Direct OpenAI-compatible call (for APIs that support browser CORS)
  async function callOpenAICompatible(apiKey, prompt, baseUrl, model) {
    const r = await fetchWithRetry(baseUrl + '/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + apiKey },
      body: JSON.stringify({
        model: model,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.3,
        max_tokens: 2000,
        stream: false
      })
    }, 3);
    const data = await r.json();
    if (data.error) throw new Error(data.error.message || data.error);
    return parseAIResponse(data.choices?.[0]?.message?.content);
  }

  // Direct Gemini call (supports browser CORS)
  async function callGemini(apiKey, prompt) {
    const r = await fetchWithRetry(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.3, maxOutputTokens: 2000 }
        })
      }, 3
    );
    const data = await r.json();
    if (data.error) throw new Error(data.error.message || data.error);
    return parseAIResponse(data.candidates?.[0]?.content?.parts?.[0]?.text);
  }

  // ─── Provider registry ───
  const PROVIDERS = {
    nvidia: {
      label: 'NVIDIA NIM',
      model: 'meta/llama-3.3-70b-instruct',
      keyPrefix: 'nvapi-',
      needsProxy: true,
      call: (key, prompt) => callViaProxy(key, prompt, 'meta/llama-3.3-70b-instruct')
    },
    openai: {
      label: 'OpenAI',
      model: 'gpt-4o-mini',
      keyPrefix: 'sk-',
      needsProxy: false,
      call: (key, prompt) => callOpenAICompatible(key, prompt, 'https://api.openai.com/v1', 'gpt-4o-mini')
    },
    gemini: {
      label: 'Google Gemini',
      model: 'gemini-2.0-flash',
      keyPrefix: 'AIza',
      needsProxy: false,
      call: (key, prompt) => callGemini(key, prompt)
    },
    anthropic: {
      label: 'Anthropic',
      model: 'claude-sonnet-4-20250514',
      keyPrefix: 'sk-ant-',
      needsProxy: true,
      call: (key, prompt) => callViaProxy(key, prompt, 'claude-sonnet-4-20250514', 'https://api.anthropic.com/v1/messages')
    }
  };

  // ─── Main enrichment function ───
  JSA.enrichWithAI = async function (results, onStatus) {
    if (!JSA.aiConfig.enabled) throw new Error('AI enrichment is disabled. Enable it in Settings.');
    if (!JSA.aiConfig.apiKey || !JSA.aiConfig.apiKey.trim()) throw new Error('No API key configured. Add your key in Settings → AI Enrichment.');

    JSA._onAIStatus = onStatus || null;
    const provider = PROVIDERS[JSA.aiConfig.provider];
    if (!provider) throw new Error('Unknown provider: ' + JSA.aiConfig.provider);

    // Check if provider needs proxy and warn if on file:// protocol
    if (provider.needsProxy && window.location.protocol === 'file:') {
      throw new Error(provider.label + ' requires a hosted server.\nRun locally: node server.js\nOr deploy to Vercel for production use.');
    }

    // Fix #2: Collect ORIGINAL references (not copies!) so enrichments persist
    const all = [];
    Object.entries(results).forEach(([cat, items]) => {
      if (!Array.isArray(items)) return;
      items.forEach(item => all.push(item)); // ← NO spread operator
    });
    all.sort((a, b) => (JSA.SEVERITY_ORDER[a.severity] || 4) - (JSA.SEVERITY_ORDER[b.severity] || 4));

    // Fix #5: Build batch with numeric IDs for reliable matching
    const topItems = all.slice(0, JSA.aiConfig.maxFindings);
    const batch = topItems.map((f, i) => ({
      id: 'finding-' + (i + 1),
      type: f.type || '',
      value: (f.value || '').substring(0, 120),
      severity: f.severity || 'info',
      confidence: f.confidence || 'medium',
      sourceFile: f.sourceFile || ''
    }));

    if (batch.length === 0) throw new Error('No findings to enrich.');

    const prompt = buildPrompt(batch);

    // Fix #10: Detailed status feedback
    if (onStatus) onStatus('Preparing ' + batch.length + ' findings...');
    await new Promise(r => setTimeout(r, 100)); // Let UI update

    // Chunking to prevent Vercel 504 Timeouts
    const CHUNK_SIZE = 5;
    const allEnrichments = [];
    
    for (let i = 0; i < batch.length; i += CHUNK_SIZE) {
      const chunk = batch.slice(i, i + CHUNK_SIZE);
      if (onStatus) {
        onStatus(`Calling ${provider.label} (Batch ${Math.floor(i/CHUNK_SIZE) + 1}/${Math.ceil(batch.length/CHUNK_SIZE)})...`);
      }
      
      const chunkPrompt = buildPrompt(chunk);
      try {
        const chunkEnrichments = await provider.call(JSA.aiConfig.apiKey, chunkPrompt);
        if (Array.isArray(chunkEnrichments)) {
          allEnrichments.push(...chunkEnrichments);
        }
      } catch (err) {
        console.error('AI Enrichment Chunk Failed:', err);
        // If a chunk fails, we just continue with the ones we got
      }
    }

    if (!allEnrichments || allEnrichments.length === 0) {
      throw new Error('AI returned no enrichments. The response may have been filtered or timed out.');
    }

    // Fix #5: Build enrichment map using numeric IDs
    const enrichMap = new Map();
    allEnrichments.forEach(e => {
      if (e.id) enrichMap.set(e.id, e);
    });

    // Fix #2: Write directly to original objects (persists after renderResults)
    let applied = 0;
    topItems.forEach((item, i) => {
      const enrichment = enrichMap.get('finding-' + (i + 1));
      if (enrichment) {
        item.aiSeverity = enrichment.severity;
        item.aiReasoning = enrichment.reasoning;
        item.aiSuggestedTest = enrichment.suggestedTest;
        applied++;
      }
    });

    if (onStatus) onStatus('Done! ' + applied + ' enriched.');
    JSA._onAIStatus = null;
    return { total: allEnrichments.length, applied };
  };

  // Load saved config on startup
  JSA.loadAIConfig();
})();
