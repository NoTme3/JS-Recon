// src/subdomain-harvester.js — Extract subdomains from discovered URLs
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  const NOISE = new Set([
    'cdn.jsdelivr.net','cdnjs.cloudflare.com','unpkg.com','fonts.googleapis.com',
    'fonts.gstatic.com','ajax.googleapis.com','www.googleapis.com','www.google-analytics.com',
    'www.googletagmanager.com','connect.facebook.net','platform.twitter.com','cdn.segment.com',
    'js.stripe.com','cdn.shopify.com','static.cloudflareinsights.com','polyfill.io',
    'browser.sentry-cdn.com','js.sentry-cdn.com','code.jquery.com','stackpath.bootstrapcdn.com',
    'maxcdn.bootstrapcdn.com','use.fontawesome.com','kit.fontawesome.com','cdn.tailwindcss.com',
    'localhost','127.0.0.1','0.0.0.0','example.com','www.example.com',
    'schema.org','www.w3.org','w3.org','json-schema.org'
  ]);

  JSA.harvestSubdomains = function (results, targetDomain) {
    const hostMap = new Map();
    ['full-urls','endpoints','dynamic'].forEach(cat => {
      (results[cat] || []).forEach(item => {
        try {
          if (!item.value.startsWith('http')) return;
          const hostname = new URL(item.value).hostname;
          if (NOISE.has(hostname) || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return;
          if (!hostMap.has(hostname)) hostMap.set(hostname, new Set());
          hostMap.get(hostname).add(item.sourceFile);
        } catch (e) {}
      });
    });

    const findings = [];
    const norm = targetDomain ? targetDomain.replace(/^(?:https?:\/\/)?(?:www\.)?/, '').replace(/\/.*$/, '').toLowerCase() : null;

    for (const [hostname, sources] of hostMap) {
      const isSub = norm && (hostname === norm || hostname.endsWith('.' + norm));
      const tags = [];
      if (isSub) tags.push('subdomain'); else tags.push('third-party');
      if (/api|admin|internal/.test(hostname)) tags.push('interesting');
      if (/staging|dev|test/.test(hostname)) tags.push('non-prod');

      findings.push({
        value: hostname, type: isSub ? 'Subdomain' : 'Third-Party Host',
        category: 'subdomains', severity: isSub ? 'medium' : 'info',
        confidence: 'high', sourceFile: Array.from(sources).join(', '),
        ruleId: 'subdomain', isBase64: false, tags: tags
      });
    }
    findings.sort((a, b) => {
      const aS = a.tags.includes('subdomain'), bS = b.tags.includes('subdomain');
      if (aS !== bS) return aS ? -1 : 1;
      return a.value.localeCompare(b.value);
    });
    return findings;
  };

  JSA.resolveSubdomain = async function (hostname) {
    try {
      const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`);
      const data = await r.json();
      if (data.Answer && data.Answer.length > 0) return { resolved: true, ips: data.Answer.filter(a => a.type === 1).map(a => a.data) };
      return { resolved: false, ips: [] };
    } catch (e) { return { resolved: false, ips: [], error: e.message }; }
  };
})();
