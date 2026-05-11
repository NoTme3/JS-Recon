// src/exporters.js — Postman Collection & OpenAPI 3.0 export
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  JSA.exportPostman = function (results, baseUrl) {
    const eps = [...(results['full-urls']||[]),...(results['endpoints']||[]),...(results['routes']||[])];
    const items = [], seen = new Set();
    for (const ep of eps) {
      const path = ep.value; if (seen.has(path)) continue; seen.add(path);
      const method = ep.method || 'GET';
      const url = path.startsWith('http') ? { raw: path } : { raw: '{{baseUrl}}' + path, host: ['{{baseUrl}}'], path: path.split('/').filter(Boolean) };
      const item = { name: method + ' ' + path, request: { method, url, header: [] } };
      if (ep.tags && ep.tags.includes('auth')) item.request.header.push({ key: 'Authorization', value: 'Bearer {{token}}', type: 'text' });
      items.push(item);
    }
    return JSON.stringify({
      info: { name: baseUrl ? 'JS Recon — ' + new URL(baseUrl).hostname : 'JS Recon Collection', schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' },
      variable: [{ key: 'baseUrl', value: baseUrl || 'https://example.com' }, { key: 'token', value: '' }],
      item: items
    }, null, 2);
  };

  JSA.exportOpenAPI = function (results, baseUrl) {
    const eps = [...(results['endpoints']||[]),...(results['routes']||[])].filter(f => f.value.startsWith('/'));
    const paths = {}, seen = new Set();
    for (const ep of eps) {
      let path = ep.value; if (seen.has(path)) continue; seen.add(path);
      path = path.replace(/:([a-zA-Z_][a-zA-Z0-9_]*)/g, '{$1}');
      const method = (ep.method || 'get').toLowerCase();
      if (!paths[path]) paths[path] = {};
      const params = []; const pm = path.match(/\{([^}]+)\}/g);
      if (pm) pm.forEach(p => params.push({ name: p.replace(/[{}]/g, ''), in: 'path', required: true, schema: { type: 'string' } }));
      paths[path][method] = { summary: 'Discovered via JS Recon', parameters: params.length > 0 ? params : undefined, responses: { '200': { description: 'OK' } } };
    }
    let serverUrl = baseUrl || 'https://example.com';
    try { serverUrl = new URL(serverUrl).origin; } catch (e) {}
    return JSON.stringify({ openapi: '3.0.3', info: { title: 'JS Recon Discovered API', version: '1.0.0' }, servers: [{ url: serverUrl }], paths }, null, 2);
  };
})();
