// src/dynamic-sandbox.js — Client-side dynamic analysis via Web Worker + iframe
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  const TIMEOUT_MS = 8000;

  // ─── Web Worker Sandbox ───
  // Executes code in an isolated worker with hooked globals
  const WORKER_BOOTSTRAP = `
    const _intercepted = { urls: [], calls: [], errors: [] };

    // Hook fetch
    self.fetch = function(url, opts) {
      _intercepted.urls.push({ type: 'fetch', url: String(url), method: (opts && opts.method) || 'GET' });
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}), text: () => Promise.resolve('') });
    };

    // Hook XMLHttpRequest
    self.XMLHttpRequest = function() {
      const x = {
        open(m, u) { _intercepted.urls.push({ type: 'xhr', url: String(u), method: m }); },
        send() {}, setRequestHeader() {}, addEventListener() {},
        onload: null, onerror: null, onreadystatechange: null,
        readyState: 4, status: 200, responseText: '{}', response: '{}'
      };
      return x;
    };

    // Hook setTimeout/setInterval string form
    const _st = self.setTimeout;
    self.setTimeout = function(fn, d) {
      if (typeof fn === 'string') _intercepted.calls.push({ type: 'setTimeout(string)', value: fn.substring(0, 200) });
    };
    const _si = self.setInterval;
    self.setInterval = function(fn, d) {
      if (typeof fn === 'string') _intercepted.calls.push({ type: 'setInterval(string)', value: fn.substring(0, 200) });
    };

    // Hook eval
    self.eval = function(code) {
      _intercepted.calls.push({ type: 'eval', value: String(code).substring(0, 200) });
    };

    // Hook Function constructor
    const _Fn = self.Function;
    self.Function = function(...args) {
      _intercepted.calls.push({ type: 'Function()', value: args.map(a => String(a).substring(0, 200)).join(', ') });
      return function() {};
    };

    // Hook importScripts
    self.importScripts = function(...urls) {
      urls.forEach(u => _intercepted.urls.push({ type: 'importScripts', url: String(u) }));
    };

    self.addEventListener('message', function(e) {
      if (e.data && e.data.type === 'execute') {
        try {
          const fn = _Fn(e.data.code);
          fn();
        } catch (err) {
          _intercepted.errors.push(err.message);
        }
        self.postMessage({ type: 'results', data: _intercepted });
      }
    });
  `;

  /**
   * Run code in a Web Worker sandbox and return intercepted behavior
   */
  JSA.runDynamic = function (code) {
    return new Promise((resolve) => {
      try {
        const blob = new Blob([WORKER_BOOTSTRAP], { type: 'application/javascript' });
        const url = URL.createObjectURL(blob);
        const worker = new Worker(url);

        const timeout = setTimeout(() => {
          worker.terminate();
          URL.revokeObjectURL(url);
          resolve({ urls: [], calls: [], errors: ['Execution timed out after ' + TIMEOUT_MS + 'ms'], timedOut: true });
        }, TIMEOUT_MS);

        worker.onmessage = function (e) {
          if (e.data && e.data.type === 'results') {
            clearTimeout(timeout);
            worker.terminate();
            URL.revokeObjectURL(url);
            resolve(e.data.data);
          }
        };

        worker.onerror = function (err) {
          clearTimeout(timeout);
          worker.terminate();
          URL.revokeObjectURL(url);
          resolve({ urls: [], calls: [], errors: [err.message || 'Worker error'], timedOut: false });
        };

        worker.postMessage({ type: 'execute', code: code });
      } catch (err) {
        resolve({ urls: [], calls: [], errors: [err.message], timedOut: false });
      }
    });
  };

  /**
   * Convert dynamic analysis results into standard finding objects
   */
  JSA.processDynamicResults = function (raw, fileName) {
    const findings = [];

    if (raw.urls) {
      raw.urls.forEach(u => {
        findings.push({
          category: 'dynamic',
          value: u.url,
          type: 'Runtime ' + u.type + (u.method ? ' (' + u.method + ')' : ''),
          severity: 'medium',
          confidence: 'high',
          sourceFile: fileName
        });
      });
    }

    if (raw.calls) {
      raw.calls.forEach(c => {
        findings.push({
          category: 'dynamic',
          value: c.type + ': ' + (c.value || '').substring(0, 150),
          type: 'Runtime Dangerous Call',
          severity: 'high',
          confidence: 'high',
          sourceFile: fileName
        });
      });
    }

    if (raw.errors) {
      raw.errors.forEach(e => {
        findings.push({
          category: 'dynamic',
          value: e,
          type: 'Runtime Error',
          severity: 'info',
          confidence: 'high',
          sourceFile: fileName
        });
      });
    }

    return findings;
  };

})();
