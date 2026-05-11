// src/taint-analyzer.js — Intra-procedural taint tracking via AST
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  const TAINT_SOURCES = {
    'location.href': 'URL', 'location.hash': 'URL Fragment', 'location.search': 'Query String',
    'location.pathname': 'URL Path', 'document.URL': 'Document URL', 'document.referrer': 'Referrer',
    'document.cookie': 'Cookie', 'window.name': 'Window Name',
    'localStorage.getItem': 'localStorage', 'sessionStorage.getItem': 'sessionStorage',
    'URLSearchParams': 'URL Params', 'FormData': 'Form Data'
  };

  const TAINT_SINKS = {
    'innerHTML': { severity: 'high', type: 'XSS Sink' },
    'outerHTML': { severity: 'high', type: 'XSS Sink' },
    'document.write': { severity: 'high', type: 'XSS Sink' },
    'document.writeln': { severity: 'high', type: 'XSS Sink' },
    'eval': { severity: 'critical', type: 'Code Injection' },
    'Function': { severity: 'critical', type: 'Code Injection' },
    'setTimeout': { severity: 'high', type: 'Code Injection (string)' },
    'setInterval': { severity: 'high', type: 'Code Injection (string)' },
    'fetch': { severity: 'medium', type: 'SSRF Risk' },
    'XMLHttpRequest.open': { severity: 'medium', type: 'SSRF Risk' },
    'postMessage': { severity: 'medium', type: 'Data Leak via postMessage' },
    'location.assign': { severity: 'high', type: 'Open Redirect' },
    'location.replace': { severity: 'high', type: 'Open Redirect' },
    'window.open': { severity: 'medium', type: 'Open Redirect' },
    'insertAdjacentHTML': { severity: 'high', type: 'XSS Sink' },
    'srcdoc': { severity: 'high', type: 'XSS Sink (iframe)' }
  };

  JSA.analyzeTaint = function (code, fileName) {
    if (typeof acorn === 'undefined') return [];
    const findings = [];

    try {
      const ast = acorn.parse(code, { ecmaVersion: 2022, sourceType: 'module', allowImportExportEverywhere: true, allowReturnOutsideFunction: true, locations: true });
      const taintedVars = new Map();

      function memberToString(node) {
        if (!node) return '';
        if (node.type === 'Identifier') return node.name;
        if (node.type === 'MemberExpression') {
          const obj = memberToString(node.object);
          const prop = node.computed ? '[…]' : (node.property.name || node.property.value || '');
          return obj + '.' + prop;
        }
        return '';
      }

      function isSource(node) {
        const str = memberToString(node);
        for (const [src, label] of Object.entries(TAINT_SOURCES)) {
          if (str.includes(src)) return { source: src, label: label };
        }
        if (node.type === 'CallExpression') {
          const callee = memberToString(node.callee);
          for (const [src, label] of Object.entries(TAINT_SOURCES)) {
            if (callee.includes(src)) return { source: src, label: label };
          }
        }
        return null;
      }

      function isSink(node) {
        if (node.type === 'AssignmentExpression' && node.left.type === 'MemberExpression') {
          const prop = node.left.property.name || '';
          if (TAINT_SINKS[prop]) return { sink: prop, ...TAINT_SINKS[prop] };
        }
        if (node.type === 'CallExpression') {
          const callee = memberToString(node.callee);
          for (const [sink, info] of Object.entries(TAINT_SINKS)) {
            if (callee.includes(sink)) return { sink: sink, ...info };
          }
        }
        return null;
      }

      function isTainted(node) {
        if (!node) return null;
        const src = isSource(node);
        if (src) return src;
        if (node.type === 'Identifier' && taintedVars.has(node.name)) return taintedVars.get(node.name);
        if (node.type === 'BinaryExpression') return isTainted(node.left) || isTainted(node.right);
        if (node.type === 'TemplateLiteral' && node.expressions) {
          for (const expr of node.expressions) { const t = isTainted(expr); if (t) return t; }
        }
        if (node.type === 'CallExpression') {
          for (const arg of node.arguments) { const t = isTainted(arg); if (t) return t; }
        }
        return null;
      }

      function walk(node) {
        if (!node || typeof node !== 'object') return;
        // Track variable declarations
        if (node.type === 'VariableDeclarator' && node.init && node.id && node.id.name) {
          const t = isTainted(node.init);
          if (t) taintedVars.set(node.id.name, t);
        }
        // Track assignments
        if (node.type === 'AssignmentExpression') {
          if (node.left.type === 'Identifier') {
            const t = isTainted(node.right);
            if (t) taintedVars.set(node.left.name, t);
          }
          const sink = isSink(node);
          if (sink) {
            const t = isTainted(node.right);
            if (t) {
              findings.push({
                category: 'taint',
                value: `${t.source} → ${sink.sink}`,
                type: `Taint Flow: ${t.label} → ${sink.type}`,
                severity: sink.severity,
                confidence: 'high',
                line: node.loc ? node.loc.start.line : null,
                sourceFile: fileName
              });
            }
          }
        }
        // Track call expressions
        if (node.type === 'ExpressionStatement' && node.expression && node.expression.type === 'CallExpression') {
          const sink = isSink(node.expression);
          if (sink) {
            for (const arg of node.expression.arguments) {
              const t = isTainted(arg);
              if (t) {
                findings.push({
                  category: 'taint',
                  value: `${t.source} → ${sink.sink}()`,
                  type: `Taint Flow: ${t.label} → ${sink.type}`,
                  severity: sink.severity,
                  confidence: 'high',
                  line: node.loc ? node.loc.start.line : null,
                  sourceFile: fileName
                });
                break;
              }
            }
          }
        }
        for (const key of Object.keys(node)) {
          if (key === 'type' || key === 'loc' || key === 'start' || key === 'end') continue;
          const child = node[key];
          if (Array.isArray(child)) child.forEach(c => { if (c && typeof c.type === 'string') walk(c); });
          else if (child && typeof child === 'object' && child.type) walk(child);
        }
      }
      walk(ast);
    } catch (e) { /* AST parse failed, skip taint */ }
    return findings;
  };
})();
