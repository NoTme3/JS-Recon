// src/ast-analyzer.js — AST-based analysis using Acorn
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  // Dangerous sinks to track in AST
  const SINK_NAMES = new Set([
    'eval', 'Function', 'setTimeout', 'setInterval',
    'document.write', 'document.writeln'
  ]);

  const SINK_PROPERTIES = new Set([
    'innerHTML', 'outerHTML'
  ]);

  const FETCH_LIKE = new Set(['fetch', 'axios', 'get', 'post', 'put', 'delete', 'patch', 'request']);

  const SECRET_VAR_NAMES = /(?:password|passwd|secret|token|api[_-]?key|apikey|auth|jwt|bearer|access[_-]?token|client[_-]?secret|private[_-]?key|crypto[_-]?key|secret[_-]?key|master[_-]?key|session[_-]?key|signing[_-]?key|encrypt|decrypt)/i;

  /**
   * Analyze JS code using AST (Acorn).
   * Returns additional findings not caught by regex.
   */
  JSA.analyzeAST = function (code, fileName) {
    if (typeof acorn === 'undefined') return [];
    const findings = [];

    let ast;
    try {
      ast = acorn.parse(code, {
        ecmaVersion: 'latest',
        sourceType: 'module',
        allowImportExportEverywhere: true,
        allowReturnOutsideFunction: true,
        allowAwaitOutsideFunction: true,
        locations: true,
        ranges: true,
        tolerant: true
      });
    } catch (e) {
      // Try as script if module parse fails
      try {
        ast = acorn.parse(code, {
          ecmaVersion: 'latest',
          sourceType: 'script',
          locations: true,
          ranges: true,
          tolerant: true
        });
      } catch (e2) {
        return []; // Unparseable
      }
    }

    // Simple recursive walker
    function walk(node) {
      if (!node || typeof node !== 'object') return;
      visit(node);
      for (const key of Object.keys(node)) {
        const child = node[key];
        if (Array.isArray(child)) {
          child.forEach(c => { if (c && typeof c.type === 'string') walk(c); });
        } else if (child && typeof child.type === 'string') {
          walk(child);
        }
      }
    }

    function visit(node) {
      // --- Detect fetch/XHR/axios calls with URL arguments ---
      if (node.type === 'CallExpression') {
        const calleeName = getCalleeName(node.callee);
        if (calleeName && FETCH_LIKE.has(calleeName.split('.').pop())) {
          const urlArg = node.arguments && node.arguments[0];
          if (urlArg) {
            const url = extractStringValue(urlArg);
            if (url && url.length > 3) {
              findings.push({
                category: url.startsWith('http') ? 'full-urls' : 'endpoints',
                value: url,
                type: 'AST: ' + calleeName + '() call',
                severity: 'info',
                confidence: 'high',
                line: node.loc ? node.loc.start.line : null,
                sourceFile: fileName
              });
            }
          }
        }

        // --- Detect dangerous sink calls ---
        if (calleeName && SINK_NAMES.has(calleeName)) {
          findings.push({
            category: 'vulnerabilities',
            value: calleeName + '()',
            type: 'AST: Dangerous Call',
            severity: 'high',
            confidence: 'high',
            line: node.loc ? node.loc.start.line : null,
            sourceFile: fileName,
            exploitKey: calleeName.toLowerCase().replace(/\./g, '')
          });
        }
      }

      // --- Detect innerHTML/outerHTML assignments ---
      if (node.type === 'AssignmentExpression' && node.left && node.left.type === 'MemberExpression') {
        const prop = node.left.property;
        const propName = prop && (prop.name || (prop.type === 'Literal' && prop.value));
        if (propName && SINK_PROPERTIES.has(propName)) {
          findings.push({
            category: 'vulnerabilities',
            value: '.' + propName + ' = ...',
            type: 'AST: Dangerous Assignment',
            severity: 'high',
            confidence: 'high',
            line: node.loc ? node.loc.start.line : null,
            sourceFile: fileName,
            exploitKey: propName.toLowerCase()
          });
        }
      }

      // --- Detect secret-like variable assignments ---
      if (node.type === 'VariableDeclarator' && node.id && node.id.name) {
        if (SECRET_VAR_NAMES.test(node.id.name) && node.init) {
          const val = extractStringValue(node.init);
          if (val && val.length >= 8) {
            findings.push({
              category: 'secrets',
              value: node.id.name + ' = "' + val.substring(0, 50) + (val.length > 50 ? '...' : '') + '"',
              type: 'AST: Secret Variable',
              severity: 'high',
              confidence: 'medium',
              line: node.loc ? node.loc.start.line : null,
              sourceFile: fileName
            });
          }
        }
      }

      // --- Detect assignment expressions with secret-like names ---
      if (node.type === 'AssignmentExpression' && node.left) {
        const leftName = getCalleeName(node.left);
        if (leftName && SECRET_VAR_NAMES.test(leftName)) {
          const val = extractStringValue(node.right);
          if (val && val.length >= 8) {
            findings.push({
              category: 'secrets',
              value: leftName + ' = "' + val.substring(0, 50) + (val.length > 50 ? '...' : '') + '"',
              type: 'AST: Secret Assignment',
              severity: 'high',
              confidence: 'medium',
              line: node.loc ? node.loc.start.line : null,
              sourceFile: fileName
            });
          }
        }
      }

      // --- Detect webpack chunk loading patterns ---
      if (node.type === 'CallExpression') {
        const calleeName = getCalleeName(node.callee);
        if (calleeName && /^__webpack_require__/.test(calleeName)) {
          const arg = node.arguments && node.arguments[0];
          if (arg) {
            const val = extractStringValue(arg);
            if (val && val.length > 2) {
              findings.push({
                category: 'libraries',
                value: val,
                type: 'AST: Webpack Chunk',
                severity: 'info',
                confidence: 'high',
                line: node.loc ? node.loc.start.line : null,
                sourceFile: fileName
              });
            }
          }
        }
      }

      // --- Detect string concatenation for chunk URLs ---
      if (node.type === 'BinaryExpression' && node.operator === '+') {
        const val = extractStringValue(node);
        if (val && /\.chunk\.js|\.bundle\.js/i.test(val)) {
          findings.push({
            category: 'libraries',
            value: val,
            type: 'AST: Chunk URL Pattern',
            severity: 'info',
            confidence: 'medium',
            line: node.loc ? node.loc.start.line : null,
            sourceFile: fileName
          });
        }
      }
    }

    // Helper: extract callee name from various node shapes
    function getCalleeName(node) {
      if (!node) return null;
      if (node.type === 'Identifier') return node.name;
      if (node.type === 'MemberExpression') {
        const obj = getCalleeName(node.object);
        const prop = node.property && (node.property.name || (node.property.type === 'Literal' && node.property.value));
        if (obj && prop) return obj + '.' + prop;
        return prop || obj;
      }
      return null;
    }

    // Helper: extract string value from a node
    function extractStringValue(node) {
      if (!node) return null;
      if (node.type === 'Literal' && typeof node.value === 'string') return node.value;
      if (node.type === 'TemplateLiteral' && node.quasis && node.quasis.length > 0) {
        return node.quasis.map(q => q.value ? q.value.raw : '').join('*');
      }
      if (node.type === 'BinaryExpression' && node.operator === '+') {
        const left = extractStringValue(node.left);
        const right = extractStringValue(node.right);
        if (left || right) return (left || '') + (right || '');
      }
      return null;
    }

    walk(ast);
    return findings;
  };

})();
