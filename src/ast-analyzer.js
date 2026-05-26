// src/ast-analyzer.js — AST-based analysis using Acorn
// Includes: constant propagation, deterministic evaluation, entropy scoring, value-based classification
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

  // Note: 'get' removed — too generic (matches headers.get(), Map.get(), etc.)
  // Only match when prefixed: axios.get, http.get, $http.get
  const FETCH_LIKE = new Set(['fetch', 'request']);
  const FETCH_METHODS = new Set(['get', 'post', 'put', 'delete', 'patch']);
  const FETCH_OBJECTS = new Set(['axios', 'http', '$http', 'api', 'client', 'ajax', 'superagent']);

  const SECRET_VAR_NAMES = /(?:password|passwd|secret|token|api[_-]?key|apikey|auth|jwt|bearer|access[_-]?token|client[_-]?secret|private[_-]?key|crypto[_-]?key|secret[_-]?key|master[_-]?key|session[_-]?key|signing[_-]?key|encrypt|decrypt)/i;

  // ─── Safety & Performance Guards (Milestone 9) ───
  const MAX_RECURSION_DEPTH = 10;
  const MAX_STRING_SIZE = 4096;
  const MAX_EVALUATIONS_PER_FILE = 10000;

  // ─── Deterministic Evaluator Registry (Milestone 6) ───
  // Only side-effect-free, deterministic built-in APIs
  const SAFE_EVALUATORS = {
    'String.fromCharCode': function (node) {
      if (!node.arguments || node.arguments.length === 0) return null;
      if (node.arguments.length > 256) return null; // safety cap
      const chars = [];
      for (const arg of node.arguments) {
        if (arg.type === 'SpreadElement') return null;
        if (arg.type !== 'Literal' || typeof arg.value !== 'number') return null;
        if (arg.value < 0 || arg.value > 0x10FFFF) return null;
        chars.push(String.fromCharCode(arg.value));
      }
      const result = chars.join('');
      return result.length <= MAX_STRING_SIZE ? result : null;
    }
  };

  // ─── Value-Based Secret Patterns (Milestone 5) ───
  // Run against resolved constant values regardless of variable name
  const VALUE_SECRET_PATTERNS = [
    { regex: /^AKIA[0-9A-Z]{16,}$/, label: 'AWS Access Key', severity: 'critical' },
    { regex: /^AIza[0-9A-Za-z\-_]{35}$/, label: 'Google API Key', severity: 'critical' },
    { regex: /^(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}$/, label: 'GitHub Token', severity: 'critical' },
    { regex: /^(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{10,}$/, label: 'Stripe Key', severity: 'critical' },
    { regex: /^xox[bposa]-[0-9a-zA-Z\-]{10,}$/, label: 'Slack Token', severity: 'critical' },
    { regex: /^eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+\/=]{10,}$/, label: 'JWT Token', severity: 'high' },
    { regex: /^-----BEGIN\s(?:RSA\s|EC\s|DSA\s|OPENSSH\s)?PRIVATE\sKEY-----/, label: 'Private Key', severity: 'critical' },
    { regex: /^(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql):\/\//, label: 'Database URL', severity: 'critical' },
    { regex: /^[a-f0-9]{64,}$/i, label: 'Long Hex Token', severity: 'high' },
    { regex: /^nvapi-[A-Za-z0-9\-_]{20,}$/, label: 'NVIDIA API Key', severity: 'critical' },
    { regex: /^sk-[A-Za-z0-9]{20,}$/, label: 'OpenAI API Key', severity: 'critical' },
    { regex: /^sk-ant-[A-Za-z0-9\-_]{20,}$/, label: 'Anthropic API Key', severity: 'critical' },
  ];

  // ─── Entropy Calculation (Shannon entropy) ───
  function calculateEntropy(str) {
    if (!str || str.length < 2) return 0;
    const len = str.length;
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    return Object.values(freq).reduce((s, f) => s - (f / len) * Math.log2(f / len), 0);
  }

  // Export for use in main.js and worker
  JSA.calculateEntropy = calculateEntropy;

  /**
   * Analyze JS code using AST (Acorn).
   * Returns additional findings not caught by regex.
   */
  JSA.analyzeAST = function (code, fileName) {
    if (typeof acorn === 'undefined') return [];
    const findings = [];

    // ─── Constant Resolution Store (Milestone 1) ───
    const constValues = new Map();
    let evalCount = 0;

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
      try {
        ast = acorn.parse(code, {
          ecmaVersion: 'latest',
          sourceType: 'script',
          locations: true,
          ranges: true,
          tolerant: true
        });
      } catch (e2) {
        return [];
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
        const parts = calleeName ? calleeName.split('.') : [];
        const methodName = parts.pop();
        const objectName = parts.pop();

        const isFetchCall = (methodName && FETCH_LIKE.has(methodName)) ||
          (methodName && FETCH_METHODS.has(methodName) && objectName && FETCH_OBJECTS.has(objectName));

        if (isFetchCall) {
          const urlArg = node.arguments && node.arguments[0];
          if (urlArg) {
            const url = extractStringValue(urlArg);
            if (url && url.length > 3 && isLikelyUrl(url)) {
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

      // ─── Constant Tracking (Milestones 1, 7) ───
      // Track VariableDeclarator for constant propagation + value-based classification
      if (node.type === 'VariableDeclarator' && node.id && node.id.name && node.init) {
        const resolved = extractStringValue(node.init);
        if (resolved && typeof resolved === 'string') {
          constValues.set(node.id.name, resolved);

          // Value-based secret classification (Milestone 5) — works regardless of variable name
          const classification = classifyResolvedValue(
            resolved, node.id.name,
            node.loc ? node.loc.start.line : null, fileName
          );
          if (classification) {
            const alreadyFound = findings.some(f =>
              f.category === 'secrets' && f.value && f.value.includes(resolved.substring(0, 20))
            );
            if (!alreadyFound) findings.push(classification);
          }
        }
      }

      // --- Detect secret-like variable assignments (name-based + entropy) ---
      if (node.type === 'VariableDeclarator' && node.id && node.id.name) {
        if (SECRET_VAR_NAMES.test(node.id.name) && node.init) {
          const val = extractStringValue(node.init);
          if (val && val.length >= 8 && !isSecretFalsePositive(val)) {
            const entropy = calculateEntropy(val);
            const alreadyFound = findings.some(f =>
              f.category === 'secrets' && f.value && f.value.includes(val.substring(0, 20))
            );
            if (!alreadyFound) {
              findings.push({
                category: 'secrets',
                value: node.id.name + ' = "' + val.substring(0, 50) + (val.length > 50 ? '...' : '') + '"',
                type: 'AST: Secret Variable',
                severity: entropy > 4.0 ? 'high' : (entropy > 3.0 ? 'medium' : 'low'),
                confidence: entropy > 4.0 ? 'high' : (entropy > 3.5 ? 'medium' : 'low'),
                line: node.loc ? node.loc.start.line : null,
                sourceFile: fileName,
                entropy: Math.round(entropy * 100) / 100
              });
            }
          }
        }
      }

      // --- Assignment expressions: constant tracking + secret detection + entropy ---
      if (node.type === 'AssignmentExpression' && node.left) {
        const leftName = getCalleeName(node.left);
        if (leftName) {
          const resolved = extractStringValue(node.right);
          if (resolved && typeof resolved === 'string') {
            constValues.set(leftName, resolved);
          }
          if (SECRET_VAR_NAMES.test(leftName) && resolved && resolved.length >= 8 && !isSecretFalsePositive(resolved)) {
            const entropy = calculateEntropy(resolved);
            findings.push({
              category: 'secrets',
              value: leftName + ' = "' + resolved.substring(0, 50) + (resolved.length > 50 ? '...' : '') + '"',
              type: 'AST: Secret Assignment',
              severity: entropy > 4.0 ? 'high' : (entropy > 3.0 ? 'medium' : 'low'),
              confidence: entropy > 4.0 ? 'high' : (entropy > 3.5 ? 'medium' : 'low'),
              line: node.loc ? node.loc.start.line : null,
              sourceFile: fileName,
              entropy: Math.round(entropy * 100) / 100
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

    // ─── Helper: extract callee name ───
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

    // ─── Helper: URL validation ───
    function isLikelyUrl(val) {
      if (/^https?:\/\//i.test(val)) return true;
      if (/^\/[a-zA-Z0-9]/.test(val)) return true;
      if (/^(?:text|application|image|audio|video|font|multipart|message|model)\//.test(val)) return false;
      if (/^(?:content-type|accept|authorization|cache-control|access-control|x-forwarded|user-agent|keep-alive)$/i.test(val)) return false;
      if (!/\//.test(val) && !/^https?:/i.test(val)) return false;
      return true;
    }

    // ─── Helper: false positive filter ───
    function isSecretFalsePositive(val) {
      if (/^\/?[a-zA-Z0-9_-]+\/[a-zA-Z0-9_\-/]+$/.test(val)) return true;
      if (/^(?:YOUR|MY|THE|ENTER|INSERT|REPLACE|SET|EXAMPLE|SAMPLE|TEST|DEMO|DUMMY|FAKE|MOCK|DEFAULT|PLACEHOLDER|TODO|FIXME|XXX|CHANGE)[_\s-]/i.test(val)) return true;
      if (/\s/.test(val) && /\b(?:api|key|token|secret|password|here|your|the|for|this|enter|place|google|base|url|proxy)\b/i.test(val)) return true;
      if (/^Bearer\s*\*?$/.test(val) || /^\$\{|^\{\{/.test(val)) return true;
      if (/^process\.env\.|^import\.meta\.env\./.test(val)) return true;
      if (/^[a-z][a-z\s-]{4,}$/i.test(val) && !/[A-Z0-9_]{8,}/.test(val) && /\s|-/.test(val)) return true;
      if (/^(?:true|false|null|undefined|none|n\/a|0|1)$/i.test(val)) return true;
      return false;
    }

    // ─── Enhanced extractStringValue (Milestones 2, 3, 4) ───
    // Supports: Literals, Identifiers (propagation), BinaryExpression (+),
    // TemplateLiterals, and deterministic CallExpressions (e.g. String.fromCharCode)
    function extractStringValue(node, depth) {
      if (!node) return null;
      depth = depth || 0;
      if (depth > MAX_RECURSION_DEPTH) return null;
      evalCount++;
      if (evalCount > MAX_EVALUATIONS_PER_FILE) return null;

      // Direct string literal
      if (node.type === 'Literal' && typeof node.value === 'string') return node.value;

      // Identifier lookup — constant propagation (Milestone 2)
      if (node.type === 'Identifier') {
        return constValues.get(node.name) || null;
      }

      // Template literal with expression resolution
      if (node.type === 'TemplateLiteral' && node.quasis) {
        let result = '';
        for (let i = 0; i < node.quasis.length; i++) {
          result += node.quasis[i].value ? node.quasis[i].value.raw : '';
          if (i < (node.expressions || []).length) {
            const exprVal = extractStringValue(node.expressions[i], depth + 1);
            if (exprVal === null) {
              // Can't fully resolve — use placeholder
              result += '*';
            } else {
              result += exprVal;
            }
          }
        }
        return result.length <= MAX_STRING_SIZE ? result : null;
      }

      // Binary concatenation — recursive folding (Milestone 4)
      if (node.type === 'BinaryExpression' && node.operator === '+') {
        const left = extractStringValue(node.left, depth + 1);
        const right = extractStringValue(node.right, depth + 1);
        if (left !== null || right !== null) {
          const result = (left || '') + (right || '');
          return result.length <= MAX_STRING_SIZE ? result : null;
        }
        return null;
      }

      // Deterministic CallExpression evaluation (Milestone 3)
      if (node.type === 'CallExpression') {
        const callee = getCalleeName(node.callee);
        if (callee && SAFE_EVALUATORS[callee]) {
          return SAFE_EVALUATORS[callee](node);
        }
      }

      return null;
    }

    // ─── Value-Based Secret Classification (Milestone 5 + Entropy) ───
    function classifyResolvedValue(value, varName, line, srcFile) {
      if (!value || value.length < 8) return null;
      if (isSecretFalsePositive(value)) return null;

      // Check against known secret provider patterns
      for (const pattern of VALUE_SECRET_PATTERNS) {
        if (pattern.regex.test(value)) {
          const entropy = calculateEntropy(value);
          return {
            category: 'secrets',
            value: (varName ? varName + ' = ' : '') + '"' + value.substring(0, 50) + (value.length > 50 ? '...' : '') + '"',
            type: 'AST: Reconstructed Secret (' + pattern.label + ')',
            severity: pattern.severity,
            confidence: 'high',
            line: line,
            sourceFile: srcFile,
            entropy: Math.round(entropy * 100) / 100
          };
        }
      }

      // Entropy-based detection for unknown patterns
      const entropy = calculateEntropy(value);
      const hasHighEntropy = entropy > 3.5 && value.length >= 16;
      const hasMixedCharset = /[a-z]/.test(value) && /[A-Z]/.test(value) && /[0-9]/.test(value);

      if (hasHighEntropy && hasMixedCharset) {
        return {
          category: 'secrets',
          value: (varName ? varName + ' = ' : '') + '"' + value.substring(0, 50) + (value.length > 50 ? '...' : '') + '"',
          type: 'AST: High-Entropy Secret',
          severity: entropy > 4.5 ? 'high' : 'medium',
          confidence: entropy > 4.0 ? 'medium' : 'low',
          line: line,
          sourceFile: srcFile,
          entropy: Math.round(entropy * 100) / 100
        };
      }

      return null;
    }

    walk(ast);
    return findings;
  };

})();
