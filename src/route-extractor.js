// src/route-extractor.js — Extract client-side routes from JS frameworks
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  // Patterns that indicate noise rather than real routes
  const NOISE_PATTERNS = /^(?:\.{1,2}\/|data:|#|javascript:|mailto:|tel:)/;
  const SOURCE_EXT = /\.(?:ts|tsx|jsx|scss|sass|css|html|json|map|svg|less|pug|styl|png|jpe?g|gif|ico|webp|woff2?|ttf|eot|otf|mp[34]|wav|pdf)(?:[?#]|$)/i;
  const BUILD_PATHS = /^\/?\b(?:src|dist|build|lib|node_modules|webpack|__webpack__|assets|img|images|fonts|styles|css|vendor)\b/i;

  /**
   * Extract client-side routes from JS code.
   * Detects React Router, Vue Router, Angular, Express-like, and generic path patterns.
   * Returns findings array for the 'routes' category.
   */
  JSA.extractRoutes = function (code, fileName) {
    const findings = [];
    const seen = new Set();

    function isNoise(val) {
      if (val.length < 2 || seen.has(val)) return true;
      if (NOISE_PATTERNS.test(val)) return true;
      if (SOURCE_EXT.test(val)) return true;
      if (BUILD_PATHS.test(val)) return true;
      // Skip common non-route strings
      if (/^(true|false|null|undefined|\d+|function|return|const|var|let|if|else|none|auto|inherit|block|flex|inline|center|left|right|top|bottom)$/.test(val)) return true;
      // Skip CSS-like values
      if (/^\d+px|^\d+%|^#[0-9a-f]+$/i.test(val)) return true;
      return false;
    }

    function addRoute(value, type, line) {
      const clean = value.replace(/^['"]|['"]$/g, '').trim();
      if (isNoise(clean)) return;
      seen.add(clean);
      findings.push({
        category: 'routes',
        value: clean,
        type: type,
        severity: 'info',
        confidence: 'medium',
        line: line || null,
        sourceFile: fileName
      });
    }

    // ─── React Router: <Route path="..." />, path: '...' ───
    // Only match path values that start with / (actual routes, not CSS/SVG paths)
    const reactRouteRegex = /(?:<Route\s[^>]*path\s*=\s*{?\s*["']([^"']+)["']|path\s*:\s*["'](\/[a-zA-Z0-9\-_/:.*]+)["'])/gi;
    let m;
    while ((m = reactRouteRegex.exec(code)) !== null) {
      const route = m[1] || m[2];
      if (route) {
        const lineNum = code.substring(0, m.index).split('\n').length;
        addRoute(route, 'React/Vue Route', lineNum);
      }
    }

    // ─── Angular routes: { path: '...', component|loadChildren|redirectTo|canActivate } ───
    const angularRegex = /\{\s*path\s*:\s*["']([^"']+)["']\s*,\s*(?:component|loadChildren|redirectTo|canActivate)/gi;
    while ((m = angularRegex.exec(code)) !== null) {
      if (m[1]) {
        const lineNum = code.substring(0, m.index).split('\n').length;
        addRoute(m[1], 'Angular Route', lineNum);
      }
    }

    // ─── Express-like: app.get('/path', ...), router.post('/path', ...) ───
    const expressRegex = /(?:app|router|server)\s*\.\s*(?:get|post|put|delete|patch|all|use|route)\s*\(\s*["']([^"']+)["']/gi;
    while ((m = expressRegex.exec(code)) !== null) {
      if (m[1]) {
        const lineNum = code.substring(0, m.index).split('\n').length;
        addRoute(m[1], 'Express Route', lineNum);
      }
    }

    // ─── Next.js pages/api patterns: '/api/...' or '/pages/...' ───
    const nextRegex = /["'](\/(?:api|pages)\/[a-zA-Z0-9\-_/[\].*]+)["']/gi;
    while ((m = nextRegex.exec(code)) !== null) {
      if (m[1]) {
        const lineNum = code.substring(0, m.index).split('\n').length;
        addRoute(m[1], 'Next.js Route', lineNum);
      }
    }


    return findings;
  };

})();
