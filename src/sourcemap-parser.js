// src/sourcemap-parser.js — Parse Source Map v3 files to extract original sources
(function () {
  'use strict';
  window.JSA = window.JSA || {};

  /**
   * Parse a Source Map v3 JSON string.
   * Returns { files: [{ path: string, content: string }], sources: string[] }
   */
  JSA.parseSourceMap = function (jsonString) {
    try {
      const map = JSON.parse(jsonString);
      const result = { files: [], sources: map.sources || [] };

      // Extract original source files from sourcesContent
      if (map.sourcesContent && Array.isArray(map.sourcesContent)) {
        map.sourcesContent.forEach((content, idx) => {
          if (content && typeof content === 'string' && content.trim().length > 0) {
            const path = (map.sources && map.sources[idx]) || `source_${idx}.js`;
            // Skip node_modules and common vendor files
            if (!path.includes('node_modules/') && !path.includes('webpack/')) {
              result.files.push({ path: path, content: content });
            }
          }
        });
      }

      // Even if no sourcesContent, the sources array itself is useful (reveals file paths)
      return result;
    } catch (e) {
      console.error('Source map parse error:', e);
      return { files: [], sources: [] };
    }
  };

  /**
   * Check if content is an inline source map data URI and extract it
   */
  JSA.extractInlineSourceMap = function (jsContent) {
    const match = jsContent.match(/\/\/[#@]\s*sourceMappingURL=data:application\/json;(?:charset=[^;]+;)?base64,([A-Za-z0-9+/=]+)/);
    if (match && match[1]) {
      try {
        return atob(match[1]);
      } catch (e) { return null; }
    }
    return null;
  };

})();
