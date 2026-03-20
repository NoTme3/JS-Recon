// Regex Patterns for analysis
const PATTERNS = {
  urls: {
    regex: /(?:https?:\/\/|wss?:\/\/|ftp:\/\/)[^\s"'<>`]+|\/(?:api|v[0-9]+|graphql)(?:\/[^\s"'<>`]*)?/gi,
    label: 'Endpoint/URL'
  },
  ips: {
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    label: 'IPv4 Address'
  },
  emails: {
    regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    label: 'Email Address'
  },
  secrets: {
    regex: /(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35}|(?:bearer|token|apikey|secret)[-_]?\s*[:=]\s*["'][a-zA-Z0-9\-_]{16,}["'])/gi,
    label: 'Potential Secret'
  }
};

/**
 * Analyzes file content and returns categorized matches with context.
 * Useful for minified js files where line numbers don't matter much.
 */
export async function analyzeFileContent(content) {
  const results = {
    urls: [],
    ips: [],
    emails: [],
    secrets: []
  };
  
  const contextLength = 60; // characters before and after

  // Use a map to prevent exact duplicate matches + context overlap
  const seen = { urls: new Set(), ips: new Set(), emails: new Set(), secrets: new Set() };

  for (const [category, patternData] of Object.entries(PATTERNS)) {
    const regex = new RegExp(patternData.regex);
    let match;
    
    while ((match = regex.exec(content)) !== null) {
      const matchText = match[0];
      
      if (seen[category].has(matchText)) {
        continue; // skip exact duplicates to avoid clutter
      }
      seen[category].add(matchText);

      const startIndex = Math.max(0, match.index - contextLength);
      const endIndex = Math.min(content.length, match.index + matchText.length + contextLength);
      
      let contextBefore = content.substring(startIndex, match.index);
      let contextAfter = content.substring(match.index + matchText.length, endIndex);
      
      // Clean up whitespace/newlines in context for cleaner UI
      contextBefore = (startIndex > 0 ? '...' : '') + contextBefore.replace(/\n\s*/g, ' ');
      contextAfter = contextAfter.replace(/\n\s*/g, ' ') + (endIndex < content.length ? '...' : '');

      results[category].push({
        value: matchText,
        type: patternData.label,
        contextBefore: escapeHtml(contextBefore),
        contextMatch: escapeHtml(matchText),
        contextAfter: escapeHtml(contextAfter)
      });
    }
  }

  return results;
}

function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}
