# JS Recon Analyzer v3

A premium JavaScript security analysis tool for penetration testers and bug bounty hunters. Analyzes JS files for secrets, endpoints, vulnerabilities, and attack surface.

## Features

- **Secret Detection** — API keys, tokens, passwords, JWTs, private keys with false positive filtering
- **Endpoint Discovery** — URLs, API routes, GraphQL operations via regex + AST + LinkFinder
- **Vulnerability Scanning** — DOM XSS sinks, prototype pollution, CORS misconfig, dangerous APIs
- **Taint Analysis** — Source-to-sink data flow tracking
- **AI Enrichment** — NVIDIA/OpenAI-powered analysis of findings
- **Dynamic Sandbox** — Runtime behavior analysis in an isolated iframe
- **Source Map Parsing** — Extract original source files from `.map` bundles
- **Workspace Persistence** — IndexedDB-backed workspaces to organize analyses
- **Web Worker Analysis** — Offloads heavy analysis to a background thread for large files (>50KB)
- **Export** — JSON, CSV, HTML, Postman, OpenAPI formats

## Architecture

```
index.html          — UI (vanilla HTML/CSS/JS, no framework)
src/
  entry.js          — Vite module entry point
  main.js           — Core app logic, UI wiring, analysis engine
  patterns.js       — Detection rules, exploit DB, categories
  ast-analyzer.js   — Acorn-based AST analysis
  analyzer.worker.js — Web Worker for off-thread analysis
  ai-analyzer.js    — AI enrichment (NVIDIA/OpenAI proxy)
  vuln-scanner.js   — Known vulnerable dependency detection
  taint-analyzer.js — Source-to-sink taint tracking
  route-extractor.js — Framework route extraction
  dynamic-sandbox.js — Runtime behavior sandbox
  workspace-store.js — IndexedDB persistence
  exporters.js      — Export formatters
  fingerprint.js    — JS framework fingerprinting
  chunkcrawler.js   — Webpack chunk discovery
  subdomain-harvester.js — Subdomain extraction
  report.js         — HTML report generation
  style.css         — All styles
server.cjs          — Local dev API proxy (for AI enrichment)
vite.config.js      — Vite build config
```

## Development

```bash
# Install dependencies
npm install

# Start API proxy (for AI enrichment)
node server.cjs

# Start Vite dev server (separate terminal)
npm run dev

# Production build
npm run build
```
