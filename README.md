# JS Recon Analyzer

A premium, client-side JavaScript reconnaissance tool for security professionals. Analyze JS files to extract secrets, API endpoints, vulnerabilities, and more — with optional AI-powered enrichment via NVIDIA NIM.

> Built for penetration testers, bug bounty hunters, and security researchers.

---

## Features

### Core Analysis Engine
- **Secret Detection** — API keys, tokens, passwords, database URLs, Bearer tokens (including `.concat()` obfuscation)
- **Endpoint Extraction** — REST API routes, GraphQL endpoints, WebSocket URLs
- **Vulnerability Scanning** — DOM XSS sinks, prototype pollution, postMessage handlers, open redirects
- **AST Analysis** — Deep code parsing via Acorn for variable-level secret detection and dangerous assignments
- **Taint Flow Analysis** — Traces data from sources (user input) to sinks (eval, innerHTML)
- **Library Fingerprinting** — Detects 25+ JS libraries (jQuery, React, Angular, Lodash, etc.) with known CVE matching
- **Dynamic Sandbox** — Executes JS in an isolated iframe to capture runtime behavior

### AI Enrichment (NVIDIA NIM)
- One-click AI analysis of all findings using **Meta Llama 3.3 70B**
- Provides severity reasoning, risk context, and suggested test payloads
- API keys stored locally in browser — never sent to third-party servers
- Proxied through a serverless function to bypass CORS restrictions

### Export & Reporting
- **JSON / CSV / HTML** report generation
- **Postman Collection** export for endpoint testing
- **OpenAPI Spec** generation from discovered routes
- Full HTML report with findings, severity breakdown, and exploit details

### Additional Capabilities
- Remote JS file fetching (paste a URL, auto-analyze)
- Subdomain harvesting from JS bundles
- Source map detection and parsing
- Webpack chunk crawling
- Code beautification (js-beautify integration)
- Workspace management for organizing analyses
- Syntax-highlighted code editor with line numbers

---

## Quick Start

### Option 1: Local Development

Requires **Node.js** (v18+).

```bash
git clone git@github.com:NoTme3/JS-Recon.git
cd JS-Recon
node server.js
```

Open **http://localhost:8000** in your browser.

### Option 2: Vercel (Production)

The repo is configured for Vercel deployment out of the box:

1. Connect the GitHub repo to Vercel
2. Deploy — no build step or environment variables needed
3. The AI proxy runs as a serverless function at `/api/analyze`

---

## AI Enrichment Setup

1. Go to **Settings** in the top-right nav
2. Scroll to **AI Enrichment**
3. Toggle **Enable AI Analysis** on
4. Select **NVIDIA NIM** as the provider
5. Paste your API key from [build.nvidia.com](https://build.nvidia.com/meta/llama-3_3-70b-instruct)
6. Run an analysis, then click **AI Enrich** in the results toolbar

The AI analyzes your findings and adds:
- **Severity assessment** with reasoning
- **Risk context** explaining the real-world impact
- **Suggested test payloads** for verification

---

## Architecture

```
js-analyzer/
├── index.html              # Main UI
├── server.js               # Local dev server + AI proxy (Node.js)
├── vercel.json             # Vercel deployment config
├── api/
│   └── analyze.js          # Vercel serverless function (AI proxy)
└── src/
    ├── main.js             # Core app logic, UI wiring, rendering
    ├── patterns.js         # Regex-based detection rules (50+ patterns)
    ├── ast-analyzer.js     # Acorn-based AST analysis
    ├── ai-analyzer.js      # AI enrichment engine (NVIDIA NIM client)
    ├── vuln-scanner.js     # Library fingerprinting + CVE database
    ├── taint-analyzer.js   # Source-to-sink taint flow tracking
    ├── route-extractor.js  # API route extraction from code
    ├── dynamic-sandbox.js  # Runtime analysis in isolated iframe
    ├── fingerprint.js      # JS library version detection
    ├── subdomain-harvester.js  # Subdomain extraction from bundles
    ├── chunkcrawler.js     # Webpack chunk URL discovery
    ├── sourcemap-parser.js # Source map detection
    ├── exporters.js        # JSON, CSV, Postman, OpenAPI export
    ├── report.js           # HTML report generation
    ├── workspace-store.js  # IndexedDB workspace persistence
    ├── analyzer.worker.js  # Web Worker for background analysis
    └── style.css           # Full UI stylesheet
```

### How the AI Proxy Works

```
Browser (ai-analyzer.js)
    │
    ▼  POST /api/analyze  { apiKey, prompt, model }
    │
┌───┴───────────────────────┐
│  server.js (local)        │  ← Development
│  OR                       │
│  api/analyze.js (Vercel)  │  ← Production
└───┬───────────────────────┘
    │
    ▼  POST (Bearer token)
    │
┌───┴───────────────────────┐
│  NVIDIA NIM API           │
│  integrate.api.nvidia.com │
└───────────────────────────┘
```

The proxy is needed because browsers block direct cross-origin requests to NVIDIA's API. The API key is passed per-request from the browser and is never stored server-side.

---

## Detection Categories

| Category | Examples |
|---|---|
| **Secrets** | AWS keys, Stripe keys, Bearer tokens, database URLs, generic tokens, long hex strings |
| **Endpoints** | REST APIs, GraphQL, WebSocket URLs, absolute/relative paths |
| **Routes** | Express/Fastify/Koa route definitions extracted via AST |
| **Vulnerabilities** | innerHTML, eval, document.write, postMessage, open redirect, prototype pollution |
| **Libraries** | jQuery, Lodash, React, Angular, Vue, Moment.js, Handlebars + 18 more with CVE data |
| **Taint Flows** | location.hash → eval, user input → innerHTML, cookie → document.write |
| **Integrations** | S3 buckets, Firebase URLs, Google Maps keys, Slack webhooks |

---

## Tech Stack

- **Frontend**: Vanilla HTML/CSS/JS — zero build step, no frameworks
- **Code Parsing**: [Acorn](https://github.com/acornjs/acorn) (AST), [js-beautify](https://github.com/beautifier/js-beautify), [Highlight.js](https://highlightjs.org/)
- **AI**: NVIDIA NIM (Meta Llama 3.3 70B Instruct) via OpenAI-compatible API
- **Backend**: Node.js (local) / Vercel Serverless Functions (production)
- **Storage**: localStorage (settings), IndexedDB (workspaces)

---

## License

MIT
