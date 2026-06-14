# JS Recon Analyzer Implementation Plan

## Goal

Make JS Recon Analyzer safer, more consistent, and easier to evolve by consolidating duplicated analysis logic, hardening network-facing endpoints, improving result normalization, and expanding regression coverage.

## Current Baseline

- `node tests/test-ast-analyzer.cjs` passes.
- `npm run build` succeeds.
- The app currently has multiple analysis paths:
  - Client main-thread analyzer in `src/main.js`
  - Worker analyzer in `src/analyzer.worker.js`
  - Vercel scanner in `api/scan.js`
  - Local server scanner in `server/analyze-engine.cjs`
- Public endpoints currently accept broad user-controlled URLs:
  - `/api/fetch`
  - `/api/discover`
  - `/api/analyze`

## Phase 1: Shared Analysis Engine

### Objective

Create one canonical analyzer so client, worker, Vercel, and local server produce the same categories, fields, filters, and deduplication behavior.

### Tasks

1. Create a shared analyzer module.
   - Suggested path: `src/analysis-engine.js`
   - Export functions for:
     - `createAnalysisContext`
     - `analyzeFileContent`
     - `normalizeFinding`
     - `dedupeResults`
     - `createEmptyResults`
     - `createEmptySeen`

2. Move duplicated logic out of:
   - `src/main.js`
   - `src/analyzer.worker.js`
   - `api/scan.js`
   - `server/analyze-engine.cjs`

3. Preserve all existing result categories from `JSA.CATEGORIES`.

4. Ensure every finding has a consistent shape:
   - `value`
   - `type`
   - `contextMatch`
   - `sourceFile`
   - `severity`
   - `confidence`
   - `ruleId`
   - `line`
   - `isBase64`
   - Optional: `exploitInfo`, `references`, `cveId`, `detectedVersion`, `fixedVersion`

5. Make backend scanning include all available modules:
   - Regex patterns
   - AST analysis
   - Route extraction
   - Vulnerable dependency scanning
   - Taint analysis

### Acceptance Criteria

- Pasted-code analysis, worker analysis, `/api/scan`, and local server scan produce equivalent results for the same fixture.
- UI rendering does not receive missing `contextMatch` or `isBase64` fields from server results.
- Existing tests still pass.

## Phase 2: Network Endpoint Hardening

### Objective

Prevent the fetch, discovery, and AI proxy routes from becoming open proxies or SSRF primitives when deployed publicly.

### Tasks

1. Add a shared URL validation helper.
   - Suggested path: `server/url-policy.cjs` and ESM equivalent for Vercel, or one portable module if build setup allows.

2. For `/api/fetch` and `/api/discover`, enforce:
   - Only `http:` and `https:`
   - Block private IPv4 ranges
   - Block loopback, link-local, multicast, and unspecified addresses
   - Block localhost hostnames
   - Resolve DNS and validate resolved IPs before fetch where runtime supports it
   - Re-check final URL after redirects
   - Limit redirect count
   - Limit response content length before and after body read
   - Limit concurrent script fetches in discovery

3. For `/api/analyze`, restrict `apiUrl`.
   - Allow only known AI provider hosts:
     - `integrate.api.nvidia.com`
     - `api.openai.com`
     - `api.anthropic.com`
     - Any explicitly configured trusted host
   - Reject arbitrary upstream URLs from the browser by default.

4. Add rate limiting or soft throttling.
   - Local server: simple in-memory IP bucket.
   - Vercel: document platform-level rate limiting or add a lightweight request guard.

5. Update CORS policy.
   - Keep permissive CORS for local development if needed.
   - For production, allow configured origins only.

### Acceptance Criteria

- Requests to `localhost`, `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, and `0.0.0.0` are rejected.
- Redirects to blocked addresses are rejected.
- AI proxy rejects unknown upstream hosts.
- Error responses are clear and do not leak sensitive request data.

## Phase 3: Safe Local Static Server

### Objective

Prevent path traversal and reduce accidental LAN exposure in `server.cjs`.

### Tasks

1. Replace direct path construction with a fixed static root.
   - Use `path.resolve`.
   - Reject resolved paths outside the project root or chosen static root.

2. Bind to `127.0.0.1` by default.
   - Allow `HOST=0.0.0.0` only when explicitly configured.

3. Add environment-configurable values:
   - `PORT`
   - `HOST`
   - `MAX_FETCH_SIZE`
   - `MAX_SCAN_SIZE`

### Acceptance Criteria

- Requests containing `../` cannot read files outside the intended root.
- Local server starts on `127.0.0.1:8000` by default.
- Existing local API routes still work.

## Phase 4: Dependency and Worker Bundling

### Objective

Remove CDN runtime dependencies where practical so the app is reproducible, offline-friendly, and CSP-compatible.

### Tasks

1. Move browser dependencies into npm:
   - `acorn`
   - `js-beautify`
   - `highlight.js`

2. Convert `src/analyzer.worker.js` to a Vite module worker.

3. Replace `importScripts` with module imports.

4. Update `index.html` to stop loading CDN scripts.

5. Add CSP guidance to the README.

### Acceptance Criteria

- App works without external CDN access.
- Worker analysis still works for large files.
- Build output includes needed dependencies.

## Phase 5: Test Coverage and Tooling

### Objective

Make regressions easier to catch and compare all analyzer paths.

### Tasks

1. Add package scripts:
   - `npm test`
   - `npm run test:ast`
   - Optional: `npm run test:fixtures`

2. Remove side effects from tests.
   - Tests should not run `npm install`.

3. Add fixture-based tests for:
   - Secrets
   - Endpoints
   - Route extraction
   - Vulnerable libraries
   - Taint flows
   - False positives
   - Server/client parity

4. Add endpoint policy tests for blocked URLs.

5. Add build verification to the documented workflow.

### Acceptance Criteria

- `npm test` runs without network access.
- Tests cover client/server analyzer parity.
- Tests cover URL blocking policy.

## Phase 6: Vulnerability Database Refresh

### Objective

Reduce drift in `src/vuln-scanner.js` and make vulnerability metadata maintainable.

### Tasks

1. Move vulnerability data out of code into JSON.
   - Suggested path: `src/data/vulnerabilities.json`

2. Add metadata:
   - Data source
   - Last updated date
   - Schema version

3. Add a script to validate the vulnerability DB schema.

4. Consider importing from:
   - Retire.js data
   - OSV snapshots
   - NVD-derived curated data

### Acceptance Criteria

- Vulnerability scanner loads data from a structured file.
- Invalid DB entries fail tests.
- UI can show the DB version/date.

## Phase 7: UX and Workflow Refinements

### Objective

Make analysis output easier to triage during real bug bounty or pentest workflows.

### Tasks

1. Add result grouping modes:
   - By severity
   - By source file
   - By category
   - By confidence

2. Add finding status fields in workspaces:
   - New
   - Reviewed
   - False positive
   - Interesting
   - Reported

3. Add notes per finding.

4. Add export options that respect filters/status.

5. Add a "copy safe report" mode that redacts secrets by default.

### Acceptance Criteria

- Users can triage findings without leaving the app.
- Exported reports can omit or redact sensitive values.
- Workspace persistence stores statuses and notes.

## Recommended Order

1. Shared analysis engine
2. Result normalization
3. URL/proxy hardening
4. Local server path safety
5. Test scripts and parity fixtures
6. CDN removal and worker bundling
7. Vulnerability DB refresh
8. UX triage improvements

## Verification Checklist

Run these after each implementation phase:

```bash
npm test
npm run build
node tests/test-ast-analyzer.cjs
```

Manual checks:

- Paste code and analyze in the browser.
- Analyze a file larger than 50KB to exercise the worker path.
- Use `/api/scan` and confirm UI rendering is complete.
- Try fetching a direct `.js` URL.
- Try discovering scripts from an HTML page.
- Confirm blocked local/private URLs are rejected.
- Export JSON, CSV, HTML, Postman, and OpenAPI.

## Notes

- Keep changes small and phase-based.
- Preserve existing UI behavior while refactoring the analyzer.
- Prefer shared helpers over copying filters between client, worker, and server.
- Treat network-facing routes as production-risky even if the primary use case is local recon.
