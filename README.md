(https://github.com/user-attachments/files/26132896/README.md)
<div align="center">
  <h1>🔍 JS Recon Analyzer </h1>
  <p><b>A modern, client-side JavaScript analyzer for extracting secrets, endpoints, vulnerabilities, and more directly in your browser.</b></p>
  <br/>
</div>

## 📖 Overview

**JS Recon Analyzer** is a powerful static and dynamic analysis tool designed specifically for JavaScript code. Whether you're a bug bounty hunter, penetration tester, or developer conducting a security audit, JS Recon helps you quickly decode and extract critical data from complex or minified JavaScript files.

It runs **100% locally** in your browser, ensuring that your target code and discovered secrets never leave your machine.

## ✨ Features

- **Local & Remote Fetching**: Drag and drop local JS files/folders or fetch scripts directly from remote URLs.
- **Deep Recon Pattern Matching**: Extracts full URLs, API endpoints, hidden routes, IPs, secrets (AWS, Stripe, API keys), emails, internal infrastructure paths, and more.
- **Advanced Code Analysis**: 
  - Uses AST analysis (`acorn`) to trace dangerous DOM sinks (`innerHTML`, `eval`) and source-map parsing to recover original source code.
  - Dynamically runs scripts in an isolated sandbox (`⚡ Dynamic`) to extract dynamically generated variables and endpoints.
- **Exploit Guidance**: Identifies potential client-side vulnerabilities alongside remediation advice, payload examples, and severity badges (Critical, High, Medium, Low).
- **Workspaces & Local Persistence**: Automatically saves your analysis sessions, parsed scripts, and security findings directly to your browser offline using `IndexedDB`. You can seamlessly rename scripts, delete old sessions, and organize multiple targets simultaneously.
- **Premium Glassmorphism UI**: Features a gorgeous, completely revamped "SaaS-style" layout featuring an interactive bento grid, floating frosted glass sidebars, dynamic scrolling headers, Tokyo-Night styled code editors, and custom in-app glass modals—completely eliminating ugly native browser prompts.
- **Built-in Editor**: Complete with a JS `Beautify` integration and smart code-highlighting precisely where your matches occur.
- **Export Ready**: Export your entire recon session effortlessly to JSON, CSV, or HTML reports.

## 🚀 Getting Started

Since JS Recon Analyzer runs entirely client-side, there are no heavy backends or databases required!

1. Clone the repository:
   ```bash
   git clone https://github.com/NoTme3/JS-Recon.git
   cd js-recon-analyzer
   ```
2. Simply open `index.html` in your favorite modern browser:
   - On Mac: `open index.html`
   - On Linux: `xdg-open index.html`
   - On Windows: Double-click the file!

## 🛠️ Tech Stack & Architecture

- **Vanilla HTML/CSS/JS**: Blazing fast, lightweight, and completely portable.
- **Acorn.js**: Used for building an Abstract Syntax Tree (AST) to securely parse nested objects and dynamic function structures.
- **JS-Beautify**: Formats aggressively obfuscated/minified code so it's readable in the built-in terminal.
- **Web Workers / Sandbox IFrames**: Safely executes dynamic script analysis without jeopardizing the security of the main application.

### Core Modules
* `main.js` - UI Orchestration, Modals, & Event Handling
* `workspace-store.js` - IndexedDB-backed Local Storage for cross-session Workspaces
* `patterns.js` - Hand-crafted regex definitions for hunting secrets & APIs 
* `ast-analyzer.js` - Abstract Syntax Tree parsing and DOM sink tracing
* `dynamic-sandbox.js` - Safely executes code in a sandboxed iframe environment
* `sourcemap-parser.js` - Looks for `*.map` files and maps minified paths back to original files
* `route-extractor.js` - Context-aware extraction of REST/Graphql routes
* `report.js` - Handling CSV, JSON, and HTML exports

## ⚠️ Disclaimer

**JS Recon Analyzer** is intended for educational purposes, authorized security auditing, and bug bounty programs. You should only analyze web applications and JavaScript files you own or have explicit, documented permission to test. Check your local laws and the rules of engagement before firing off the scanner against production URLs.

---
<div align="center">
Made with ❤️ for the Infosec Community
</div>
