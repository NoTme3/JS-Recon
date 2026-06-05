// Entry point — loads all modules in the correct order
// This replaces the individual <script> tags in index.html

import { inject } from '@vercel/analytics';

inject();

import './style.css';
import './patterns.js';
import './workspace-store.js';
import './ast-analyzer.js';
import './dynamic-sandbox.js';
import './sourcemap-parser.js';
import './route-extractor.js';
import './report.js';
import './vuln-scanner.js';
import './taint-analyzer.js';
import './fingerprint.js';
import './exporters.js';
import './chunkcrawler.js';
import './ai-analyzer.js';
import './main.js';
