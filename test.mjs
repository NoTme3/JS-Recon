import fs from 'fs';
import { analyzeFileContent } from './src/analyzer.js';

const content = fs.readFileSync('/tmp/dummy-minified.js', 'utf-8');

async function test() {
  const results = await analyzeFileContent(content);
  console.log("URLs:", results.urls.length);
  console.log("IPs:", results.ips.length);
  console.log("Emails:", results.emails.length);
  console.log("Secrets:", results.secrets.length);
  console.dir(results, { depth: null });
}

test();
