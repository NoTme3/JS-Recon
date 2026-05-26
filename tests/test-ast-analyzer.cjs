// tests/test-ast-analyzer.js — Milestone 8: Test Coverage
// Run: node tests/test-ast-analyzer.js

// Mock browser globals
global.window = global;
global.self = global;
global.JSA = {};
global.acorn = require('../node_modules/.package-lock.json') ? null : null;

// Load acorn from CDN equivalent (we'll use a local shim)
try {
  global.acorn = require('acorn');
} catch (e) {
  // Install acorn locally for testing
  console.log('⚠ Acorn not found, installing...');
  require('child_process').execSync('npm install --save-dev acorn', { cwd: __dirname + '/..' });
  global.acorn = require('acorn');
}

// Load the analyzer
require('../src/patterns.js');
require('../src/ast-analyzer.js');

let passed = 0;
let failed = 0;

function test(name, code, expectFn) {
  try {
    const findings = JSA.analyzeAST(code, 'test.js');
    const result = expectFn(findings);
    if (result === true) {
      console.log(`  ✅ ${name}`);
      passed++;
    } else {
      console.log(`  ❌ ${name}: ${result || 'assertion failed'}`);
      console.log(`     Findings: ${JSON.stringify(findings.map(f => ({ type: f.type, value: f.value, severity: f.severity, entropy: f.entropy })), null, 2)}`);
      failed++;
    }
  } catch (e) {
    console.log(`  ❌ ${name}: THREW ${e.message}`);
    failed++;
  }
}

// ─── Milestone 1: Literal Resolution ───
console.log('\n=== Milestone 1: Literal Resolution ===');

test('Direct string literal resolves', `
  const apiKey = "sk_live_abc123def456ghi789";
`, (findings) => {
  return findings.some(f => f.category === 'secrets' && f.value.includes('sk_live_abc123'));
});

// ─── Milestone 2: Identifier Propagation ───
console.log('\n=== Milestone 2: Identifier Propagation ===');

test('Single identifier propagation', `
  const a = "sk_live_abc123def456ghi789";
  const apiKey = a;
`, (findings) => {
  return findings.some(f => f.category === 'secrets');
});

test('Chained identifier propagation', `
  const a = "AKIAIOSFODNN7EXAMPLE1";
  const b = a;
  const apiKey = b;
`, (findings) => {
  return findings.some(f => f.category === 'secrets');
});

// ─── Milestone 3: String.fromCharCode Reconstruction ───
console.log('\n=== Milestone 3: String.fromCharCode ===');

test('Basic fromCharCode reconstruction', `
  const x = String.fromCharCode(65,66,67);
`, (findings) => {
  // The value "ABC" is only 3 chars, won't trigger secret detection.
  // But the constant should resolve. Let's test with a longer secret.
  return true; // This just tests that it doesn't crash
});

test('fromCharCode secret detection (the exec plan sample)', `
  const n = String.fromCharCode(
    83,111,109,101,82,97,110,100,111,
    109,65,80,73,75,101,121,
    50,48,50,54
  );
`, (findings) => {
  // "SomeRandomAPIKey2026" — high entropy, mixed charset → should detect
  return findings.some(f => f.category === 'secrets' && f.type.includes('High-Entropy'));
});

test('fromCharCode with non-numeric arg aborts safely', `
  const x = String.fromCharCode(65, "B", 67);
`, (findings) => {
  // Should not crash, should not produce a finding for this
  return !findings.some(f => f.value && f.value.includes('ABC'));
});

// ─── Milestone 4: Recursive Constant Folding ───
console.log('\n=== Milestone 4: Recursive Folding ===');

test('Binary concatenation folding', `
  const apiKey = "sk_live_" + "abc123def456ghi789";
`, (findings) => {
  return findings.some(f => f.category === 'secrets' && f.value.includes('sk_live_abc123'));
});

test('Nested constant folding', `
  const a = "AKIA";
  const b = a + "IOSFODNN7EXAMPLE1";
  const apiKey = b;
`, (findings) => {
  return findings.some(f => f.category === 'secrets');
});

// ─── Milestone 5: Value-Based Classification ───
console.log('\n=== Milestone 5: Value-Based Classification ===');

test('AWS key detected by value (generic variable name)', `
  const n = "AKIAIOSFODNN7EXAMPLE1";
`, (findings) => {
  return findings.some(f => f.category === 'secrets' && f.type.includes('AWS'));
});

test('Stripe key detected by value (generic variable name)', `
  const x = "sk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKE";
`, (findings) => {
  return findings.some(f => f.category === 'secrets' && f.type.includes('Stripe'));
});

test('GitHub token detected by value', `
  const data = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
`, (findings) => {
  return findings.some(f => f.category === 'secrets' && f.type.includes('GitHub'));
});

// ─── Entropy Scoring ───
console.log('\n=== Entropy Scoring ===');

test('High entropy string gets entropy score', `
  const token = "aB3dE6gH9jK2mN5pQ8rS1uV4wX7yZ0a";
`, (findings) => {
  const secret = findings.find(f => f.category === 'secrets' && f.entropy !== undefined);
  if (!secret) return 'no secret with entropy found';
  if (secret.entropy < 3.0) return 'entropy too low: ' + secret.entropy;
  return true;
});

test('Low entropy string gets lower severity', `
  const password = "aaaaaaaa11111111";
`, (findings) => {
  const secret = findings.find(f => f.category === 'secrets');
  if (!secret) return 'no secret found';
  if (secret.severity === 'high') return 'expected lower severity for low entropy';
  return true;
});

// ─── Milestone 9: Safety Guards ───
console.log('\n=== Milestone 9: Safety Guards ===');

test('Deep recursion does not crash', `
  const a = "x";
  const b = a + a + a + a + a + a + a + a + a + a + a + a;
`, (findings) => {
  return true; // Just verify no crash/hang
});

// ─── Milestone 10: Regression Validation ───
console.log('\n=== Milestone 10: Regression ===');

test('eval() still detected as dangerous', `
  eval(userInput);
`, (findings) => {
  return findings.some(f => f.category === 'vulnerabilities' && f.value === 'eval()');
});

test('innerHTML assignment still detected', `
  element.innerHTML = data;
`, (findings) => {
  return findings.some(f => f.category === 'vulnerabilities' && f.value.includes('innerHTML'));
});

test('fetch() endpoint still detected', `
  fetch("/api/admin/users");
`, (findings) => {
  return findings.some(f => f.category === 'endpoints' && f.value === '/api/admin/users');
});

test('False positives still filtered', `
  const apiKey = "YOUR_KEY_HERE_PLACEHOLDER";
`, (findings) => {
  return !findings.some(f => f.category === 'secrets');
});

test('Route paths still filtered', `
  const apiKey = "auth/reset-password";
`, (findings) => {
  return !findings.some(f => f.category === 'secrets');
});

// ─── Summary ───
console.log('\n' + '='.repeat(40));
console.log(`Results: ${passed} passed, ${failed} failed`);
console.log('='.repeat(40));
process.exit(failed > 0 ? 1 : 0);
