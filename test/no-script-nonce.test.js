// node test/no-script-nonce.test.js
//
// The CSP in the published pages must not carry a script nonce. The pages are
// static, so a nonce is the same for every visitor and is readable by anyone:
// an injected <script nonce="..."> would run. The only script is the
// same-origin bundle, which 'self' already allows. And the two places that
// turned fetched text into markup must not: the recipient tokenizer renders
// its value as text, and the search page escapes a key's user ID.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const docs = path.join(__dirname, '..', 'docs');
const pages = [path.join(docs, 'index.html')].concat(
  fs.readdirSync(path.join(docs, 'app')).filter((f) => f.endsWith('.html')).map((f) => path.join(docs, 'app', f)));
assert.ok(pages.length >= 12, 'expected the published pages under docs/');

for (const p of pages) {
  const html = fs.readFileSync(p, 'utf8');
  const csp = /content="([^"]*)"/.exec(/<meta http-equiv="Content-Security-Policy"[^>]*>/.exec(html)[0])[1];
  const script = csp.split(';').map((s) => s.trim()).find((s) => s.startsWith('script-src'));
  assert.ok(script, `${p}: no script-src`);
  assert.ok(!/nonce-/.test(script), `${p}: script-src carries a nonce: ${script}`);
  assert.ok(!/'unsafe-inline'/.test(script), `${p}: script-src allows inline scripts`);
  assert.ok(!/<script[^>]* nonce=/.test(html), `${p}: a script tag carries a nonce`);
}

const bundles = fs.readdirSync(path.join(docs, 'app')).filter((f) => /^bundle\.[0-9a-f]+\.js$/.test(f));
assert.strictEqual(bundles.length, 1, `expected one bundle, found ${bundles}`);
const bundle = fs.readFileSync(path.join(docs, 'app', bundles[0]), 'utf8');
assert.ok(bundle.includes('.text(this.value).append(this.$icon)'), 'bundle: tokenizer still appends its value as HTML');
assert.ok(!bundle.includes('.append(this.value)'), 'bundle: tokenizer still appends its value as HTML');
assert.ok(bundle.includes('okEsc(r.pgp.userids[0].components.email)'), 'bundle: search does not escape the user ID');

const tokenizer = fs.readFileSync(path.join(__dirname, '..', 'src', 'lib', 'jquery.tokenizer.js'), 'utf8');
assert.ok(tokenizer.includes('.text(this.value)') && !tokenizer.includes('.append(this.value'), 'src: tokenizer');
const search = fs.readFileSync(path.join(__dirname, '..', 'src', 'plugins', 'search', 'search.js'), 'utf8');
assert.strictEqual((search.match(/esc\(theKey\.pgp\.userids\[0\]\.components\.(email|username)\)/g) || []).length, 4, 'src: search escapes');

const cfg = fs.readFileSync(path.join(__dirname, '..', 'webpack.config.js'), 'utf8');
assert.ok(/nonceEnabled: \{\s*'script-src': false/.test(cfg), 'webpack.config.js: script-src nonce still enabled');

console.log('no-script-nonce: ok');
