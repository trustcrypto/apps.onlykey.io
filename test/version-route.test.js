// node test/version-route.test.js
'use strict';
const assert = require('assert');
const r = require('../src/onlykey-fido2/onlykey/version-route.js');
const at = (hostname, pathname = '/app/decrypt', search = '', hash = '') => ({ hostname, pathname, search, hash });

// The numeric triple decides, not the keyword suffix.
assert.deepStrictEqual(r.parseFirmwareVersion('v3.0.5-prodc'), [3, 0, 5]);
assert.strictEqual(r.parseFirmwareVersion('v0.2-beta.8c'), null);
assert.strictEqual(r.isNewFirmware('v3.0.5-prod'), true);
assert.strictEqual(r.isNewFirmware('v3.0.5-test'), true);
assert.strictEqual(r.isNewFirmware('v3.0.4-prod'), false);
assert.strictEqual(r.isNewFirmware('v3.1.0'), true);
assert.strictEqual(r.isNewFirmware('v2.10.9'), false);
assert.strictEqual(r.isNewFirmware('v0.2-beta.8c'), false);
assert.strictEqual(r.isNewFirmware(''), false);

// The four cases in the deploy plan, plus staging.
assert.strictEqual(r.afterHandshake(at('apps.crp.to'), 'v3.0.4-prod').action, 'stay');
assert.strictEqual(r.afterHandshake(at('apps.crp.to'), 'v3.0.5-prod').url, 'https://apps.onlykey.io/app/decrypt');
assert.strictEqual(r.afterHandshake(at('apps.onlykey.io'), 'v3.0.5-prod').action, 'stay');
assert.strictEqual(r.afterHandshake(at('apps.onlykey.io'), 'v3.0.4-prod').url, 'https://apps.crp.to/app/decrypt');
for (const fw of ['v3.0.4-prod', 'v3.0.5-test']) {
  assert.strictEqual(r.afterHandshake(at('onlyagent.app'), fw).action, 'stay');
  assert.strictEqual(r.afterHandshake(at('localhost'), fw).action, 'stay');
}

// Paths: shared pages keep their path, query and fragment; others go home.
assert.strictEqual(r.afterHandshake(at('apps.crp.to', '/app/encrypt.html', '?type=e', '#m'), 'v3.0.5-prod').url,
  'https://apps.onlykey.io/app/encrypt?type=e#m');
assert.strictEqual(r.afterHandshake(at('apps.crp.to', '/app/password-generator'), 'v3.0.5-prod').url,
  'https://apps.onlykey.io/');

// No answer: a hint on apps.onlykey.io only, and never a redirect.
assert.strictEqual(r.noAnswerHint(at('apps.onlykey.io')).url, 'https://apps.crp.to/app/decrypt');
assert.strictEqual(r.noAnswerHint(at('apps.crp.to')), null);
assert.strictEqual(r.noAnswerHint(at('onlyagent.app')), null);

const e = require('../src/onlykey-fido2/onlykey/device-errors.js');
assert.match(e.explainDeviceError('Error stored key use over FIDO2 not enabled\u0000'), /webcryptpolicy 1/);
assert.strictEqual(e.explainDeviceError('Error no key set in this slot'), 'Error no key set in this slot');

console.log('version-route: all assertions passed');
