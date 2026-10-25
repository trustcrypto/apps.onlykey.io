// node test/derive-connects-first.test.js
//
// Every derive is an encrypted OKCONNECT, and the transit framing is chosen
// from the firmware version only a plain OKCONNECT returns. A derive on a page
// that had not connected yet framed v1 at a v2 device and got back bytes that
// were not the key. Each derive entry point must connect first, and must not
// reach the device at all when that connect fails.
'use strict';
const assert = require('assert');
const nodeCrypto = require('crypto');

const LIB = '../src/onlykey-fido2/onlykey/';

function fakeApi(connectWorks) {
  const calls = [];
  const api = {
    init: false,
    browser: 'Chrome',
    os: 'Linux',
    // A working connect leaves what onlykey-api.js's does: init set and a
    // transit key in sharedsec.
    connect: async () => {
      calls.push('connect');
      if (connectWorks) { api.init = true; api.sharedsec = new Uint8Array(32).fill(7); }
    },
    ctaphid_via_webauthn: async () => { calls.push('ctaphid'); return { error: 'stub device' }; },
  };
  return { api, calls };
}

function load(onlykeyApi) {
  const imports = {
    nacl: require(LIB + 'nacl.min.js'),
    forge: require(LIB + 'forge.min.js'),
    console: { log() {}, info() {}, warn() {}, error() {} },
    window: { crypto: nodeCrypto.webcrypto, btoa: (s) => Buffer.from(s, 'latin1').toString('base64'),
      atob: (s) => Buffer.from(s, 'base64').toString('latin1'),
    },
  };
  return require(LIB + 'onlykey-3rd-party.js')(imports, onlykeyApi)();
}

const call = (fn) => new Promise((resolve) => {
  const timer = setTimeout(() => resolve({ timedOut: true }), 2000);
  fn((err, value) => { clearTimeout(timer); resolve({ err, value }); });
});

const ENTRY_POINTS = {
  derive_public_key: (ok, cb) => ok.derive_public_key('a phrase', 1, false, cb),
  derive_shared_secret: (ok, cb) => ok.derive_shared_secret('a phrase', Buffer.alloc(32, 9).toString('base64url'), 3, false, cb),
  derive_xwing_recipient: (ok, cb) => ok.derive_xwing_recipient('age:personal', cb),
  derive_xwing_decap: (ok, cb) => ok.derive_xwing_decap('age:personal', new Uint8Array(1120), cb),
};

(async () => {
  for (const [name, run] of Object.entries(ENTRY_POINTS)) {
    // Not connected, and the connect fails: the device is never asked, and the
    // caller hears why instead of waiting on a callback that never comes.
    {
      const { api, calls } = fakeApi(false);
      const r = await call((cb) => run(load(api), cb));
      assert.ok(!r.timedOut, `${name}: no callback when the connect failed`);
      assert.match(String(r.err), /not connected/, `${name}: wrong error ${r.err}`);
      assert.deepStrictEqual(calls, ['connect'], `${name}: reached the device without a connection`);
    }
    // Not connected, and the connect works: connect comes first.
    {
      const { api, calls } = fakeApi(true);
      await call((cb) => run(load(api), cb));
      assert.strictEqual(calls[0], 'connect', `${name}: did not connect first (${calls})`);
      assert.ok(calls.includes('ctaphid'), `${name}: never made its request after connecting`);
    }
    // Already connected: no second connect.
    {
      const { api, calls } = fakeApi(true);
      api.init = true;
      api.sharedsec = new Uint8Array(32).fill(7);
      await call((cb) => run(load(api), cb));
      assert.ok(!calls.includes('connect'), `${name}: connected again although already connected`);
    }
  }
  console.log('derive-connects-first: ok');
})().catch((e) => { console.error(e); process.exit(1); });
