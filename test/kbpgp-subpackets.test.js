// A public key made by current GnuPG (2.4 and 2.5) carries signature subpacket
// 34 (preferred AEAD algorithms), which kbpgp 2.1.0 predates. Unknown
// non-critical subpackets must be ignored (RFC 4880 5.2.3.1), so the key
// imports and its self-signatures still verify. Run: node test/kbpgp-subpackets.test.js
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const kbpgp = require('../src/onlykey-fido2/onlykey/kbpgp-2.1.0.ok.ecc.js')(false, console);

const armored = fs.readFileSync(path.join(__dirname, 'fixtures', 'gnupg-subpacket34-rsa.asc'), 'utf8');

kbpgp.KeyManager.import_from_armored_pgp({ armored }, (err, km) => {
  assert.ifError(err);
  assert.strictEqual(km.get_pgp_fingerprint().toString('hex'), 'f3afbeed9f63731ab8ea42e31c2fb9af0e16edf7');
  assert.deepStrictEqual(km.get_userids().map((u) => u.utf8()), ['rsa test <rsa@test>']);
  console.log('ok - a GnuPG key with signature subpacket 34 imports');
  kbpgp.box({ msg: 'hello', encrypt_for: km }, (err2, armoredMsg) => {
    assert.ifError(err2);
    assert.ok(armoredMsg.startsWith('-----BEGIN PGP MESSAGE-----'));
    console.log('ok - a message encrypts to it');
  });
});
