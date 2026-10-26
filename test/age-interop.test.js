// npm run test:age-interop   (built through webpack like test:pqc / test:age-kat)
//
// The web app's age files against other age implementations. The fixtures in
// test/fixtures/age/ were written by age 1.3.2, rage 0.12.1 and typage 0.3.1 to
// the post-quantum test key published in C2SP age.md, so this can decrypt them
// with that key, here, the way the device would. The other direction (what this
// app writes, read by those tools) is checked by the same tools in the release
// interop run; this file pins what can be pinned without them:
//
//   - every fixture opens, including a file with two mlkem768x25519 stanzas
//     where ours is the second (age_file.js used to try only the first);
//   - a payload that is an exact multiple of 64 KiB ends in a full final chunk,
//     not an extra empty one (age and typage refuse an empty final chunk);
//   - output is ASCII armor that a strict reader accepts, and the armor reader
//     refuses what age.md says to refuse;
//   - files this app wrote before these changes (bare base64, trailing empty
//     chunk) still open.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');
const { shake256 } = require('@noble/hashes/sha3.js');
const { x25519 } = require('@noble/curves/ed25519.js');
const { chacha20poly1305 } = require('@noble/ciphers/chacha.js');
const { extract: hkdfExtract, expand: hkdfExpand } = require('@noble/hashes/hkdf.js');
const { sha256 } = require('@noble/hashes/sha2.js');
const ageFile = require('../src/onlykey-fido2/onlykey/age_file.js');
const agePqc = require('../src/onlykey-fido2/onlykey/age_pqc.js');

// process.cwd(), not __dirname - webpack's node target mocks __dirname (see pqc.test.js).
const FIX = path.join(process.cwd(), 'test', 'fixtures', 'age');
// C2SP age.md's mlkem768x25519 example identity (public test key).
const IDENTITY = 'AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR';

function identitySeed(s) {
  const lower = s.toLowerCase();
  const pos = lower.lastIndexOf('1');
  const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const data = Array.from(lower.slice(pos + 1, -6), (c) => CH.indexOf(c));
  let acc = 0, bits = 0; const out = [];
  for (const v of data) { acc = (acc << 5) | v; bits += 5; while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); } }
  return new Uint8Array(out);
}
const seed = identitySeed(IDENTITY);
const expanded = shake256(seed, { dkLen: 96 });
const { publicKey: pkM, secretKey: dkM } = ml_kem768.keygen(expanded.subarray(0, 64));
const skX = expanded.subarray(64, 96);
const pkX = x25519.getPublicKey(skX);
const recipientPk = new Uint8Array([...pkM, ...pkX]);

let decaps = 0;
function decapsulate(enc) {
  decaps++;
  const ctM = enc.subarray(0, 1088), ctX = enc.subarray(1088, 1120);
  return agePqc.xwingCombiner(ml_kem768.decapsulate(ctM, dkM), x25519.getSharedSecret(skX, ctX), ctX, pkX);
}

(async () => {
  // The recipient age.md publishes for this identity is the native spelling of our key.
  const native = agePqc.encodeNativeRecipient(recipientPk);
  assert.ok(native.startsWith('age1pq1x34nzsvr0rxjsgdn8zgyhfe8j7ceq5r9rdelkjuh3y235jzxshfg87pzf5zrq'), 'native recipient spelling');
  assert.deepStrictEqual(Buffer.from(agePqc.decodeRecipient(native)), Buffer.from(recipientPk));
  assert.deepStrictEqual(Buffer.from(agePqc.decodeRecipient(agePqc.encodeRecipient(recipientPk))), Buffer.from(recipientPk));

  // Files written by other implementations.
  const expected = {
    'age13-two-recipients.age': 'Written by age 1.3.2 to two post-quantum recipients; the OnlyKey test key is the second.\n',
    'rage.age': 'Written by rage 0.12.1 (via age-plugin-pq).\n',
    'typage.age': 'Written by typage 0.3.1.\n',
  };
  for (const [name, text] of Object.entries(expected)) {
    const armored = fs.readFileSync(path.join(FIX, name), 'utf8');
    assert.ok(ageFile.isArmored(armored), `${name}: armored`);
    decaps = 0;
    const out = await ageFile.decryptAgeFile(ageFile.armorDecode(armored), decapsulate);
    assert.strictEqual(Buffer.from(out).toString('utf8'), text, `${name}: plaintext`);
    if (name.startsWith('age13-two')) assert.strictEqual(decaps, 2, 'tried both stanzas, in order');
  }

  // A payload that is an exact multiple of 64 KiB: one full chunk, flagged final.
  for (const n of [0, 1, 65535, 65536, 65537, 131072]) {
    const plaintext = new Uint8Array(n).map((_, i) => i & 0xff);
    const enc = agePqc.xwingEncapsHost(recipientPk);
    const file = ageFile.encryptAgeFile(plaintext, enc);
    const headerEnd = Buffer.from(file).indexOf('\n---') + 1;
    const bodyStart = Buffer.from(file).indexOf('\n', headerEnd) + 1 + 16;
    const chunks = Math.max(1, Math.ceil(n / 65536));
    assert.strictEqual(file.length - bodyStart, n + 16 * chunks, `${n} bytes: ${chunks} chunk(s), no empty final chunk`);
    const back = await ageFile.decryptAgeFile(ageFile.armorDecode(ageFile.armorEncode(file)), decapsulate);
    assert.deepStrictEqual(Buffer.from(back), Buffer.from(plaintext), `${n} bytes round trip`);
  }

  // A file written the old way (bare base64; 64 KiB payload with a trailing empty
  // final chunk) still opens: rebuild its STREAM by hand under the same keys.
  {
    const plaintext = new Uint8Array(65536).fill(7);
    const file = ageFile.encryptAgeFile(plaintext, agePqc.xwingEncapsHost(recipientPk));
    const headerEnd = Buffer.from(file).indexOf('\n---') + 1;
    const nonceStart = Buffer.from(file).indexOf('\n', headerEnd) + 1;
    // recover the file key the way decryptAgeFile does, to re-encrypt the STREAM
    let fileKey;
    const stanzaLine = Buffer.from(file).toString('latin1').split('\n')[1];
    const enc = new Uint8Array(Buffer.from(stanzaLine.split(' ')[2], 'base64'));
    const body = new Uint8Array(Buffer.from(Buffer.from(file).toString('latin1').split('\n')[2], 'base64'));
    fileKey = ageFile.openFileKey(decapsulate(enc), enc, body);
    const streamNonce = file.subarray(nonceStart, nonceStart + 16);
    const payloadKey = hkdfExpand(sha256, hkdfExtract(sha256, fileKey, streamNonce), new TextEncoder().encode('payload'), 32);
    const nonce = (c, last) => { const x = new Uint8Array(12); x[10] = c; x[11] = last ? 1 : 0; return x; };
    const legacyStream = new Uint8Array([
      ...chacha20poly1305(payloadKey, nonce(0, false)).encrypt(plaintext),
      ...chacha20poly1305(payloadKey, nonce(1, true)).encrypt(new Uint8Array(0)),
    ]);
    const legacy = new Uint8Array([...file.subarray(0, nonceStart + 16), ...legacyStream]);
    const back = await ageFile.decryptAgeFile(legacy, decapsulate);
    assert.deepStrictEqual(Buffer.from(back), Buffer.from(plaintext), 'legacy trailing empty chunk still opens');
  }

  // Armor: canonical output, strict input.
  const sample = ageFile.encryptAgeFile(new TextEncoder().encode('armor'), agePqc.xwingEncapsHost(recipientPk));
  const armored = ageFile.armorEncode(sample);
  const lines = armored.trimEnd().split('\n');
  assert.strictEqual(lines[0], '-----BEGIN AGE ENCRYPTED FILE-----');
  assert.strictEqual(lines[lines.length - 1], '-----END AGE ENCRYPTED FILE-----');
  assert.ok(lines.slice(1, -2).every((l) => l.length === 64) && lines[lines.length - 2].length <= 64, '64-column lines');
  assert.deepStrictEqual(Buffer.from(ageFile.armorDecode('\n  ' + armored.replace(/\n/g, '\r\n') + '  \n')), Buffer.from(sample), 'CRLF and surrounding whitespace accepted');
  assert.throws(() => ageFile.armorDecode(armored + 'trailing'), /armored/);
  assert.throws(() => ageFile.armorDecode(armored.replace(/\n([A-Za-z0-9+/]{64})\n/, '\n$1$1\n')), /64 base64/);
  assert.throws(() => ageFile.armorDecode('-----BEGIN AGE ENCRYPTED FILE-----\nYQ\n-----END AGE ENCRYPTED FILE-----\n'), /canonical/);

  // Malformed stanzas are refused before anything is decapsulated.
  decaps = 0;
  const bad = Buffer.from(sample).toString('latin1').replace(/^(-> mlkem768x25519 \S+)/m, '$1 extra');
  await assert.rejects(ageFile.decryptAgeFile(new Uint8Array(Buffer.from(bad, 'latin1')), decapsulate), /1 argument/);
  assert.strictEqual(decaps, 0);

  console.log('age-interop: ok');
})().catch((e) => { console.error(e); process.exit(1); });
