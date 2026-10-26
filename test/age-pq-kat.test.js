// npm run test:age-kat   (built through webpack like test:pqc, so the vendored
// @noble packages' bare imports resolve through resolve.alias)
//
// Known-answer test against the C2SP age specification. The identity,
// encapsulated key and stanza body are the mlkem768x25519 example from age.md
// (github.com/C2SP/C2SP). Recovering its file key proves the web app writes and
// reads the construction the age tool does: the X-Wing shared secret straight
// into the HPKE key schedule, info "age-encryption.org/mlkem768x25519".
'use strict';
const assert = require('assert');
const { ml_kem768 } = require('@noble/post-quantum/ml-kem.js');
const { shake256 } = require('@noble/hashes/sha3.js');
const { x25519 } = require('@noble/curves/ed25519.js');
const ageFile = require('../src/onlykey-fido2/onlykey/age_file.js');
const agePqc = require('../src/onlykey-fido2/onlykey/age_pqc.js');

const IDENTITY = 'AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR';
const ENC_B64 = [
  'U7E10Aon27j1oDrH7fP3B++SPROSnDVvQpBemzOM+ZcsojxJifUbeeYWejMYKNB+H3rlXNvgtDKf',
  'SCkt78oqncr3faY1JtMj0GQPBZ2g6t8o1cMzZgyLMepeVuTQKxLqnM6L48n8dJL2y0N3i7WSOV6c',
  'sB79r9tcIs88Al9iCwVLpt74OzDXAIwD1QlCAvj75ZEnwtgP6Xr6s+wHg9hLD0OSSQOaTdCqzR5s',
  'hQWyrjVs7GCqd/5WbNGYNaolPQJBu9wTNhHjP9XGCTv8iKXkYwXDYujInkF5hOjpCHE8Vu+9UeMI',
  '+l0GJAEervT51bwaf288GiqgapP5g4HF8V4P0+03B/SwXhvxxZpKjTU2OcFS8I9chtEZ7Ucw5bvP',
  'kC1lyjNnqQXZyc4JnAqbFQTlPGnwbEsm0UGE+v0FOxTBznIivHoPHV++5PuYpombiV/lfYy8BFx0',
  'Hk1igNI3iLNjlIg4MLXNWjN3VROlXIiSsWNXjr/Frh/OE87PXoaKhsDPWfv6akd9PxSDqJMQ4j8k',
  '11kCSOnnU8Rw4TSVnTpt7gfYzBULrMr7qDgyH/TYvp0o7mAq4IaraFJmTqm+LjfAJT4PCQOpnMNR',
  'HLyXZn6mtMUujNv7+zR/I9Vqi+bJdQBwNWdJcUQVarqx2zxV2rM7l+j0gsmxjxp5yAPyALzla7Xz',
  'VvbboLMnHeM+CzN4GoB2PC4neVDSw7Dfs8vbm7f9CeDGvhjWrzcSCOsUCalvH1WkbpE0b9cE/TSJ',
  'qwXFXEc8npTSQWH58RXDALNF3qCbW5LaboD4wCloClEakgljT0s0mTdqIwzj4xtdlX0S2dCtaV5M',
  'HQJiQHGwPvBSCiIsh8ZWJPwZ7Ron7xoWgNI0lXRqhKm7fvFNCzF+Ray2kOyKWHbsMy3a5Zx3yZxC',
  'GFwexAxgYfAH9HJ1raHi1XYGpNpBlDXg47U1y4uU7RBeBb4ewETv/B/p8sGW88tIY87dHM2xHjnn',
  'tGXLvkCIkmjXGNULAVYHxDPJTygxSF7uTVPYCBUk5KeLnDVcgWF8p/wxigza47ptMtpVtm9ZrSEu',
  '9vzOnaTN3KO75RkkLuZszhXfmMZ46NQrdS7Y6duCiN501BnR5BUC4dX4iMxchix6aLN3pKv6UOEw',
  'wcx2aSF4Ib963MAtTPEjhqe+dt0VcTar/08uLWv1kQQueFaEGet4KQ975ZqaoU3PmZH9gqTOumX1',
  'EKf0Pnl0F3NMW+lEOlnCEce99zHBwBf7LV0pLNLDONBxpQySrZUQsNfhAq2Ktf5nG2hcGAMFMWIs',
  'EOuOyzEe+l2aHW4/ojOjU1Oqy4TLzVVRlWmPxQde7qKbvBN7CQhDqJHJA2nphQT/4DOdLqkwRiau',
  'Mmnfx9FI3+hYnX25NpnyvM/Pt94vpsRkhcuttu4/G4xOYTNQd2YWjGwhypZ0oPSiriuTbhj6y2qm',
  '33jiwxvegeDz8CmAIhOEY2JoVpjjX9XzuNR2f5KTLmLzEkOcJQ',
].join('');
const BODY_B64 = 'c/k+TjhBA6Je1DF8rxZhe2Jm8CN0zbkV9rre6nA8g98';
// Recovered by OpenBase with the spec parameters (and by nothing else);
// python-onlykey's tests/test_age_pq_kat.py pins the same value.
const FILE_KEY = Buffer.from('df56f61c8e496609c18d25c197451803', 'hex');

const b64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

// bech32 without the 90-char cap, as the app's decoder does; age.md's identity
// is short enough for either.
function identitySeed(s) {
  const lower = s.toLowerCase();
  const pos = lower.lastIndexOf('1');
  const hrp = lower.slice(0, pos);
  assert.strictEqual(hrp, 'age-secret-key-pq-');
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const data = Array.from(lower.slice(pos + 1, -6), (c) => CHARSET.indexOf(c));
  assert.ok(data.every((v) => v >= 0), 'bad bech32 character');
  let acc = 0, bits = 0; const out = [];
  for (const v of data) { acc = (acc << 5) | v; bits += 5; while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); } }
  return new Uint8Array(out);
}

// What the device does for a stored X-Wing key: SHAKE256 expansion to
// d || z || sk_X, ML-KEM decaps, X25519, combiner.
function identityDecaps(seed, enc) {
  const expanded = shake256(seed, { dkLen: 96 });
  const dz = expanded.subarray(0, 64);
  const skX = expanded.subarray(64, 96);
  const { secretKey: dkM } = ml_kem768.keygen(dz);
  const pkX = x25519.getPublicKey(skX);
  const ctM = enc.subarray(0, 1088), ctX = enc.subarray(1088, 1120);
  const ssM = ml_kem768.decapsulate(ctM, dkM);
  const ssX = x25519.getSharedSecret(skX, ctX);
  return agePqc.xwingCombiner(ssM, ssX, ctX, pkX);
}

const seed = identitySeed(IDENTITY);
const enc = b64(ENC_B64);
const body = b64(BODY_B64);
assert.strictEqual(seed.length, 32);
assert.strictEqual(enc.length, 1120);
assert.strictEqual(body.length, 32);
const ss = identityDecaps(seed, enc);

assert.deepStrictEqual(Buffer.from(ageFile.openFileKey(ss, enc, body)), FILE_KEY, 'open: not the spec construction');
assert.deepStrictEqual(Buffer.from(ageFile.sealFileKey(ss, enc, FILE_KEY)), Buffer.from(body), 'seal: not the spec construction');

// A wrong secret fails (both constructions).
const bad = Uint8Array.from(ss); bad[0] ^= 1;
assert.throws(() => ageFile.openFileKey(bad, enc, body));
assert.throws(() => ageFile.openFileKey(ss, enc, body.subarray(1)), /32 bytes/);

console.log('age-pq-kat: ok');
