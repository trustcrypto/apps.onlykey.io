/**
 * Vault encryption: every secret is a standard age file (age-encryption.org/v1)
 * encrypted to the OnlyKey's derived ML-KEM-768 + X25519 (X-Wing) key for the
 * label "vault:<service>" - the same derived keys and file format as the age
 * page and age-plugin-onlykey.
 *
 * - Store: the page asks the OnlyKey for the service's X-Wing public key (no
 *   press) and writes an age file to it here: an mlkem768x25519 recipient
 *   stanza (HPKE X-Wing wraps a random 16-byte file key) and a
 *   ChaCha20-Poly1305 STREAM body. The private key never leaves the OnlyKey.
 * - Read: the stanza's 1120-byte X-Wing ciphertext goes to the OnlyKey, which
 *   decapsulates it (both halves) after you confirm on the device and returns
 *   the shared secret; the file key and then the secret are opened here.
 * - Command line: the same file opens with
 *       age -d -i identity.txt
 *   where identity.txt holds identityFor(service) and age-plugin-onlykey is
 *   installed.
 *
 * Entries are { v: 3, serviceId, age: <armored age file>, policy }.
 *
 * Plain CommonJS with no bundler-only imports, so the test kit can require it
 * under Node. age_pqc.js and age_file.js are passed in by the caller.
 */
"use strict";

var LABEL_PREFIX = "vault:";
var XWING_PK = 1216;
var VERSION = 3;

function labelFor(serviceId) {
    return LABEL_PREFIX + serviceId;
}

function toBytes(v) {
    if (v instanceof Uint8Array) return v;
    if (Array.isArray(v)) return new Uint8Array(v);
    throw new Error("unexpected value from the OnlyKey");
}

function callback(fn) {
    return new Promise(function(resolve, reject) {
        fn(function(err, value) {
            if (err) reject(new Error(String(err && err.message ? err.message : err)));
            else resolve(value);
        });
    });
}

/**
 * ok      - the onlykey3rd() api object (derive_xwing_recipient/_decap)
 * agePqc  - age_pqc.js (xwingEncapsHost, encodeIdentity)
 * ageFile - age_file.js (encryptAgeFile, decryptAgeFile, armor)
 */
function create(ok, agePqc, ageFile) {

    function recipient(serviceId) {
        return callback(function(cb) { ok.derive_xwing_recipient(labelFor(serviceId), cb); })
            .then(function(r) {
                r = toBytes(r);
                if (r.length !== XWING_PK) {
                    throw new Error("X-Wing public key must be " + XWING_PK + " bytes, got " + r.length);
                }
                return r;
            });
    }

    function decap(serviceId, kemCt) {
        return callback(function(cb) { ok.derive_xwing_decap(labelFor(serviceId), kemCt, cb); })
            .then(toBytes);
    }

    /**
     * Encrypt a secret for a service. No press.
     * Returns { entry, secret }: secret is a copy of the X-Wing shared secret,
     * for the session cache.
     */
    async function seal(serviceId, plaintext) {
        var pk = await recipient(serviceId);
        var e = agePqc.xwingEncapsHost(pk);
        try {
            var file = ageFile.encryptAgeFile(new TextEncoder().encode(plaintext),
                { ciphertext: e.ciphertext, sharedSecret: e.sharedSecret });
            return {
                entry: { v: VERSION, serviceId: serviceId, age: ageFile.armorEncode(file) },
                secret: Uint8Array.from(e.sharedSecret)
            };
        } finally {
            e.sharedSecret.fill(0);
        }
    }

    /**
     * Decrypt an entry. With cachedSecret (from an earlier seal/open of this
     * same entry) the OnlyKey is not asked; otherwise it decapsulates, after
     * a press. Returns { plaintext, secret }: secret is the shared secret the
     * OnlyKey returned (a copy, for the session cache), or null if the cache
     * was used.
     */
    async function open(entry, cachedSecret) {
        if (entry.v !== VERSION) throw new Error("Unsupported vault entry version " + entry.v);
        var fresh = null;
        var bytes = await ageFile.decryptAgeFile(ageFile.armorDecode(entry.age), async function(kemCt) {
            if (cachedSecret) return Uint8Array.from(cachedSecret);
            var ss = await decap(entry.serviceId, kemCt);
            fresh = Uint8Array.from(ss);
            return ss;
        });
        return { plaintext: new TextDecoder().decode(bytes), secret: fresh };
    }

    /** The age identity line that opens this service's entries with age-plugin-onlykey. */
    function identityFor(serviceId) {
        return agePqc.encodeIdentity(labelFor(serviceId));
    }

    return {
        seal: seal,
        open: open,
        identityFor: identityFor
    };
}

/** Tag a cached secret with the entry it opens: each secret belongs to one age file. */
function cacheTag(entry) {
    return entry.age;
}

/** Import check: an entry this page can open. */
function isValidEntry(entry) {
    return !!entry && entry.v === VERSION &&
        typeof entry.serviceId === "string" && entry.serviceId.length > 0 &&
        typeof entry.age === "string" &&
        /^\s*-----BEGIN AGE ENCRYPTED FILE-----/.test(entry.age);
}

module.exports = {
    create: create,
    cacheTag: cacheTag,
    isValidEntry: isValidEntry,
    labelFor: labelFor,
    VERSION: VERSION
};
