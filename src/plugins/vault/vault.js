/**
 * OnlyKey Vault - hardware-encrypted credential manager.
 *
 * Each secret is an age file encrypted to the OnlyKey's derived
 * ML-KEM-768 + X25519 (X-Wing) key for the service; see vault-crypto.js.
 * IndexedDB stores only the age files. The session cache holds the X-Wing
 * shared secrets of unlocked entries in memory with TTL policies, and zeroes
 * them when they expire or are locked.
 */

var vaultCrypto = require("./vault-crypto.js");

var pagesList = {
    "vault": {
        sort: 36,
        icon: "fa-shield",
        title: "Vault"
    }
};

// ── IndexedDB ciphertext store ──────────────────────────────────────────

var OKVault = (function() {
    var DB_NAME = "onlyagent-vault";
    var DB_VERSION = 1;
    var STORE_NAME = "credentials";

    function openDB() {
        return new Promise(function(resolve, reject) {
            var req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = function() {
                var db = req.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME, { keyPath: "serviceId" });
                }
            };
            req.onsuccess = function() { resolve(req.result); };
            req.onerror = function() { reject(req.error); };
        });
    }

    return {
        put: async function(entry) {
            var now = Date.now();
            var record = Object.assign({}, entry, {
                updatedAt: now,
                createdAt: entry.createdAt || now
            });
            var db = await openDB();
            return new Promise(function(resolve, reject) {
                var t = db.transaction(STORE_NAME, "readwrite");
                t.objectStore(STORE_NAME).put(record);
                t.oncomplete = function() { resolve(record); };
                t.onerror = function() { reject(t.error); };
            });
        },

        get: async function(serviceId) {
            var db = await openDB();
            return new Promise(function(resolve, reject) {
                var t = db.transaction(STORE_NAME, "readonly");
                var req = t.objectStore(STORE_NAME).get(serviceId);
                req.onsuccess = function() { resolve(req.result || null); };
                req.onerror = function() { reject(req.error); };
            });
        },

        remove: async function(serviceId) {
            var db = await openDB();
            return new Promise(function(resolve, reject) {
                var t = db.transaction(STORE_NAME, "readwrite");
                t.objectStore(STORE_NAME).delete(serviceId);
                t.oncomplete = function() { resolve(); };
                t.onerror = function() { reject(t.error); };
            });
        },

        list: async function() {
            var db = await openDB();
            return new Promise(function(resolve, reject) {
                var t = db.transaction(STORE_NAME, "readonly");
                var req = t.objectStore(STORE_NAME).getAll();
                req.onsuccess = function() { resolve(req.result || []); };
                req.onerror = function() { reject(req.error); };
            });
        },

        exportJSON: async function() {
            var entries = await this.list();
            return JSON.stringify({
                version: vaultCrypto.VERSION,
                exportedAt: new Date().toISOString(),
                credentials: entries
            }, null, 2);
        },

        importJSON: async function(json, force) {
            var data = JSON.parse(json);
            if (!data.credentials || !Array.isArray(data.credentials) ||
                data.version !== vaultCrypto.VERSION) {
                throw new Error("Invalid vault export format");
            }
            var existing = await this.list();
            var existingIds = {};
            existing.forEach(function(e) { existingIds[e.serviceId] = true; });
            var imported = 0, skipped = 0;
            for (var i = 0; i < data.credentials.length; i++) {
                var entry = data.credentials[i];
                if (!vaultCrypto.isValidEntry(entry)) { skipped++; continue; }
                if (existingIds[entry.serviceId] && !force) { skipped++; continue; }
                await this.put(entry);
                imported++;
            }
            return { imported: imported, skipped: skipped, total: data.credentials.length };
        }
    };
})();

// ── Session cache (TTL-cached non-extractable CryptoKeys) ───────────────

var OKSessionCache = (function() {
    var _cache = new Map();
    var _policies = new Map();
    var _defaultPolicy = "session:30m";
    var _reaperInterval = null;

    function wipe(serviceId) {
        var entry = _cache.get(serviceId);
        if (entry && entry.secret instanceof Uint8Array) entry.secret.fill(0);
        _cache.delete(serviceId);
    }

    function parsePolicy(policyStr) {
        if (!policyStr || policyStr === "always") {
            return { ttlMs: 0, sliding: false, noCache: true };
        }
        if (policyStr === "startup") {
            return { ttlMs: 0, sliding: false, noCache: false };
        }
        var match = policyStr.match(/^session:(\d+)(m|h)$/);
        if (!match) {
            return { ttlMs: 0, sliding: false, noCache: true };
        }
        var value = parseInt(match[1], 10);
        var ttlMs = match[2] === "h" ? value * 3600000 : value * 60000;
        return { ttlMs: ttlMs, sliding: ttlMs <= 3600000, noCache: false };
    }

    return {
        getPolicy: function(serviceId) {
            return _policies.get(serviceId) || _defaultPolicy;
        },

        setPolicy: function(serviceId, policy) {
            _policies.set(serviceId, policy);
            if (policy === "always") wipe(serviceId);
        },

        get: function(serviceId, tag) {
            var entry = _cache.get(serviceId);
            if (!entry) return null;
            if (tag !== undefined && entry.tag !== tag) return null;
            if (entry.ttlMs > 0) {
                var ref = entry.sliding ? entry.lastUsedAt : entry.createdAt;
                if (Date.now() - ref > entry.ttlMs) {
                    wipe(serviceId);
                    return null;
                }
            }
            entry.lastUsedAt = Date.now();
            return entry.secret;
        },

        put: function(serviceId, secret, tag) {
            var policyStr = this.getPolicy(serviceId);
            var parsed = parsePolicy(policyStr);
            if (parsed.noCache) { secret.fill(0); return; }
            wipe(serviceId);
            var now = Date.now();
            _cache.set(serviceId, {
                secret: secret,
                tag: tag,
                createdAt: now,
                lastUsedAt: now,
                policy: policyStr,
                ttlMs: parsed.ttlMs,
                sliding: parsed.sliding
            });
        },

        evict: function(serviceId) { wipe(serviceId); },
        clear: function() { Array.from(_cache.keys()).forEach(wipe); },

        status: function() {
            var now = Date.now();
            var entries = [];
            _cache.forEach(function(entry, serviceId) {
                var ref = entry.sliding ? entry.lastUsedAt : entry.createdAt;
                var remaining = entry.ttlMs > 0 ? Math.max(0, entry.ttlMs - (now - ref)) : Infinity;
                entries.push({
                    serviceId: serviceId,
                    policy: entry.policy,
                    remainingFormatted: remaining === Infinity
                        ? "until close" : Math.ceil(remaining / 60000) + "m"
                });
            });
            return entries;
        },

        reap: function() {
            var now = Date.now();
            var expired = [];
            _cache.forEach(function(entry, serviceId) {
                if (entry.ttlMs > 0) {
                    var ref = entry.sliding ? entry.lastUsedAt : entry.createdAt;
                    if (now - ref > entry.ttlMs) expired.push(serviceId);
                }
            });
            expired.forEach(function(id) { wipe(id); });
        },

        startReaper: function() {
            if (_reaperInterval) return;
            var self = this;
            _reaperInterval = setInterval(function() { self.reap(); }, 30000);
        }
    };
})();

// ── Plugin module ───────────────────────────────────────────────────────

module.exports = {
    pagesList: pagesList,
    consumes: ["app"],
    provides: ["plugin_vault"],
    setup: function(options, imports, register) {

        var init = false;
        var page = {
            view: require("./vault.page.html").default,
            init: function(app, $page, pathname) {
                init = true;
                page.setup(app, $page, pathname);
            },
            setup: function(app, $page, pathname) {
                if (!init)
                    return page.init(app, $page, pathname);

                var $ = app.$;
                var onlykey3rd = app.onlykey3rd;
                // node-onlykey's onlykey3rd() constructor takes no
                // arguments in the currently-bundled library version -
                // keytype/press_required are per-call arguments on
                // derive_public_key/derive_shared_secret themselves, not
                // bound at construction. `onlykey3rd(1, 0)` is a harmless
                // no-op, kept to match history.js's still-working call.
                var ok = onlykey3rd(1, 0);
                // Required here, not at the top: webpack.config.js requires
                // this module under plain Node to read pagesList, and
                // age_pqc.js needs the bundler's @noble aliases.
                var agePqc = require("../../onlykey-fido2/onlykey/age_pqc.js");
                var ageFile = require("../../onlykey-fido2/onlykey/age_file.js");
                var vc = vaultCrypto.create(ok, agePqc, ageFile);

                ok.on("status", function(msg) { log(msg); });
                ok.on("challenge", function(code) {
                    var box = document.getElementById("challenge_code_box");
                    var out = document.getElementById("challenge_code");
                    if (!box || !out) return;
                    if (code && code.length) {
                        out.textContent = code.join("  ");
                        box.style.display = "block";
                    } else {
                        box.style.display = "none";
                    }
                });
                ok.on("error", function(err) { log("OnlyKey error: " + err); });

                function log(msg) {
                    var div = document.createElement("div");
                    div.textContent = msg;
                    var el = document.getElementById("messages");
                    if (el) {
                        el.appendChild(div);
                        el.scrollTop = el.scrollHeight;
                    }
                }

                function esc(s) {
                    var d = document.createElement("div");
                    d.textContent = String(s);
                    return d.innerHTML;
                }

                // Decrypt an entry, with the shared secret from the session
                // cache or from the OnlyKey (X-Wing decapsulation on the
                // device, after you confirm there).
                async function reveal(entry) {
                    var tag = vaultCrypto.cacheTag(entry);
                    var cached = OKSessionCache.get(entry.serviceId, tag);
                    if (!cached) log("Confirm on your OnlyKey to unlock \"" + entry.serviceId + "\"...");
                    var r = await vc.open(entry, cached);
                    if (r.secret) {
                        OKSessionCache.put(entry.serviceId, r.secret, tag);
                        renderSessions();
                    }
                    return r.plaintext;
                }

                // Encrypt a secret as an age file to the service's OnlyKey
                // X-Wing public key, and store it. Getting the public key
                // needs no press.
                async function store(serviceId, plaintext, policy) {
                    var r = await vc.seal(serviceId, plaintext);
                    r.entry.policy = policy;
                    var saved = await OKVault.put(r.entry);
                    OKSessionCache.put(serviceId, r.secret, vaultCrypto.cacheTag(r.entry));
                    renderSessions();
                    return saved;
                }

                async function renderVault() {
                    var entries = await OKVault.list();
                    var $list = $page.find("#vault_list");
                    if (entries.length === 0) {
                        $list.html('<p class="text-muted">No credentials stored yet.</p>');
                        return;
                    }
                    var html = entries.map(function(e) {
                        var hasSession = !!OKSessionCache.get(e.serviceId, vaultCrypto.cacheTag(e));
                        return '<fieldset class="vault-entry" data-service="' + esc(e.serviceId) + '">' +
                            '<input readonly type="text" value="' + esc(e.serviceId) +
                            ' · ' + esc(e.policy || "session:30m") +
                            (vaultCrypto.isValidEntry(e) ? '' : ' · old test format, delete and add again') +
                            (hasSession ? ' · session active' : '') + '" />' +
                            '<button type="button" class="btn-secondary vault-copy-blob">Copy age file</button>' +
                            '<button type="button" class="btn-secondary vault-copy-identity">Copy age identity</button>' +
                            '<button type="button" class="btn-secondary vault-copy-secret">Copy secret (touch)</button>' +
                            '<button type="button" class="btn-danger vault-delete">Delete</button>' +
                            '</fieldset>';
                    }).join("");
                    $list.html(html);
                }

                function renderSessions() {
                    var entries = OKSessionCache.status();
                    var $s = $page.find("#vault_sessions");
                    if (entries.length === 0) {
                        $s.html('<p class="text-muted">No active sessions — next use requires touch.</p>');
                        return;
                    }
                    var html = entries.map(function(e) {
                        return '<p>' + esc(e.serviceId) + ' — ' + esc(e.remainingFormatted) +
                            ' (' + esc(e.policy) + ')</p>';
                    }).join("");
                    $s.html(html);
                }

                // ── Add credential ──
                $page.find("#vault_add_btn").off("click").on("click", async function() {
                    var serviceId = $page.find("#vault_service").val().trim();
                    var secret = $page.find("#vault_secret").val();
                    var policy = $page.find("#vault_policy").val();
                    if (!serviceId || !secret) {
                        log("Service name and secret are required");
                        return;
                    }
                    try {
                        OKSessionCache.setPolicy(serviceId, policy);
                        log("Getting the vault key for \"" + serviceId + "\" from your OnlyKey...");
                        var saved = await store(serviceId, secret, policy);
                        $page.find("#vault_secret").val("");
                        $page.find("#vault_add_result").val(saved.age).removeClass("startHidden");
                        log('Encrypted and stored "' + serviceId + '" — plaintext cleared');
                        renderVault();
                    } catch (err) {
                        log("Error: " + err.message);
                    }
                });

                // ── Credential list actions (delegated) ──
                $page.find("#vault_list").off("click").on("click", "button", async function() {
                    var serviceId = $(this).closest(".vault-entry").attr("data-service");
                    var entry = await OKVault.get(serviceId);
                    if (!entry) return;

                    if ($(this).hasClass("vault-copy-blob")) {
                        await navigator.clipboard.writeText(entry.age);
                        log('Copied the age file for "' + serviceId + '"');
                    } else if ($(this).hasClass("vault-copy-identity")) {
                        await navigator.clipboard.writeText(vc.identityFor(serviceId) + "\n");
                        log('Copied the age identity for "' + serviceId + '" - save it as identity.txt for age -d -i identity.txt (needs age-plugin-onlykey)');
                    } else if ($(this).hasClass("vault-copy-secret")) {
                        try {
                            var plaintext = await reveal(entry);
                            await navigator.clipboard.writeText(plaintext);
                            log('Secret for "' + serviceId + '" copied to clipboard');
                            plaintext = null;
                        } catch (err) {
                            log("Decrypt error: " + err.message);
                        }
                    } else if ($(this).hasClass("vault-delete")) {
                        await OKVault.remove(serviceId);
                        OKSessionCache.evict(serviceId);
                        log('Deleted "' + serviceId + '"');
                        renderVault();
                        renderSessions();
                    }
                });

                // ── Sessions / export / import ──
                $page.find("#vault_lock_all").off("click").on("click", function() {
                    OKSessionCache.clear();
                    log("All sessions locked");
                    renderSessions();
                    renderVault();
                });

                $page.find("#vault_export").off("click").on("click", async function() {
                    var json = await OKVault.exportJSON();
                    var blob = new Blob([json], { type: "application/json" });
                    var a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = "onlykey-vault-export.json";
                    a.click();
                    URL.revokeObjectURL(a.href);
                    log("Vault exported (ciphertext only — safe to store anywhere)");
                });

                $page.find("#vault_import_btn").off("click").on("click", function() {
                    $page.find("#vault_import_file").trigger("click");
                });

                $page.find("#vault_import_file").off("change").on("change", async function(ev) {
                    var file = ev.target.files[0];
                    if (!file) return;
                    try {
                        var text = await file.text();
                        var result = await OKVault.importJSON(text);
                        log("Imported " + result.imported + ", skipped " + result.skipped);
                        var entries = await OKVault.list();
                        entries.forEach(function(e) {
                            if (e.policy) OKSessionCache.setPolicy(e.serviceId, e.policy);
                        });
                        renderVault();
                    } catch (err) {
                        log("Import error: " + err.message);
                    }
                    ev.target.value = "";
                });

                // ── Init ──
                OKSessionCache.startReaper();
                OKVault.list().then(function(entries) {
                    entries.forEach(function(e) {
                        if (e.policy) OKSessionCache.setPolicy(e.serviceId, e.policy);
                    });
                    renderVault();
                    renderSessions();
                    log("Vault loaded: " + entries.length + " credential(s)");
                });
                setInterval(renderSessions, 10000);
            }
        };

        pagesList["vault"] = page;

        register(null, {
            "plugin_vault": {
                pagesList: pagesList
            }
        });
    }
};
