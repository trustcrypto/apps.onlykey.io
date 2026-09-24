/*
 * Device error strings that need more than the device can say in 64 bytes.
 *
 * Each explanation opens by restating the firmware's message in plain words,
 * so a user quoting the page can still be matched to the firmware source.
 */
'use strict';

var EXPLAIN = {
  // ok_extension.cpp: a stored-slot OKSIGN/OKDECRYPT (PGP, and the PGP-PQC
  // composite slots) at webcrypt level 1. Off by default; field 31 bit 0
  // (OKWC_ALLOW_STORED_KEY) turns it on. Firmware before libraries 6ddc82b
  // dropped this message, so the page just stopped.
  'Error stored key use over FIDO2 not enabled':
    'Stored-key (PGP) use by the web app is not enabled on this OnlyKey. ' +
    'To allow it, put the key in config mode and turn on "Allow Webcrypt to use ' +
    'my stored keys (PGP)" in the OnlyKey app\'s Preferences, or run ' +
    '"onlykey-cli webcryptpolicy 1". Derived keys work without it.',
};

/** Return a user-facing message for a device error string. */
function explainDeviceError(text) {
  var t = String(text || '').replace(/\0+$/, '').trim();
  return EXPLAIN[t] || t;
}

module.exports = { explainDeviceError: explainDeviceError, EXPLAIN: EXPLAIN };
