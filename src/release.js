module.exports = {
  "name": "OnlyKey Webcrypt App",
  "version": "4.0.0",
  "stage": "prod",
  "change_log": [
    "For OnlyKey firmware newer than v3.0.4 (served at apps.onlykey.io)",
    "Post-quantum: age with derived X-Wing keys, and PGP with PQC composite keys",
    "Authenticated transit encryption (v2) between the app and the key",
    "Clear message when stored-key (PGP) use is not enabled on the key",
    "Added Multiple Recipient Support for GPG Encryption",
    "Added Password Generator",
    "Added ECC PGP Key Support",
    "Added 3rd Party Support"
  ],
  "authors":[
    "Brad ~ bmatusiak.us",
    "Tim ~ onlykey.io"
  ],
  //"firmware_release_url":"https://github.com/trustcrypto/OnlyKey-Firmware/releases"
  "mode": process.env.NODE_ENV
};