# apps.onlykey.io

Production build of the OnlyKey web app for **OnlyKey firmware newer than
v3.0.4**, published with GitHub Pages at https://apps.onlykey.io.

This repository holds build output only.

## Which site serves which key

| firmware | site |
|---|---|
| v3.0.4 and earlier | https://apps.crp.to |
| newer than v3.0.4 | https://apps.onlykey.io (this one) |

Firmware only answers the web app from origins compiled into it
(`webcryptcheck()`, `fido2/device.cpp`). Newer firmware trusts both sites;
v3.0.4 and earlier trust only apps.crp.to. After the handshake each site
reads the firmware version and sends a key to the site that serves it.
When a key does not answer here at all - which is what an older key looks
like - the page says so and goes to apps.crp.to after 5 seconds (with a
"Stay here" link). No key at all looks the same, which is harmless:
apps.crp.to sends a newer key straight back here after its handshake, and a
visitor apps.crp.to has just sent here is never sent back.

## Rebuilding

From the web app source:

```sh
npm install
OK_CNAME=apps.onlykey.io bash BUILD.sh 1      # production: no-op console
node test/version-route.test.js
# copy docs/ (including CNAME and .nojekyll) to the root of this repository
```

## DNS

Production is published from `trustcrypto/apps.onlykey.io`.
`apps.onlykey.io` needs a CNAME record pointing at `trustcrypto.github.io`
(DNS only - not proxied - until GitHub has issued the certificate). Then
enable "Enforce HTTPS" in that repository's Pages settings.
