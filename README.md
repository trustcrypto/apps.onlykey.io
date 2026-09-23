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
reads the firmware version and establishes a session key with the site.

## Rebuilding

From the web app source:

```sh
npm install
OK_CNAME=apps.onlykey.io bash BUILD.sh 1      # production: no-op console
node test/version-route.test.js
# copy docs/ (including CNAME and .nojekyll) to the root of this repository
```
