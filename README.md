# apps.onlykey.io

The OnlyKey web app for **OnlyKey firmware newer than v3.0.4**, published with
GitHub Pages at https://apps.onlykey.io.

This repository holds the web app source and its production build. GitHub
Pages serves the build from `docs/`.

## Which site serves which key

| firmware | site |
|---|---|
| v3.0.4 and earlier | https://apps.crp.to |
| newer than v3.0.4 | https://apps.onlykey.io (this one) |

Firmware only answers the web app from origins compiled into it
(`webcryptcheck()`, `fido2/device.cpp`). Newer firmware trusts both sites;
v3.0.4 and earlier trust only apps.crp.to. After the handshake each site
reads the firmware version and establishes a session key with the site.

## Building

```sh
npm install
bash BUILD.sh 1                      # production build into docs/
node test/version-route.test.js
```

`BUILD.sh 1` writes the production build (no debug console) to `docs/`, with
`docs/CNAME` set to `apps.onlykey.io`. Commit `docs/` to publish it. The
version shown in the app is `version` in `src/release.js`.
