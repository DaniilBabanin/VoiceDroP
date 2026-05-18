# tools/release

Release-integrity assets and helpers (DR19 / plan §12).

## `expected-signing-cert.sha256`

SHA-256 fingerprint of the X.509 certificate inside `app/release.keystore`,
lowercase hex, no colons, one line, no trailing whitespace.

Asserted by `.github/workflows/release.yml` after `assembleRelease`: the
workflow runs `apksigner verify --print-certs` on the freshly signed APK,
extracts the SHA-256 of the signer cert, and hard-fails the build on any
mismatch. Any change to the signing keystore must be paired with an update
to this file in the same commit.

To re-derive locally from the keystore (PKCS12, store password = key
password = `voicedrop`):

```bash
openssl pkcs12 -in app/release.keystore -password pass:voicedrop -nokeys -clcerts \
  | openssl x509 -noout -fingerprint -sha256 \
  | awk -F= '{print tolower($2)}' \
  | tr -d ':'
```

## DR19 deferred items

See `DR19-FOLLOWUPS.md` for the §12 controls that need an online CI bootstrap
before they can be turned on (dep-verification hashes, Actions SHA pinning,
build-time schema-diff).
