# VoiceDrop

Async, walkie-talkie-style voice messaging for Android. No accounts, no server-side audio storage, E2E encrypted (X25519 → HKDF → XChaCha20-Poly1305). Private keys stay in AndroidKeyStore.

Messages deliver over LAN (mDNS), STUN, Cloudflare Worker relay, or outbox queue. The worker handles signaling and relay queuing only; it never touches audio.

---

## 1. Deploy the Cloudflare Worker

```bash
npm install -g wrangler && wrangler login
cd cloudflare-worker && npm install && wrangler deploy
```

Wrangler prints the worker URL. Verify: `curl -I <url>/` should return HTTP 426.

---

## 2. Install

Download `app-release.apk` from [Releases](../../releases). Enable "Install from unknown sources," then `adb install app-release.apk`.

---

## 3. First-time setup (both phones)

Open VoiceDrop → menu → Settings. Set a display name, paste the signaling URL as `wss://<worker-subdomain>.workers.dev/signal`, tap Test Connection, then Save.

---

## 4. Pair contacts

**QR (same room):** Phone A: tap + → My QR. Phone B: tap + → Scan → point at Phone A. Both phones show a 4-emoji code — verify verbally, tap "Codes match — Confirm" on both.

**File (remote):** Phone A: tap + → My QR → Share Contact Card, send the `.voicedrop` file. Phone B: open it or tap + → Import File. Verify the emoji code out-of-band, then confirm on both.

The emoji verification matters. Skip it and the pairing is MITM-able.

---

## 5. Send a voice message

Pull down Quick Settings (drag the VoiceDrop tile in if it's missing). Tap the tile, pick a contact, speak. Tile turns red. Tap again to stop and send. Incoming messages arrive as notifications → Play.

Message history: tap a contact. Delete contact: swipe left. Auto-delete timer (None / 1 h / 24 h / 7 d): overflow menu inside message history.

---

## 6. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Tile missing | Edit Quick Settings → drag VoiceDrop in |
| "Connection failed" | URL must use `wss://` not `https://` |
| Pairing fails | Both devices need internet; retry once |
| Message stuck | Both phones must use the same signaling URL |
| No notifications | Grant POST_NOTIFICATIONS (Android 13+) |

---

## Architecture

Delivery: LAN mDNS, STUN hole-punch, Cloudflare Worker store-and-forward relay, outbox queue when offline. The worker never sees plaintext, audio, or contact data.

Crypto: X25519 ECDH → HKDF-SHA256 → XChaCha20-Poly1305. Storage: Room DB + encrypted blobs in `filesDir/messages/`.

---

## Building and releasing

GitHub Actions builds on tags. Push a `v*` tag to trigger:

```bash
git tag v0.1.0.30 && git push origin v0.1.0.30
```

`v0.*` tags go to `prerelease.yml` (debug APK). `v1.*` tags go to `release.yml` (signed APK), which needs 4 repo secrets: `KEYSTORE_BASE64`, `KEY_ALIAS`, `KEY_PASSWORD`, `STORE_PASSWORD`.

To generate a keystore: `keytool -genkey -v -keystore release.keystore -alias voicedrop -keyalg RSA -keysize 2048 -validity 10000 -storetype PKCS12`. Base64-encode it, set as `KEYSTORE_BASE64`, then push a `v1.0.0` tag.

---

See [SECURITY.md](SECURITY.md) for the threat model, vulnerability reporting, and export controls.
