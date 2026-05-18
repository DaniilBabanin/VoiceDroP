# VoiceDrop

Async, walkie-talkie-style voice messaging for Android. No accounts, no plaintext on the server, E2E encrypted with a Signal-style Double Ratchet (X25519 bootstrap → per-message symmetric ratchet → ChaCha20-Poly1305) so each message has its own key and a stolen handset can't decrypt history. Private keys stay in AndroidKeyStore.

Messages deliver over LAN (mDNS), STUN, Cloudflare Worker relay, or outbox queue. The worker handles signaling and relays encrypted blobs only; it never sees plaintext audio or decryption keys, and relayed blobs are deleted on recipient pickup.

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

**Disable battery optimization for VoiceDrop.** Android Settings → Apps → VoiceDrop → Battery → Unrestricted (path varies by OEM). Without this, Android will eventually kill the background listener and incoming messages won't arrive until you reopen the app. VoiceDrop avoids Firebase/Google push to keep the app fully open source and account-free, so message delivery relies on a long-lived WebSocket held by a foreground service — which the OS only keeps alive if battery optimization is off.

---

## 4. Pair contacts

**QR (same room):** Phone A: tap + → My QR. Phone B: tap + → Scan → point at Phone A. Both phones show a 4-emoji code — verify verbally, tap "Codes match — Confirm" on both.

**File (remote):** Phone A: tap + → My QR → Share Contact Card, send the `.voicedrop` file. Phone B: open it or tap + → Import File. Verify the emoji code out-of-band, then confirm on both.

The emoji verification matters. Skip it and the pairing is MITM-able.

**Reset / re-pair.** If a device gets restored from backup, swapped, or you suspect compromise, open the contact and pick "Reset secure session" (clears the ratchet state on both sides, keeps the contact and history) or "Re-pair" (wipes the contact's identity and starts over with a fresh QR scan). Both sides converge automatically; the second device just gets a banner explaining what happened.

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

Delivery: LAN mDNS, STUN hole-punch, Cloudflare Worker store-and-forward relay, outbox queue when offline. The worker sees ciphertext blobs and routing fingerprints — never plaintext audio, decryption keys, or display names; relayed blobs are deleted on recipient pickup.

Crypto: X25519 bootstrap → Double Ratchet (HKDF-SHA256 root + chain keys, fresh DH ratchet on every receive) → ChaCha20-Poly1305 AEAD. Each message gets a unique key; compromise of the current state does not reveal past messages (forward secrecy) and a fresh DH from the peer recovers confidentiality going forward (post-compromise security). Wrapped ratchet state is bound to its `(table, row)` location via HMAC, and AndroidKeyStore holds the wrap key. Storage: Room DB + encrypted blobs in `filesDir/messages/`. Spec: [`plan/08-dr/`](plan/08-dr/).

---

## Building and releasing

GitHub Actions is the only build path; there is no supported local build. Push a `v1.MAJOR.MINOR.BUILD` tag to trigger `release.yml`:

```bash
# Pre-release (default for day-to-day work)
git tag v1.2.0.12-pre.1 && git push origin v1.2.0.12-pre.1

# Stable (explicit only — no -pre.N suffix)
git tag v1.2.0.12 && git push origin v1.2.0.12
```

Tag suffix `-pre.N` flips the GitHub release to pre-release; bare tags are stable. The 4-component `versionName` in `app/build.gradle.kts` must match the tag exactly; `versionCode` must increment with every push.

The signing keystore (`app/release.keystore`, PKCS12) is committed; CI signs with hard-coded passwords. The release workflow asserts the signed APK's X.509 certificate SHA-256 matches the value pinned in [`tools/release/expected-signing-cert.sha256`](tools/release/expected-signing-cert.sha256) and refuses to publish on mismatch. Released APKs also include their `classes*.dex` SHA-256 in the release body so anyone can rebuild and compare bytes. Build-integrity scope and deferred follow-ups (dependency-hash pinning, Actions SHA-pinning, full reproducible-build) are tracked in [`tools/release/DR19-FOLLOWUPS.md`](tools/release/DR19-FOLLOWUPS.md).

---

## Legal

- [PRIVACY.md](PRIVACY.md) — what data the app stores, what metadata third parties (Cloudflare, Google STUN) see, and the limits of deletion. Linked from in-app Settings.
- [SECURITY.md](SECURITY.md) — threat model and vulnerability reporting.

VoiceDrop uses strong cryptography (X25519, HKDF-SHA256, ChaCha20-Poly1305). Users are responsible for compliance with any import, export, or use restrictions that apply in their own jurisdiction.
