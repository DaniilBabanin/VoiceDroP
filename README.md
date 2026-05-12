# VoiceDrop

Walkie-talkie-style async voice messaging for Android. No accounts. No server-side message storage. End-to-end encrypted with X25519 + XChaCha20-Poly1305.

## How it works

1. You and a contact exchange **cryptographic contact cards** by QR code or `.voicedrop` file
2. A 4-emoji verification ceremony confirms neither side was MITM'd during pairing
3. From then on, pull down Quick Settings → tap the tile → record → release to send
4. Messages are delivered over LAN (mDNS), STUN hole-punch, or queued for next connectivity
5. A self-hosted Cloudflare Worker handles signaling only — it never sees audio

---

## 1. Deploy the Cloudflare Worker (signaling server)

You need to do this once before testing. The worker handles WebSocket signaling between devices; it never stores or relays voice data.

### Prerequisites

```bash
npm install -g wrangler
wrangler login
```

### Deploy

```bash
cd cloudflare-worker
npm install
wrangler deploy
```

Wrangler will print the worker URL, e.g.:
```
https://voicedrop-signaling.<your-subdomain>.workers.dev
```

Copy this URL — you'll paste it into the app's Settings screen.

### Verify

```bash
curl -I https://voicedrop-signaling.<your-subdomain>.workers.dev/
# Should return HTTP 426 (Upgrade Required — WebSocket endpoint)
```

---

## 2. Build and install the APK

### Option A — Download from GitHub Releases (recommended for 0.1.0 testing)

1. Go to the [Releases page](../../releases) and download `app-debug.apk`
2. Enable "Install from unknown sources" on both test phones
3. Transfer the APK (ADB, email, USB) and install

### Option B — Build locally

Requirements: JDK 17, Android SDK 35

```bash
./scripts/build-local.sh debug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

Install via ADB:
```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## 3. First-time setup (do on both phones)

1. Open **VoiceDrop**
2. Tap the ⚙️ menu → **Settings**
3. Enter a **Display Name** (e.g. "Alice") and tap **Save**
4. Paste the Cloudflare Worker URL into **Signaling Server URL**:
   ```
   wss://voicedrop-signaling.<your-subdomain>.workers.dev/signal
   ```
5. Tap **Test Connection** — should show "Connection OK"
6. Tap **Save**

---

## 4. Pair contacts

Both phones must run through this pairing flow once.

**Method A — QR code (same room)**

1. On Phone A: tap **+** → **My QR** tab — your QR is shown
2. On Phone B: tap **+** → **Scan** tab → point camera at Phone A's screen
3. Both phones show the same **4 emoji verification code** — confirm verbally that they match
4. Both phones tap **"Codes match — Confirm"**
5. The contact appears in the list on both phones

**Method B — File share (remote pairing)**

1. On Phone A: tap **+** → **My QR** tab → **Share Contact Card**
2. Send the `.voicedrop` file to Phone B (Signal, email, etc.)
3. On Phone B: open the `.voicedrop` file or tap **+** → **Import File**
4. Verify the 4-emoji code over a separate channel (phone call, in-person)
5. Confirm on both devices

> ⚠️ **Security note**: The emoji verification is mandatory and cryptographically meaningful. Skipping it makes the pairing vulnerable to MITM. Always verify out-of-band.

---

## 5. Send a voice message

1. Pull down Quick Settings
2. Tap the **VoiceDrop tile** (microphone icon)
3. If you have multiple contacts, a picker appears — select one
4. Speak — the tile turns red while recording
5. Tap again to stop and send
6. The tile briefly shows a send arrow, then returns to idle

To play an incoming message: tap the notification → **Play**.

---

## 6. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Tile doesn't appear | Add it: Edit Quick Settings → drag "VoiceDrop" tile in |
| "Connection failed" in settings | Check the worker URL — must be `wss://` not `https://` |
| Contact pairing fails | Ensure both devices are on the internet, retry once |
| Message stuck in sending | Both phones must have the same signaling URL configured |
| No incoming notification | Grant POST_NOTIFICATIONS permission (Android 13+) |

---

## Architecture

```
Phone A                 Cloudflare Worker          Phone B
  │                    (signaling only)               │
  │── WebSocket ──────────────────────────────────────│ (when available)
  │                                                   │
  │── mDNS / direct TCP ──────────────────────────────│ (same LAN)
  │                                                   │
  │── outbox queue (Room DB) ─────────────────────────│ (offline delivery)
```

**Crypto stack**: X25519 ECDH → HKDF-SHA256 session key → XChaCha20-Poly1305 per message  
**Storage**: Room DB (SQLite), encrypted blobs in `filesDir/messages/`  
**No cloud relay**: The worker never sees plaintext, audio, or contact lists

---

## Known limitations in v0.1.0

- **No message history UI**: Contacts listed, but tapping a contact doesn't show message history yet (v1.0.0)
- **STUN hole-punch**: Falls back to outbox queue if direct TCP fails; STUN integration completes in v1.0.0
- **AndroidKeyStore wrapping**: Session key stored directly in SharedPreferences in v0.1.0; hardware-backed wrapping in v1.0.0
- **No delete contact UI**: Contacts can't be removed from the UI in v0.1.0

---

## Path to v1.0.0

| # | Item | Status |
|---|------|--------|
| 1 | Message history list in ContactListActivity | v1.0.0 |
| 2 | Incoming frame decryption + notification in ConnectionManager | v1.0.0 |
| 3 | STUN hole-punch fully wired | v1.0.0 |
| 4 | AndroidKeyStore session key wrapping | v1.0.0 |
| 5 | Delete contact UI | v1.0.0 |
| 6 | Per-contact auto-delete setting | v1.0.0 |
| 7 | Release APK signing (production keystore) | v1.0.0 |
| 9 | Fix bugs found in v0.1.0 testing | v1.0.0 |

---

## Building a release APK (v1.0.0)

```bash
export KEYSTORE_PATH=/path/to/release.keystore
export KEY_ALIAS=voicedrop
export KEY_PASSWORD=<key-password>
export STORE_PASSWORD=<store-password>
./scripts/build-local.sh release
```

Or generate a keystore first:
```bash
keytool -genkey -v -keystore release.keystore \
  -alias voicedrop -keyalg RSA -keysize 2048 \
  -validity 10000 -storetype PKCS12
```

---

## Security

See [SECURITY.md](SECURITY.md) for the threat model, vulnerability reporting, and export control notice.
