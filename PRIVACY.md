# Privacy Policy

**Effective date:** 2026-06-11
**Version:** 1.2
**Applies to:** VoiceDrop for Android, all versions through 1.4.x.

VoiceDrop is an account-free, end-to-end-encrypted voice messaging app. There is no developer-operated backend, no telemetry, and no sign-up. This policy describes the data the app stores on your device, the limited metadata that traverses third-party infrastructure during message delivery, and the practical limits of deletion and erasure.

If you do not agree with this policy, do not install or use VoiceDrop.

For security vulnerability reporting and the cryptography export notice, see [SECURITY.md](SECURITY.md).

---

## Summary

- **No account, no registration, no analytics.** The *developer* operates no service that identifies you. Third-party infrastructure (Cloudflare, Google STUN) does see your IP address — see Sections 2 and 3.
- **Message audio is end-to-end encrypted** with a Double Ratchet (X25519 ECDH ratchet → HKDF-SHA256 → ChaCha20-Poly1305), deriving a fresh key per message. It is never transmitted or stored in plaintext outside your device or your recipient's device.
- **The Cloudflare Worker** used for signaling and relay sees ciphertext, IP addresses, connection timing, and stable per-contact key fingerprints — but no plaintext audio, display names, or decryption keys.
- **STUN servers** (Cloudflare and Google) see your public IP address and UDP port when the app performs NAT discovery.
- **Forward secrecy applies in transit, not at rest.** Per-message keys protect past traffic against a key compromise, but messages already stored on your device are readable by anyone who can read your device's storage (see Section 5).
- **Deletion across devices is best-effort.** Deleting on your phone removes the message locally immediately; the recipient's copy may or may not be deleted depending on connectivity.

---

## 1. Controllers and roles

VoiceDrop is designed so that no central party processes your messages. The roles are:

- **The developer** (the maintainer of the VoiceDrop GitHub repository) ships the source code and signed APK. The developer operates **no server, no database, and no logs** that touch user data. The developer is therefore not a "controller" (GDPR Art. 4(7)) or "business" (CCPA § 1798.140(d)) of message content. For privacy-related questions, open an issue at https://github.com/DaniilBabanin/VoiceDroP/issues.
- **You** are the controller of the data on your own device. When you operate your own Cloudflare Worker for signaling and relay, you are also the controller of any logs that Worker produces.
- **Cloudflare** is an independent controller of the operational logs produced by its edge in front of your Worker and by its STUN service. Cloudflare's handling is governed by https://www.cloudflare.com/privacypolicy/.
- **Google** is an independent controller of the operational logs produced by its public STUN endpoints. Governed by https://policies.google.com/privacy.

The developer is neither controller nor processor of any data that your self-hosted Worker handles. The Worker code is distributed under the LICENSE file and is operated solely by you.

---

## 2. What the app collects and stores locally

Everything below stays on your device. Nothing in this section is transmitted to any server operated by the developer.

- **Voice recordings** — stored in `filesDir/messages/` inside the app's private storage, protected by Android file-based encryption (no app-layer at-rest envelope; the Double Ratchet protects data in transit). Cryptographic key material in the local database is wrapped by Android Keystore.
- **Contacts** — display name and public keys for each paired contact, in a local Room database.
- **Per-contact preferences** — auto-delete timer (None / 1 h / 24 h / 7 d), pairing verification state, last-seen timestamps.
- **Outbox queue** — pending outbound messages waiting for delivery, encrypted with the recipient's key.
- **App settings** — your display name, signaling server URL, onboarding state.

VoiceDrop does not transmit to the developer or collect from your device: your Android contact list, location, advertising ID, device identifiers (IMEI, MAC, Android ID), phone number, microphone input outside of recording sessions you initiate, or any usage analytics.

**Lawful basis (GDPR Art. 6).** All local processing relies on your consent, given by installing the app and recording a message. Network transmission to peers, the Worker, and STUN servers also relies on Art. 6(1)(a) consent. The developer's legitimate interest (Art. 6(1)(f)) is limited to documenting how the open-source software is designed to work — the developer does not itself process personal data on these grounds.

---

## 3. What the Cloudflare Worker receives

VoiceDrop uses a Cloudflare Worker (URL configured by you during first-run setup) for two purposes: WebSocket signaling between paired contacts, and short-lived store-and-forward relay when peer-to-peer delivery fails. **The Worker is operated by you, not by the developer.**

The Worker sees:

- **Your IP address** (visible to Cloudflare's edge as the TCP source).
- **Standard TLS/WebSocket handshake metadata** (User-Agent string from OkHttp, TLS ciphersuite list). The app does not send a unique device identifier; these handshake bits can contribute to a fingerprint when combined with your IP but do not themselves identify your installation.
- **STUN-discovered public address** when included in a peer-discovery signal.
- **WebSocket connection timing** — when you connect and disconnect from the signaling channel.
- **Stable per-contact key fingerprints** (64 hexadecimal characters) used to route signaling and relay messages. A fingerprint reveals which paired contact pair a connection belongs to; it does not reveal display names or message content.
- **Ciphertext blobs** for relayed messages, addressed only by the recipient fingerprint.

The Worker does **not** see: plaintext audio, your display name, your contacts' display names, message content, or any decryption key.

**Retention on the Worker.** Relayed ciphertext is deleted from Durable Object storage **once the recipient acknowledges pulling it**. Undelivered ciphertext expires automatically after **7 days** (a Durable Object alarm sweeps expired frames). As the Worker operator you can additionally purge frames at any time by redeploying or clearing storage.

**International transfers.** When the app contacts your Cloudflare Worker, your IP address may be transferred outside the EEA, UK, and your home jurisdiction depending on which Cloudflare edge serves the request. These transfers rely on Cloudflare's own transfer mechanisms (Standard Contractual Clauses, EU-US Data Privacy Framework where applicable). The developer is not a party to those transfers; the data exchange is between your device and Cloudflare.

**Opting out of the relay.** Settings contains an "Allow server relay fallback" switch (default on). When you turn it off, the app will neither upload encrypted frames to the Worker for store-and-forward nor pull frames the Worker is holding for you. The signaling WebSocket is still used for peer presence and STUN-address exchange so that LAN and direct P2P delivery continue to work; only the store-and-forward path is disabled. Messages to a peer who is not reachable directly will remain queued in your local outbox and be retried when the peer next comes online.

---

## 4. What STUN providers receive

To establish a peer-to-peer connection through NAT, the app sends STUN binding requests to the following hard-coded servers (the list is not user-configurable in v1.0.x):

- `stun.cloudflare.com:3478` (Cloudflare)
- `stun.l.google.com:19302` and `stun1.l.google.com:19302` (Google)

These servers see **your IP address and UDP source port** for the duration of the STUN exchange. They do not receive any VoiceDrop-specific data, contact identity, or message content. Their handling of this metadata is governed by their respective privacy policies (linked in Section 1). Direct LAN delivery via mDNS does not contact STUN servers; if your peer is on the same Wi-Fi network, no STUN traffic is generated.

---

## 5. Forward secrecy and stored history

VoiceDrop encrypts every message with a Double Ratchet: an X25519 DH ratchet feeds HKDF-SHA256 chain keys, and each message is sealed with a fresh ChaCha20-Poly1305 key. Compromising any single message key does not expose earlier traffic (forward secrecy), and the DH ratchet plus the session-reset protocol restore security after a state compromise (post-compromise security). The long-term identity private key is stored wrapped by Android Keystore.

**Implication for stored history:** forward secrecy protects traffic on the wire, not the archive on your device. Received messages are stored decrypted inside the app's private storage (protected by Android file-based encryption and the auto-delete timers). An attacker with full access to your unlocked device can read whatever messages are still stored. Use the auto-delete timers for content that should not persist.

---

## 6. Delete propagation across devices

When you delete a message on your device, the app:

1. Removes the database row, overwrites the audio file with zeros in place, and unlinks it from the app's private storage. (Note: on flash storage with wear leveling, the overwrite is best-effort — old data may persist on remapped physical blocks. The app does not perform cryptographic erasure of the underlying flash cells.)
2. Sends a DELETE signal to the peer through the signaling channel, asking the peer's app to do the same.

The DELETE signal is **best-effort**. If the peer is offline, the signal queues; if the queue is purged or the peer never reconnects to the same signaling URL, the peer's copy is **not deleted**. You should assume that any message you have sent may persist on the recipient's device indefinitely, regardless of your local deletion action.

---

## 7. Auto-delete and spoliation

The per-contact auto-delete timer (None / 1 h / 24 h / 7 d) affects messages your contact has set on **their** copy of the conversation; the timer is enforced on the device that holds the message.

- **Messages you receive:** the timer starts when delivery completes on your device. After the interval elapses, the database row is removed and the encrypted audio file is unlinked, with the same flash-storage caveat described in Section 6.
- **Messages you send:** your local outbound copy is **not** auto-deleted. Sent messages remain on your device until you delete them manually or uninstall the app.

You are solely responsible for compliance with any legal hold, e-discovery, regulatory retention, or evidence-preservation obligation that may apply to communications you send or receive. If you are subject to such obligations, set auto-delete to **None** and do not delete messages manually. VoiceDrop is not designed or warranted as a record-keeping system for any regulated communication (including HIPAA, GLBA, SOX, MiFID, or similar regimes).

---

## 8. Your rights (GDPR, UK GDPR, CCPA, and similar laws)

If you are a data subject under the EU GDPR, UK GDPR, the California Consumer Privacy Act / CPRA, or another similar regime, the following applies.

### 8.1 Rights you can exercise yourself, on your own device

Because all message content lives on your device, you already have:

- **Access** to all messages and contact data via the app.
- **Rectification** by editing your display name, signaling URL, or per-contact settings.
- **Erasure** by deleting messages, removing contacts, clearing app data from Android Settings, or uninstalling the app — any of these removes locally stored data.
- **Restriction** by toggling network state or revoking permissions in Android Settings.
- **Objection** by uninstalling the app at any time.

VoiceDrop does not provide a separate export feature in v1.0.x; on a non-rooted device, the encrypted message archive is not extractable, by design.

### 8.2 Rights against the developer

The developer holds no personal data of yours on any server. Subject access, deletion, and correction requests directed at the developer in respect of message content cannot be acted on because the relevant data does not exist on developer-controlled systems. The developer is not a "business" under CCPA § 1798.140(d) (no revenue threshold met, no personal information processed by the developer), so the statutory request infrastructure (toll-free number, 45-day response window, etc.) is not applicable.

### 8.3 Rights against third parties

- **Cloudflare** holds the operational logs produced by its edge in front of your Worker and by its STUN service. Erasure or access requests for that data must be directed to Cloudflare via their published process.
- **Google** holds the operational logs produced by its STUN endpoints. Requests must be directed to Google.
- **Other VoiceDrop users** hold the copy of any message that you sent to them. The best-effort DELETE signal (Section 6) is your only technical remedy; legally, your erasure right against another individual is limited by applicable law.

### 8.4 Children

VoiceDrop is **not directed at children under 13** (COPPA, 15 U.S.C. §§ 6501–6506). In the EEA and UK, GDPR Art. 8 sets a digital-services consent age between 13 and 16 depending on Member State (13 in the UK; 16 by default in the EU unless lowered nationally). The app has no mechanism to verify user age. By installing the app, you represent that you are old enough under your local law to consent to the processing described here, or that you have parental consent. The app does not knowingly collect personal information from children below these ages. A parent or guardian who wishes to remove any data of a child user need only uninstall the app from the child's device or clear its data from Android Settings.

### 8.5 No sale, no sharing for cross-context advertising

The developer does not sell or share personal information as those terms are defined under the CCPA/CPRA, and has never done so. The app makes no advertising-related network requests. The app does not respond to Do Not Track headers because the app sends no web tracking signals to which a DNT response would apply.

### 8.6 Complaints

If you are in the EEA, you may lodge a complaint with the supervisory authority in your Member State of residence (GDPR Art. 77). If you are in the UK, the supervisory authority is the Information Commissioner's Office (https://ico.org.uk/). Other jurisdictions have analogous channels.

---

## 9. Sensitive content warning

Voice recordings may contain protected health information, biometric voiceprints, financial information, communications subject to attorney-client or other privileges, or other sensitive personal data. VoiceDrop is **not** a HIPAA-covered service, **not** a HIPAA Business Associate, and **not** designed for collection or storage of biometric identifiers under Illinois BIPA, Texas CUBI, the Washington My Health My Data Act, or similar regimes. Do not use VoiceDrop for content whose handling is regulated under those frameworks.

---

## 10. Data retention

| Where | What | How long |
|---|---|---|
| Your device | Message audio, contacts, settings | Until you delete a message, the auto-delete timer expires it (receiving side only), you clear app data, or you uninstall. |
| Your Cloudflare Worker | Relayed ciphertext blobs | Until the recipient acknowledges pickup, or 7 days, whichever comes first. |
| Cloudflare edge / STUN | IP-level operational logs | Per Cloudflare's published retention policy. |
| Google STUN | IP-level operational logs | Per Google's published retention policy. |
| Developer systems | (none) | Not applicable — the developer operates no server. |

**Retention criteria for relayed ciphertext on your Worker:** deleted upon acknowledged recipient pickup; otherwise expired automatically after 7 days.

---

## 11. Permissions used

VoiceDrop requests only the Android permissions it needs to function. The exhaustive list, matching `AndroidManifest.xml`:

- `RECORD_AUDIO` — to record voice messages when you tap the Quick Settings tile or record button.
- `INTERNET`, `ACCESS_NETWORK_STATE` — for signaling, STUN, peer-to-peer, and relay delivery.
- `ACCESS_WIFI_STATE`, `CHANGE_WIFI_MULTICAST_STATE` — for mDNS-based LAN peer discovery.
- `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_MICROPHONE`, `FOREGROUND_SERVICE_MEDIA_PLAYBACK` — so Android does not kill the recording or playback service mid-message.
- `POST_NOTIFICATIONS` (Android 13+) — to notify you of incoming messages and ongoing recording state.
- `CAMERA` — for the QR pairing flow. Used only while the pairing screen is open; never in the background.
- `WAKE_LOCK` — to keep the device awake during active recording or live streaming.
- `VIBRATE` — to vibrate on incoming-message notifications.

The app does **not** request location, contacts, SMS, call log, phone state, or storage permissions.

---

## 12. Security reporting

To report a security vulnerability, see [SECURITY.md](SECURITY.md). Please do **not** open public GitHub issues for security reports.

For privacy-related questions that are not security vulnerabilities, open an issue at https://github.com/DaniilBabanin/VoiceDroP/issues.

---

## 13. Changes to this policy

This policy is versioned alongside the app. Material changes will:

1. Increment the version number at the top of this document.
2. Update the effective date.
3. Be summarized in the GitHub release notes for the version that introduces them.

The full revision history is visible in the Git log for this file.

---

## 14. Disclaimer

VoiceDrop is open-source software distributed under the terms of the LICENSE file in this repository. The software is provided "as is" without warranty of any kind. This privacy policy describes the design of the software; it is not a contract and does not create rights against the developer beyond those that already exist under applicable law in your jurisdiction.
