# Security Policy

## Supported Versions

Only the latest release tag on the `main` branch receives security fixes.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email the maintainer at the address in the repository contact card. Include:

1. A clear description of the vulnerability
2. Steps to reproduce or proof-of-concept
3. The potential impact (confidentiality, integrity, availability)
4. Any suggested mitigations

You will receive an acknowledgement within 48 hours and a resolution timeline within 7 days.

## Security Design

VoiceDrop is designed with the following security properties:

- **End-to-end encryption with forward secrecy**: All voice messages are encrypted with a Double Ratchet (X25519 ECDH ratchet → HKDF-SHA256 chain keys → ChaCha20-Poly1305 AEAD) deriving a fresh key per message. Compromising a message key does not expose earlier messages (forward secrecy), and the DH ratchet plus the session-reset protocol restore security after a state compromise (post-compromise security). The signaling server never sees plaintext.
- **No plaintext on the server**: Voice data is end-to-end encrypted before it leaves the device. The Cloudflare Worker handles signaling and store-and-forward relay of ciphertext blobs only — it never sees plaintext audio or decryption keys. Relayed ciphertext is deleted from Durable Object storage once the recipient acknowledges pickup, and undelivered blobs expire after 7 days.
- **Local key protection**: The X25519 private key is wrapped with an AES-256-GCM key stored in the Android Keystore hardware-backed TEE/StrongBox.
- **Verified pairing**: Contact exchange supports a 6-emoji short-authentication-string (SAS) out-of-band verification ceremony to detect MITM during pairing.
- **No accounts**: No user accounts, no phone numbers, no email addresses are collected.
- **`allowBackup="false"`**: App data is excluded from Android cloud backup.
- **Secure deletion (best-effort)**: Message files are overwritten with zeros in place before deletion. On modern flash storage with wear leveling and file-based encryption this is best-effort, not a guarantee — old blocks may survive at the physical layer.

## Export Control Notice

This software uses strong cryptography (X25519, ChaCha20-Poly1305, AES-256-GCM). Export, re-export, or transfer of this software may be subject to export control laws in your jurisdiction. It is your responsibility to comply with applicable export control laws before downloading, using, or distributing this software.

## Cryptographic Libraries

VoiceDrop relies on the following audited cryptographic libraries:

- **Google Tink** (Apache 2.0) — X25519, ChaCha20-Poly1305
- **Android JCA / Keystore System** — HMAC-SHA256 (HKDF), AES-256-GCM hardware-backed key wrapping
- **libopus** (BSD-3-Clause) — audio codec (not a security primitive); attribution in [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES)

## Known Limitations

- **Metadata**: Message timing, IP addresses, and the contact graph (per-pair key fingerprints) are visible to the signaling server operator.
- **Device compromise**: If the device is compromised, all locally stored messages and keys on that device are exposed. Stored history is plaintext-at-rest behind Android file-based encryption (the ratchet protects data in transit, not a seized unlocked device).
- **Update authenticity for sideload users**: The release keystore is committed to this repository (documented, intentional — see README), so the APK signature proves nothing about who built an update. The only trust anchor is the SHA-256 hash and dex witnesses published on each GitHub release page: verify the hash of any APK before installing it over an existing install.
- **Lock-screen recording widget**: by design (walkie-talkie UX) the home-screen widget starts recording without unlocking the device when the mic permission is already granted. Recorded audio can only go to your own paired contacts; anyone holding the locked phone could still send them a voice message.
