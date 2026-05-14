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

- **End-to-end encryption**: All voice messages are encrypted with XChaCha20-Poly1305 using a per-contact session key derived via X25519 ECDH + HKDF-SHA256. The signaling server never sees plaintext.
- **No server-side message storage**: The Cloudflare Worker is signaling-only. Voice data is never relayed or stored by the server.
- **Local key protection**: The X25519 private key is wrapped with an AES-256-GCM key stored in the Android Keystore hardware-backed TEE/StrongBox.
- **Verified pairing**: Contact exchange requires a 4-emoji HMAC-SHA256 out-of-band verification ceremony to prevent MITM during pairing.
- **No accounts**: No user accounts, no phone numbers, no email addresses are collected.
- **`allowBackup="false"`**: App data is excluded from Android cloud backup.
- **Secure deletion**: Message files are overwritten with zeros before deletion.

## Export Control Notice

This software uses strong cryptography (X25519, XChaCha20-Poly1305, AES-256-GCM). Export, re-export, or transfer of this software may be subject to export control laws in your jurisdiction, including the U.S. Export Administration Regulations (EAR). It is your responsibility to comply with applicable export control laws before downloading, using, or distributing this software.

This software is classified under ECCN 5D002 and is eligible for the TSU exception under EAR 740.13(e) as publicly available encryption source code.

## Cryptographic Libraries

VoiceDrop relies on the following audited cryptographic libraries:

- **Google Tink** (Apache 2.0) — X25519, HKDF, XChaCha20-Poly1305
- **Android Keystore System** — AES-256-GCM hardware-backed key storage
- **libopus** (BSD-3-Clause) — audio codec (not a security primitive); attribution in [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES)

## Known Limitations

- **Forward secrecy**: v1.0 does not implement forward secrecy (Double Ratchet). Session keys are static per contact. Forward secrecy via Signal Protocol is planned for v1.1.
- **Metadata**: Message timing and contact graph are visible to the signaling server operator.
- **Device compromise**: If the device is compromised, all messages and keys on that device are exposed.
