# Export Control Notice

**Last updated:** 2026-05-14

VoiceDrop implements strong cryptography (XChaCha20-Poly1305 with 256-bit keys, X25519 elliptic-curve key exchange, HKDF-SHA256, AES-256-GCM via Android Keystore). Distribution of cryptographic software is subject to the United States Export Administration Regulations (EAR, 15 CFR Parts 730–774).

This file describes the authorities under which VoiceDrop is distributed, the destinations to which it must not be exported, and the certifications expected of downloaders.

---

## Classification

- **ECCN:** 5D002 (information security software)
- **Source code authority:** [15 CFR § 742.15(b)](https://www.bis.doc.gov/index.php/documents/regulations-docs/2329-742-15/file) — publicly available encryption source code. Source distributed via the public GitHub repository at https://github.com/DaniilBabanin/VoiceDroP is "publicly available" within the meaning of EAR § 734.3(b)(3) and § 734.7(a)(4) and, once notification is filed with BIS and NSA, is **not subject to the EAR** as source code.
- **Compiled binary authority:** [15 CFR § 740.17(b)(1)](https://www.bis.doc.gov/index.php/documents/regulations-docs/2330-740-17/file) — License Exception ENC, self-classification tier. Signed APK binaries distributed through GitHub Releases are released under this self-classification.

A one-time email notification of the public source-code URL has been (or will be, prior to the first public release tag) sent to:

- `crypt@bis.doc.gov` — Bureau of Industry and Security
- `enc@nsa.gov` — NSA Center for Cybersecurity Standards

Annual self-classification reports (or equivalent ongoing obligations) are filed as required by the EAR.

---

## Prohibited destinations

You may **not** download, install, use, re-export, or otherwise transfer VoiceDrop to, in, or for the benefit of any of the following:

- **Comprehensively sanctioned destinations:** Cuba, Iran, North Korea (Democratic People's Republic of Korea), Syria, the Crimea region of Ukraine, the so-called Donetsk People's Republic (DNR) region of Ukraine, and the so-called Luhansk People's Republic (LNR) region of Ukraine.
- **Any other destination** to which export is prohibited by [EAR Part 746](https://www.bis.doc.gov/index.php/documents/regulations-docs/2354-part-746-embargoes-and-other-special-controls/file) or by sanctions administered by the [US Office of Foreign Assets Control (OFAC)](https://ofac.treasury.gov/sanctions-programs-and-country-information).
- **Any person or entity** on the OFAC Specially Designated Nationals and Blocked Persons (SDN) List, the BIS Entity List, the BIS Denied Persons List, or any equivalent list maintained by the US Government.
- **Military end users or for military end uses** as defined in [EAR § 744.21](https://www.bis.doc.gov/index.php/documents/regulations-docs/2347-744-21/file) where § 744.21 controls apply to the destination.
- **End uses prohibited by EAR Part 744**, including but not limited to design, development, production, or use of weapons of mass destruction or their means of delivery.

The above list reflects US export controls as of the "Last updated" date above. Controls change frequently; consult the current EAR and OFAC sources before exporting.

---

## End-user certification

By downloading, installing, or using VoiceDrop, you represent and warrant that:

1. You are not located in, under the control of, or a national or resident of any country listed in the **Prohibited destinations** section above.
2. You are not on the OFAC SDN List, the BIS Entity List, the BIS Denied Persons List, or any equivalent restricted-party list.
3. You will not use VoiceDrop for any end use prohibited by US law, including but not limited to those described in EAR Part 744.
4. You will not re-export, transfer, or otherwise make VoiceDrop available to any destination, person, or end use prohibited by the EAR or OFAC sanctions.

If you cannot make these representations, you must not download or use VoiceDrop.

---

## Contact

For export-control questions specifically, open an issue at https://github.com/DaniilBabanin/VoiceDroP/issues. The maintainer is not export-control counsel and cannot provide legal advice. If you are uncertain whether your intended use is permitted, consult qualified counsel or contact the [Bureau of Industry and Security](https://www.bis.doc.gov/) directly.
