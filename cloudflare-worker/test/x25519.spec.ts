import { describe, it, expect } from 'vitest';

describe('X25519 JWK persistence', () => {
  it('keygen -> jwk export -> jwk import -> deriveBits round-trips', async () => {
    const a = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
    const b = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;

    // Persist A's private key as JWK and re-import (simulates DO storage round-trip).
    const aPrivJwk = await crypto.subtle.exportKey('jwk', a.privateKey);
    const aPriv2 = await crypto.subtle.importKey('jwk', aPrivJwk, { name: 'X25519' }, true, ['deriveBits']);

    const ss1 = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: b.publicKey }, aPriv2, 256));
    const ss2 = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: a.publicKey }, b.privateKey, 256));
    expect(Buffer.from(ss1).equals(Buffer.from(ss2))).toBe(true);

    // raw export of a PUBLIC key must work (we send serverPub raw)
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', a.publicKey));
    expect(raw.length).toBe(32);
  });
});
