import { describe, it, expect, beforeEach } from 'vitest';
import { getAuthSecret, getServerKeyPair, serverPublicRaw, toHex, fromHex, b64encode, b64decode, verifyProof, buildProofMac, mintToken, verifyToken, TOKEN_TTL_MS } from '../src/auth';

// Minimal in-memory storage stub matching the bits of DurableObjectStorage we use.
class MemStore {
  private m = new Map<string, unknown>();
  async get<T>(k: string): Promise<T | undefined> { return this.m.get(k) as T | undefined; }
  async put<T>(k: string, v: T): Promise<void> { this.m.set(k, v as unknown); }
}

describe('auth helpers', () => {
  let store: MemStore;
  beforeEach(() => { store = new MemStore() as unknown as MemStore; });

  it('hex/base64 round-trip', () => {
    const bytes = new Uint8Array([0, 1, 2, 254, 255]);
    expect(toHex(fromHex(toHex(bytes)))).toBe(toHex(bytes));
    expect(toHex(b64decode(b64encode(bytes)))).toBe(toHex(bytes));
  });

  it('getAuthSecret is stable across calls (generate once, persist)', async () => {
    const k1 = await getAuthSecret(store as any);
    const k2 = await getAuthSecret(store as any);
    const sig1 = new Uint8Array(await crypto.subtle.sign('HMAC', k1, new Uint8Array([1, 2, 3])));
    const sig2 = new Uint8Array(await crypto.subtle.sign('HMAC', k2, new Uint8Array([1, 2, 3])));
    expect(toHex(sig1)).toBe(toHex(sig2));
  });

  it('getServerKeyPair is stable; serverPublicRaw is 32 bytes', async () => {
    const kp1 = await getServerKeyPair(store as any);
    const pub1 = await serverPublicRaw(kp1);
    const kp2 = await getServerKeyPair(store as any);
    const pub2 = await serverPublicRaw(kp2);
    expect(pub1.length).toBe(32);
    expect(toHex(pub1)).toBe(toHex(pub2));
  });
});

describe('verifyProof', () => {
  it('accepts a correct proof and rejects a tampered mac', async () => {
    const server = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
    const identity = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
    const identityPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', identity.publicKey));
    const fpBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', identityPubRaw));
    const nonce = new Uint8Array(16); crypto.getRandomValues(nonce);

    // Client side computes ss with its private key against serverPub:
    const serverPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', server.publicKey));
    const mac = await buildProofMac(identity.privateKey, serverPubRaw, nonce, fpBytes); // returns Uint8Array

    expect(await verifyProof(server.privateKey, identityPubRaw, nonce, fpBytes, b64encode(mac))).toBe(true);

    const bad = mac.slice(); bad[0] ^= 0xff;
    expect(await verifyProof(server.privateKey, identityPubRaw, nonce, fpBytes, b64encode(bad))).toBe(false);
  });

  // GOLDEN cross-language vector — must equal PullAuthTest.golden_vector (Part 0).
  // Test-only: derive ss from the raw SERVER_PRIV scalar with @noble/curves, since the
  // worker runtime cannot raw-import a private scalar to a CryptoKey. @noble stays out of src/.
  it('matches the frozen Kotlin golden vector', async () => {
    const { x25519 } = await import('@noble/curves/ed25519'); // test dependency only
    const serverPriv = fromHex('2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40');
    const identityPub = fromHex('07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c'); // from Part 0
    const nonce = fromHex('000102030405060708090a0b0c0d0e0f');
    const fpBytes = fromHex('aaa8fff703b50b2297f4f6e13508f72420d96fd01ebb84cb074449caaef64041'); // from Part 0 (== SHA-256(IDENTITY_PUB))

    const ss = x25519.getSharedSecret(serverPriv, identityPub); // server side: X25519(serverPriv, identityPub)
    const ssKey = await crypto.subtle.importKey('raw', ss, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const ctx = new TextEncoder().encode('vdrop-pull-auth-v1');
    const msg = new Uint8Array([...ctx, ...nonce, ...fpBytes]);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', ssKey, msg));
    expect(toHex(mac)).toBe('26a80279407ebd04de55ca3702578ebce77debb73129c853caadee7883a32317'); // == Kotlin GOLDEN_MAC
  });
});

describe('token mint/verify', () => {
  it('mints a token that verifies for the right fp and not others', async () => {
    const store = new MemStore() as any;
    const secret = await getAuthSecret(store);
    const fpBytes = new Uint8Array(32); crypto.getRandomValues(fpBytes);
    const now = 1_700_000_000_000;
    const { token, expiresAt } = await mintToken(secret, fpBytes, now);
    expect(expiresAt).toBe(now + TOKEN_TTL_MS);
    expect(await verifyToken(secret, token, toHex(fpBytes), now + 1000)).toBe(true);
    expect(await verifyToken(secret, token, toHex(fpBytes), now + TOKEN_TTL_MS + 1)).toBe(false); // expired
    const otherFp = new Uint8Array(32); crypto.getRandomValues(otherFp);
    expect(await verifyToken(secret, token, toHex(otherFp), now + 1000)).toBe(false); // wrong fp
  });

  it('rejects a tampered token and garbage input', async () => {
    const store = new MemStore() as any;
    const secret = await getAuthSecret(store);
    const fpBytes = new Uint8Array(32);
    const now = 1_700_000_000_000;
    const { token } = await mintToken(secret, fpBytes, now);
    const raw = b64decode(token); raw[50] ^= 0xff;
    expect(await verifyToken(secret, b64encode(raw), toHex(fpBytes), now + 1000)).toBe(false);
    expect(await verifyToken(secret, 'not base64!!', toHex(fpBytes), now)).toBe(false);
  });
});
