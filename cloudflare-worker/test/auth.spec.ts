import { describe, it, expect, beforeEach } from 'vitest';
import { getAuthSecret, getServerKeyPair, serverPublicRaw, toHex, fromHex, b64encode, b64decode } from '../src/auth';

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
