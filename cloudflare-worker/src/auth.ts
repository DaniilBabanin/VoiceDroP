// src/auth.ts — Pull-auth primitives (Finding #1). See plan/2026-05-29_A1-challenge-response-design.md.

const MAC_CONTEXT = new TextEncoder().encode('vdrop-pull-auth-v1');
export const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

// --- byte helpers ---
export function toHex(b: Uint8Array): string {
  let s = ''; for (const x of b) s += x.toString(16).padStart(2, '0'); return s;
}
export function fromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
export function b64encode(b: Uint8Array): string {
  let s = ''; for (const x of b) s += String.fromCharCode(x); return btoa(s);
}
export function b64decode(s: string): Uint8Array {
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out;
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len); let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; } return out;
}
function beU64(n: number): Uint8Array {
  const out = new Uint8Array(8); const dv = new DataView(out.buffer);
  dv.setBigUint64(0, BigInt(n), false); return out;
}
function readBeU64(b: Uint8Array): number {
  return Number(new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0, false));
}

// Subset of DurableObjectStorage we depend on (keeps unit tests stub-able).
export interface KvLike { get<T>(k: string): Promise<T | undefined>; put<T>(k: string, v: T): Promise<void>; }

// --- per-DO secret (HMAC key for tokens) ---
export async function getAuthSecret(storage: KvLike): Promise<CryptoKey> {
  let stored = await storage.get<string>('auth_secret_b64');
  if (!stored) {
    const bytes = new Uint8Array(32); crypto.getRandomValues(bytes);
    stored = b64encode(bytes); await storage.put('auth_secret_b64', stored);
  }
  return crypto.subtle.importKey('raw', b64decode(stored), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

// --- per-DO persistent server X25519 keypair ---
export async function getServerKeyPair(storage: KvLike): Promise<CryptoKeyPair> {
  const stored = await storage.get<{ priv: JsonWebKey; pub: JsonWebKey }>('server_x25519');
  if (stored) {
    const privateKey = await crypto.subtle.importKey('jwk', stored.priv, { name: 'X25519' }, true, ['deriveBits']);
    const publicKey = await crypto.subtle.importKey('jwk', stored.pub, { name: 'X25519' }, true, []);
    return { privateKey, publicKey };
  }
  const kp = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits'])) as CryptoKeyPair;
  const priv = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const pub = await crypto.subtle.exportKey('jwk', kp.publicKey);
  await storage.put('server_x25519', { priv, pub });
  return kp;
}
export async function serverPublicRaw(kp: CryptoKeyPair): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
}

// helpers re-used by Task W3/W4
export { MAC_CONTEXT, concat, beU64, readBeU64 };
