import { describe, it, expect } from 'vitest';

describe('webcrypto', () => {
  it('exposes subtle + getRandomValues', () => {
    expect(typeof crypto.subtle.deriveBits).toBe('function');
    const b = new Uint8Array(4); crypto.getRandomValues(b);
    expect(b.some((x) => x !== 0)).toBe(true);
  });
});
