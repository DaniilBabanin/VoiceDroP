import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { env } from 'cloudflare:test';

const FP = 'a'.repeat(64); // any 64-hex; no token bound to it
const ROOM = FP + FP;       // sorted concat of (FP, FP)

describe('/pull auth', () => {
  it('401s without a token', async () => {
    const res = await worker.fetch(new Request(`https://x/pull/${ROOM}/${FP}`), env as any);
    expect(res.status).toBe(401);
  });
  it('401s with a garbage bearer', async () => {
    const res = await worker.fetch(
      new Request(`https://x/pull/${ROOM}/${FP}`, { headers: { Authorization: 'Bearer nope' } }),
      env as any,
    );
    expect(res.status).toBe(401);
  });
});
