import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        // Load bindings (SIGNALING_ROOM DO, RELAY_STORE KV, migrations) + main + compat
        // date from the real wrangler.toml so /pull tests hit the same binding topology
        // as production. Without this, env.SIGNALING_ROOM is undefined in the isolate.
        wrangler: { configPath: './wrangler.toml' },
        // nodejs_compat is required by the vitest-pool-workers harness only; it is NOT in
        // wrangler.toml because the production worker uses just WebCrypto + DO APIs.
        miniflare: { compatibilityFlags: ['nodejs_compat'] },
      },
    },
  },
});
