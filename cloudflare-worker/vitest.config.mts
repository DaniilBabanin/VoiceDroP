import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    cloudflareTest({
      // Load bindings (SIGNALING_ROOM DO, migrations) + main + compat date from the
      // real wrangler.toml so /pull tests hit the same binding topology as production.
      // Without this, env.SIGNALING_ROOM is undefined in the isolate.
      wrangler: { configPath: './wrangler.toml' },
      // nodejs_compat is required by the vitest-pool-workers harness only; it is NOT in
      // wrangler.toml because the production worker uses just WebCrypto + DO APIs.
      miniflare: { compatibilityFlags: ['nodejs_compat'] },
    }),
  ],
});
