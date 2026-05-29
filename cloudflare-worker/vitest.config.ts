import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        main: './src/index.ts',
        // nodejs_compat is required by @cloudflare/vitest-pool-workers' harness; the
        // production worker uses only WebCrypto + DO APIs, so wrangler.toml needs no flag.
        miniflare: { compatibilityDate: '2024-01-01', compatibilityFlags: ['nodejs_compat'] },
      },
    },
  },
});
