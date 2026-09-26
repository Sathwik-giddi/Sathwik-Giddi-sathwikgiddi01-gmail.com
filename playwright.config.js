import { defineConfig, devices } from '@playwright/test';

const PORT = 8124;

// One process serves both halves, so the test server is the real server — not a
// stand-in. `npm test` builds the SPA first, then boots it against a throwaway DB.
export default defineConfig({
  testDir: 'tests',
  timeout: 30_000,
  fullyParallel: false,        // the tests mutate shared org state, so keep them ordered
  workers: 1,
  reporter: [['list']],

  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'retain-on-failure',
  },

  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

  webServer: {
    // `npm run build` added, and this is the second change to this file. The suite serves the
    // built bundle, because NODE_ENV is production below and production serves `dist/` rather than
    // the Vite middleware. So `npm test` was asserting against whatever happened to be in `dist/`,
    // which is whatever the last build produced and nothing more.
    //
    // That is not a hypothetical. While writing tests/device-actions.spec.js I mutated the source to
    // put a `window.confirm` back and the "no native dialog" test still passed, because the bundle
    // on disk was from before the mutation. A green suite that is testing stale code is worse than
    // no suite, because it is believed. Building here means every invocation asserts the code in
    // the working tree, whatever was run to start it.
    command: 'npm run build && node scripts/load-db.js && node server/index.js',
    url: `http://localhost:${PORT}/v1/auth/me`,
    reuseExistingServer: false,
    timeout: 30_000,
    env: {
      DATABASE_FILE: 'e2e.db',
      PORT: String(PORT),
      NODE_ENV: 'production',
      JWT_SECRET: 'e2e-secret',
      // Added, not in the hand-out. The server now refuses to boot in production without this,
      // because a known key makes the stored refresh/invite token hashes reproducible by anyone
      // holding the database. `JWT_SECRET` alone is no longer enough to start the test server.
      APP_HASH_KEY: 'e2e-hash-key',
      // Same again, and this one is load-bearing for security rather than hygiene: without a pepper
      // the `password_hash` column is crackable offline on its own, whatever the KDF cost.
      PASSWORD_PEPPER: 'e2e-pepper',
    },
  },
});
