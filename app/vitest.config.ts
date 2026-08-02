import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Live-DNS suites are slow and flaky by nature; they are opt-in via LIVE_DNS=1.
    exclude: process.env.LIVE_DNS ? [] : ['test/**/*.live.test.ts'],
    testTimeout: 30_000,
  },
});
