import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // One emulator, shared: files must not clear each other's data mid-run.
    fileParallelism: false,
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
