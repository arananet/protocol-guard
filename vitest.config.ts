import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        '.next/',
        '**/*.d.ts',
        '**/*.config.*',
        '**/tests/**',
      ],
    },
  },
  resolve: {
    alias: {
      '@protocol-tester/shared': path.resolve(__dirname, './packages/shared/src'),
      '@protocol-tester/mcp-sdk': path.resolve(__dirname, './packages/mcp-sdk/src'),
      '@protocol-tester/a2a-sdk': path.resolve(__dirname, './packages/a2a-sdk/src'),
    },
  },
});
