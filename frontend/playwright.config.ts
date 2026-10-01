import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './e2e', workers: 1, timeout: 120000,
  use: { baseURL: process.env.E2E_BASE_URL || 'http://localhost:15173', browserName: 'chromium', headless: true },
  reporter: 'list',
});
