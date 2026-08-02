// @ts-check
import node from '@astrojs/node';
import { defineConfig } from 'astro/config';

export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'standalone' }),
  server: { host: true, port: 3000 },
  // Caddy terminates TLS and adds the forwarded headers the rate limiter reads.
  site: process.env.PUBLIC_SITE_URL || 'http://localhost:3000',
});
