// @ts-check
import node from '@astrojs/node';
import { defineConfig } from 'astro/config';

export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'standalone' }),
  server: { host: true, port: 3000 },
  // Caddy terminates TLS and adds the forwarded headers the rate limiter reads.
  site: process.env.PUBLIC_SITE_URL || 'http://localhost:3000',
  /*
   * Off, because it was deleting spaces from sentences.
   *
   * The default collapses the newline and indentation between a line of prose and an
   * inline element on the next line — and that whitespace is a *word space*, not layout.
   * Text wrapped the way every file here wraps it came out as "The<a>full dataset</a> is
   * published", including in the site footer, which put it on every page.
   *
   * The alternative is keeping each inline link on the same source line as the text
   * around it, which means unbounded line lengths and a rule nobody will remember. The
   * few hundred bytes of indentation this costs are not worth one missing space.
   */
  compressHTML: false,
});
