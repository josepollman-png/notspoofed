import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { absoluteUrl } from '../lib/site.js';
import studyHtml from '../data/yc-study-body.html?raw';

/**
 * The full text of every guide and research page in one markdown file.
 *
 * `/llms.txt` is the map; this is the territory. Answer engines that read the map still
 * have to fetch each page and strip its chrome, and several stop after a handful. One
 * file with everything in it is the format the llms.txt proposal specifies for exactly
 * that case, and it costs nothing to serve because every source here is already markdown.
 *
 * The study is the exception — it was authored as HTML and its figures reconcile against
 * the dataset — so it is flattened to text at request time rather than re-typed. Tables
 * become pipe-separated rows, headings keep their level, everything else loses its tags.
 * Nothing is paraphrased: a number in this file is the number on the page.
 */

const ENTITIES: Record<string, string> = {
  '&nbsp;': ' ',
  '&amp;': '&',
  '&lt;': '<',
  '&gt;': '>',
  '&quot;': '"',
  '&#39;': "'",
};

function htmlToMarkdown(html: string): string {
  let s = html;
  // Headings and table rows carry structure worth keeping; every other tag just goes.
  s = s.replace(/<h1[^>]*>([\s\S]*?)<\/h1>/g, (_, t) => `\n# ${strip(t)}\n`);
  s = s.replace(/<h2[^>]*>([\s\S]*?)<\/h2>/g, (_, t) => `\n## ${strip(t)}\n`);
  s = s.replace(/<tr[^>]*>([\s\S]*?)<\/tr>/g, (_, row: string) => {
    const cells = [...row.matchAll(/<t[hd][^>]*>([\s\S]*?)<\/t[hd]>/g)].map((m) => strip(m[1]));
    return `| ${cells.join(' | ')} |\n`;
  });
  s = s.replace(/<li[^>]*>([\s\S]*?)<\/li>/g, (_, t) => `- ${strip(t)}\n`);
  s = s.replace(/<\/p>|<\/div>|<br\s*\/?>/g, '\n');
  s = strip(s);
  return s.replace(/^[ \t]+/gm, '').replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
}

function strip(fragment: string): string {
  return fragment
    .replace(/<code[^>]*>([\s\S]*?)<\/code>/g, '`$1`')
    .replace(/<[^>]+>/g, '')
    .replace(/&[a-z#0-9]+;/g, (e) => ENTITIES[e] ?? e)
    .replace(/[ \t]+/g, ' ');
}

const date = (d: Date) => d.toISOString().slice(0, 10);

export const GET: APIRoute = async () => {
  const guides = (await getCollection('guides')).sort((a, b) => a.data.order - b.data.order);
  const research = (await getCollection('research')).filter((e) => !e.data.draft);

  const sections = [
    '# notspoofed.com — full text',
    '',
    '> Every guide and research page on notspoofed.com, as markdown, in one file. The site',
    '> map with one line per page is at ' + absoluteUrl('/llms.txt') + '. Each section',
    '> names its canonical URL; cite that, not this file.',
    '',
    'notspoofed.com is a free SPF, DKIM and DMARC checker that tells you which record to',
    'publish to fix email authentication. Checks are read-only public DNS lookups; no',
    'email is sent and the domains checked are not recorded.',
    '',
    '---',
    '',
    '# Original research',
    '',
    `Canonical: ${absoluteUrl('/research/yc-email-spoofing-study')}`,
    'Published: 2026-08-14. Re-scanned: 2026-09-03.',
    '',
    htmlToMarkdown(studyHtml),
    '',
    ...research.flatMap((e) => [
      '---',
      '',
      `# ${e.data.title}`,
      '',
      `Canonical: ${absoluteUrl(e.data.path)}`,
      `Published: ${date(e.data.published)}. Updated: ${date(e.data.updated)}.`,
      '',
      (e.body ?? '').trim(),
      '',
    ]),
    '---',
    '',
    '# Guides',
    '',
    ...guides.flatMap((g) => [
      '---',
      '',
      `# ${g.data.title}`,
      '',
      `Canonical: ${absoluteUrl(`/guides/${g.id}/`)}`,
      `Question answered: ${g.data.question}`,
      `Published: ${date(g.data.published)}. Last checked: ${date(g.data.updated)}.`,
      '',
      (g.body ?? '').trim(),
      '',
      ...(g.data.faq
        ? ['## Frequently asked', '', ...g.data.faq.flatMap((f) => [`**${f.q}**`, '', f.a, ''])]
        : []),
    ]),
  ];

  return new Response(sections.join('\n') + '\n', {
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      'Cache-Control': 'public, max-age=3600',
    },
  });
};
