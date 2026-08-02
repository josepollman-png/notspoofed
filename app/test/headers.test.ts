import { describe, expect, it } from 'vitest';
import { alignmentOf, analyzeHeaders } from '../src/lib/headers/analyze.js';
import { parseAuthResults, parseHeaders, parseReceived, splitHeaders } from '../src/lib/headers/parse.js';

/** A clean delivery: DKIM signed by the From domain, everything aligned. */
const ALIGNED = `Delivered-To: you@example.org
Received: from mx.google.com (mx.google.com [209.85.220.41])
        by mail.example.org with ESMTPS id abc123
        for <you@example.org>; Mon, 27 Jul 2026 09:15:02 -0700 (PDT)
Received: from out.sender.com (out.sender.com [203.0.113.5])
        by mx.google.com with ESMTPS id def456
        for <you@example.org>; Mon, 27 Jul 2026 09:14:22 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@sender.com header.s=selector1 header.b=AbCd;
       spf=pass (google.com: domain of bounce@sender.com designates 203.0.113.5 as permitted sender) smtp.mailfrom=bounce@sender.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sender.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=sender.com;
        s=selector1; h=from:to:subject:date; bh=abc=; b=xyz=
Return-Path: <bounce@sender.com>
From: Sender Support <hello@sender.com>
To: you@example.org
Subject: Your receipt
Date: Mon, 27 Jul 2026 16:14:20 +0000
Message-ID: <abc@sender.com>`;

/** The failure this tool exists to explain: SPF passes, but for the ESP's own
 *  domain, and nothing is DKIM signed by the From domain. */
const MISALIGNED = `Received: from mx.google.com (mx.google.com [209.85.220.41])
        by mail.example.org; Mon, 27 Jul 2026 09:20:00 -0700 (PDT)
Received: from mail.esp-vendor.net (mail.esp-vendor.net [198.51.100.9])
        by mx.google.com; Mon, 27 Jul 2026 09:14:00 -0700 (PDT)
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of bounce@esp-vendor.net designates 198.51.100.9 as permitted sender) smtp.mailfrom=bounce@esp-vendor.net;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=yourcompany.com
Return-Path: <bounce@esp-vendor.net>
From: Your Company <hello@yourcompany.com>
To: you@example.org
Subject: Newsletter`;

describe('field splitting', () => {
  it('unfolds continuation lines', () => {
    // The DKIM-Signature above is wrapped across two lines. Failing to unfold makes
    // every tag after the wrap invisible.
    const parsed = parseHeaders(ALIGNED);
    expect(parsed.dkim[0]).toMatchObject({ domain: 'sender.com', selector: 'selector1' });
    expect(parsed.dkim[0]!.signedHeaders).toEqual(['from', 'to', 'subject', 'date']);
  });

  it('stops at the blank line separating headers from body', () => {
    const fields = splitHeaders('From: a@b.com\nSubject: hi\n\nFrom: not-a-header@evil.com');
    expect(fields.map((f) => f.key)).toEqual(['from', 'subject']);
  });

  it('handles CRLF line endings', () => {
    expect(splitHeaders('From: a@b.com\r\nSubject: hi\r\n')).toHaveLength(2);
  });

  it('keeps repeated headers rather than collapsing them', () => {
    expect(parseHeaders(ALIGNED).hops).toHaveLength(2);
  });
});

describe('address extraction', () => {
  it('reads the address out of a display-name form', () => {
    const p = parseHeaders(ALIGNED);
    expect(p.from).toBe('hello@sender.com');
    expect(p.fromDomain).toBe('sender.com');
    expect(p.returnPath).toBe('bounce@sender.com');
  });
});

describe('Received chain', () => {
  it('reverses into the order the message actually travelled', () => {
    // Relays prepend, so the raw list is newest-first. Getting this backwards makes
    // every delay negative and the path read inside out.
    const hops = parseHeaders(ALIGNED).hops;
    expect(hops[0]!.by).toBe('mx.google.com');
    expect(hops[1]!.by).toBe('mail.example.org');
  });

  it('computes hop delays', () => {
    const hops = parseHeaders(ALIGNED).hops;
    expect(hops[0]!.delaySeconds).toBeUndefined(); // nothing to compare against
    expect(hops[1]!.delaySeconds).toBe(40);
  });

  it('clamps negative delays caused by relay clock skew', () => {
    const skewed = parseReceived([
      'from b by second; Mon, 27 Jul 2026 09:00:00 +0000',
      'from a by first; Mon, 27 Jul 2026 09:00:30 +0000',
    ]);
    expect(skewed[1]!.delaySeconds).toBe(0);
  });

  it('survives a hop with an unparseable date', () => {
    const hops = parseReceived([
      'from c by third; Mon, 27 Jul 2026 09:02:00 +0000',
      'from b by second; not-a-date',
      'from a by first; Mon, 27 Jul 2026 09:00:00 +0000',
    ]);
    expect(hops[1]!.date).toBeUndefined();
    // Delay is measured against the last hop that had a usable clock.
    expect(hops[2]!.delaySeconds).toBe(120);
  });

  it('extracts from/by/for clauses', () => {
    const [hop] = parseReceived([
      'from out.sender.com (out.sender.com [203.0.113.5]) by mx.google.com with ESMTPS id def456 for <you@example.org>; Mon, 27 Jul 2026 09:14:22 -0700',
    ]);
    expect(hop).toMatchObject({ from: 'out.sender.com', by: 'mx.google.com', with: 'ESMTPS', for: 'you@example.org' });
  });
});

describe('Authentication-Results', () => {
  it('splits on semicolons outside parentheses', () => {
    // The SPF comment contains a semicolon-free colon, but real ones often contain
    // semicolons; splitting naively loses every method after the first comment.
    const a = parseAuthResults(
      'mx.google.com; spf=pass (google.com: domain of x@y.com; designates 1.2.3.4) smtp.mailfrom=x@y.com; dmarc=fail header.from=z.com',
    );
    expect(a.authservId).toBe('mx.google.com');
    expect(a.methods.map((m) => m.method)).toEqual(['spf', 'dmarc']);
  });

  it('reads method properties', () => {
    const a = parseHeaders(ALIGNED).auth[0]!;
    const spf = a.methods.find((m) => m.method === 'spf')!;
    expect(spf.result).toBe('pass');
    expect(spf.properties['smtp.mailfrom']).toBe('bounce@sender.com');
    const dkim = a.methods.find((m) => m.method === 'dkim')!;
    expect(dkim.properties['header.i']).toBe('@sender.com');
  });
});

describe('alignment', () => {
  it('recognises exact and organisational matches', () => {
    expect(alignmentOf('example.com', 'example.com')).toBe('strict');
    expect(alignmentOf('mail.example.com', 'example.com')).toBe('relaxed');
    expect(alignmentOf('example.co.uk', 'mail.example.co.uk')).toBe('relaxed');
    expect(alignmentOf('vendor.net', 'example.com')).toBe('none');
  });

  it('does not treat a shared public suffix as alignment', () => {
    // The naive "last two labels" approach says these align. They do not.
    expect(alignmentOf('attacker.co.uk', 'victim.co.uk')).toBe('none');
  });

  it('handles missing domains', () => {
    expect(alignmentOf(undefined, 'example.com')).toBe('none');
    expect(alignmentOf('example.com', undefined)).toBe('none');
  });
});

describe('analysis', () => {
  it('reports a clean aligned delivery as passing', () => {
    const a = analyzeHeaders(parseHeaders(ALIGNED));
    expect(a.dmarcResult).toBe('pass');
    expect(a.spf.alignment).toBe('strict');
    expect(a.dkim[0]!.alignment).toBe('strict');
    expect(a.findings.map((f) => f.id)).toContain('header-dmarc-pass');
    expect(a.findings.some((f) => f.severity === 'critical')).toBe(false);
  });

  it('explains SPF passing for the wrong domain', () => {
    const a = analyzeHeaders(parseHeaders(MISALIGNED));
    expect(a.spf.result).toBe('pass');
    expect(a.spf.authenticatedDomain).toBe('esp-vendor.net');
    expect(a.spf.alignment).toBe('none');

    const ids = a.findings.map((f) => f.id);
    expect(ids).toContain('header-spf-not-aligned');
    expect(ids).toContain('header-dmarc-fail');
    expect(ids).toContain('header-no-dkim');

    // With nothing else carrying the message, the misalignment is the critical fault
    // and the fix must name DKIM as the remedy.
    const f = a.findings.find((x) => x.id === 'header-spf-not-aligned')!;
    expect(f.severity).toBe('critical');
    expect(f.fix?.kind).toBe('action');
    expect(JSON.stringify(f.fix)).toMatch(/DKIM/);
  });

  it('downgrades SPF misalignment when an aligned DKIM signature carries the message', () => {
    const a = analyzeHeaders(parseHeaders(ALIGNED.replace('smtp.mailfrom=bounce@sender.com', 'smtp.mailfrom=bounce@esp.net')));
    expect(a.spf.alignment).toBe('none');
    const f = a.findings.find((x) => x.id === 'header-spf-not-aligned')!;
    expect(f.severity).toBe('info');
  });

  it('flags headers with no Authentication-Results as unverifiable', () => {
    const a = analyzeHeaders(parseHeaders('From: a@b.com\nSubject: hi'));
    expect(a.unverified).toBe(true);
    expect(a.findings.map((f) => f.id)).toContain('header-no-auth-results');
  });

  it('does not crash on empty or junk input', () => {
    expect(() => analyzeHeaders(parseHeaders(''))).not.toThrow();
    expect(() => analyzeHeaders(parseHeaders('nonsense without colons'))).not.toThrow();
  });

  it('flags a slow hop', () => {
    const slow = ALIGNED.replace('09:15:02 -0700', '09:20:22 -0700');
    const a = analyzeHeaders(parseHeaders(slow));
    expect(a.findings.map((f) => f.id)).toContain('header-slow-hop');
  });
});
