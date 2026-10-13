import { describe, expect, it } from 'vitest';
import { apiBody } from '../src/lib/api-body.js';
import { runCheck } from '../src/lib/check.js';
import { FakeDns, type Zone } from './fake-dns.js';

const noDnssec = async (domain: string) => ({ signed: false, zone: domain, unknown: true });
const check = (domain: string, zone: Zone) =>
  runCheck(domain, { dns: new FakeDns(zone), dnssec: noDnssec });

describe('dmarc.pct in the API body', () => {
  it('is 100 with pctTag null when the record has no pct= (gmail.com shape)', async () => {
    const r = await check('example.com', {
      TXT: { 'example.com': ['v=spf1 -all'], '_dmarc.example.com': ['v=DMARC1; p=none; sp=quarantine; rua=mailto:d@example.com'] },
    });
    expect(apiBody(r).dmarc).toMatchObject({ pct: 100, pctTag: null });
  });
});
