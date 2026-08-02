import { describe, expect, it } from 'vitest';
import { InvalidDomainError, normaliseDomain } from '../src/lib/check.js';

describe('accepts what people actually paste', () => {
  it.each([
    ['example.com', 'example.com'],
    ['  Example.COM  ', 'example.com'],
    ['example.com.', 'example.com'],
    ['https://example.com', 'example.com'],
    ['http://example.com/pricing?utm=1#x', 'example.com'],
    ['someone@example.com', 'example.com'],
    ['example.com:443', 'example.com'],
    ['mail.example.co.uk', 'mail.example.co.uk'],
  ])('%s → %s', (input, expected) => {
    expect(normaliseDomain(input)).toBe(expected);
  });
});

describe('rejects everything that is not a public domain', () => {
  // This endpoint makes outbound DNS queries on user input. Without these rejections
  // it is a DNS scanning proxy aimed at whatever the caller names.
  it.each([
    ['', 'empty'],
    ['   ', 'whitespace'],
    ['localhost', 'single label'],
    ['127.0.0.1', 'IPv4 literal'],
    ['::1', 'IPv6 literal'],
    ['192.168.1.1', 'private IPv4'],
    ['router.local', 'mDNS suffix'],
    ['db.internal', 'internal suffix'],
    ['thing.test', 'reserved TLD'],
    ['no-dots', 'no suffix'],
    ['例え.jp', 'non-punycode IDN'],
  ])('rejects %s (%s)', (input) => {
    expect(() => normaliseDomain(input)).toThrow(InvalidDomainError);
  });

  it('discards path-like junk instead of carrying it into a query', () => {
    // Not a rejection: everything from the first slash is dropped, so the traversal
    // attempt reduces to an ordinary domain. What matters is that no part of the
    // path survives into a DNS name.
    expect(normaliseDomain('a.com/../../etc/passwd')).toBe('a.com');
    expect(normaliseDomain('a.com/%00')).toBe('a.com');
  });

  it('rejects an over-long name', () => {
    expect(() => normaliseDomain(`${'a'.repeat(250)}.com`)).toThrow(InvalidDomainError);
  });

  it('explains itself rather than throwing a bare error', () => {
    expect(() => normaliseDomain('127.0.0.1')).toThrow(/not an IP address/);
    expect(() => normaliseDomain('localhost')).toThrow(/not a public domain/);
  });
});
