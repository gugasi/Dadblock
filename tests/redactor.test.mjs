import test from 'node:test';
import assert from 'node:assert/strict';
import { redactPII } from '../extension/utils/redactor.js';

test('returns an empty string for empty input', () => {
  assert.equal(redactPII(''), '');
  assert.equal(redactPII(null), '');
  assert.equal(redactPII(undefined), '');
});

test('leaves ordinary text alone', () => {
  const text = 'Your prize is waiting. Pay a small shipping fee to claim it.';
  assert.equal(redactPII(text), text);
});

test('removes email addresses', () => {
  const out = redactPII('Write to jane.doe+news@example.co.uk for details');
  assert.ok(!out.includes('jane.doe'));
  assert.ok(out.includes('[REDACTED_EMAIL]'));
});

test('removes payment card numbers, with or without spaces and dashes', () => {
  for (const card of ['4111 1111 1111 1111', '4111-1111-1111-1111', '4111111111111111']) {
    const out = redactPII(`card ${card} expires soon`);
    assert.ok(!out.includes('4111'), card);
    assert.ok(out.includes('[REDACTED_CREDIT_CARD]'), card);
  }
});

test('removes US-style SSNs', () => {
  const out = redactPII('ssn 123-45-6789');
  assert.ok(!out.includes('6789'));
  assert.ok(out.includes('[REDACTED_SSN]'));
});

test('removes IPv4 addresses', () => {
  const out = redactPII('connected from 203.0.113.42 today');
  assert.ok(!out.includes('203.0.113.42'));
  assert.ok(out.includes('[REDACTED_IP]'));
});

test('removes common phone number formats', () => {
  for (const phone of ['(555) 123-4567', '555-123-4567', '555.123.4567', '+43 660 9192030']) {
    const out = redactPII(`call ${phone} now`);
    assert.ok(!/\d{3}[ .-]?\d{4}/.test(out.replace(/\[REDACTED_[A-Z_]+\]/g, '')), phone);
    assert.ok(out.includes('[REDACTED_PHONE]'), phone);
  }
});

test('redacts several kinds of PII in one text', () => {
  const out = redactPII('mail a@b.io, call 555-123-4567, card 4111 1111 1111 1111, from 10.0.0.1');
  for (const tag of ['EMAIL', 'PHONE', 'CREDIT_CARD', 'IP']) {
    assert.ok(out.includes(`[REDACTED_${tag}]`), tag);
  }
});

// Documented limitation (see README): redaction is best-effort pattern matching.
test('known limitation: long ID-like numbers can be over-redacted', () => {
  assert.ok(redactPII('order 1234567890123').includes('[REDACTED_'));
});
