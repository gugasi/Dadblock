import test from 'node:test';
import assert from 'node:assert/strict';
import {
  FINDING_CATEGORIES,
  validatePublicAudit,
  validateTypedModelAudit,
  normalizeNonDangerAudit,
} from '../extension/utils/audit-verdicts.js';

const safe = { judgment: 'SAFE', analysis: 'Nothing concrete found.', evidence: [], dadTip: 'Stay alert.', isStorefront: false };

test('exposes the finding categories', () => {
  assert.ok(FINDING_CATEGORIES.includes('FRAUDULENT_PAYMENT_REQUEST'));
  assert.ok(FINDING_CATEGORIES.includes('CREDENTIAL_THEFT_REQUEST'));
});

test('a SAFE answer with no evidence is accepted', () => {
  assert.ok(validateTypedModelAudit(safe, { sourceText: 'hello world' }));
});

test('a SAFE answer that carries evidence is rejected', () => {
  const bad = { ...safe, evidence: [{ quote: 'hello', category: 'OTHER_CONTEXT', source: 'PAGE' }] };
  assert.equal(validateTypedModelAudit(bad, { sourceText: 'hello world' }), null);
});

test('a SCAM answer without any evidence is rejected', () => {
  assert.equal(validateTypedModelAudit({ ...safe, judgment: 'SCAM' }, { sourceText: 'x' }), null);
});

test('unknown judgments and extra keys are rejected', () => {
  assert.equal(validateTypedModelAudit({ ...safe, judgment: 'DEFINITELY_FINE' }), null);
  assert.equal(validateTypedModelAudit({ ...safe, surprise: true }), null);
});

test('an over-long tip is rejected', () => {
  assert.equal(validateTypedModelAudit({ ...safe, dadTip: 'x'.repeat(400) }), null);
});

test('an INBOX verdict can never be a storefront', () => {
  assert.equal(validateTypedModelAudit({ ...safe, judgment: 'INBOX', isStorefront: true }), null);
});

test('evidence that is not in the page text is not accepted as a SCAM', () => {
  const made_up = {
    judgment: 'SCAM', analysis: 'Asks for a fee.', dadTip: 'Do not pay.', isStorefront: false,
    evidence: [{ quote: 'pay a $9.99 verification fee', category: 'FRAUDULENT_PAYMENT_REQUEST', source: 'PAGE' }],
  };
  assert.equal(validateTypedModelAudit(made_up, { sourceText: 'A page about sourdough bread.' }), null);
});

test('non-danger answers are trimmed instead of rejected', () => {
  const out = normalizeNonDangerAudit({ ...safe, evidence: ['stray'], dadTip: 'x'.repeat(500) });
  assert.deepEqual(out.evidence, []);
  assert.ok(out.dadTip.length <= 320);
});

test('the public contract rejects malformed worker responses', () => {
  assert.equal(validatePublicAudit(null, 'SAFE'), null);
  assert.equal(validatePublicAudit({ evidence: [], auditFindings: [], dadTip: 'ok', isStorefront: false }, 'NOPE'), null);
  assert.ok(validatePublicAudit({ evidence: [], auditFindings: [], dadTip: 'ok', isStorefront: false }, 'SAFE'));
});
