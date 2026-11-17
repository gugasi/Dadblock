import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ext = path.resolve('extension');
const manifest = JSON.parse(fs.readFileSync(path.join(ext, 'manifest.json'), 'utf8'));
const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
  e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]);
const files = walk(ext);

test('is a Manifest V3 extension with a version', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
});

test('every file the manifest points to exists', () => {
  const refs = [manifest.background?.service_worker, manifest.action?.default_popup, manifest.options_page,
    ...Object.values(manifest.icons ?? {}),
    ...(manifest.content_scripts ?? []).flatMap((c) => [...(c.js ?? []), ...(c.css ?? [])]),
    ...(manifest.declarative_net_request?.rule_resources ?? []).map((r) => r.path)].filter(Boolean);
  for (const ref of refs) assert.ok(fs.existsSync(path.join(ext, ref)), `missing ${ref}`);
});

test('requests only the permissions the Web Store listing explains', () => {
  const allowed = new Set(['storage', 'declarativeNetRequest', 'scripting', 'alarms', 'offscreen', 'webNavigation']);
  for (const p of manifest.permissions ?? []) assert.ok(allowed.has(p), `unexpected permission: ${p}`);
});

test('every JavaScript file parses', () => {
  for (const f of files.filter((x) => x.endsWith('.js'))) {
    execFileSync(process.execPath, ['--check', f], { stdio: 'pipe' });
  }
});

test('ships no secrets or private keys', () => {
  const patterns = [/gsk_[A-Za-z0-9]{20,}/, /sk-[A-Za-z0-9]{20,}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /AKIA[0-9A-Z]{16}/];
  for (const f of files.filter((x) => /\.(js|json|html)$/.test(x))) {
    const text = fs.readFileSync(f, 'utf8');
    for (const p of patterns) assert.ok(!p.test(text), `${path.relative(ext, f)} matches ${p}`);
  }
});

test('the rules file is valid declarativeNetRequest JSON', () => {
  const rules = JSON.parse(fs.readFileSync(path.join(ext, 'rules.json'), 'utf8'));
  assert.ok(Array.isArray(rules) && rules.length > 0);
  const ids = new Set();
  for (const r of rules) { assert.ok(!ids.has(r.id), `duplicate rule id ${r.id}`); ids.add(r.id); assert.ok(r.action && r.condition); }
});
