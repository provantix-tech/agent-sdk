// PRO-19: the two verifiers read a head's outside time-stamp the same way, say "not anchored" when there is none and never "failed" for that,
// and refuse one that is present and wrong. The token check is embedded in each verifier (the export verifier imports nothing from the repository);
// this test keeps the copies identical to rfc3161.mjs so they cannot drift.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { anchorState as fromModule } from '../rfc3161.mjs';
import { anchorState as fromExport } from '../verify-export.mjs';
import { anchorState as fromMirror, checkLog, treeRoot } from '../verify-log.mjs';
import { makeFakeTsa } from './fake-tsa.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (f) => fs.readFileSync(path.join(here, '..', f), 'utf8').replace(/\r\n/g, '\n'); // a checkout may use either line ending
const block = (src) => { const a = src.indexOf('// <<< rfc3161-check'); const b = src.indexOf('// >>> rfc3161-check'); return a < 0 || b < 0 ? null : src.slice(a, b); };

test('the token check embedded in each verifier is identical to rfc3161.mjs', () => {
  const master = block(read('rfc3161.mjs'));
  assert.ok(master && master.length > 2000, 'the shared block exists');
  assert.equal(block(read('verify-export.mjs')), master, 'verify-export.mjs has a different copy: re-embed it from rfc3161.mjs');
  assert.equal(block(read('verify-log.mjs')), master, 'verify-log.mjs has a different copy: re-embed it from rfc3161.mjs');
});

const canonical = (v) => `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${JSON.stringify(v[k])}`).join(',')}}`;
const headFor = (size, root) => ({ version: 1, log_id: 'tlog_x', tree_size: size, root_hash: root, timestamp: '2026-11-12T08:00:00.000Z', key_id: 'k1' });
const bytes = (h) => Buffer.from(canonical({ version: h.version, log_id: h.log_id, tree_size: h.tree_size, root_hash: h.root_hash, timestamp: h.timestamp, key_id: h.key_id }));

test('anchored, not anchored, pending and invalid are told apart the same way by the module and both verifiers', () => {
  const tsa = makeFakeTsa({ now: () => new Date('2026-11-12T09:00:00Z') });
  const head = headFor(3, 'a'.repeat(64));
  const digest = createHash('sha256').update(bytes(head)).digest();
  const anchor = { method: 'rfc3161', authority: 'https://tsa.example.test', digest_sha256: digest.toString('hex'), token: tsa.stamp(digest).toString('base64'), gen_time: '2026-11-12T09:00:00.000Z' };
  const cases = [
    ['anchored', { ...head, anchor }, 'anchored'],
    ['absent', head, 'not_anchored'],
    ['pending', { ...head, anchor: { status: 'pending', reason: 'the authority could not be reached' } }, 'not_anchored'],
    ['a token for another head', { ...head, anchor: { ...anchor, token: tsa.stamp(createHash('sha256').update('other').digest()).toString('base64'), digest_sha256: undefined } }, 'invalid'],
    ['a digest that is not this head\'s', { ...head, anchor: { ...anchor, digest_sha256: 'b'.repeat(64) } }, 'invalid'],
    ['a damaged token', { ...head, anchor: { ...anchor, token: Buffer.from('damaged').toString('base64') } }, 'invalid'],
  ];
  for (const [name, h, state] of cases) {
    const results = [fromModule(h, bytes(h)), fromExport(h, bytes(h)), fromMirror(h, bytes(h))];
    for (const r of results) assert.equal(r.state, state, name);
    assert.deepEqual(results[1], results[0], `${name}: the export verifier agrees with the module`);
    assert.deepEqual(results[2], results[0], `${name}: the mirror agrees with the module`);
  }
  assert.match(fromModule(cases[1][1], bytes(head)).text, /^not anchored$/, 'absent reads "not anchored", not "failed"');
  assert.match(fromModule(cases[2][1], bytes(head)).text, /^not anchored yet \(the authority could not be reached\)$/);
  assert.match(fromModule(cases[0][1], bytes(head)).text, /chain is not checked here/, 'it says what it did not check');
});

test('the mirror check: anchors on heads pass, an absent one is not a failure, a wrong one is', () => {
  const entries = [0, 1, 2].map((i) => ({ seq: i, leaf: { v: 1, n: i }, leaf_hash: '' }));
  // build real leaf hashes the way the verifier does, by using its own treeRoot on hashes we compute
  const sha = (...p) => createHash('sha256').update(Buffer.concat(p)).digest();
  const canon = (v) => (Array.isArray(v) ? `[${v.map(canon).join(',')}]` : v && typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}` : JSON.stringify(v));
  for (const e of entries) e.leaf_hash = sha(Buffer.from([0]), Buffer.from(canon(e.leaf))).toString('hex');
  const root = treeRoot(entries.map((e) => e.leaf_hash));
  const tsa = makeFakeTsa();
  const base = headFor(3, root);
  const stamp = (h) => { const d = createHash('sha256').update(bytes(h)).digest(); return { method: 'rfc3161', authority: 'x', digest_sha256: d.toString('hex'), token: tsa.stamp(d).toString('base64'), gen_time: '2026-11-12T09:00:00.000Z' }; };

  const plain = checkLog({ head: base, entries, keys: null, previous: null });
  assert.equal(plain.ok, true);
  assert.equal(plain.checks.some((c) => /time-stamp/.test(c.name)), false, 'no anchors: no check at all, so nothing can "fail"');
  assert.deepEqual([plain.anchors.anchored, plain.anchors.not_anchored, plain.anchors.invalid], [0, 1, 0]);

  const good = checkLog({ head: { ...base, anchor: stamp(base) }, entries, keys: null, previous: null });
  assert.equal(good.ok, true);
  assert.match(good.checks.find((c) => /time-stamp/.test(c.name)).detail, /1 of 1 head carry one/);

  const bad = checkLog({ head: { ...base, anchor: { ...stamp(base), token: stamp(headFor(9, 'c'.repeat(64))).token } }, entries, keys: null, previous: null });
  assert.equal(bad.ok, false);
  assert.match(bad.checks.find((c) => /time-stamp/.test(c.name)).detail, /does not verify|different/);

  // a kept earlier head that is anchored, with the current head not yet
  const earlier = { ...headFor(2, treeRoot(entries.slice(0, 2).map((e) => e.leaf_hash))) };
  const mixed = checkLog({ head: base, entries, keys: null, previous: null, retained: [{ ...earlier, anchor: stamp(earlier) }] });
  assert.equal(mixed.ok, true);
  assert.match(mixed.checks.find((c) => /time-stamp/.test(c.name)).detail, /1 of 2 heads carry one.*the others are not anchored/);
});
