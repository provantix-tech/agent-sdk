// Conformance: the standalone verifier must match expected.json on every vector, the Python
// implementation must agree with it, and the standalone verifier must not depend on this repository.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifyExport, parseEmitterKeys } from '../verify-export.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsDir = path.join(here, '..', 'vectors');
const expected = JSON.parse(fs.readFileSync(path.join(vectorsDir, 'expected.json'), 'utf8'));
const failingNames = (r) => r.checks.filter((c) => !c.ok).map((c) => c.name).sort();
// An entry may name another vector directory (`dir`) and the auditor's key file (`emitter_keys`), so one export
// is checked both without and with a key the auditor holds.
const dirOf = (name, exp) => path.join(vectorsDir, exp.dir ?? name);
const keysOf = (exp) => (exp.emitter_keys ? parseEmitterKeys(fs.readFileSync(path.join(vectorsDir, exp.emitter_keys), 'utf8')) : null);

/** What an entry says about the emitter proof, from a result's summary. */
const proofOf = (p) => ({ signed: p.records_signed, total: p.records_total, failed: p.records_failed, missing: p.missing_from_export.length, refused: p.refused_at_ingest.length, key_sources: p.key_sources });

for (const [name, exp] of Object.entries(expected)) {
  test(`node verifier: vector ${name}`, () => {
    const r = verifyExport(dirOf(name, exp), { emitterKeys: keysOf(exp) });
    assert.equal(r.ok, exp.ok);
    assert.deepEqual(failingNames(r), [...exp.failing].sort());
    if (exp.emitter_proof) {
      const got = proofOf(r.emitter_proof);
      for (const [k, v] of Object.entries(exp.emitter_proof)) {
        if (k === 'key_sources') assert.deepEqual(got.key_sources, v, `${name}: key sources`);
        else assert.equal(got[k], v, `${name}: ${k}`);
      }
    }
  });
}

test('every export states its emitter proof in words, never as a bare pass, and names whose key it rests on', () => {
  for (const [name, exp] of Object.entries(expected)) {
    const r = verifyExport(dirOf(name, exp), { emitterKeys: keysOf(exp) });
    const text = r.emitter_proof.lines.join('\n');
    assert.match(text, /^emitter proof: \d+ of \d+ records signed by the emitter's key/, name);
    if (r.emitter_proof.present && r.emitter_proof.records_signed > 0) assert.match(text, /key source: /, `${name}: whose key vouches for it`);
  }
  const unsealed = verifyExport(path.join(vectorsDir, 'valid'));
  assert.match(unsealed.emitter_proof.lines.join('\n'), /did not seal \(not covered, not failed\)/);
});

test('an auditor key file is refused when it holds something that is not a public key', () => {
  assert.throws(() => parseEmitterKeys('-----BEGIN PUBLIC KEY-----\nnot a key\n-----END PUBLIC KEY-----'));
});

function python() {
  for (const cmd of ['python', 'python3']) {
    const probe = spawnSync(cmd, ['--version'], { encoding: 'utf8' });
    if (probe.status === 0) return cmd;
  }
  return null;
}

test('python verifier agrees with the node verifier on every vector', (t) => {
  const py = python();
  if (!py) {
    t.skip('python not installed');
    return;
  }
  const script = path.join(here, '..', 'python', 'verify_export.py');
  for (const [name, exp] of Object.entries(expected)) {
    const args = [script, dirOf(name, exp), ...(exp.emitter_keys ? ['--emitter-keys', path.join(vectorsDir, exp.emitter_keys)] : []), '--json'];
    const run = spawnSync(py, args, { encoding: 'utf8' });
    assert.equal(run.status, exp.ok ? 0 : 1, `${name}: exit code (${run.stderr})`);
    const r = JSON.parse(run.stdout);
    assert.equal(r.ok, exp.ok, name);
    assert.deepEqual(failingNames(r), [...exp.failing].sort(), name);
    // The two implementations report the same emitter proof, down to the words.
    const node = verifyExport(dirOf(name, exp), { emitterKeys: keysOf(exp) });
    assert.deepEqual(proofOf(r.emitter_proof), proofOf(node.emitter_proof), `${name}: emitter proof counts`);
    assert.deepEqual(r.emitter_proof.lines, node.emitter_proof.lines, `${name}: emitter proof wording`);
    assert.deepEqual(r.emitter_proof.refused_at_ingest, node.emitter_proof.refused_at_ingest, `${name}: refused at ingest`);
  }
});

test('python refuses a key file that is not a P-256 public key, and checks a signature the way node does', (t) => {
  const py = python();
  if (!py) { t.skip('python not installed'); return; }
  const script = path.join(here, '..', 'python', 'verify_export.py');
  const bad = path.join(vectorsDir, 'sealed-valid', 'manifest.json'); // JSON, but not keys
  const run = spawnSync(py, [script, dirOf('sealed-valid', {}), '--emitter-keys', bad], { encoding: 'utf8' });
  assert.equal(run.status, 2);
  assert.match(run.stderr, /cannot read the emitter keys file/);
});

test('the standalone verifier imports nothing from this repository', () => {
  const src = fs.readFileSync(path.join(here, '..', 'verify-export.mjs'), 'utf8');
  const imports = [...src.matchAll(/from '([^']+)'/g)].map((m) => m[1]);
  for (const spec of imports) {
    assert.ok(spec.startsWith('node:'), `unexpected import ${spec}`);
  }
});
