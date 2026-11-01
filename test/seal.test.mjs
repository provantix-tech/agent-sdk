// SDK 0.2.0: the emitter seals its batches by default (plan/24-per-record-emitter-proof.md, step 5). The seal is
// the emitter's own signature over the hash of every record in the batch, so an auditor can check, with the
// emitter's public key, that the emitter vouched for each record.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { AgentEmitter, buildAAR } from '../src/index.mjs';
import { verifySeal, verifyBatchSignature, SEALED_BATCH_VERSION, BATCH_VERSION } from '../src/vendor/batch.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

function emitter(opts = {}) {
  const keys = AgentEmitter.generateKeys();
  const e = new AgentEmitter({ emitterId: 'emi_sdkseal', tenantId: 'tenant_demo', privateKeyPem: keys.privateKeyPem, ...opts });
  return { e, keys };
}
const emit = (e, n) => {
  for (let i = 0; i < n; i += 1) {
    e.emitAAR(buildAAR({ tenantId: 'tenant_demo', emitterId: 'emi_sdkseal', system: 'openai', agent: { vendor: 'acme', vendorAgentId: 'agent-42' }, action: { type: 'call_model', targetSystem: 'llm' }, model: { modelId: 'gpt-x', tokensIn: 12 + i, tokensOut: 5 } }));
  }
};

test('an emitter seals its batches by default, and the seal verifies with the emitter\'s public key', () => {
  const { e, keys } = emitter();
  emit(e, 3);
  const batch = e.flush();
  assert.equal(batch.batch_version, SEALED_BATCH_VERSION);
  assert.equal(batch.seal.statement.record_count, 3);
  assert.deepEqual(batch.seal.statement.record_hashes, batch.records.map((r) => r.integrity.record_hash));
  assert.deepEqual(verifySeal(batch, keys.publicKeyPem), { ok: true });
  assert.equal(verifyBatchSignature(batch, keys.publicKeyPem), true);
});

test('seal: false gives the older unsealed batch, for a platform that does not know seals yet', () => {
  const { e } = emitter({ seal: false });
  emit(e, 2);
  const batch = e.flush();
  assert.equal(batch.batch_version, BATCH_VERSION);
  assert.equal('seal' in batch, false);
});

test('a seal made by this emitter does not verify with another emitter\'s key', () => {
  const { e } = emitter();
  const other = AgentEmitter.generateKeys();
  emit(e, 1);
  assert.equal(verifySeal(e.flush(), other.publicKeyPem).ok, false);
});

test('the vendored batch and collector modules match the engine, apart from their import line', (t) => {
  const engine = path.join(here, '..', '..', '..', 'ledger', 'packages', 'collector-core', 'src');
  if (!fs.existsSync(engine)) { t.skip('the engine is not alongside this package'); return; }
  const norm = (s) => s.replace(/\r\n/g, '\n').replace(/from '[./]*aar-schema\/src\/index\.mjs'/, "from './aar.mjs'");
  for (const file of ['batch.mjs', 'collector.mjs']) {
    assert.equal(norm(fs.readFileSync(path.join(here, '..', 'src', 'vendor', file), 'utf8')), norm(fs.readFileSync(path.join(engine, file), 'utf8')), `${file} has drifted from the engine`);
  }
});
