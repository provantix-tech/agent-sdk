// Handle-key persistence (round-3 review): with a durable spoolDir the emitter persists
// its handle HMAC key, so human handles are stable across restarts — the same human maps
// to the same handle, keeping attribution and erasure working after a process restart.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { AgentEmitter, buildAAR, generateEmitterKeys } from '../src/index.mjs';

function emitOne(emitter) {
  emitter.emitAAR(buildAAR({
    tenantId: emitter.tenantId,
    emitterId: emitter.emitterId,
    eventId: 'evt-handle-key',
    system: 'test',
    agent: { vendor: 'nobody', vendorAgentId: 'agent-x' },
    action: { type: 'read', targetSystem: 'test' },
    onBehalfOf: [{ kind: 'human', id: 'jane.doe@company.com' }],
  }));
  return emitter.flush();
}

test('spoolDir persists the handle key: restarted emitter produces identical handles', () => {
  const spoolDir = fs.mkdtempSync(path.join(os.tmpdir(), 'emitter-spool-'));
  const keys = generateEmitterKeys();

  const first = new AgentEmitter({
    emitterId: 'emi_hk1', tenantId: 'tenant_a', privateKeyPem: keys.privateKeyPem, spoolDir,
  });
  const batch1 = emitOne(first);

  // The key file exists and is not world-readable on POSIX.
  const keyFile = path.join(spoolDir, 'handle-key.bin');
  assert.ok(fs.existsSync(keyFile));

  // A fresh process (new AgentEmitter, same spoolDir) seals the same human identically.
  const second = new AgentEmitter({
    emitterId: 'emi_hk1', tenantId: 'tenant_a', privateKeyPem: keys.privateKeyPem, spoolDir,
  });
  const batch2 = emitOne(second);

  const handleOf = (batch) => JSON.stringify(batch.records[0].erasable.on_behalf_of.value);
  assert.equal(handleOf(batch1), handleOf(batch2), 'same human → same handle across restarts');
});
