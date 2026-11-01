// AAR builder contract tests (WO-H2): targetSystem must be a stable system name; a
// GUID/ULID there is a loud warning, not a throw — a hard failure would silence all
// telemetry from a misconfigured emitter, and the control plane flags the same defect as a
// data_health finding.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAAR } from '../src/aar.mjs';

const BASE = {
  tenantId: 't',
  emitterId: 'emi_test',
  system: 'cruzclaw',
  agent: { vendor: 'acme', vendorAgentId: 'bot-1' },
};

function captureWarnings(fn) {
  const original = console.warn;
  const lines = [];
  console.warn = (...args) => lines.push(args.join(' '));
  try {
    fn();
  } finally {
    console.warn = original;
  }
  return lines;
}

test('a GUID-shaped targetSystem warns and points at the contract', () => {
  const warnings = captureWarnings(() => buildAAR({
    ...BASE,
    action: { type: 'execute', targetSystem: '6b3ff78e-3718-4b08-844f-864eefd1228c' },
  }));
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /per-run id/);
  assert.match(warnings[0], /targetEntityId/);
});

test('the same run id warns once per process', () => {
  const guid = 'aa41bd84-8dde-4b2e-b391-bc6d9dae190c';
  const first = captureWarnings(() => buildAAR({ ...BASE, action: { type: 'execute', targetSystem: guid } }));
  const second = captureWarnings(() => buildAAR({ ...BASE, action: { type: 'execute', targetSystem: guid } }));
  assert.equal(first.length, 1);
  assert.equal(second.length, 0, 'deduplicated per value');
});

test('a stable system name is silent', () => {
  const warnings = captureWarnings(() => buildAAR({
    ...BASE,
    action: { type: 'execute', targetSystem: 'cruzclaw-backend', targetEntityId: 'run-123' },
  }));
  assert.equal(warnings.length, 0);
});

test('targetEntityId maps through to the record unchanged', () => {
  const aar = buildAAR({
    ...BASE,
    action: { type: 'execute', targetSystem: 'cruzclaw-backend', targetEntityId: '6b3ff78e-3718-4b08-844f-864eefd1228c' },
  });
  assert.equal(aar.action.target_system, 'cruzclaw-backend');
  assert.equal(aar.action.target_entity_id, '6b3ff78e-3718-4b08-844f-864eefd1228c');
});
