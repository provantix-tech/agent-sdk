// SDK 0.3.0: an emitter can say where it runs and what it acts on, as short codes (plan/26 in the Provantix repo). The
// location rides in the sealed record, so the seal and the batch signature cover it. Nothing finer than a country is kept.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { AgentEmitter, buildAAR, sanitizeLocation, locationFromEnv } from '../src/index.mjs';
import { verifySeal, verifyBatchSignature } from '../src/vendor/batch.mjs';
import { sanitizeLocation as platformSanitize } from '../../../ledger/packages/aar-schema/src/location.mjs';

function emitter(opts = {}) {
  const keys = AgentEmitter.generateKeys();
  const e = new AgentEmitter({ emitterId: 'emi_loc', tenantId: 'tenant_demo', privateKeyPem: keys.privateKeyPem, ...opts });
  return { e, keys };
}
const aar = (extra = {}) => buildAAR({
  tenantId: 'tenant_demo', emitterId: 'emi_loc', system: 'openai', agent: { vendor: 'acme', vendorAgentId: 'agent-42' },
  action: { type: 'call_tool', targetSystem: 'crm' }, ...extra,
});

test('an emitter given a location puts it, with its basis, in every record, and the seal covers it', () => {
  const { e, keys } = emitter({ location: { runtime: { provider: 'AWS', region: 'EU-West-1' }, target: { region: 'us-east-1' } } });
  e.emitAAR(aar());
  const batch = e.flush();
  assert.deepEqual(batch.records[0].fields.location, {
    runtime: { provider: 'aws', region: 'eu-west-1', basis: 'declared' },
    target: { region: 'us-east-1', basis: 'declared' },
  });
  assert.deepEqual(verifySeal(batch, keys.publicKeyPem), { ok: true });
  assert.equal(verifyBatchSignature(batch, keys.publicKeyPem), true);

  const tampered = structuredClone(batch);
  tampered.records[0].fields.location.runtime.region = 'ap-south-1';
  assert.equal(verifyBatchSignature(tampered, keys.publicKeyPem), false, 'changing the region breaks the signature');
});

test('a location on one action overrides the emitter\'s, and a record with none carries none', () => {
  const { e } = emitter({ location: { runtime: { region: 'eu-west-1' } } });
  e.emitAAR(aar({ location: { runtime: { region: 'ap-south-1' } } }));
  const none = emitter({ location: null });
  none.e.emitAAR(aar());
  assert.equal(e.flush().records[0].fields.location.runtime.region, 'ap-south-1');
  assert.equal('location' in none.e.flush().records[0].fields, false);
});

test('a city, an address or free text is dropped before it can be sealed', () => {
  const { e } = emitter({ location: { runtime: { region: 'eu-west-1', city: 'Dublin', address: '1 Main St' }, note: 'office' } });
  e.emitAAR(aar());
  const stored = JSON.stringify(e.flush().records[0].fields.location);
  for (const finer of ['Dublin', 'Main St', 'office']) assert.ok(!stored.includes(finer));
});

test('without a setting, the emitter reads the cloud region it runs in, and says nothing when there is none', () => {
  assert.deepEqual(locationFromEnv({ AWS_REGION: 'us-west-2' }), { runtime: { provider: 'aws', region: 'us-west-2', basis: 'declared' } });
  assert.deepEqual(locationFromEnv({ FLY_REGION: 'FRA' }), { runtime: { provider: 'fly', region: 'fra', basis: 'declared' } });
  assert.equal(locationFromEnv({}), null);
});

test('the SDK and the platform keep exactly the same codes', () => {
  const inputs = [
    { runtime: { provider: 'AWS', region: 'EU-West-1', zone: 'eu-west-1a', country: 'ie', city: 'Dublin' }, target: { region: 'us-east-1', country: 'US', note: 'x' } },
    { runtime: { region: 'not a region!' } },
    { runtime: { region: 'a'.repeat(80) }, target: { country: 'USA' } },
    { runtime: { provider: 'Fly', region: 'fra', basis: 'edge' } },
    { runtime: { region: 'x', basis: 'made-up' } },
    null, 'text', 7, {},
  ];
  for (const input of inputs) assert.deepEqual(sanitizeLocation(input), platformSanitize(input).fields, JSON.stringify(input));
});
