// PRO-97 follow-on: an SDK emitter can say which feature flag variant a step ran under, the same way an OpenTelemetry span does, so Provantix can check that the same
// cohort is on the expected variant after a rollback, and keep evaluation windows under different configurations apart. The package must also be self-contained:
// nothing it ships may import a file outside it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildAAR, otelGenAiToAAR, AgentEmitter } from '../src/index.mjs';
import { normaliseConfiguration } from '../src/vendor/configuration.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const src = path.join(here, '..', 'src');
const T0 = Date.parse('2026-11-14T10:00:00.000Z');
const base = { tenantId: 'tenant_demo', emitterId: 'emi_cfg', system: 'openai', agent: { vendor: 'acme', vendorAgentId: 'agent-42' }, action: { type: 'call_model', targetSystem: 'llm' }, model: { id: 'm1', provider: 'openai' } };

test('buildAAR keeps the flags a step ran under in ext.configuration, beside tags and anything else the caller put in ext', () => {
  const aar = buildAAR({ ...base, tags: { department: 'support' }, ext: { note: 'x' }, configuration: [{ flag: 'new-prompt', variant: 'v1', provider: 'launchdarkly' }, { flag: 'wide-tools', variant: true }, { flag: 'retries', variant: 3 }] });
  assert.deepEqual(aar.ext.configuration, [
    { flag: 'new-prompt', variant: 'v1', provider: 'launchdarkly' }, { flag: 'wide-tools', variant: 'true', provider: null }, { flag: 'retries', variant: '3', provider: null },
  ]);
  assert.deepEqual([aar.ext.tags, aar.ext.note], [{ department: 'support' }, 'x']);
  assert.equal(buildAAR(base).ext, null, 'no configuration, no tags, no ext: still null');
  assert.deepEqual(buildAAR({ ...base, configuration: [] }).ext, null);
});

test('a wrong configuration is refused when it is written, with a message that names the problem', () => {
  const bad = (configuration, re) => assert.throws(() => buildAAR({ ...base, configuration }), re);
  bad('v1', /must be a list/);
  bad([null], /configuration\[0\] must be an object/);
  bad([{ variant: 'v1' }], /configuration\[0\]\.flag is required/);
  bad([{ flag: 'f', variant: { big: 'object' } }], /variant must be a string, a number or a boolean/);
  bad([{ flag: 'f', variant: Infinity }], /finite number/);
  bad([{ flag: 'f', prompt: 'secret' }], /"prompt" is not a field/);
  bad([{ flag: 'f', provider: 7 }], /provider must be a string/);
  bad(Array.from({ length: 11 }, (_, i) => ({ flag: `f${i}`, variant: 'v' })), /at most 10 flags/);
  assert.equal(normaliseConfiguration([{ flag: ' f ', variant: 'x'.repeat(300) }])[0].variant.length, 100, 'long values are cut');
  assert.equal(normaliseConfiguration([{ flag: 'f', variant: 'a' }, { flag: 'f', variant: 'a' }]).length, 1, 'the same flag and variant is kept once');
});

test('the same span gives the same configuration through the SDK exporter and through the hosted intake', async () => {
  let hostedAvailable = true;
  let intake;
  try { intake = await import('../../../ledger/packages/ingest/src/intake.mjs'); } catch { hostedAvailable = false; }
  const attrs = { 'gen_ai.operation.name': 'chat', 'gen_ai.system': 'openai', 'gen_ai.request.model': 'm1', 'feature_flag.key': 'new-prompt', 'feature_flag.result.variant': 'v1', 'feature_flag.provider.name': 'launchdarkly' };
  const event = { name: 'feature_flag.evaluation', attributes: { 'feature_flag.key': 'wide-tools', 'feature_flag.variant': 'on' } };
  const sdk = otelGenAiToAAR({ traceId: 'a'.repeat(32), spanId: 'b'.repeat(16), name: 'chat', kind: 'client', startTime: T0, endTime: T0 + 5, attributes: attrs, events: [event, { name: 'something.else', attributes: { 'feature_flag.key': 'ignored', 'feature_flag.variant': 'x' } }], status: { code: 'OK' } },
    { tenantId: 'tenant_demo', emitterId: 'emi_cfg' });
  const expected = [{ flag: 'new-prompt', variant: 'v1', provider: 'launchdarkly' }, { flag: 'wide-tools', variant: 'on', provider: null }];
  assert.deepEqual(sdk.ext.configuration, expected);
  if (!hostedAvailable) return;
  const kv = (o) => Object.entries(o).map(([key, v]) => ({ key, value: { stringValue: String(v) } }));
  const payload = { resourceSpans: [{ resource: { attributes: [] }, scopeSpans: [{ scope: { name: 't' }, spans: [{
    traceId: 'aa'.repeat(16), spanId: 'bb'.repeat(8), name: 'chat', kind: 3, startTimeUnixNano: String(BigInt(T0) * 1_000_000n), endTimeUnixNano: String(BigInt(T0 + 5) * 1_000_000n),
    status: { code: 1 }, attributes: kv({ ...attrs, 'trace.metadata.agent_id': 'agt_1' }),
    events: [{ name: 'feature_flag.evaluation', timeUnixNano: String(BigInt(T0) * 1_000_000n), attributes: kv(event.attributes) }] }] }] }] };
  const hosted = intake.spanToRecord(intake.normalizeOtlpSpans(payload)[0], { intake_id: 'i', tenant_id: 't', label: 'x', default_agent: null }, { connectorInstance: 'intake:i', nowIso: new Date(T0).toISOString() }).record;
  assert.deepEqual(hosted.erasable.ext.value.configuration, expected);
});

test('a step sent through the emitter arrives sealed with its configuration where the platform reads it', () => {
  const keys = AgentEmitter.generateKeys();
  const e = new AgentEmitter({ emitterId: 'emi_cfg', tenantId: 'tenant_demo', privateKeyPem: keys.privateKeyPem });
  e.emitAAR(buildAAR({ ...base, configuration: [{ flag: 'new-prompt', variant: 'v1' }], correlation: { traceId: 'c'.repeat(32), spanId: 'd'.repeat(16) } }));
  const rec = e.flush().records[0];
  assert.deepEqual(rec.erasable.ext.value.configuration, [{ flag: 'new-prompt', variant: 'v1', provider: null }]);
  assert.equal(rec.fields.correlation.trace_id, 'c'.repeat(32), 'the run identity travels with it');
});

test('the package is self-contained: nothing it ships imports a file outside src/', () => {
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith('.mjs') ? [path.join(d, e.name)] : []));
  const offenders = [];
  for (const file of walk(src)) {
    const text = fs.readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const m of text.matchAll(/(?:import|export)[^'"`;]*?from\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/g)) {
      const spec = m[1] ?? m[2];
      if (!spec.startsWith('.')) continue;
      const target = path.resolve(path.dirname(file), spec);
      if (!target.startsWith(src + path.sep)) offenders.push(`${path.relative(src, file)} imports ${spec}`);
    }
  }
  assert.deepEqual(offenders, []);
});

test('the vendored schema modules match the engine, so the SDK reads a span the way the platform does', (t) => {
  const engine = path.join(here, '..', '..', '..', 'ledger', 'packages', 'aar-schema', 'src');
  if (!fs.existsSync(engine)) { t.skip('the engine is not alongside this package'); return; }
  const norm = (s) => s.replace(/\r\n/g, '\n');
  for (const file of ['delegation.mjs', 'tool-payload.mjs', 'usage.mjs', 'tags.mjs', 'configuration.mjs']) {
    assert.equal(norm(fs.readFileSync(path.join(src, 'vendor', file), 'utf8')), norm(fs.readFileSync(path.join(engine, file), 'utf8')), `${file} has drifted from the engine`);
  }
});
