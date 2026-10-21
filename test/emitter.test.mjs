// Agent SDK tests: OTel mapping, AAR validation, and a full integration test that
// registers an emitter against a real control plane, ships OTel-derived telemetry and
// verifies ingest, attribution, timeline, reporting and offline export.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';

import { buildAAR, validateAAR, otelGenAiToAAR, otelBatchToAARs, AgentEmitter } from '../src/index.mjs';
import { createLedgerApi } from '../../server/api.mjs';

// ---------- unit: AAR ----------

test('buildAAR produces a valid export-profile record', () => {
  const aar = buildAAR({
    tenantId: 'tenant_demo',
    emitterId: 'emi_test',
    system: 'openai',
    agent: { vendor: 'acme', vendorAgentId: 'agent-42' },
    action: { type: 'call_model', targetSystem: 'llm' },
    model: { modelId: 'gpt-x', tokensIn: 12, tokensOut: 5 },
  });
  assert.equal(validateAAR(aar).length, 0);
  assert.equal(aar.profile_version, '1.0');
  assert.equal(aar.source.vantage, 'inside');
});

test('validateAAR rejects bad action types and data classes', () => {
  const aar = buildAAR({ tenantId: 't', emitterId: 'e', system: 's', action: { type: 'explode' } });
  aar.action.data_classes = ['nuclear'];
  const problems = validateAAR(aar);
  assert.ok(problems.some((p) => p.includes('explode')));
  assert.ok(problems.some((p) => p.includes('nuclear')));
});

// ---------- unit: OTel mapping ----------

const SPAN_CHAT = {
  traceId: 'aabbccddeeff00112233445566778899',
  spanId: '0011223344556677',
  kind: 'client',
  startTime: Date.parse('2026-10-17T10:00:00Z'),
  endTime: Date.parse('2026-10-17T10:00:01.250Z'),
  attributes: {
    'gen_ai.operation.name': 'chat',
    'gen_ai.system': 'openai',
    'gen_ai.request.model': 'gpt-x',
    'gen_ai.usage.input_tokens': 320,
    'gen_ai.usage.output_tokens': 88,
    'gen_ai.conversation.id': 'conv-9',
    'gen_ai.agent.id': 'support-copilot',
  },
  status: { code: 'OK' },
};

test('otelGenAiToAAR maps a chat span to call_model', () => {
  const aar = otelGenAiToAAR(SPAN_CHAT, { tenantId: 't', emitterId: 'e' });
  assert.equal(aar.action.action_type, 'call_model');
  assert.equal(aar.model.provider, 'openai');
  assert.equal(aar.model.tokens_in, 320);
  assert.equal(aar.model.latency_ms, 1250);
  assert.equal(aar.correlation.trace_id, 'aabbccddeeff00112233445566778899');
  assert.equal(aar.agent_hint.vendor_agent_id, 'support-copilot');
  assert.equal(aar.quality.outcome, 'success');
  assert.equal(validateAAR(aar).length, 0);
});

test('otelGenAiToAAR maps tool and agent spans', () => {
  const tool = otelGenAiToAAR({
    ...SPAN_CHAT,
    attributes: { 'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'crm.update' },
  }, { tenantId: 't', emitterId: 'e' });
  assert.equal(tool.action.action_type, 'call_tool');
  assert.equal(tool.action.tool_name, 'crm.update');
  assert.equal(tool.action.target_entity_id, 'crm.update');

  const invoke = otelGenAiToAAR({
    ...SPAN_CHAT,
    attributes: { 'gen_ai.operation.name': 'invoke_agent', 'gen_ai.agent.id': 'sub-1' },
  }, { tenantId: 't', emitterId: 'e' });
  assert.equal(invoke.action.action_type, 'call_agent');
});

test('otelGenAiToAAR returns null for non-GenAI spans and maps errors', () => {
  assert.equal(otelGenAiToAAR({ name: 'http.get', attributes: { 'http.route': '/x' } }, { tenantId: 't', emitterId: 'e' }), null);
  const err = otelGenAiToAAR({ ...SPAN_CHAT, status: { code: 'ERROR', message: 'rate limited' } }, { tenantId: 't', emitterId: 'e' });
  assert.equal(err.quality.outcome, 'failure');
  assert.equal(err.quality.error_class, 'rate limited');
});

// ---------- integration: emitter -> control plane ----------
// Runs against an isolated database created on DATABASE_URL (the role needs CREATEDB, which
// the compose user has); a shared database would make agent/emitter fixtures collide with
// other runs. Without DATABASE_URL the integration tests skip and only the unit tests run.

const hasDatabase = Boolean(process.env.DATABASE_URL);
const dataDir = new URL('./it-data', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const TOKEN = 'demo-admin-token-0123456789';
const authed = { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' };
let api;
let server;
let base;
let itDbName = null;
let originalDatabaseUrl = null;
const call = async (method, p, body) => {
  const res = await fetch(base + p, { method, headers: authed, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json();
  if (!res.ok) throw new Error(`${method} ${p} -> ${res.status}: ${data.error}`);
  return data;
};

before(async () => {
  if (!hasDatabase) return;
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required for the integration test');
  const { migrate } = await import('../../../ledger/packages/ingest/src/migrate.mjs');
  const { default: pg } = await import('pg');
  originalDatabaseUrl = process.env.DATABASE_URL;
  itDbName = `sdk_it_${process.pid}`;
  const admin = new pg.Client({ connectionString: originalDatabaseUrl });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${itDbName} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${itDbName}`);
  await admin.end();
  process.env.DATABASE_URL = originalDatabaseUrl.replace(/\/[^/]+$/, `/${itDbName}`);
  // The tenancy model resolves one deployment tenant (never a synthetic fallback), so the
  // isolated integration database declares its own.
  process.env.LEDGER_TENANT_ID = 'tenant_it';
  await migrate(process.env.DATABASE_URL);

  fs.rmSync(dataDir, { recursive: true, force: true });
  api = await createLedgerApi({ dataDir, adminToken: TOKEN });
  server = http.createServer(api.handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  if (!hasDatabase) return;
  server?.close();
  await api?.close();
  process.env.DATABASE_URL = originalDatabaseUrl;
  delete process.env.LEDGER_TENANT_ID;
  if (itDbName) {
    const { default: pg } = await import('pg');
    const admin = new pg.Client({ connectionString: originalDatabaseUrl });
    try {
      await admin.connect();
      await admin.query(`DROP DATABASE IF EXISTS ${itDbName} WITH (FORCE)`);
    } finally {
      await admin.end();
    }
  }
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('emitter ships OTel telemetry: ingested, attributed, reported, exportable', { skip: !hasDatabase && 'needs DATABASE_URL' }, async () => {
  // The agent must exist in inventory with matching vendor + vendor_agent_id.
  const agent = await call('POST', '/v1/agents', {
    display_name: 'Support Copilot',
    vendor: 'otel',
    vendor_agent_id: 'support-copilot',
    kind: 'copilot',
  });
  await call('POST', `/v1/agents/${agent.agent_id}/lifecycle`, { to: 'active', reason: 'sdk test' });

  // Register the emitter (what POST /api/emitters does for real deployments).
  const registration = await call('POST', '/api/emitters', { name: 'copilot-runtime-1' });
  assert.match(registration.emitter_id, /^emi_/);
  assert.match(registration.private_key_pem, /PRIVATE KEY/);

  // Emit three OTel spans through the SDK and drain to the control plane.
  const now = Date.now();
  const emitter = new AgentEmitter({
    emitterId: registration.emitter_id,
    tenantId: registration.tenant_id,
    privateKeyPem: registration.private_key_pem,
  });
  const nowSpan = { ...SPAN_CHAT, startTime: now - 1300, endTime: now };
  emitter.emitOtelSpan(nowSpan, { agent: { vendor: 'otel', vendorAgentId: 'support-copilot' } });
  emitter.emitOtelSpan({
    ...nowSpan,
    spanId: '0011223344556678',
    attributes: { 'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'crm.update', 'gen_ai.system': 'openai' },
  }, { agent: { vendor: 'otel', vendorAgentId: 'support-copilot' } });
  emitter.emitOtelSpan({
    ...nowSpan,
    spanId: '0011223344556679',
    attributes: { 'gen_ai.operation.name': 'chat', 'gen_ai.system': 'openai', 'gen_ai.request.model': 'gpt-x' },
    status: { code: 'ERROR', message: 'timeout' },
  }, { agent: { vendor: 'otel', vendorAgentId: 'support-copilot' } });
  const drain = await emitter.flushAndDrain(base);
  assert.equal(drain.sent, 1);
  assert.equal(drain.error, null);
  assert.equal(drain.results[0].accepted, 3, JSON.stringify(drain.results[0].rejections ?? []));
  assert.equal(drain.results[0].rejected, 0);

  // Ingest attributed them to the agent by explicit platform id.
  const timeline = await call('GET', `/v1/timeline?agent_id=${agent.agent_id}&limit=50`);
  const records = timeline.filter((r) => r.kind === 'record');
  assert.equal(records.length, 3);
  assert.ok(records.every((r) => r.attribution_method === 'explicit_platform_id' && r.attribution_confidence === 0.95));

  // They arrived on this emitter's connector.
  const onConnector = await call('POST', '/api/reporting/query', {
    table: 'records',
    filters: [{ field: 'connector_instance', op: '=', value: registration.connector_instance }],
    groupBy: ['attribution_method'],
    metric: 'count',
  });
  assert.equal(onConnector.rows[0].n, 3);
  assert.equal(onConnector.rows[0].attribution_method, 'explicit_platform_id');

  // They appear in the reporting engine.
  const byAction = await call('POST', '/api/reporting/query', {
    table: 'records',
    filters: [{ field: 'agent_id', op: '=', value: agent.agent_id }],
    groupBy: ['action_type'],
    metric: 'count',
  });
  assert.equal(byAction.row_count, 2); // call_model + call_tool
  assert.equal(byAction.rows.reduce((s, r) => s + r.n, 0), 3);

  // Model telemetry is queryable (tokens spent by the agent).
  const tokens = await call('POST', '/api/reporting/query', {
    table: 'records',
    filters: [{ field: 'agent_id', op: '=', value: agent.agent_id }],
    metric: 'count',
  });
  assert.ok(tokens.row_count >= 1);

  // Emitters list shows the shipped records.
  const emitters = await call('GET', '/api/emitters');
  const mine = emitters.find((e) => e.emitter_id === registration.emitter_id);
  assert.equal(mine.records_shipped, 3);

  // The export verifies offline with the agent telemetry inside it (open days stay unrooted
  // by design; roots are write-once and a day roots 48h after it closes).
  const exp = await call('POST', '/v1/exports', {});
  const verify = await call('POST', '/v1/exports/verify', { export_id: exp.export_id });
  assert.equal(verify.ok, true);
});

test('emitter without a matching agent stays unattributed but verifiable', { skip: !hasDatabase && 'needs DATABASE_URL' }, async () => {
  const registration = await call('POST', '/api/emitters', {});
  const emitter = new AgentEmitter({
    emitterId: registration.emitter_id,
    tenantId: registration.tenant_id,
    privateKeyPem: registration.private_key_pem,
  });
  emitter.emitAAR(buildAAR({
    tenantId: registration.tenant_id,
    emitterId: registration.emitter_id,
    system: 'custom',
    agent: { vendor: 'nobody', vendorAgentId: 'unknown-agent' },
    action: { type: 'execute', targetSystem: 'internal' },
  }));
  await emitter.flushAndDrain(base);

  const un = await call('POST', '/api/reporting/query', {
    table: 'records',
    filters: [{ field: 'connector_instance', op: '=', value: registration.connector_instance }],
    groupBy: ['agent_id', 'attribution_method'],
    metric: 'count',
  });
  assert.equal(un.row_count, 1);
  assert.equal(un.rows[0].agent_id, 'unknown');
});
