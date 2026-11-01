// Agent SDK tests: OTel mapping, AAR validation, and a full integration test that
// registers an emitter against a real control plane, ships OTel-derived telemetry and
// verifies ingest, attribution, timeline, reporting and offline export.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';

import { buildAAR, validateAAR, otelGenAiToAAR, otelBatchToAARs, AgentEmitter } from '../src/index.mjs';

// The integration tests need the Provantix control plane next to this package (the monorepo). In the public SDK
// repository it is absent and they are skipped; every other test here runs on its own.
let createLedgerApi = null;
try { ({ createLedgerApi } = await import('../../server/api.mjs')); } catch { /* not in the monorepo */ }

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

// P1: delegation chain from span parentage — a three-level trace (orchestrator chat →
// invoke_agent → worker chat → tool) must reconstruct [orchestrator, worker] without the
// reader ever touching span ids. A lone actor carries an empty chain.
test('otelBatchToAARs reconstructs the delegation chain from span parentage', () => {
  const root = {
    ...SPAN_CHAT,
    spanId: '1000000000000001',
    parentSpanId: undefined,
    attributes: { ...SPAN_CHAT.attributes, 'gen_ai.agent.id': 'orchestrator' },
  };
  const invoke = {
    ...SPAN_CHAT,
    spanId: '1000000000000002',
    parentSpanId: '1000000000000001',
    attributes: { 'gen_ai.operation.name': 'invoke_agent', 'gen_ai.agent.id': 'orchestrator' },
  };
  const worker = {
    ...SPAN_CHAT,
    spanId: '1000000000000003',
    parentSpanId: '1000000000000002',
    attributes: { ...SPAN_CHAT.attributes, 'gen_ai.agent.id': 'worker' },
  };
  const tool = {
    ...SPAN_CHAT,
    spanId: '1000000000000004',
    parentSpanId: '1000000000000003',
    attributes: { 'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'db.query' },
  };

  const aars = otelBatchToAARs([root, invoke, worker, tool], { tenantId: 't', emitterId: 'e' });
  assert.equal(aars.length, 4);
  for (const aar of aars) assert.equal(validateAAR(aar).length, 0);

  const rootAar = aars.find((a) => a.agent_hint.vendor_agent_id === 'orchestrator' && a.action.action_type === 'call_model');
  assert.deepEqual(rootAar.delegation_chain, [], 'lone actor: no delegation happened');

  const invokeAar = aars.find((a) => a.action.action_type === 'call_agent');
  assert.equal(invokeAar.action.target_entity_id, 'worker', 'callee derived from the child worker span');

  const workerAar = aars.find((a) => a.agent_hint.vendor_agent_id === 'worker');
  assert.deepEqual(workerAar.delegation_chain, [
    { kind: 'agent', id: 'orchestrator' },
    { kind: 'agent', id: 'worker' },
  ]);

  const toolAar = aars.find((a) => a.action.action_type === 'call_tool');
  assert.equal(toolAar.agent_hint.vendor_agent_id, 'worker', 'tool span inherits its nearest agent ancestor');
  assert.deepEqual(toolAar.delegation_chain, [
    { kind: 'agent', id: 'orchestrator' },
    { kind: 'agent', id: 'worker' },
  ]);
});

test('otelGenAiToAAR returns null for non-GenAI spans and maps errors', () => {
  assert.equal(otelGenAiToAAR({ name: 'http.get', attributes: { 'http.route': '/x' } }, { tenantId: 't', emitterId: 'e' }), null);
  const err = otelGenAiToAAR({ ...SPAN_CHAT, status: { code: 'ERROR', message: 'rate limited' } }, { tenantId: 't', emitterId: 'e' });
  assert.equal(err.quality.outcome, 'failure');
  assert.equal(err.quality.error_class, 'rate limited');
});

// E1: provantix.approval.* attributes — mapped here, converted to a keyed handle at the
// boundary, sealed as the erasable authorization block.
test('otelGenAiToAAR maps provantix.approval.* into the authorization block', () => {
  const aar = otelGenAiToAAR({
    ...SPAN_CHAT,
    attributes: {
      ...SPAN_CHAT.attributes,
      'provantix.approval.id': 'apr_9',
      'provantix.approval.approver': 'jane@corp.example',
      'provantix.approval.policy': 'pol-sensitive',
      'provantix.approval.ticket': 'CHG-1001',
    },
  }, { tenantId: 't', emitterId: 'e' });
  assert.equal(aar.authorization.approval_id, 'apr_9');
  assert.equal(aar.authorization.approver, 'jane@corp.example', 'raw at mapping; the boundary converts to a handle');
  assert.equal(aar.authorization.policy_id, 'pol-sensitive');
  assert.equal(aar.authorization.ticket, 'CHG-1001');
  assert.equal(validateAAR(aar).length, 0);

  const bare = otelGenAiToAAR(SPAN_CHAT, { tenantId: 't', emitterId: 'e' });
  assert.equal(bare.authorization, null);
});

test('validateAAR requires approval id and approver on the authorization block', () => {
  const aar = buildAAR({ tenantId: 't', emitterId: 'e', system: 's', action: { type: 'delete' } });
  aar.authorization = { ticket: 'CHG-1' };
  const problems = validateAAR(aar);
  assert.ok(problems.some((p) => p.includes('authorization.approval_id')));
  assert.ok(problems.some((p) => p.includes('authorization.approver')));
});

test('the emitter seals the approver as a keyed handle; the raw id never leaves and the record verifies', async () => {
  const { verifyRecord } = await import('../src/vendor/aar.mjs');
  const keys = AgentEmitter.generateKeys();
  const emitter = new AgentEmitter({
    emitterId: 'emi_approval', tenantId: 't', privateKeyPem: keys.privateKeyPem,
    handleKey: Buffer.alloc(32, 7),
  });
  emitter.emitOtelSpan({
    ...SPAN_CHAT,
    attributes: {
      'gen_ai.operation.name': 'execute_tool',
      'gen_ai.tool.name': 'crm.wipe',
      'provantix.approval.id': 'apr_9',
      'provantix.approval.approver': 'jane@corp.example',
    },
  });
  const batch = emitter.flush();
  assert.equal(batch.records.length, 1);
  const rec = batch.records[0];
  assert.equal(rec.erasable.authorization.value.approval_id, 'apr_9');
  assert.match(rec.erasable.authorization.value.approver, /^hdl:[0-9a-f]{16}$/);
  assert.ok(!JSON.stringify(rec).includes('jane@corp.example'), 'raw approver id must not survive sealing');
  assert.equal(verifyRecord(rec).valid, true, `sealed record must verify: ${verifyRecord(rec).reasons?.join('; ')}`);
});

// ---------- P3: tool payloads, data classes, external recipient ----------

test('otelBatchToAARs maps tool arguments/result into content and leaves prompts out', () => {
  const [aar] = otelBatchToAARs([{
    ...SPAN_CHAT,
    attributes: {
      'gen_ai.operation.name': 'execute_tool',
      'gen_ai.tool.name': 'db.query',
      'gen_ai.tool.call.arguments': '{"sql":"select * from t where id = 7"}',
      'gen_ai.tool.call.result': '{"rows":1}',
    },
  }], { tenantId: 't', emitterId: 'e' });
  assert.equal(aar.action.action_type, 'call_tool');
  assert.equal(aar.content.input_text, '{"sql":"select * from t where id = 7"}');
  assert.equal(aar.content.output_text, '{"rows":1}');
  assert.equal(aar.action.external_recipient, null);
  assert.equal(validateAAR(aar).length, 0);

  // A chat span carries no content mapping (prompt/completion stay hash-only).
  const chat = otelBatchToAARs([{ ...SPAN_CHAT, attributes: { ...SPAN_CHAT.attributes, 'gen_ai.content.prompt': 'secret prompt' } }], { tenantId: 't', emitterId: 'e' });
  assert.equal(chat[0].content, undefined);
});

test('send actions carry external_recipient from messaging attributes or tool arguments', () => {
  const [messaging] = otelBatchToAARs([{
    ...SPAN_CHAT,
    attributes: { 'gen_ai.system': 'acme', 'messaging.operation': 'send', 'messaging.destination.name': 'vendor-payments' },
  }], { tenantId: 't', emitterId: 'e' });
  assert.equal(messaging.action.action_type, 'send');
  assert.equal(messaging.action.external_recipient, 'vendor-payments');
  assert.equal(validateAAR(messaging).length, 0);

  const [tool] = otelBatchToAARs([{
    ...SPAN_CHAT,
    attributes: {
      'gen_ai.operation.name': 'execute_tool',
      'gen_ai.tool.name': 'send_email',
      'gen_ai.tool.call.arguments': '{"to":"client@external.com","subject":"statement"}',
    },
  }], { tenantId: 't', emitterId: 'e' });
  assert.equal(tool.action.action_type, 'call_tool');
  assert.equal(tool.action.external_recipient, 'client@external.com');
});

test('the collector seals tool arguments redacted and truncated, derives data classes, record verifies', async () => {
  const { verifyRecord } = await import('../src/vendor/aar.mjs');
  const keys = AgentEmitter.generateKeys();
  const emitter = new AgentEmitter({
    emitterId: 'emi_p3', tenantId: 't', privateKeyPem: keys.privateKeyPem,
    handleKey: Buffer.alloc(32, 7),
  });
  emitter.emitOtelSpan({
    ...SPAN_CHAT,
    attributes: {
      'gen_ai.operation.name': 'execute_tool',
      'gen_ai.tool.name': 'db.query',
      'gen_ai.tool.call.arguments': '{"sql":"select email from users","notify":"bob@corp.example"}',
      'gen_ai.tool.call.result': '{"rows":3}',
    },
  });
  const batch = emitter.flush();
  assert.equal(batch.records.length, 1);
  const rec = batch.records[0];

  // Redacted, sealed as the erasable summary; the raw email never leaves.
  assert.match(rec.erasable.input_summary.value, /select email from users/);
  assert.match(rec.erasable.input_summary.value, /<email>/);
  assert.ok(!rec.erasable.input_summary.value.includes('bob@corp.example'));
  assert.ok(!JSON.stringify(rec).includes('bob@corp.example'), 'raw id must not survive sealing');
  assert.equal(rec.erasable.output_summary.value, '{"rows":3}');

  // Data classes derived from redaction hits; counts say what was replaced.
  assert.deepEqual(rec.fields.action.data_classes, ['pii']);
  assert.equal(rec.fields.redaction.counts.email, 1);

  assert.equal(verifyRecord(rec).valid, true, `sealed record must verify: ${verifyRecord(rec).reasons?.join('; ')}`);
});

test('the collector truncates oversized summaries at the 2 KB cap and flags it', async () => {
  const keys = AgentEmitter.generateKeys();
  const emitter = new AgentEmitter({
    emitterId: 'emi_p3big', tenantId: 't', privateKeyPem: keys.privateKeyPem,
    handleKey: Buffer.alloc(32, 7),
  });
  emitter.emitOtelSpan({
    ...SPAN_CHAT,
    attributes: {
      'gen_ai.operation.name': 'execute_tool',
      'gen_ai.tool.name': 'extract.report',
      'gen_ai.tool.call.arguments': JSON.stringify({ blob: 'x'.repeat(5000) }),
    },
  });
  const rec = emitter.flush().records[0];
  assert.ok(rec.erasable.input_summary.value.endsWith('\u2026[truncated]') || rec.erasable.input_summary.value.includes('[truncated]'));
  assert.ok(rec.erasable.input_summary.value.length < 2100, 'summary capped near 2 KB');
  assert.equal(rec.fields.redaction.truncated, true);
});

// ---------- integration: emitter -> control plane ----------
// Runs against an isolated database created on DATABASE_URL (the role needs CREATEDB, which
// the compose user has); a shared database would make agent/emitter fixtures collide with
// other runs. Without DATABASE_URL the integration tests skip and only the unit tests run.

const hasDatabase = Boolean(process.env.DATABASE_URL && createLedgerApi);
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
