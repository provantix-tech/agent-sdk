// Demo: emit agent telemetry to a running control plane.
//
//   node examples/emit-demo.mjs [baseUrl] [adminToken]
//
// There is deliberately no built-in default token (review C4): pass the admin token your
// control plane was started with (LEDGER_ADMIN_TOKEN / LEDGER_TOKENS, or the generated
// .admin-token file in its data directory).
// With `npm run dev` running (app/web), in another shell:
//   node app/agent-sdk/examples/emit-demo.mjs http://localhost:3000 <admin-token>
// Then open the app: the "Support Copilot" agent has new inside-vantage records, and the
// emitter appears on the Connectors page.

import { AgentEmitter, otelBatchToAARs } from '../src/index.mjs';

const base = process.argv[2] ?? 'http://localhost:3000';
const token = process.argv[3] ?? process.env.LEDGER_ADMIN_TOKEN;
if (!token) {
  console.error('admin token required: pass it as argv[3] or set LEDGER_ADMIN_TOKEN');
  process.exit(1);
}
const auth = { authorization: `Bearer ${token}`, 'content-type': 'application/json' };

const call = async (method, p, body) => {
  const res = await fetch(base + p, { method, headers: auth, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json();
  if (!res.ok) throw new Error(`${method} ${p} -> ${res.status}: ${data.error}`);
  return data;
};

// 1. Ensure the agent exists (vendor + vendor_agent_id drive attribution).
let agents = await call('GET', '/v1/agents');
let agent = agents.find((a) => a.vendor === 'otel' && a.vendor_agent_id === 'support-copilot');
if (!agent) {
  agent = await call('POST', '/v1/agents', { display_name: 'Support Copilot', vendor: 'otel', vendor_agent_id: 'support-copilot', kind: 'copilot' });
  await call('POST', `/v1/agents/${agent.agent_id}/lifecycle`, { to: 'active', reason: 'emitter demo' });
  console.log('created agent:', agent.display_name, agent.agent_id);
} else {
  console.log('agent exists:', agent.display_name, agent.agent_id);
}

// 2. Register an emitter (the private key is shown once — store it like any credential).
const registration = await call('POST', '/api/emitters', { name: 'copilot-runtime-demo' });
console.log('emitter registered:', registration.emitter_id, '-> connector', registration.connector_instance);

// 3. Simulate a conversation: model call -> tool calls -> model call with an error.
const now = Date.now();
const trace = [...Array(16)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
const spans = [
  {
    traceId: trace, spanId: '0000000000000001', kind: 'client',
    startTime: now - 9000, endTime: now - 8000,
    attributes: {
      'gen_ai.operation.name': 'chat', 'gen_ai.system': 'openai', 'gen_ai.request.model': 'gpt-x',
      'gen_ai.usage.input_tokens': 412, 'gen_ai.usage.output_tokens': 96,
      'gen_ai.conversation.id': 'conv-demo-1', 'gen_ai.agent.id': 'support-copilot',
    },
    status: { code: 'OK' },
  },
  {
    traceId: trace, spanId: '0000000000000002', parentSpanId: '0000000000000001', kind: 'client',
    startTime: now - 7900, endTime: now - 7100,
    attributes: {
      'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'crm.search',
      'gen_ai.system': 'openai', 'server.address': 'salesforce',
    },
    status: { code: 'OK' },
  },
  {
    traceId: trace, spanId: '0000000000000003', parentSpanId: '0000000000000001', kind: 'client',
    startTime: now - 7000, endTime: now - 6300,
    attributes: {
      'gen_ai.operation.name': 'execute_tool', 'gen_ai.tool.name': 'tickets.create',
      'gen_ai.system': 'openai', 'server.address': 'servicenow',
    },
    status: { code: 'OK' },
  },
  {
    traceId: trace, spanId: '0000000000000004', kind: 'client',
    startTime: now - 2000, endTime: now - 900,
    attributes: {
      'gen_ai.operation.name': 'chat', 'gen_ai.system': 'openai', 'gen_ai.request.model': 'gpt-x',
      'gen_ai.usage.input_tokens': 820, 'gen_ai.usage.output_tokens': 240,
      'gen_ai.conversation.id': 'conv-demo-1', 'gen_ai.agent.id': 'support-copilot',
    },
    status: { code: 'ERROR', message: 'model timeout after retries' },
  },
];

// 4. Emit and drain.
const emitter = new AgentEmitter({
  emitterId: registration.emitter_id,
  tenantId: registration.tenant_id,
  privateKeyPem: registration.private_key_pem,
  spoolDir: '.demo-spool',
});
for (const span of spans) {
  emitter.emitOtelSpan(span, { agent: { vendor: 'otel', vendorAgentId: 'support-copilot' } });
}
const drain = await emitter.flushAndDrain(base);
console.log(`shipped ${drain.sent} batch(es):`, JSON.stringify(drain.results.map((r) => ({ accepted: r.accepted, rejected: r.rejected }))));

// 5. Show what the platform saw.
const timeline = await call('GET', `/v1/timeline?agent_id=${agent.agent_id}&limit=10`);
const mine = timeline.filter((r) => r.kind === 'record').slice(0, 4);
for (const r of mine) {
  console.log(`  ${r.at}  ${r.action_type?.padEnd(11)} ${r.target_system ?? ''}  ${r.attribution_method} @ ${r.attribution_confidence}`);
}
console.log('\nOpen', base, '→ Agents → Support Copilot → Activity, or Investigate filtered by the agent.');
