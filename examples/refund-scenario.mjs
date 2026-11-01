// P7 refund scenario (product-value-assessment-2026-10-23.md §12.12) — "refund above threshold".
//
// One scripted run, twice, under the SAME policy ('payments' is approval-required for both
// agents):
//   RUN 1 (approved)   a user asks for a refund → a human approves (approval id on the span)
//                      → the gated agent calls issue_refund on the payments system. The record
//                      carries the sealed authorization block → no finding.
//   RUN 2 (unapproved) the identical request, run by an UNGATED twin that never records
//                      approvals → the SAME tool call raises sensitive_action_without_approval.
//
// Why two agents: the shipped E2 rule (behaviour.mjs §7) is per-agent with a 7-day adoption
// window — any approved record in the window means the agent has a gate and the condition
// clears. One agent doing both runs would clear its own finding, which would teach the wrong
// lesson. Two agents under the same policy is what the rule actually distinguishes: an agent
// that records its approvals versus one that acts on an approval-required system without any.
//
// A destination-vantage record (the payments system of record acknowledging the refund) is
// emitted alongside RUN 1. It is labelled simulated: until a D2 destination connector ships,
// the example stands in for the system of record so the run view shows both sides.
//
// runRefundDemo() speaks plain HTTP against any control plane and returns everything it did,
// so the test-suite can assert on it. examples/refund-demo.mjs is the thin CLI wrapper.

import { AgentEmitter, buildAAR, otelBatchToAARs, aarToSourceEvent } from '../src/index.mjs';

const AGENT_APPROVED = { vendor: 'acme', vendorAgentId: 'refund-agent', displayName: 'Refund Agent' };
const AGENT_UNAPPROVED = { vendor: 'acme', vendorAgentId: 'refund-agent-no-gate', displayName: 'Refund Agent (no gate)' };
const POLICY = { id: 'apr_refund_1042', approver: 'ops.lead@corp.example', policy: 'refund-over-threshold', ticket: 'CHG-2201' };

function spansForRun({ trace, now, withApproval, agent }) {
  const agentAttrs = {
    'gen_ai.agent.name': agent.vendor, // attribution hint: vendor
    'gen_ai.agent.id': agent.vendorAgentId, // attribution hint: vendor_agent_id
  };
  const toolAttrs = {
    ...agentAttrs,
    'gen_ai.operation.name': 'execute_tool',
    'gen_ai.system': 'acme-runtime',
    'gen_ai.tool.name': 'issue_refund',
    'db.name': 'payments',
    'gen_ai.tool.call.arguments': JSON.stringify({ order_id: 'ord_7841', amount_cents: 42000, reason: 'damaged goods' }),
    'gen_ai.tool.call.result': JSON.stringify({ refund_id: 'ref_9917', status: 'settled' }),
  };
  if (withApproval) {
    toolAttrs['provantix.approval.id'] = POLICY.id;
    toolAttrs['provantix.approval.approver'] = POLICY.approver;
    toolAttrs['provantix.approval.policy'] = POLICY.policy;
    toolAttrs['provantix.approval.ticket'] = POLICY.ticket;
    toolAttrs['provantix.approval.approved_at'] = new Date(now - 60_000).toISOString();
  }
  return [
    {
      traceId: trace, spanId: '0000000000000001', kind: 'client',
      startTime: now - 4000, endTime: now - 3300,
      attributes: {
        ...agentAttrs,
        'gen_ai.operation.name': 'chat', 'gen_ai.system': 'acme-runtime', 'gen_ai.request.model': 'acme-1',
        'gen_ai.usage.input_tokens': 210, 'gen_ai.usage.output_tokens': 60,
        'user.id': 'alex@customer.example',
        'gen_ai.conversation.id': 'conv-refund-7841',
      },
      status: { code: 'OK' },
    },
    {
      traceId: trace, spanId: '0000000000000002', parentSpanId: '0000000000000001', kind: 'client',
      startTime: now - 3200, endTime: now - 1200,
      attributes: toolAttrs,
      status: { code: 'OK' },
    },
  ];
}

function destinationRecord({ trace, now }) {
  // Simulated system of record: what the payments system would report about the same refund.
  // Destination vantage, same correlation ids — this is what a D2 connector will produce for
  // real; the example emits it so said-vs-landed has two sides today.
  return buildAAR({
    tenantId: 'pending', // replaced by the emitter at emit time
    emitterId: 'pending',
    system: 'payments',
    vantage: 'destination',
    agent: { vendor: AGENT_APPROVED.vendor, vendorAgentId: AGENT_APPROVED.vendorAgentId },
    action: { type: 'execute', targetSystem: 'payments', operation: 'refund.settle', dataClasses: ['financial'] },
    correlation: { traceId: trace, spanId: '00000000000000f0' },
    observedAt: new Date(now - 1100).toISOString(),
  });
}

async function call(fetchImpl, base, token, method, p, body) {
  const res = await fetchImpl(base + p, {
    method,
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${method} ${p} -> ${res.status}: ${data.error ?? res.statusText}`);
  return data;
}

/**
 * @param {object} o
 * @param {string} o.base        control-plane base URL
 * @param {string} o.token       admin bearer token
 * @param {Function} [o.fetchImpl]
 * @param {string} [o.spoolDir]  durable spool (recommended for the CLI)
 * @param {Function} [o.log]
 * @param {number} [o.now]       fixed clock for tests
 * @param {object} [o.emitter]   pre-registered emitter registration (the test suite registers
 *   via the product helper; when omitted the scenario self-registers over POST /api/emitters)
 */
export async function runRefundDemo({ base, token, fetchImpl = fetch, spoolDir = null, log = () => {}, now = Date.now(), emitter: preRegistered = null }) {
  const get = (p) => call(fetchImpl, base, token, 'GET', p);
  const post = (p, body) => call(fetchImpl, base, token, 'POST', p, body);

  // 1. Both agents exist and 'payments' is approval-required for each — the same policy,
  // one gated agent that records approvals, one that never has.
  const ensureAgent = async (spec) => {
    const agents = await get('/v1/agents');
    let a = agents.find((x) => x.vendor === spec.vendor && x.vendor_agent_id === spec.vendorAgentId);
    if (!a) {
      a = await post('/v1/agents', { display_name: spec.displayName, vendor: spec.vendor, vendor_agent_id: spec.vendorAgentId, kind: 'agent' });
      await post(`/v1/agents/${a.agent_id}/lifecycle`, { to: 'active', reason: 'refund demo' });
      log(`agent created: ${a.display_name} (${a.agent_id})`);
    } else {
      log(`agent exists: ${a.display_name} (${a.agent_id})`);
    }
    return post(`/v1/agents/${a.agent_id}/approval-required`, { system: 'payments' });
  };
  const gatedAgent = await ensureAgent(AGENT_APPROVED);
  const ungatedAgent = await ensureAgent(AGENT_UNAPPROVED);
  log("policy: 'payments' is approval-required for both agents");

  // 2. An emitter with its own signing key.
  const registration = preRegistered ?? await post('/api/emitters', { name: 'refund-demo' });
  const emitter = new AgentEmitter({
    emitterId: registration.emitter_id,
    tenantId: registration.tenant_id,
    privateKeyPem: registration.private_key_pem,
    spoolDir,
  });

  const emitSpans = (spans) => {
    const aars = otelBatchToAARs(spans, { tenantId: registration.tenant_id, emitterId: registration.emitter_id });
    for (const aar of aars) emitter.collector.ingest(aarToSourceEvent(aar, emitter));
  };

  // 3. RUN 1 — approved, on the gated agent.
  const approvedTrace = [...Array(32)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
  emitSpans(spansForRun({ trace: approvedTrace, now, withApproval: true, agent: AGENT_APPROVED }));
  const dest = destinationRecord({ trace: approvedTrace, now });
  dest.tenant_id = registration.tenant_id;
  dest.emitter_id = registration.emitter_id;
  emitter.emitAAR(dest);
  const drain1 = await emitter.flushAndDrain(base);
  log(`run 1 (approved, ${gatedAgent.display_name}): trace ${approvedTrace} — ${drain1.results[0]?.accepted ?? 0} record(s) shipped`);

  // 4. RUN 2 — same request, no approval, on the agent that has never recorded one.
  const unapprovedTrace = [...Array(32)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
  emitSpans(spansForRun({ trace: unapprovedTrace, now: now + 60_000, withApproval: false, agent: AGENT_UNAPPROVED }));
  const drain2 = await emitter.flushAndDrain(base);
  log(`run 2 (unapproved, ${ungatedAgent.display_name}): trace ${unapprovedTrace} — ${drain2.results[0]?.accepted ?? 0} record(s) shipped`);

  // 5. Findings pass — the rule is per-agent, so match on the ungated agent.
  await post('/v1/findings/run', {});
  const findings = (await get('/v1/findings')).filter((f) => f.subject === ungatedAgent.agent_id);
  const sensitive = findings.filter((f) => f.kind === 'sensitive_action_without_approval');
  log(sensitive.length
    ? `finding raised: sensitive_action_without_approval (${sensitive[0].status}) on ${ungatedAgent.display_name} — acting on an approval-required system with no recorded approval`
    : 'no sensitive_action_without_approval finding');

  return {
    agents: { approved: gatedAgent, unapproved: ungatedAgent },
    emitter: registration,
    approved_trace: approvedTrace,
    unapproved_trace: unapprovedTrace,
    findings,
    sensitive_findings: sensitive,
  };
}
