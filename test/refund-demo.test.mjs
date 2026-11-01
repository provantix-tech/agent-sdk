// P7 refund scenario test (product-value-assessment-2026-10-23.md §12.12): runs the example
// end to end against an isolated embedded-Postgres control plane (core API; the product API
// enforces pgvector at boot, which the embedded image lacks — the run view itself is P4's
// tested surface) and asserts the acceptance line — the approved run carries the approval on
// the record, the identical run without approval raises sensitive_action_without_approval,
// and the export verifies offline.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { freshStore, stopTestPg } from '../../../ledger/packages/ingest/test/pg.mjs';
import { createApp } from '../../../ledger/packages/ingest/src/index.mjs';
import { verifyExportDir } from '../../../ledger/packages/ingest/src/exporter.mjs';
import { registerEmitter } from '../../server/api.mjs';
import { runRefundDemo } from '../examples/refund-scenario.mjs';

after(stopTestPg);

const ADMIN = 'test-admin-token-p7';
// Fixed near-real clock: ingest rejects records more than 5 minutes in the future
// (record_in_future), so the scenario clock must stay inside the tolerance band.
const NOW = Date.now() - 60_000;

let app, store, base, exportDir;

before(async () => {
  ({ store } = await freshStore());
  exportDir = fs.mkdtempSync(path.join(os.tmpdir(), 'refund-demo-exports-'));
  app = createApp({ store, adminTokens: [{ token: ADMIN, name: 'test' }], exportDir, rootDir: path.join(exportDir, 'roots') });
  await new Promise((r) => app.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${app.address().port}`;
});

after(() => {
  app?.close();
  fs.rmSync(exportDir, { recursive: true, force: true });
});

const auth = { authorization: `Bearer ${ADMIN}` };
const getJson = async (p) => {
  const res = await fetch(base + p, { headers: auth });
  assert.equal(res.status, 200, `${p} -> ${res.status}`);
  return res.json();
};

test('P7: approved refund — approval on the record, no finding; unapproved twin raises it; export verifies', async () => {
  // Emitter registration is a product-API surface (/api/emitters); the core API under test has
  // no such route, so register through the shared helper (same store, same audit) and inject.
  process.env.LEDGER_TENANT_ID = 'ten_p7';
  const registration = await registerEmitter({ store, tenantId: 'ten_p7', name: 'refund-demo', actor: 'test' });
  const result = await runRefundDemo({ base, token: ADMIN, now: NOW, emitter: registration });
  assert.match(result.approved_trace, /^[0-9a-f]{32}$/);
  assert.match(result.unapproved_trace, /^[0-9a-f]{32}$/);
  const { approved: gatedAgent, unapproved: ungatedAgent } = result.agents;
  assert.notEqual(gatedAgent.agent_id, ungatedAgent.agent_id);

  // Both agents exist under the same policy: 'payments' is approval-required for each.
  const agents = await getJson('/v1/agents');
  for (const a of [gatedAgent, ungatedAgent]) {
    const row = agents.find((x) => x.agent_id === a.agent_id);
    assert.deepEqual(JSON.parse(row.approval_required_systems), ['payments'], `${a.display_name} has the payments policy`);
  }

  // Timeline: both runs landed, attributed to their own agent (2 spans x 2 runs + the simulated
  // destination record on the gated agent's trace).
  const timeline = await getJson(`/v1/timeline?limit=50`);
  const records = timeline.filter((r) => r.kind === 'record');
  assert.equal(records.length, 5);
  assert.ok(records.every((r) => r.attribution_method === 'explicit_platform_id'));
  assert.equal(records.filter((r) => r.agent_id === gatedAgent.agent_id).length, 3);
  assert.equal(records.filter((r) => r.agent_id === ungatedAgent.agent_id).length, 2);

  // The approved refund record carries the sealed authorization block; the unapproved twin
  // does not. Read the bodies straight from the store (the drawer/route rendering is P4's
  // tested surface).
  const bodies = await store.query('SELECT source_vantage, trace_id, body FROM records ORDER BY observed_at, record_id');
  const approvedRefund = bodies.find((r) => r.trace_id === result.approved_trace && JSON.parse(r.body).fields.action.tool_name === 'issue_refund');
  const unapprovedRefund = bodies.find((r) => r.trace_id === result.unapproved_trace && JSON.parse(r.body).fields.action.tool_name === 'issue_refund');
  assert.equal(JSON.parse(approvedRefund.body).erasable.authorization.value.approval_id, 'apr_refund_1042');
  assert.equal(JSON.parse(approvedRefund.body).erasable.authorization.value.approver.startsWith('hdl:'), true, 'approver is a handle, never a raw id');
  assert.equal(JSON.parse(unapprovedRefund.body).erasable.authorization.value, null);
  const destination = bodies.find((r) => r.source_vantage === 'destination');
  assert.equal(JSON.parse(destination.body).fields.action.target_system, 'payments');

  // The finding fired on the ungated agent only; the gated agent — which recorded an approval
  // inside the adoption window — is clean (the E2 rule's designed behaviour).
  assert.equal(result.sensitive_findings.length, 1);
  const finding = result.sensitive_findings[0];
  assert.equal(finding.subject, ungatedAgent.agent_id);
  assert.equal(finding.status, 'open');
  const detail = await getJson(`/v1/findings/${finding.finding_id}`);
  const unapprovedId = (await store.query(
    "SELECT record_id FROM records WHERE trace_id = $1 AND action_type = 'call_tool'",
    result.unapproved_trace,
  ))[0].record_id;
  const approvedId = (await store.query(
    "SELECT record_id FROM records WHERE trace_id = $1 AND action_type = 'call_tool'",
    result.approved_trace,
  ))[0].record_id;
  assert.ok(detail.record_ids?.includes(unapprovedId), 'finding points at the unapproved refund record');
  assert.ok(!detail.record_ids?.includes(approvedId), 'the approved refund is not flagged');
  const gatedFindings = (await getJson('/v1/findings')).filter((f) => f.subject === gatedAgent.agent_id && f.kind === 'sensitive_action_without_approval');
  assert.equal(gatedFindings.length, 0, 'the gated agent that records approvals is not flagged');

  // The org-wide export verifies offline with the canonical verifier.
  const expRes = await fetch(`${base}/v1/exports`, {
    method: 'POST',
    headers: { ...auth, 'content-type': 'application/json' },
    body: JSON.stringify({}),
  });
  assert.equal(expRes.status, 201);
  const exp = await expRes.json();
  assert.equal(exp.record_count, 5);
  const verification = verifyExportDir(path.join(exportDir, exp.export_id));
  assert.equal(verification.ok, true, `export must verify: ${verification.checks.filter((c) => !c.ok).map((c) => c.name).join('; ')}`);
});
