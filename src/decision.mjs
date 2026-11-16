// Decision evidence for the SDK (PRO-34): record why an agent chose an action, as references and short summaries, never as raw reasoning.
//
// An agent that decides something with consequences (restart a service, roll back a deploy, issue a refund) emits one decision record BEFORE it
// acts, and puts a pointer to it on the action's own record:
//
//   const decision = buildDecisionAAR({ tenantId, emitterId, system, agent, taskId: 'INC-4821', targetSystem: 'payments-prod',
//     hypothesis: { summary: 'Latency began at the 14:02 deploy', evidence: [{ ref: 'metric://p99/payments', sha256: '…', kind: 'metric' }] },
//     candidates: [{ id: 'c1', action: 'roll back deploy 41' }, { id: 'c2', action: 'scale out' }],
//     selected: { candidateId: 'c1', actionId: 'act_7' }, rejected: [{ candidateId: 'c2', reason: 'would not remove the cause' }] });
//   emitter.collector.ingest(aarToSourceEvent(decision.aar, emitter));
//   ... later, the action itself:
//   buildAAR({ ..., action: { type: 'call_tool', toolName: 'rollback', targetSystem: 'payments-prod' }, ext: { decision_ref: decision.ref } });
//
// What is kept: short summaries and references (a metric id, a ticket, a hash), capped in length. What is refused: anything that looks like a
// credential, and any field this contract does not name, so a raw prompt or a reasoning trace cannot ride along by accident. What it shows: what
// the agent said it considered and chose. It does not show the reasoning was sound or was the real reason, and it never writes a rationale the
// agent did not give: leave `hypothesis`, `rejected` or the risk reference out and they read as not recorded.
//
// Keep the rules in step with ledger/packages/aar-schema/src/decision-evidence.mjs; a test in the monorepo compares them.

import { buildAAR } from './aar.mjs';

export const DECISION_VERSION = 1;
export const DECISION_SOURCES = Object.freeze(['agent', 'human', 'system']);
export const DECISION_LIMITS = Object.freeze({ text: 500, ref: 300, items: 20 });

const SECRET_LIKE = [
  /sk-[A-Za-z0-9_-]{16,}/, /AKIA[0-9A-Z]{16}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /Bearer\s+[A-Za-z0-9._~+/-]{20,}/,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, /rzp_(test|live)_[A-Za-z0-9]{8,}/, /(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}/i,
];

const ALLOWED = {
  top: ['taskId', 'source', 'hypothesis', 'candidates', 'selected', 'rejected', 'riskAssessmentRef', 'decisionId', 'intentRef', 'modelRef'],
  hypothesis: ['summary', 'evidence'], evidence: ['ref', 'sha256', 'kind'], candidate: ['id', 'action', 'summary', 'riskRef'], selected: ['candidateId', 'actionId'], intent: ['ref', 'sha256', 'kind'], model: ['modelId', 'provider', 'modelVersion', 'invocationRef'], rejected: ['candidateId', 'reason'],
};

function checkKeys(obj, allowed, where) {
  for (const k of Object.keys(obj)) if (!allowed.includes(k)) throw new TypeError(`${where}: "${k}" is not part of the decision contract (raw prompts and reasoning traces are not kept; use a short summary or a reference)`);
}
function text(v, max, where) {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v !== 'string') throw new TypeError(`${where} must be a string`);
  if (v.length > max) throw new TypeError(`${where} is ${v.length} characters; the limit is ${max}. Keep a short summary and put the rest behind a reference`);
  if (SECRET_LIKE.some((re) => re.test(v))) throw new TypeError(`${where} looks like it holds a credential, so it was refused`);
  return v;
}
const need = (v, where) => { if (!v) throw new TypeError(`${where} is required`); return v; };
const list = (v, where) => {
  if (v === undefined || v === null) return [];
  if (!Array.isArray(v)) throw new TypeError(`${where} must be a list`);
  if (v.length > DECISION_LIMITS.items) throw new TypeError(`${where} has more than ${DECISION_LIMITS.items} items`);
  return v;
};

/**
 * Build the decision record and the pointer for the action's record.
 * @returns {{ aar: object, decision: object, ref: { decision_id: string, candidate_id: string, action_id: string } }}
 */
export function buildDecisionAAR(a) {
  if (!a || typeof a !== 'object') throw new TypeError('a decision needs its details');
  checkKeys(a, [...ALLOWED.top, 'tenantId', 'emitterId', 'system', 'agent', 'targetSystem', 'correlation', 'observedAt', 'eventId', 'onBehalfOf', 'vantage'], 'decision');
  const source = a.source ?? 'agent';
  if (!DECISION_SOURCES.includes(source)) throw new TypeError(`source must be one of ${DECISION_SOURCES.join(', ')}`);
  const candidates = list(a.candidates, 'candidates').map((c, i) => {
    checkKeys(c, ALLOWED.candidate, `candidates[${i}]`);
    return {
      id: text(need(c.id, `candidates[${i}].id`), DECISION_LIMITS.ref, `candidates[${i}].id`),
      action: text(need(c.action, `candidates[${i}].action`), DECISION_LIMITS.text, `candidates[${i}].action`),
      ...(c.summary ? { summary: text(c.summary, DECISION_LIMITS.text, `candidates[${i}].summary`) } : {}),
      ...(c.riskRef ? { risk_ref: text(c.riskRef, DECISION_LIMITS.ref, `candidates[${i}].riskRef`) } : {}),
    };
  });
  if (!candidates.length) throw new TypeError('a decision needs at least one candidate action');
  const ids = new Set();
  for (const c of candidates) { if (ids.has(c.id)) throw new TypeError(`candidate id ${c.id} is used twice`); ids.add(c.id); }
  need(a.selected, 'selected'); checkKeys(a.selected, ALLOWED.selected, 'selected');
  const selected = { candidate_id: text(need(a.selected.candidateId, 'selected.candidateId'), DECISION_LIMITS.ref, 'selected.candidateId'), action_id: text(need(a.selected.actionId, 'selected.actionId'), DECISION_LIMITS.ref, 'selected.actionId') };
  if (!ids.has(selected.candidate_id)) throw new TypeError('the selected candidate is not among the candidates');
  const rejected = list(a.rejected, 'rejected').map((r, i) => {
    checkKeys(r, ALLOWED.rejected, `rejected[${i}]`);
    const id = text(need(r.candidateId, `rejected[${i}].candidateId`), DECISION_LIMITS.ref, `rejected[${i}].candidateId`);
    if (!ids.has(id)) throw new TypeError(`rejected candidate ${id} is not among the candidates`);
    if (id === selected.candidate_id) throw new TypeError('the selected candidate cannot also be rejected');
    return { candidate_id: id, ...(r.reason ? { reason: text(r.reason, DECISION_LIMITS.text, `rejected[${i}].reason`) } : {}) };
  });
  let hypothesis;
  if (a.hypothesis) {
    checkKeys(a.hypothesis, ALLOWED.hypothesis, 'hypothesis');
    hypothesis = {
      summary: text(need(a.hypothesis.summary, 'hypothesis.summary'), DECISION_LIMITS.text, 'hypothesis.summary'),
      evidence: list(a.hypothesis.evidence, 'hypothesis.evidence').map((e, i) => {
        checkKeys(e, ALLOWED.evidence, `hypothesis.evidence[${i}]`);
        if (e.sha256 && !/^[0-9a-f]{64}$/i.test(e.sha256)) throw new TypeError(`hypothesis.evidence[${i}].sha256 must be 64 hex characters`);
        return { ref: text(need(e.ref, `hypothesis.evidence[${i}].ref`), DECISION_LIMITS.ref, `hypothesis.evidence[${i}].ref`), ...(e.sha256 ? { sha256: e.sha256.toLowerCase() } : {}), ...(e.kind ? { kind: text(e.kind, 60, `hypothesis.evidence[${i}].kind`) } : {}) };
      }),
    };
  }
  // The instruction this decision answers (a ticket, a request id, a hash of the instruction) and the model invocation behind it: references only.
  let intentRef;
  if (a.intentRef) {
    checkKeys(a.intentRef, ALLOWED.intent, 'intentRef');
    if (a.intentRef.sha256 && !/^[0-9a-f]{64}$/i.test(a.intentRef.sha256)) throw new TypeError('intentRef.sha256 must be 64 hex characters');
    intentRef = { ref: text(need(a.intentRef.ref, 'intentRef.ref'), DECISION_LIMITS.ref, 'intentRef.ref'), ...(a.intentRef.sha256 ? { sha256: a.intentRef.sha256.toLowerCase() } : {}), ...(a.intentRef.kind ? { kind: text(a.intentRef.kind, 60, 'intentRef.kind') } : {}) };
  }
  let modelRef;
  if (a.modelRef) {
    checkKeys(a.modelRef, ALLOWED.model, 'modelRef');
    modelRef = {
      model_id: text(need(a.modelRef.modelId, 'modelRef.modelId'), DECISION_LIMITS.ref, 'modelRef.modelId'),
      ...(a.modelRef.provider ? { provider: text(a.modelRef.provider, 100, 'modelRef.provider') } : {}),
      ...(a.modelRef.modelVersion ? { model_version: text(a.modelRef.modelVersion, 100, 'modelRef.modelVersion') } : {}),
      ...(a.modelRef.invocationRef ? { invocation_ref: text(a.modelRef.invocationRef, DECISION_LIMITS.ref, 'modelRef.invocationRef') } : {}),
    };
  }
  const decision = {
    v: DECISION_VERSION,
    decision_id: a.decisionId ? text(a.decisionId, DECISION_LIMITS.ref, 'decisionId') : `dec_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`,
    ...(a.taskId ? { task_id: text(a.taskId, DECISION_LIMITS.ref, 'taskId') } : {}),
    source,
    ...(intentRef ? { intent_ref: intentRef } : {}),
    ...(modelRef ? { model_ref: modelRef } : {}),
    ...(hypothesis ? { hypothesis } : {}),
    candidates,
    selected,
    ...(rejected.length ? { rejected } : {}),
    ...(a.riskAssessmentRef ? { risk_assessment_ref: text(a.riskAssessmentRef, DECISION_LIMITS.ref, 'riskAssessmentRef') } : {}),
  };
  const aar = buildAAR({
    tenantId: a.tenantId, emitterId: a.emitterId, system: a.system, agent: a.agent, correlation: a.correlation, onBehalfOf: a.onBehalfOf,
    observedAt: a.observedAt, eventId: a.eventId, vantage: a.vantage, eventType: 'AgentDecision',
    // a decision is a reasoning step by the agent, recorded as a model-side action on the system it is deciding about
    action: { type: 'call_model', operation: 'decision', targetSystem: a.targetSystem },
    ext: { decision },
  });
  return { aar, decision, ref: { decision_id: decision.decision_id, candidate_id: selected.candidate_id, action_id: selected.action_id } };
}

/** The pointer an action's record carries to its decision: pass it as `ext: { decision_ref }` when building the action's record. */
export const decisionRef = (decision) => ({ decision_id: decision.decision_id, candidate_id: decision.selected.candidate_id, action_id: decision.selected.action_id });
