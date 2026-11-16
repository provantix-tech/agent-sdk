// Control decision evidence for the SDK (PRO-42): record what an enforcement tool decided about an action an agent proposed.
//
// This is for the enforcement side, or for glue code next to it: an agent gateway, a runtime security product, a policy engine, an approval step.
// When it decides allow, ask, deny or steer, it emits one control decision record. Provantix does not make the decision and is not in the path. It
// keeps the verdict with the policy and version that produced it, and compares it with what the destination later shows: a denied action that
// still has a record is "denied, but executed", and a finding.
//
//   const control = buildControlDecisionAAR({
//     tenantId, emitterId, system: 'agent-gateway', agent: { vendor: 'acme', vendorAgentId: 'sre-agent' },
//     enforcer: { name: 'agent-gateway', version: '2.1' }, verdict: 'deny', policy: { id: 'prod-changes', version: '7' },
//     reason: 'exposes a bucket to the internet', actionId: 'act_7',
//     proposed: { targetSystem: 'payments-prod', toolName: 'open_firewall' }, correlation: { traceId },
//   });
//   emitter.collector.ingest(aarToSourceEvent(control.aar, emitter));
//
// To join exactly, put the same action id on the action's own record (`ext: { control_ref: controlRef(control.control) }`, or the decision pointer or
// claim it already carries). Without one, Provantix joins by the same trace, system and tool soon after, and says the join is probable.
//
// What is kept: a short reason and references. What is refused: anything that looks like a credential, and any field this contract does not name
// (a raw prompt or a tool's full arguments). A verdict is the enforcer's own statement: it is not Provantix's judgement and not proof the control worked.
// Keep the rules in step with ledger/packages/aar-schema/src/control-evidence.mjs; a test in the monorepo compares them.

import { buildAAR } from './aar.mjs';

export const CONTROL_VERSION = 1;
export const CONTROL_VERDICTS = Object.freeze(['allow', 'ask', 'deny', 'steer']);
export const CONTROL_LIMITS = Object.freeze({ text: 500, ref: 300 });

const SECRET_LIKE = [
  /sk-[A-Za-z0-9_-]{16,}/, /AKIA[0-9A-Z]{16}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /Bearer\s+[A-Za-z0-9._~+/-]{20,}/,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, /rzp_(test|live)_[A-Za-z0-9]{8,}/, /(password|passwd|secret|api[_-]?key|token)\s*[:=]\s*\S{6,}/i,
];
const ENVELOPE = ['tenantId', 'emitterId', 'system', 'agent', 'correlation', 'observedAt', 'eventId', 'onBehalfOf', 'vantage', 'targetSystem'];
const ALLOWED = {
  top: ['controlId', 'enforcer', 'verdict', 'policy', 'reason', 'riskRef', 'approvalRef', 'decidedAt', 'actionId', 'proposed'],
  enforcer: ['name', 'version'], policy: ['id', 'version'], proposed: ['actionType', 'targetSystem', 'targetEntityId', 'toolName', 'summary'],
};

function checkKeys(obj, allowed, where) {
  for (const k of Object.keys(obj)) if (!allowed.includes(k)) throw new TypeError(`${where}: "${k}" is not part of the control decision contract (a raw prompt or a tool's full arguments are not kept; use a short summary or a reference)`);
}
function text(v, max, where) {
  if (v === undefined || v === null || v === '') return null;
  if (typeof v !== 'string') throw new TypeError(`${where} must be a string`);
  if (v.length > max) throw new TypeError(`${where} is ${v.length} characters; the limit is ${max}. Keep a short summary and put the rest behind a reference`);
  if (SECRET_LIKE.some((re) => re.test(v))) throw new TypeError(`${where} looks like it holds a credential, so it was refused`);
  return v;
}
const need = (v, where) => { if (!v) throw new TypeError(`${where} is required`); return v; };
const put = (o, k, v) => { if (v !== null && v !== undefined) o[k] = v; return o; };

/**
 * Build the control decision record, and the content that a pointer on the action's record is made from.
 * @returns {{ aar: object, control: object }}
 */
export function buildControlDecisionAAR(a) {
  if (!a || typeof a !== 'object') throw new TypeError('a control decision needs its details');
  checkKeys(a, [...ALLOWED.top, ...ENVELOPE], 'control decision');
  if (!CONTROL_VERDICTS.includes(a.verdict)) throw new TypeError(`verdict must be one of ${CONTROL_VERDICTS.join(', ')} (map your tool's words onto these: block is deny, require approval is ask)`);
  need(a.enforcer, 'enforcer'); checkKeys(a.enforcer, ALLOWED.enforcer, 'enforcer');
  need(a.policy, 'policy'); checkKeys(a.policy, ALLOWED.policy, 'policy');
  const enforcer = put({ name: text(need(a.enforcer.name, 'enforcer.name'), CONTROL_LIMITS.ref, 'enforcer.name') }, 'version', text(a.enforcer.version, 60, 'enforcer.version'));
  const policy = put({ id: text(need(a.policy.id, 'policy.id'), CONTROL_LIMITS.ref, 'policy.id') }, 'version', text(a.policy.version, 60, 'policy.version'));
  if (a.decidedAt !== undefined && Number.isNaN(Date.parse(a.decidedAt))) throw new TypeError('decidedAt must be a date and time');
  let proposed = null;
  if (a.proposed) {
    checkKeys(a.proposed, ALLOWED.proposed, 'proposed');
    proposed = {};
    put(proposed, 'action_type', text(a.proposed.actionType, 60, 'proposed.actionType'));
    put(proposed, 'target_system', text(a.proposed.targetSystem, CONTROL_LIMITS.ref, 'proposed.targetSystem'));
    put(proposed, 'target_entity_id', text(a.proposed.targetEntityId, CONTROL_LIMITS.ref, 'proposed.targetEntityId'));
    put(proposed, 'tool_name', text(a.proposed.toolName, CONTROL_LIMITS.ref, 'proposed.toolName'));
    put(proposed, 'summary', text(a.proposed.summary, CONTROL_LIMITS.text, 'proposed.summary'));
  }
  const control = { v: CONTROL_VERSION, control_id: text(a.controlId, CONTROL_LIMITS.ref, 'controlId') ?? `ctl_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`, enforcer, verdict: a.verdict, policy };
  put(control, 'reason', text(a.reason, CONTROL_LIMITS.text, 'reason'));
  put(control, 'risk_ref', text(a.riskRef, CONTROL_LIMITS.ref, 'riskRef'));
  put(control, 'approval_ref', text(a.approvalRef, CONTROL_LIMITS.ref, 'approvalRef'));
  put(control, 'decided_at', a.decidedAt ? new Date(a.decidedAt).toISOString() : null);
  put(control, 'action_id', text(a.actionId, CONTROL_LIMITS.ref, 'actionId'));
  if (proposed && Object.keys(proposed).length) control.proposed = proposed;
  const aar = buildAAR({
    tenantId: a.tenantId, emitterId: a.emitterId, system: a.system, agent: a.agent, correlation: a.correlation, onBehalfOf: a.onBehalfOf,
    observedAt: a.observedAt, eventId: a.eventId, eventType: 'ControlDecision', vantage: a.vantage ?? 'boundary',
    // a control decision is not an action on a target: it is recorded as an operation of this type so it is told apart by its event type
    action: { type: 'unknown', operation: 'control_decision', targetSystem: a.targetSystem ?? proposed?.target_system },
    ext: { control },
  });
  return { aar, control };
}

/** The pointer an action's own record can carry so the control decision joins to it exactly: `ext: { control_ref: controlRef(control) }`. */
export const controlRef = (control) => ({ control_id: control.control_id, action_id: control.action_id ?? null });
