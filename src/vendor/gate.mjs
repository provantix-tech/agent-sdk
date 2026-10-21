// Principal gate: decides what a collector may turn into a full record.
// Design: plan/02-data-model.md section 2 and plan/04-connectors.md section 1.
//
// Output classes:
//   'full'        - produce a stored record with everything the source gave us
//   'obo_window'  - a human record inside an agent session window; kept, flagged, and
//                   expires unless attributed (7 days, enforced by retention, not here)
//   'rollup'      - count only: (principal, system, action, hour) with no entity IDs
//
// The gate never emits 'drop' for agent-linked activity. Human activity outside any
// agent window is rolled up, not discarded, because discovery heuristics need the counts.

export const CLASS = Object.freeze({
  FULL: 'full',
  OBO_WINDOW: 'obo_window',
  ROLLUP: 'rollup',
});

// Record types that are agent-specific by construction (plan/04-connectors.md).
export const AGENT_SPECIFIC_RECORD_TYPES = Object.freeze(new Set([
  'CopilotInteraction',
  'AgentforceSession',
  'AgentforceAction',
  'CopilotStudioTranscript',
  'CopilotStudioBotMessage',
  'ServiceNowAIAgentExecution',
  'ServiceNowAIToolExecution',
]));

const NON_HUMAN_KINDS = Object.freeze(new Set(['service', 'agent', 'application']));

/**
 * @param {object} event
 * @param {'human'|'service'|'agent'|'application'|'unknown'} event.principalKind
 * @param {string} event.principalId  normalized principal id (or '' if none)
 * @param {string} event.recordType   source record type, e.g. 'Message', 'CopilotInteraction'
 * @param {object} ctx
 * @param {Set<string>} ctx.inventoryPrincipals   principal ids mapped to agents
 * @param {Set<string>} ctx.candidatePrincipals   principal ids under candidate review
 * @param {Set<string>} ctx.oboHumanIds       human handles inside an active agent window
 * @returns {{class: string, reason: string}}
 */
export function classify(event, ctx) {
  const { principalKind, principalId, recordType } = event;

  if (AGENT_SPECIFIC_RECORD_TYPES.has(recordType)) {
    return { class: CLASS.FULL, reason: 'agent-specific record type' };
  }
  if (principalId && ctx.inventoryPrincipals.has(principalId)) {
    return { class: CLASS.FULL, reason: 'principal mapped to an inventoried agent' };
  }
  if (principalId && ctx.candidatePrincipals.has(principalId)) {
    return { class: CLASS.FULL, reason: 'principal under candidate review' };
  }
  if (NON_HUMAN_KINDS.has(principalKind)) {
    return { class: CLASS.FULL, reason: 'non-human principal' };
  }
  if (principalKind === 'human') {
    if (principalId && ctx.oboHumanIds.has(principalId)) {
      return { class: CLASS.OBO_WINDOW, reason: 'human inside an agent session window' };
    }
    return { class: CLASS.ROLLUP, reason: 'human activity outside agent windows' };
  }
  // Unknown principal kind: fail toward minimization, not toward collection.
  return { class: CLASS.ROLLUP, reason: 'principal kind unknown; minimized' };
}
