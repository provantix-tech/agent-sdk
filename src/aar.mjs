// Agent Action Record (AAR) builder and validator.
// Schema: plan/02-data-model.md section 1.1 (export profile). The export profile is public —
// nothing here is platform-specific, so emitters written against this file work against any
// conforming control plane.

import { normaliseConfiguration } from './vendor/configuration.mjs';

export const PROFILE_VERSION = '1.0';

export const ACTION_TYPES = Object.freeze([
  'read', 'write', 'create', 'update', 'delete', 'send', 'execute', 'approve', 'escalate',
  'call_model', 'call_tool', 'call_agent', 'login', 'grant', 'revoke', 'download', 'upload', 'unknown',
]);

export const VANTAGES = Object.freeze(['inside', 'boundary', 'destination', 'identity']);

export const DATA_CLASSES = Object.freeze([
  'pii', 'phi', 'pci', 'financial', 'hr', 'secret', 'customer', 'internal', 'public', 'unknown',
]);

let eventCounter = 0;

// Run-id shape detection — keep the patterns in sync with
// ledger/packages/aar-schema/src/run-id.mjs (control-plane copy).
const RUN_ID_GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RUN_ID_ULID_RE = /^[0-9a-hjkmnp-tv-z]{26}$/i;
const warnedRunIds = new Set();

function looksLikeRunId(value) {
  if (typeof value !== 'string') return false;
  const v = value.trim();
  return RUN_ID_GUID_RE.test(v) || RUN_ID_ULID_RE.test(v);
}

/**
 * Contract (WO-H2): action.targetSystem is the STABLE name of the system the action touched
 * (e.g. "cruzclaw-backend", "salesforce"), never a per-run or per-object id. A GUID/ULID here
 * mints a new "system" on every run and breaks reach, coverage and cost grouping; the
 * per-run id belongs in action.targetEntityId (mapped to record.target_entity_id). The check
 * is a loud warning, not a throw: a hard failure would stop all telemetry from a
 * misconfigured emitter, and the control plane flags the same defect as a data-health
 * finding (data_health.guid_target_system) so it cannot stay silent.
 */
function warnOnRunIdTargetSystem(action) {
  if (!looksLikeRunId(action?.targetSystem)) return;
  const value = action.targetSystem.trim();
  if (warnedRunIds.has(value)) return;
  warnedRunIds.add(value);
  console.warn(
    `[provantix-sdk] action.targetSystem "${value}" looks like a per-run id, not a system name. ` +
    'Use a stable system name for targetSystem and pass the run id as targetEntityId instead. ' +
    'See the SDK README "Target system contract".',
  );
}

/**
 * Build an Agent Action Record.
 * @param {object} a
 * @param {string} a.tenantId
 * @param {string} a.emitterId         emitter (collector) id, also scopes event ids
 * @param {string} [a.observedAt]      ISO timestamp, default now
 * @param {string} a.system            registry slug of the emitting system/vendor, e.g. 'openai', 'internal-tools'
 * @param {'inside'|'boundary'|'destination'|'identity'} [a.vantage]
 * @param {object} a.agent             { vendor, vendorAgentId, version, principal, clientId, tokenActor, userAgent }
 * @param {object} a.action            { type, targetSystem, targetEntityType, targetEntityId, operation, toolName, fieldNames, dataClasses, externalRecipient }
 * @param {object} [a.correlation]     { traceId, spanId, parentSpanId, sessionId, conversationId }. Give every step of one run the same traceId: expected steps and recovery checks group a run by it
 * @param {object[]} [a.configuration] [{ flag, variant, provider? }]: the feature flags this step ran under and the variant each served (at most ten)
 * @param {object} [a.onBehalfOf]      [{ kind, id, idp }]  (human ids become handles at the boundary)
 * @param {object} [a.authorization]   { approval_id, approver, policy_id, ticket, approved_at, binding } — binding (optional):
 *                                      { target_system, target_entity_id, action_type, max_amount_minor, currency, expires_at, policy_version }
 *                                      says what the approval covers —
 *                                      human approval for a sensitive action; approver becomes
 *                                      a handle at the boundary (Epic E)
 * @param {object} [a.model]           { provider, modelId, modelVersion, tokensIn, tokensOut, latencyMs, tokensCacheRead, tokensCacheWrite, tokensReasoning, serviceTier, usageBasis }
 *                                      tokensIn is ALL input tokens including the cached part; tokensOut is ALL output including reasoning. The last five are optional.
 * @param {object} [a.quality]         { outcome, errorClass, humanOverride }
 * @param {object} [a.content]         { inputText, outputText } — raw text; the boundary redacts it
 * @param {Record<string, string>} [a.tags] cost tags, e.g. { department: 'sales', cost_center: 'CC-42', product: 'crm', project: 'apollo', environment: 'prod', region: 'emea' }.
 *                                      Any name is a tag; a name never seen before becomes a dimension on the platform.
 * @param {string} [a.eventId]         source-unique id; default derived from emitter + counter + random
 */
export function buildAAR(a) {
  if (!a.tenantId) throw new TypeError('tenantId required');
  if (!a.emitterId) throw new TypeError('emitterId required');
  if (!a.system) throw new TypeError('system required');
  const action = a.action ?? {};
  if (!action.type) throw new TypeError('action.type required');
  warnOnRunIdTargetSystem(action);

  return {
    profile_version: PROFILE_VERSION,
    observed_at: a.observedAt ?? new Date().toISOString(),
    source: {
      system: a.system,
      event_id: a.eventId ?? `${a.emitterId}-${Date.now().toString(36)}-${(eventCounter++).toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
      event_type: a.eventType ?? 'AgentAction',
      vantage: a.vantage ?? 'inside',
    },
    agent_hint: {
      vendor: a.agent?.vendor ?? null,
      vendor_agent_id: a.agent?.vendorAgentId ?? null,
      agent_version: a.agent?.version ?? null,
      principal: a.agent?.principal ?? null,
      client_id: a.agent?.clientId ?? null,
      token_actor: a.agent?.tokenActor ?? null,
      user_agent: a.agent?.userAgent ?? null,
    },
    ...(a.location ? { location: a.location } : {}),
    on_behalf_of: a.onBehalfOf ?? [],
    delegation_chain: a.delegationChain ?? [],
    authorization: a.authorization ?? null,
    correlation: {
      trace_id: a.correlation?.traceId ?? null,
      span_id: a.correlation?.spanId ?? null,
      parent_span_id: a.correlation?.parentSpanId ?? null,
      session_id: a.correlation?.sessionId ?? null,
      conversation_id: a.correlation?.conversationId ?? null,
    },
    action: {
      action_type: action.type,
      target_system: action.targetSystem ?? null,
      target_entity_type: action.targetEntityType ?? null,
      target_entity_id: action.targetEntityId ?? null,
      operation: action.operation ?? null,
      tool_name: action.toolName ?? null,
      field_names: action.fieldNames ?? [],
      record_count: action.recordCount ?? null,
      external_recipient: action.externalRecipient ?? null,
      data_classes: action.dataClasses ?? [],
    },
    content: a.content
      ? { input_text: a.content.inputText ?? null, output_text: a.content.outputText ?? null }
      : undefined,
    model: a.model
      ? {
          provider: a.model.provider ?? null,
          model_id: a.model.modelId ?? null,
          model_version: a.model.modelVersion ?? null,
          tokens_in: a.model.tokensIn ?? null,
          tokens_out: a.model.tokensOut ?? null,
          latency_ms: a.model.latencyMs ?? null,
          // Token kinds (all optional, kept only when given): tokensIn is ALL input including the cached part, tokensOut ALL output including reasoning.
          ...(a.model.tokensCacheRead != null ? { tokens_cache_read: a.model.tokensCacheRead } : {}),
          ...(a.model.tokensCacheWrite != null ? { tokens_cache_write: a.model.tokensCacheWrite } : {}),
          ...(a.model.tokensReasoning != null ? { tokens_reasoning: a.model.tokensReasoning } : {}),
          ...(a.model.serviceTier ? { service_tier: a.model.serviceTier } : {}),
          ...(a.model.usageBasis ? { usage_basis: a.model.usageBasis } : {}),
          // what the source says the call cost, in USD: kept as that source's figure beside the estimate, never in its place (PRO-66)
          ...(Number.isFinite(Number(a.model.reportedCostUsd)) && a.model.reportedCostUsd !== null && Number(a.model.reportedCostUsd) >= 0 ? { reported_cost_usd: Number(a.model.reportedCostUsd), reported_cost_by: String(a.model.reportedCostBy ?? 'source').slice(0, 40) } : {}),
          // a hash of the stable start of the prompt (or the system prompt), computed by the application: lets Provantix see calls that sent the same beginning without reading a cache (PRO-74). Never the prompt.
          ...(typeof a.model.promptPrefixHash === 'string' && /^[0-9a-f]{16,128}$/i.test(a.model.promptPrefixHash) ? { prompt_prefix_hash: a.model.promptPrefixHash.toLowerCase() } : {}),
        }
      : null,
    quality: a.quality
      ? { outcome: a.quality.outcome ?? 'unknown', error_class: a.quality.errorClass ?? null, human_override: a.quality.humanOverride ?? null }
      : null,
    // Cost tags (PRO-63): what this source says about department, cost center, product, project, environment or anything else. Kept in the record as stated; the platform
    // cleans the names and values and works out what it makes of them apart from the record.
    ext: extOf(a),
  };
}

/**
 * The record's `ext`: what the caller put there, with the cost tags and the configuration the step ran under added. The configuration is `[{ flag, variant, provider? }]`,
 * the feature flag and the variant served (at most ten), kept as the source's statement: Provantix does not know whether the flag changed anything.
 */
function extOf(a) {
  const ext = { ...(a.ext ?? {}) };
  if (a.tags && typeof a.tags === 'object' && Object.keys(a.tags).length) ext.tags = { ...a.tags };
  const configuration = normaliseConfiguration(a.configuration);
  if (configuration.length) ext.configuration = configuration;
  return Object.keys(ext).length ? ext : (a.ext ?? null);
}

/** Structural validation against the export profile. Throws with a readable message. */
export function validateAAR(aar) {
  const problems = [];
  if (!aar || typeof aar !== 'object') return ['record is not an object'];
  if (aar.profile_version !== PROFILE_VERSION) problems.push(`profile_version must be "${PROFILE_VERSION}"`);
  if (!aar.observed_at || Number.isNaN(Date.parse(aar.observed_at))) problems.push('observed_at must be an ISO timestamp');
  if (!aar.source?.system) problems.push('source.system required');
  if (!aar.source?.event_id) problems.push('source.event_id required');
  if (aar.source?.vantage && !VANTAGES.includes(aar.source.vantage)) problems.push(`vantage must be one of ${VANTAGES.join(', ')}`);
  if (!aar.action?.action_type) problems.push('action.action_type required');
  else if (!ACTION_TYPES.includes(aar.action.action_type)) problems.push(`unknown action_type "${aar.action.action_type}"`);
  for (const dc of aar.action?.data_classes ?? []) {
    if (!DATA_CLASSES.includes(dc)) problems.push(`unknown data_class "${dc}"`);
  }
  for (const actor of [...(aar.on_behalf_of ?? []), ...(aar.delegation_chain ?? [])]) {
    if (!['human', 'agent', 'service', 'unknown'].includes(actor.kind)) problems.push(`actor kind "${actor.kind}" invalid`);
    if (!actor.id) problems.push('actor id required');
  }
  if (aar.authorization != null) {
    const az = aar.authorization;
    if (typeof az !== 'object' || Array.isArray(az)) problems.push('authorization must be an object');
    else {
      if (!az.approval_id) problems.push('authorization.approval_id required');
      if (!az.approver) problems.push('authorization.approver required');
      if (az.binding != null) {
        const b = az.binding;
        if (typeof b !== 'object' || Array.isArray(b)) problems.push('authorization.binding must be an object');
        else {
          if (b.max_amount_minor != null && b.max_amount_minor !== '' && !Number.isSafeInteger(Number(b.max_amount_minor))) problems.push('authorization.binding.max_amount_minor must be a whole number in minor units');
          if (b.expires_at != null && Number.isNaN(Date.parse(b.expires_at))) problems.push('authorization.binding.expires_at must be a date and time');
        }
      }
    }
  }
  return problems;
}
