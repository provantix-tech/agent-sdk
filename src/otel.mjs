// OTel GenAI semantic conventions -> Agent Action Record mapping.
// plan/14-sdk-and-open-spec.md expresses the export profile in GenAI-convention terms;
// this module is the reference implementation of that mapping.
//
// Supported input: a plain object describing one OTel span (what a SpanExporter receives):
// {
//   traceId, spanId, parentSpanId, name, kind ('internal'|'client'|'server'|'producer'|'consumer'),
//   startTime, endTime,                       // epoch ms or ISO
//   attributes: { 'gen_ai.operation.name': 'chat', 'gen_ai.system': 'openai', ... },
//   status: { code: 'OK'|'ERROR', message },
// }

import { buildAAR } from './aar.mjs';
import { computeDelegationChains, invokeAgentCallees, inheritedAgentBySpan } from '../../../ledger/packages/aar-schema/src/delegation.mjs';
import { toolCallText, isSendAction, extractExternalRecipient } from '../../../ledger/packages/aar-schema/src/tool-payload.mjs';

const OPERATION_TO_ACTION = {
  chat: 'call_model',
  generate_content: 'call_model',
  text_completion: 'call_model',
  embeddings: 'call_model',
  execute_tool: 'call_tool',
  invoke_agent: 'call_agent',
};

const AT = (span, name) => span.attributes?.[name] ?? null;
const NUM = (v) => (v === null || v === undefined ? null : Number(v));

/**
 * Convert one OTel span carrying GenAI attributes into an AAR.
 * Spans without gen_ai.* attributes return null (they are not agent telemetry for our purposes).
 * opts.delegationChain / opts.callee come from otelBatchToAARs (P1: span parentage); when this
 * function is called directly on a single span they default to empty. The collector seals
 * human chain actors as handles at sign time.
 */
export function otelGenAiToAAR(span, opts = {}) {
  const delegationChain = opts.delegationChain ?? [];
  const operation = AT(span, 'gen_ai.operation.name');
  const toolName = AT(span, 'gen_ai.tool.name');
  const isGenAi = operation || toolName || AT(span, 'gen_ai.system') || AT(span, 'gen_ai.request.model');
  if (!isGenAi) return null;

  const kind = span.kind ?? 'internal';
  let actionType = OPERATION_TO_ACTION[operation] ?? (toolName ? 'call_tool' : 'unknown');
  // P3: a messaging send operation is a send action (E2's sensitive predicate matches
  // action_type 'send'); the recipient lands in action.external_recipient below.
  if (actionType === 'unknown' && AT(span, 'messaging.operation') === 'send') actionType = 'send';
  // A server/producer span on a named route is an agent executing work (RAG fetch, API call).
  if (actionType === 'unknown' && ['server', 'producer'].includes(kind)) actionType = 'execute';

  const error = span.status?.code === 'ERROR';
  const peer = AT(span, 'server.address') ?? AT(span, 'net.peer.name') ?? AT(span, 'db.name');

  const conversationId = AT(span, 'gen_ai.conversation.id');
  const agentId = AT(span, 'gen_ai.agent.id') ?? AT(span, 'service.name');

  // E1: human approval attached to the action. The approver is converted to a handle by the
  // collector at seal time (HMAC with the persisted handle key), like on-behalf-of ids.
  const approvalId = AT(span, 'provantix.approval.id');
  const authorization = approvalId
    ? {
        approval_id: approvalId,
        approver: AT(span, 'provantix.approval.approver'),
        policy_id: AT(span, 'provantix.approval.policy'),
        ticket: AT(span, 'provantix.approval.ticket'),
        approved_at: AT(span, 'provantix.approval.approved_at'),
      }
    : null;

  // P3: tool calls carry their arguments and result as content; the collector redacts,
  // truncates and seals them as the erasable input/output summaries. Prompt/completion
  // attributes stay out of the mapping (hash-only stance, as in hosted intake).
  const toolText = actionType === 'call_tool' ? toolCallText(span.attributes) : { argumentsText: null, resultText: null };
  const externalRecipient = isSendAction({ actionType, operation, toolName })
    ? extractExternalRecipient(span.attributes)
    : null;

  return buildAAR({
    tenantId: opts.tenantId,
    emitterId: opts.emitterId,
    observedAt: toIso(span.startTime),
    delegationChain,
    system: AT(span, 'gen_ai.system') ?? opts.system ?? 'otel-genai',
    vantage: opts.vantage ?? 'inside',
    agent: {
      vendor: opts.agent?.vendor ?? AT(span, 'gen_ai.agent.name') ?? opts.system ?? null,
      vendorAgentId: opts.agent?.vendorAgentId ?? agentId ?? opts.inheritedAgent ?? null,
      version: opts.agent?.version ?? null,
      principal: opts.agent?.principal ?? null,
      clientId: AT(span, 'gen_ai.client.id'),
      tokenActor: null,
    },
    correlation: {
      traceId: hex(span.traceId),
      spanId: hex(span.spanId),
      parentSpanId: hex(span.parentSpanId),
      sessionId: AT(span, 'session.id'),
      conversationId,
    },
    action: {
      type: actionType,
      targetSystem: peer ?? (toolName ? 'tooling' : null),
      targetEntityType: toolName ? 'tool' : (actionType === 'call_agent' ? 'agent' : null),
      targetEntityId: toolName ?? opts.callee ?? null,
      operation: span.name ?? null,
      toolName,
      externalRecipient,
      dataClasses: [],
    },
    content: toolText.argumentsText || toolText.resultText
      ? { inputText: toolText.argumentsText, outputText: toolText.resultText }
      : undefined,
    model: {
      provider: AT(span, 'gen_ai.system'),
      modelId: AT(span, 'gen_ai.request.model') ?? AT(span, 'gen_ai.response.model'),
      modelVersion: AT(span, 'gen_ai.response.model'),
      tokensIn: NUM(AT(span, 'gen_ai.usage.input_tokens')),
      tokensOut: NUM(AT(span, 'gen_ai.usage.output_tokens')),
      latencyMs: latencyMs(span),
    },
    quality: {
      outcome: error ? 'failure' : 'success',
      errorClass: error ? (span.status?.message ?? 'error') : null,
      humanOverride: null,
    },
    authorization,
    ext: {
      otel: {
        span_kind: kind,
        scope: AT(span, 'otel.scope.name'),
        operation_name: operation,
      },
    },
  });
}

/** Convert a batch of spans (SpanExporter.export shape). */
export function otelBatchToAARs(spans, opts = {}) {
  // P1: resolve delegation chains and invoke_agent callees over the whole batch — a parent
  // invoke_agent span and its child can arrive in the same export — so each record carries
  // the delegation tree without anyone re-reading span ids later.
  const chains = computeDelegationChains(spans);
  const callees = invokeAgentCallees(spans);
  const inherited = inheritedAgentBySpan(spans);
  return spans
    .map((s) => otelGenAiToAAR(s, {
      ...opts,
      delegationChain: chains.get(hex(s.spanId)) ?? [],
      callee: callees.get(hex(s.spanId)) ?? null,
      inheritedAgent: inherited.get(hex(s.spanId)) ?? null,
    }))
    .filter(Boolean);
}

function toIso(t) {
  if (t === undefined || t === null) return new Date().toISOString();
  if (typeof t === 'number') return new Date(t).toISOString();
  return new Date(t).toISOString();
}

function latencyMs(span) {
  if (span.startTime === undefined || span.endTime === undefined) return null;
  const start = typeof span.startTime === 'number' ? span.startTime : Date.parse(span.startTime);
  const end = typeof span.endTime === 'number' ? span.endTime : Date.parse(span.endTime);
  return Math.max(0, Math.round(end - start));
}

function hex(v) {
  if (!v) return null;
  if (typeof v === 'string') return v.length === 32 || v.length === 16 ? v : v;
  if (v instanceof Uint8Array) return [...v].map((b) => b.toString(16).padStart(2, '0')).join('');
  return String(v);
}
