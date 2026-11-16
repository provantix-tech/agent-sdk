// Delegation chain construction from span parentage (P1,
// product-value-assessment-2026-10-23.md §12.12).
//
// Pure functions over already-normalized spans — the same shape the hosted intake
// (ingest/src/intake.mjs normalizeOtlpSpans) and the SDK SpanExporter path
// (app/agent-sdk/src/otel.mjs) both produce:
//   { traceId, spanId, parentSpanId, name, kind, attributes: {...}, ... }
//
// Semantics: when an invoke_agent span (agent X) has children, each child's record carries
// [X, childAgent] in delegation_chain — the invoking agents down to the acting agent, in order.
// Nested agents extend the array (orchestrator → worker → subworker). A span that answers to
// nobody (no delegating parent) carries an empty chain: no delegation happened. Human actors in
// the chain stay raw here; the sealer converts them to handles (SDK: HMAC with the persisted
// handle key; hosted intake: sha256-derived h_ handle).

const AGENT_ATTRS = ['trace.metadata.agent_id', 'trace.metadata.agent', 'gen_ai.agent.id'];
const HUMAN_ATTR = 'user.id';

function hexId(v) {
  if (!v) return null;
  if (v instanceof Uint8Array) return [...v].map((b) => b.toString(16).padStart(2, '0')).join('');
  return String(v);
}

function actorOf(span) {
  const attrs = span.attributes ?? {};
  for (const key of AGENT_ATTRS) {
    if (attrs[key]) return { kind: 'agent', id: String(attrs[key]) };
  }
  if (attrs[HUMAN_ATTR]) return { kind: 'human', id: String(attrs[HUMAN_ATTR]) };
  return null;
}

const sameActor = (a, b) => a && b && a.kind === b.kind && a.id === b.id;

/**
 * Walk each span's parent chain within its trace and build the delegation path.
 * @param {Array} spans normalized spans (any number of traces)
 * @returns {Map<string, Array<{kind: string, id: string}>>} spanId -> chain, outermost first
 */
export function computeDelegationChains(spans) {
  const byTrace = new Map();
  for (const span of spans) {
    const traceId = hexId(span.traceId);
    if (!traceId || !span.spanId) continue;
    if (!byTrace.has(traceId)) byTrace.set(traceId, new Map());
    byTrace.get(traceId).set(hexId(span.spanId), span);
  }

  const chains = new Map();
  for (const span of spans) {
    const traceId = hexId(span.traceId);
    const spanId = hexId(span.spanId);
    if (!traceId || !spanId) continue;
    const spanById = byTrace.get(traceId);

    const path = [];
    const seen = new Set();
    let cur = span;
    while (cur && !seen.has(hexId(cur.spanId))) {
      seen.add(hexId(cur.spanId));
      const actor = actorOf(cur);
      if (actor && !sameActor(path[0], actor)) path.unshift(actor);
      const parentId = hexId(cur.parentSpanId);
      cur = parentId ? spanById.get(parentId) : null;
    }

    // A lone actor means the span answers to nobody: no delegation, empty chain.
    chains.set(spanId, path.length >= 2 ? path : []);
  }
  return chains;
}

/**
 * For invoke_agent (call_agent) spans: the callee is the first child span that names a
 * different agent than the caller. Returns Map<spanId, calleeAgentId>.
 */
export function invokeAgentCallees(spans) {
  const byTrace = new Map();
  for (const span of spans) {
    const traceId = hexId(span.traceId);
    if (!traceId) continue;
    if (!byTrace.has(traceId)) byTrace.set(traceId, []);
    byTrace.get(traceId).push(span);
  }

  const callees = new Map();
  for (const span of spans) {
    const operation = span.attributes?.['gen_ai.operation.name'];
    if (operation !== 'invoke_agent') continue;
    const spanId = hexId(span.spanId);
    const caller = actorOf(span);
    const children = (byTrace.get(hexId(span.traceId)) ?? [])
      .filter((c) => hexId(c.parentSpanId) === spanId);
    for (const child of children) {
      const callee = actorOf(child);
      if (callee && callee.kind === 'agent' && !sameActor(callee, caller)) {
        callees.set(spanId, callee.id);
        break;
      }
    }
  }
  return callees;
}

/**
 * Agent inheritance for attribution: a span with no agent identity of its own (a typical tool
 * span) acts as whatever agent its nearest agent-carrying ancestor belongs to. Returns
 * Map<spanId, agentId> for spans that have an ancestor agent but no own agent identity.
 */
export function inheritedAgentBySpan(spans) {
  const byTrace = new Map();
  for (const span of spans) {
    const traceId = hexId(span.traceId);
    if (!traceId || !span.spanId) continue;
    if (!byTrace.has(traceId)) byTrace.set(traceId, new Map());
    byTrace.get(traceId).set(hexId(span.spanId), span);
  }

  const inherited = new Map();
  for (const span of spans) {
    const traceId = hexId(span.traceId);
    const spanId = hexId(span.spanId);
    if (!traceId || !spanId) continue;
    if (actorOf(span)) continue; // names its own actor: nothing to inherit
    const spanById = byTrace.get(traceId);
    const seen = new Set([spanId]);
    let cur = spanById.get(hexId(span.parentSpanId));
    while (cur && !seen.has(hexId(cur.spanId))) {
      seen.add(hexId(cur.spanId));
      const actor = actorOf(cur);
      if (actor?.kind === 'agent') { inherited.set(spanId, actor.id); break; }
      cur = spanById.get(hexId(cur.parentSpanId));
    }
  }
  return inherited;
}
