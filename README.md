# Provantix Agent SDK

Agent-side emitter for [Provantix](https://www.provantix.tech), the telemetry layer for
enterprise AI agents. Agents you control emit **Agent Action Records (AAR)** or plain
**OTel GenAI spans**, and the SDK turns them into signed, hash-chained batches that ship
through the `/v1/batches` endpoint. Agent telemetry inherits the full integrity model:
per-field salted commitments, chains, daily roots and offline-verifiable exports.

No dependencies. Node 20+.

## Install

```bash
npm install @provantix/agent-sdk
```

Until the package is on npm, install straight from this repo:

```bash
npm install github:provantix-tech/agent-sdk
```

Docs: [docs.provantix.tech/ingest/node-sdk](https://docs.provantix.tech/ingest/node-sdk).
Full API reference: [docs.provantix.tech/reference/api](https://docs.provantix.tech/reference/api).

## Quick start

Register an emitter in the Provantix app (Setup page, or admin API — the private key is
shown once, store it securely):

```js
import { AgentEmitter } from '@provantix/agent-sdk';

const emitter = new AgentEmitter({
  emitterId: 'emi_01j…',           // from registration
  tenantId: 'tenant_…',            // your organization
  privateKeyPem: '-----BEGIN PRIVATE KEY-----\n…',
});

// Option A: emit OTel spans carrying GenAI attributes (OpenTelemetry JS SDK SpanExporter-shaped objects)
emitter.emitOtelSpan(span, { agent: { vendor: 'otel', vendorAgentId: 'support-copilot' } });

// Option B: build an Agent Action Record directly
import { buildAAR } from '@provantix/agent-sdk';
emitter.emitAAR(buildAAR({
  tenantId, emitterId, system: 'internal-tools',
  agent: { vendor: 'acme', vendorAgentId: 'agent-42' },
  action: { type: 'execute', targetSystem: 'erp', targetEntityId: 'po-123' },
}));

await emitter.flushAndDrain('https://app.provantix.tech');
```

## How attribution connects telemetry to your agent

Create the agent once with matching `vendor` + `vendor_agent_id`:

```bash
curl -X POST https://app.provantix.tech/v1/agents \
  -H "authorization: Bearer …" -H "content-type: application/json" \
  -d '{"display_name":"Support Copilot","vendor":"otel","vendor_agent_id":"support-copilot"}'
```

Every record the emitter ships then attributes at **0.95 confidence by
`explicit_platform_id`** (`agent_hint.vendor` + `agent_hint.vendor_agent_id`). If no agent
matches, the record is still stored, chained and verifiable, as `unknown`, and shows up in
the candidates/findings flow.

## OTel GenAI mapping

| OTel span | AAR |
|---|---|
| `gen_ai.operation.name`: chat / generate_content / text_completion / embeddings | `call_model` |
| `gen_ai.operation.name`: execute_tool (+ `gen_ai.tool.name`) | `call_tool` |
| `gen_ai.operation.name`: invoke_agent | `call_agent` |
| `gen_ai.system`, `gen_ai.request/response.model` | `model.provider`, `model.model_id` |
| `gen_ai.usage.input/output_tokens` | `model.tokens_in/out` |
| span start/end | `model.latency_ms`, `observed_at` |
| trace/span/parent ids, `gen_ai.conversation.id` | `correlation.*` |
| `status.code == ERROR` | `quality.outcome = failure`, `error_class = status.message` |
| `gen_ai.agent.id`, `service.name` | `agent_hint.vendor_agent_id` |
| server/db peer attributes | `action.target_system` |

Spans without `gen_ai.*` attributes are ignored (return `null`), route them to your normal
trace backend.

## Files

- `src/aar.mjs` — AAR builder + validator (action enums, data classes, actor kinds)
- `src/otel.mjs` — OTel GenAI span → AAR reference mapping
- `src/emitter.mjs` — `AgentEmitter`: gate, handles, redaction, batching, signing, spool, drain
- `test/emitter.test.mjs` — unit tests + integration through a real control plane
  (ingest → attribution → reporting → export verify)
- `examples/emit-demo.mjs` — end-to-end demo against a running app

## Run tests

```bash
npm test        # node --test test/*.test.mjs
node examples/emit-demo.mjs
```

## License

MIT, see [LICENSE](./LICENSE).
