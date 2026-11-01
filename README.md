# Provantix Agent SDK

Agent-side emitter for [Provantix](https://www.provantix.tech), the telemetry layer for
enterprise AI agents. Agents you control emit **Agent Action Records (AAR)** or plain
**OTel GenAI spans**, and the SDK turns them into signed, hash-chained batches that ship
through the `/v1/batches` endpoint. Agent telemetry inherits the full integrity model:
per-field salted commitments, chains, daily roots and offline-verifiable exports.

No dependencies. Node 20+.

## Install

Published on npm:

```bash
npm install @provantix/agent-sdk
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

## Target system contract

`action.targetSystem` is the **stable name of the system the action touched** — the same
value across every run, e.g. `cruzclaw-backend`, `salesforce`, `internal-tools`. It is the
grouping key for reach, coverage and cost, so a per-run or per-object id mints a new
"system" on every run and breaks all three.

- **Never put a GUID or ULID in `targetSystem`.** The SDK warns loudly when it sees one.
  The control plane keeps the record (it is still evidence) but raises a
  `data_health.guid_target_system` finding until the emitter is fixed.
- **Per-run or per-object ids go in `action.targetEntityId`** (stored as
  `target_entity_id`). One stable system, many distinct entities.

Before / after:

```js
// Wrong: every run appears as a new system
buildAAR({ …, action: { type: 'execute', targetSystem: run.id } });

// Right: stable system name, run id in the entity slot
buildAAR({ …, action: { type: 'execute', targetSystem: 'cruzclaw-backend', targetEntityId: run.id } });
```

## Sealed batches (0.2.0)

From 0.2.0 the emitter signs a second, smaller statement with every batch: the hash of each record in it. This is the **batch seal**. It lets an auditor check, with your emitter's public key and without trusting Provantix, that the emitter itself vouched for exactly these records. It survives erasure, because a record hash never contained a value that is later erased.

Sealing is on by default. Nothing in your code changes:

```js
const emitter = new AgentEmitter({ emitterId, tenantId, privateKeyPem, spoolDir: '.spool' });
// seal: true is the default; pass seal: false only to match a platform that does not know seals yet
```

**Upgrading.** Upgrade to 0.2.0 and redeploy. Sealed batches are accepted alongside unsealed ones, so you can upgrade emitter by emitter. A batch whose seal does not match its records is refused as `seal_invalid`, which in practice means a bug or a tampered batch, not a configuration problem.

**The deadline.** Provantix accepts unsealed batches only until the end of the notice period it sends you (90 days from the notice). After that an unsealed emitter is refused and its source shows "telemetry paused, SDK upgrade needed". Pilot and trial sources are exempt. The deadline is judged on when a batch was created, and 0.2.0 seals whatever an older version had queued on the host when it next sends, so upgrading loses nothing a paused emitter had stored up. Until then an emitter that seals and later stops raises the finding "Batches lost their seal".

**Your key matters.** The proof is independent of Provantix only if the public key an auditor checks against came from you, not from Provantix. If you registered your own key (recommended), keep a copy of the public key and give it to your auditor. If Provantix generated the key, it once held the private key, and the proof is only Provantix's own attestation.

## Evidence is never rewritten

No UPDATE or DELETE on `records`, `batches` or any chain table — not to fix a name, not to
remove a test row, never. Stored evidence is hash-chained and rooted; changing it breaks
verification for every later record on the same chain. Display problems are fixed in the
alias layer or at the emitter; integrity problems are never traded for cosmetics.

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
