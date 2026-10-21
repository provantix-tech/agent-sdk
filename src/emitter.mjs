// AgentEmitter: the agent-side SDK surface.
//
//   const emitter = new AgentEmitter({ emitterId, tenantId, privateKeyPem, spoolDir: '.spool' })
//   emitter.emitOtelSpan(span)            // or emitter.emitAAR(aar)
//   await emitter.flushAndDrain('http://localhost:3000')
//
// Internally it is a collector: AAR records are gated, humans become handles, text is redacted,
// records are sealed with per-field commitments and shipped as ECDSA-signed batches to the
// control plane's /v1/batches endpoint — the same path boundary collectors use, so agent
// telemetry inherits the full integrity model (chains, daily roots, offline verification).

import fs from 'node:fs';
import path from 'node:path';
import { Collector } from '../../../ledger/packages/collector-core/src/collector.mjs';
import { Spool } from '../../../ledger/packages/collector-core/src/spool.mjs';
import { generateCollectorKeys } from '../../../ledger/packages/collector-core/src/batch.mjs';
import { newHandleKey } from '../../../ledger/packages/collector-core/src/handles.mjs';
import { validateAAR } from './aar.mjs';
import { otelGenAiToAAR } from './otel.mjs';

class MemorySpool {
  constructor() {
    this.seq = 0;
    this.batches = new Map();
  }
  nextSeq() {
    return ++this.seq;
  }
  enqueue(batch) {
    this.batches.set(batch.batch_seq, batch);
  }
  list() {
    return [...this.batches.values()].sort((a, b) => a.batch_seq - b.batch_seq);
  }
  ack(seq) {
    this.batches.delete(seq);
  }
  count() {
    return this.batches.size;
  }
}

// Human handles are HMAC(principal, handleKey). A fresh random key per process means the
// same human maps to a different handle after every restart, breaking attribution continuity
// (round-2 review). When a durable spool directory is configured we persist the key there so
// handles stay stable across restarts, the same place the batch counter is persisted.
function resolveHandleKey({ spoolDir, handleKey }) {
  if (handleKey) return handleKey;
  if (spoolDir) {
    const keyFile = path.join(spoolDir, 'handle-key.bin');
    try {
      return fs.readFileSync(keyFile);
    } catch {
      const generated = newHandleKey();
      const tmp = keyFile + '.tmp';
      fs.writeFileSync(tmp, generated, { mode: 0o600 });
      fs.renameSync(tmp, keyFile);
      return generated;
    }
  }
  console.warn(
    '[agent-sdk] no handleKey or spoolDir configured: human handles are keyed with a random '
    + 'per-process key, so the same human will map to different handles after a restart. '
    + 'Pass spoolDir (persists the key and the batch counter) or handleKey for production emitters.',
  );
  return newHandleKey();
}

export class AgentEmitter {
  /**
   * @param {object} opts
   * @param {string} opts.emitterId       from POST /api/emitters (emi_…)
   * @param {string} opts.tenantId        tenant the emitter was registered for
   * @param {string} opts.privateKeyPem   emitter signing key (shown once at registration; keep secret)
   * @param {string} [opts.spoolDir]      durable spool directory — persists the batch sequence
   *                                      counter and the handle key across restarts (recommended;
   *                                      without it a restart reuses sequence numbers and the
   *                                      control plane rejects the chain as forked)
   * @param {Buffer} [opts.handleKey]     HMAC key for human handles (default: persisted in
   *                                      spoolDir, else generated per process with a warning)
   * @param {number} [opts.maxBatchRecords]
   */
  constructor({ emitterId, tenantId, privateKeyPem, spoolDir = null, handleKey = null, maxBatchRecords = 200 }) {
    if (!emitterId || !tenantId || !privateKeyPem) throw new TypeError('emitterId, tenantId and privateKeyPem required');
    this.emitterId = emitterId;
    this.tenantId = tenantId;
    this.connectorInstance = `otel:${emitterId}`;
    if (!spoolDir) {
      console.warn(
        `[agent-sdk] emitter ${emitterId}: running without a durable spoolDir. Batches and the `
        + 'sequence counter live in memory only; a process restart will reuse sequence numbers '
        + 'and the control plane will reject them as a forked chain. Pass spoolDir in production.',
      );
    }
    this.collector = new Collector({
      collectorId: emitterId,
      privateKeyPem,
      handleKey: resolveHandleKey({ spoolDir, handleKey }),
      spool: spoolDir ? new Spool(spoolDir) : new MemorySpool(),
      maxBatchRecords,
    });
    // Agent principals are non-human, so the gate keeps full records; context is a safety net
    // for human on-behalf-of windows if the app supplies them.
    this.collector.setContext({ inventoryPrincipals: [], candidatePrincipals: [], oboHumanIds: [] });
  }

  static generateKeys() {
    return generateCollectorKeys();
  }

  connector() {
    return this.connectorInstance;
  }

  /** Emit one Agent Action Record. Throws on validation errors. */
  emitAAR(aar) {
    const problems = validateAAR(aar);
    if (problems.length) throw new TypeError(`invalid AAR: ${problems.join('; ')}`);
    return this.collector.ingest(aarToSourceEvent(aar, this));
  }

  /** Emit one OTel span carrying GenAI attributes. Returns the gate decision, or null if the span is not GenAI telemetry. */
  emitOtelSpan(span, opts = {}) {
    const aar = otelGenAiToAAR(span, { tenantId: this.tenantId, emitterId: this.emitterId, ...opts });
    if (!aar) return null;
    return this.collector.ingest(aarToSourceEvent(aar, this));
  }

  /** Seal pending records into a batch (also called automatically at maxBatchRecords). */
  flush() {
    return this.collector.flush();
  }

  get stats() {
    return this.collector.stats;
  }

  explain() {
    return this.collector.explain();
  }

  /** Flush, then ship every spooled batch in order. Throws on transport failure. */
  async flushAndDrain(baseUrl, { fetchImpl = fetch } = {}) {
    this.flush();
    const results = [];
    const result = await this.collector.drain(async (batch) => {
      const res = await fetchImpl(`${baseUrl}/v1/batches`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(batch),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) return { ok: false, error: `${res.status}: ${data?.error ?? res.statusText}` };
      results.push(data);
      return { ok: true };
    });
    if (result.error) throw new Error(`drain failed after ${result.sent} batch(es): ${result.error}`);
    return { ...result, results };
  }
}

// AAR (export profile) -> collector source event.
// The collector applies the boundary guarantees (handles, redaction, commitments, signatures).
export function aarToSourceEvent(aar, emitter) {
  return {
    tenant_id: emitter.tenantId,
    observed_at: aar.observed_at,
    connector_instance: emitter.connectorInstance,
    source_event_id: aar.source.event_id,
    source_system: aar.source.system,
    source_event_type: aar.source.event_type ?? null,
    source_vantage: aar.source.vantage ?? 'inside',
    principal_kind: 'agent',
    principal_id: aar.agent_hint?.principal ?? aar.agent_hint?.vendor_agent_id ?? null,
    record_type: 'OtelGenAiSpan',
    agent_hint: {
      vendor: aar.agent_hint?.vendor ?? null,
      vendor_agent_id: aar.agent_hint?.vendor_agent_id ?? null,
      agent_version: aar.agent_hint?.agent_version ?? null,
      client_id: aar.agent_hint?.client_id ?? null,
      token_actor: aar.agent_hint?.token_actor ?? null,
      user_agent: aar.agent_hint?.user_agent ?? null,
    },
    action: {
      action_type: aar.action.action_type,
      target_system: aar.action.target_system ?? null,
      target_entity_type: aar.action.target_entity_type ?? null,
      target_entity_id: aar.action.target_entity_id ?? null,
      operation: aar.action.operation ?? null,
      tool_name: aar.action.tool_name ?? null,
      field_names: aar.action.field_names ?? [],
      record_count: aar.action.record_count ?? null,
      external_recipient: aar.action.external_recipient ?? null,
      data_classes: aar.action.data_classes ?? [],
    },
    resources_touched: aar.resources_touched ?? [],
    correlation: aar.correlation ?? {},
    model: aar.model ?? null,
    quality: aar.quality ?? null,
    content: aar.content ? { input_text: aar.content.input_text ?? null, output_text: aar.content.output_text ?? null } : undefined,
    on_behalf_of: aar.on_behalf_of ?? [],
    delegation_chain: aar.delegation_chain ?? [],
    ext: aar.ext ?? null,
  };
}
