// The collector: runs inside the customer's boundary.
// Takes source events, applies the principal gate, converts humans to handles, redacts text,
// seals records with commitments, and ships signed batches through a durable spool.
// Spec: plan/03-architecture.md section 1.1 and 3; plan/02-data-model.md sections 2, 6.

import { classify, CLASS } from './gate.mjs';
import { makeHandle } from './handles.mjs';
import { redact, redactDeep, REDACTION_PROFILE_ID } from './redact.mjs';
import { buildBatch } from './batch.mjs';
import { sealRecord } from './aar.mjs';

const REQUIRED = ['tenant_id', 'observed_at', 'connector_instance', 'source_event_id', 'principal_kind', 'record_type'];

export class Collector {
  /**
   * @param {object} opts
   * @param {string} opts.collectorId
   * @param {string} opts.privateKeyPem   collector signing key (never leaves the customer)
   * @param {Buffer} opts.handleKey       customer-held HMAC key for handles
   * @param {import('./spool.mjs').Spool} opts.spool
   * @param {number} [opts.maxBatchRecords=500]
   * @param {() => Date} [opts.clock]
   */
  constructor({ collectorId, privateKeyPem, handleKey, spool, maxBatchRecords = 500, clock = () => new Date() }) {
    this.collectorId = collectorId;
    this.privateKeyPem = privateKeyPem;
    this.handleKey = handleKey;
    this.spool = spool;
    this.maxBatchRecords = maxBatchRecords;
    this.clock = clock;
    this.ctx = { inventoryPrincipals: new Set(), candidatePrincipals: new Set(), oboHumanIds: new Set() };
    this.pending = [];
    this.rollups = new Map();
    this.stats = { full: 0, [CLASS.OBO_WINDOW]: 0, rollup: 0, rejected: 0 };
  }

  /** Inventory context pushed from the control plane (ids are raw, never sent back). */
  setContext({ inventoryPrincipals = [], candidatePrincipals = [], oboHumanIds = [] }) {
    this.ctx = {
      inventoryPrincipals: new Set(inventoryPrincipals),
      candidatePrincipals: new Set(candidatePrincipals),
      oboHumanIds: new Set(oboHumanIds),
    };
  }

  /**
   * Process one source event. Returns the gate decision.
   * @param {object} ev source event (see README for the shape)
   */
  ingest(ev) {
    for (const k of REQUIRED) {
      if (ev[k] === undefined || ev[k] === null || ev[k] === '') {
        this.stats.rejected += 1;
        throw new TypeError(`event missing ${k}`);
      }
    }
    if (!ev.action || !ev.action.action_type) {
      this.stats.rejected += 1;
      throw new TypeError('event missing action.action_type');
    }
    const decision = classify(
      { principalKind: ev.principal_kind, principalId: ev.principal_id ?? '', recordType: ev.record_type },
      this.ctx,
    );
    if (decision.class === CLASS.ROLLUP) {
      this.#rollup(ev);
      this.stats.rollup += 1;
      return decision;
    }
    this.pending.push(this.#buildRecord(ev, decision));
    this.stats[decision.class] += 1;
    if (this.pending.length >= this.maxBatchRecords) this.flush();
    return decision;
  }

  #principalValue(ev) {
    if (!ev.principal_id) return null;
    return ev.principal_kind === 'human' ? makeHandle(this.handleKey, ev.principal_id) : ev.principal_id;
  }

  #humanHandle(actor) {
    return actor.kind === 'human' ? makeHandle(this.handleKey, actor.id) : actor.id;
  }

  #buildRecord(ev, decision) {
    const hint = ev.agent_hint ?? {};
    const principal = this.#principalValue(ev);
    const contentIn = redact(ev.content?.input_text ?? null);
    const contentOut = redact(ev.content?.output_text ?? null);
    const ext = redactDeep(ev.ext ?? null);

    const fields = {
      tenant_id: ev.tenant_id,
      observed_at: ev.observed_at,
      gate_class: decision.class,
      source: {
        connector_instance: ev.connector_instance,
        system: ev.source_system ?? null,
        event_id: ev.source_event_id,
        event_type: ev.source_event_type ?? null,
        vantage: ev.source_vantage ?? 'destination',
      },
      principal: { kind: ev.principal_kind, id: principal },
      agent_hint: {
        vendor: hint.vendor ?? null,
        vendor_agent_id: hint.vendor_agent_id ?? null,
        agent_version: hint.agent_version ?? null,
        client_id: hint.client_id ?? null,
        token_actor: hint.token_actor ?? null,
      },
      action: {
        action_type: ev.action.action_type,
        target_system: ev.action.target_system ?? null,
        target_entity_type: ev.action.target_entity_type ?? null,
        target_entity_id: ev.action.target_entity_id ?? null,
        operation: ev.action.operation ?? null,
        tool_name: ev.action.tool_name ?? null,
        field_names: ev.action.field_names ?? [],
        record_count: ev.action.record_count ?? null,
        external_recipient: ev.action.external_recipient ?? null,
        data_classes: ev.action.data_classes ?? [],
      },
      resources_touched: (ev.resources_touched ?? []).map((r) => ({
        system: r.system,
        entity_type: r.entity_type ?? null,
        entity_id: r.entity_id,
        action_type: r.action_type ?? null,
      })),
      correlation: {
        trace_id: ev.correlation?.trace_id ?? null,
        span_id: ev.correlation?.span_id ?? null,
        parent_span_id: ev.correlation?.parent_span_id ?? null,
        session_id: ev.correlation?.session_id ?? null,
        conversation_id: ev.correlation?.conversation_id ?? null,
      },
      model: ev.model ?? null,
      quality: ev.quality ?? null,
      redaction: {
        profile: REDACTION_PROFILE_ID,
        counts: mergeCounts(contentIn.counts, contentOut.counts, ext.counts),
      },
    };

    const erasable = {
      on_behalf_of: (ev.on_behalf_of ?? []).map((a) => ({ kind: a.kind, id: this.#humanHandle(a) })),
      delegation_chain: (ev.delegation_chain ?? []).map((a) => ({ kind: a.kind, id: this.#humanHandle(a) })),
      input_summary: contentIn.text,
      output_summary: contentOut.text,
      attribution_evidence: null,
      ext: ext.value,
      user_agent: hint.user_agent ?? null,
    };

    return sealRecord(fields, erasable);
  }

  #rollup(ev) {
    const principal = this.#principalValue(ev) ?? '(none)';
    const hour = new Date(ev.observed_at);
    hour.setUTCMinutes(0, 0, 0);
    const hourIso = hour.toISOString();
    const key = [ev.principal_kind, principal, ev.action.target_system ?? '', ev.action.action_type, hourIso].join('|');
    let entry = this.rollups.get(key);
    if (!entry) {
      entry = {
        principal_kind: ev.principal_kind,
        principal,
        system: ev.action.target_system ?? null,
        action_type: ev.action.action_type,
        hour: hourIso,
        count: 0,
        entities: new Set(),
      };
      this.rollups.set(key, entry);
    }
    entry.count += 1;
    if (ev.action.target_entity_id) {
      // Distinct count only. Entity ids are keyed-hashed so the count cannot be reversed.
      entry.entities.add(makeHandle(this.handleKey, String(ev.action.target_entity_id)));
    }
  }

  /** Seal pending records and rollups into one signed batch and spool it. */
  flush() {
    if (this.pending.length === 0 && this.rollups.size === 0) return null;
    const batchSeq = this.spool.nextSeq();
    const rollups = [...this.rollups.values()].map((r) => ({
      principal_kind: r.principal_kind,
      principal: r.principal,
      system: r.system,
      action_type: r.action_type,
      hour: r.hour,
      count: r.count,
      distinct_entities: r.entities.size,
    }));
    const batch = buildBatch({
      collectorId: this.collectorId,
      batchSeq,
      records: this.pending,
      rollups,
      createdAt: this.clock().toISOString(),
      privateKeyPem: this.privateKeyPem,
    });
    this.spool.enqueue(batch);
    this.pending = [];
    this.rollups.clear();
    return batch;
  }

  /**
   * Send spooled batches in order. transport(batch) must resolve to { ok: boolean }.
   * A batch is acknowledged (removed from the spool) only on ok. Stops at the first failure.
   */
  async drain(transport) {
    let sent = 0;
    for (const batch of this.spool.list()) {
      const res = await transport(batch);
      if (!res || !res.ok) {
        return { sent, remaining: this.spool.count(), error: res?.error ?? 'transport failed' };
      }
      this.spool.ack(batch.batch_seq);
      sent += 1;
    }
    return { sent, remaining: 0, error: null };
  }

  /** What leaves the boundary, stated plainly for the DPO. */
  explain() {
    return {
      collector_id: this.collectorId,
      leaves_boundary: {
        full_records: {
          when: 'principal is non-human, inventoried, a candidate, or the record type is agent-specific',
          fields: ['tenant_id', 'observed_at', 'source.*', 'principal (human as handle)', 'agent_hint.*', 'action.*', 'resources_touched', 'correlation.*', 'model', 'quality', 'redaction counts'],
          erasable: ['on_behalf_of (handles)', 'delegation_chain (handles)', 'input_summary (redacted)', 'output_summary (redacted)', 'ext (redacted)', 'user_agent'],
          never: ['raw human identifiers', 'display names', 'unredacted text', 'raw payloads', 'the handle key'],
        },
        obo_window_records: {
          when: 'human inside an agent session window (expires at 7 days unless attributed by the control plane)',
          same_fields_as: 'full_records',
        },
        rollups: {
          when: 'all other human activity',
          fields: ['principal (handle)', 'system', 'action_type', 'hour', 'count', 'distinct_entities (keyed count)'],
          never: ['entity ids', 'content', 'per-event timestamps'],
        },
      },
      redaction_profile: REDACTION_PROFILE_ID,
      stats: { ...this.stats },
      pending_records: this.pending.length,
      spooled_batches: this.spool.count(),
    };
  }
}

function mergeCounts(...maps) {
  const out = {};
  for (const m of maps) {
    for (const [k, v] of Object.entries(m)) out[k] = (out[k] ?? 0) + v;
  }
  return out;
}
