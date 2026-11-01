// Durable on-disk queue of signed batches. Batches survive restarts and replay in sequence order.
// A batch is removed only after ingest acknowledges it. Writes are atomic (temp file + rename).
// The batch sequence counter is persisted here too, so restarts never reuse a sequence number.

import fs from 'node:fs';
import path from 'node:path';

export class Spool {
  constructor(dir, { maxBytes = 2 * 1024 ** 3 } = {}) {
    this.dir = dir;
    this.maxBytes = maxBytes;
    fs.mkdirSync(dir, { recursive: true });
    this.seqFile = path.join(dir, 'seq.txt');
    // P6: track spooled bytes incrementally. The previous bytes() scanned and stat'ed every
    // file on every enqueue — O(n) per batch, O(n²) per outage — which dominated the
    // exporter benchmark (60% of CPU in fs.statSync with a few thousand spooled batches).
    this.#sizes = new Map(); // batch_seq -> file size
    for (const f of fs.readdirSync(this.dir)) {
      if (f.endsWith('.json')) {
        this.#sizes.set(Number.parseInt(f, 10), fs.statSync(path.join(this.dir, f)).size);
      }
    }
  }

  #sizes;
  #seq;

  #file(seq) {
    return path.join(this.dir, String(seq).padStart(12, '0') + '.json');
  }

  readSeq() {
    try {
      return Number.parseInt(fs.readFileSync(this.seqFile, 'utf8'), 10) || 0;
    } catch {
      return 0;
    }
  }

  nextSeq() {
    // P6: the in-memory counter avoids a read per batch; the write stays per batch so a
    // crash never reuses a sequence number (fork detection at the control plane).
    const next = (this.#seq ??= this.readSeq()) + 1;
    const tmp = this.seqFile + '.tmp';
    fs.writeFileSync(tmp, String(next));
    fs.renameSync(tmp, this.seqFile);
    this.#seq = next;
    return next;
  }

  bytes() {
    let total = 0;
    for (const s of this.#sizes.values()) total += s;
    return total;
  }

  enqueue(batch) {
    const body = JSON.stringify(batch);
    const size = Buffer.byteLength(body);
    if (this.bytes() + size > this.maxBytes) {
      throw new Error('spool full: collector cannot accept more records until ingest is reachable');
    }
    const target = this.#file(batch.batch_seq);
    const tmp = target + '.tmp';
    fs.writeFileSync(tmp, body);
    fs.renameSync(tmp, target);
    this.#sizes.set(batch.batch_seq, size);
  }

  list() {
    return fs
      .readdirSync(this.dir)
      .filter((f) => f.endsWith('.json'))
      .sort()
      .map((f) => JSON.parse(fs.readFileSync(path.join(this.dir, f), 'utf8')));
  }

  ack(seq) {
    fs.rmSync(this.#file(seq), { force: true });
    this.#sizes.delete(seq);
  }

  count() {
    return fs.readdirSync(this.dir).filter((f) => f.endsWith('.json')).length;
  }
}
