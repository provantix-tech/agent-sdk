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
  }

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
    const next = this.readSeq() + 1;
    const tmp = this.seqFile + '.tmp';
    fs.writeFileSync(tmp, String(next));
    fs.renameSync(tmp, this.seqFile);
    return next;
  }

  bytes() {
    let total = 0;
    for (const f of fs.readdirSync(this.dir)) {
      if (f.endsWith('.json')) total += fs.statSync(path.join(this.dir, f)).size;
    }
    return total;
  }

  enqueue(batch) {
    const body = JSON.stringify(batch);
    if (this.bytes() + Buffer.byteLength(body) > this.maxBytes) {
      throw new Error('spool full: collector cannot accept more records until ingest is reachable');
    }
    const target = this.#file(batch.batch_seq);
    const tmp = target + '.tmp';
    fs.writeFileSync(tmp, body);
    fs.renameSync(tmp, target);
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
  }

  count() {
    return fs.readdirSync(this.dir).filter((f) => f.endsWith('.json')).length;
  }
}
