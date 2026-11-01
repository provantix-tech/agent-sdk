// Standalone offline verifier for a Provantix export directory (the P7 "verify it yourself"
// ending). Needs nothing from the control plane: record hashes recompute from the files
// alone, chain links are checked where consecutive positions are both present, and every
// file's sha256 is compared against the manifest.
//
//   node examples/verify-export.mjs <export-dir>
//
// Works on a complete export (Exports page / POST /v1/exports) and on a run export zip
// (unzip it first — it carries manifest.json + records.jsonl). Daily roots are only
// recomputable on complete exports; partial exports say so and pass.
//
// The record-level checks are the canonical verifyRecord/chainLink implementations vendored
// in this repository (src/vendor/integrity.mjs), so what runs here is byte-for-byte what the
// platform's own verifier runs.

import fs from 'node:fs';
import path from 'node:path';

import { verifyRecord } from '../src/vendor/integrity.mjs';

const dir = process.argv[2];
if (!dir) {
  console.error('usage: node examples/verify-export.mjs <export-dir>');
  process.exit(2);
}

let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures += 1;
};

const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
check('manifest readable', true, `${manifest.record_count} record(s), filter ${JSON.stringify(manifest.filter ?? {})}`);

for (const f of manifest.files ?? []) {
  const full = path.join(dir, f.path);
  if (!fs.existsSync(full)) { check(`file present: ${f.path}`, false); continue; }
  const hash = fs.createHash('sha256').update(fs.readFileSync(full)).digest('hex');
  check(`file hash: ${f.path}`, hash === f.sha256, hash === f.sha256 ? '' : 'differs from manifest');
}

const lines = fs.readFileSync(path.join(dir, 'records.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
let bad = 0;
for (const rec of lines) {
  const v = verifyRecord({ fields: rec.fields, erasable: rec.erasable, integrity: rec.integrity });
  if (!v.valid) { bad += 1; check(`record ${rec.record_id}`, false, v.reasons.join('; ')); }
}
check('records recompute', bad === 0, `${lines.length - bad} of ${lines.length} ok`);

// Chain links: each record names the previous record's hash in its chain position.
const byChain = new Map();
for (const r of lines) {
  if (!byChain.has(r.chain_key)) byChain.set(r.chain_key, []);
  byChain.get(r.chain_key).push(r);
}
let broken = 0;
for (const list of byChain.values()) {
  const bySeq = new Map(list.map((r) => [r.chain_seq, r]));
  for (const r of list) {
    const prev = bySeq.get(r.chain_seq - 1);
    if (prev && r.prev_record_hash !== prev.integrity.record_hash) broken += 1;
  }
}
check('chain links hold', broken === 0, broken ? `${broken} broken` : `${byChain.size} chain(s)`);

if (manifest.complete) {
  for (const day of manifest.roots_included ?? []) {
    check(`root ${day}`, fs.existsSync(path.join(dir, 'roots', `${day}.json`)), 'root file present (recompute with the platform verifier)');
  }
} else {
  check('daily roots', true, 'partial export — roots verify against a complete export only');
}

console.log(failures === 0 ? '\nVERIFIED: every record recomputes from this directory alone.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
