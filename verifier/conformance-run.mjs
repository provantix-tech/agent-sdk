#!/usr/bin/env node
// Conformance runner: shows whether a verifier agrees with the published vectors, on every vector.
//
//   node conformance-run.mjs -- <your verifier command>     run your verifier on every vector and compare with expected.json
//   node conformance-run.mjs --table                        print the vector table that CONFORMANCE.md holds
//
// Your verifier is run once per vector as:   <command> <exportDir> [--emitter-keys <file>] --json
// and must print a JSON object to standard output with
//   "ok":      true or false, whether every check passed, and
//   "checks":  an array of { "name": "<check name>", "ok": true|false } (more fields are ignored).
// The runner compares "ok" and the sorted names of the failing checks with expected.json. It reads nothing else, and passes if all vectors agree.
// Exit code: 0 every vector agrees, 1 at least one differs, 2 usage error.
//
// Example, for the verifiers in this folder:
//   node conformance-run.mjs -- node verify-export.mjs
//   node conformance-run.mjs -- python3 python/verify_export.py

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const vectorsDir = path.join(here, 'vectors');

export const loadExpected = (dir = vectorsDir) => JSON.parse(fs.readFileSync(path.join(dir, 'expected.json'), 'utf8'));
const dirOf = (dir, name, exp) => path.join(dir, exp.dir ?? name);

/** The markdown table of vectors that CONFORMANCE.md holds, generated from expected.json so it cannot go stale unnoticed. */
export function vectorTable(expected = loadExpected()) {
  const rows = Object.entries(expected).map(([name, exp]) => {
    const keys = exp.emitter_keys ? ` (with \`${exp.emitter_keys}\`)` : '';
    const failing = exp.failing.length ? exp.failing.map((f) => `\`${f}\``).join(', ') : 'none';
    return `| \`${name}\`${keys} | ${exp.ok ? 'passes' : 'fails'} | ${failing} |`;
  });
  return ['| Vector | Expected | Failing checks, by name |', '|---|---|---|', ...rows].join('\n');
}

/**
 * Run a verifier command on every vector. Pure of side effects except running the command.
 * @returns {{ name: string, ok: boolean, detail: string }[]}
 */
export function runConformance(command, { dir = vectorsDir, expected = loadExpected(dir) } = {}) {
  const [cmd, ...baseArgs] = command;
  const results = [];
  for (const [name, exp] of Object.entries(expected)) {
    const args = [...baseArgs, dirOf(dir, name, exp), ...(exp.emitter_keys ? ['--emitter-keys', path.join(dir, exp.emitter_keys)] : []), '--json'];
    const run = spawnSync(cmd, args, { encoding: 'utf8', cwd: here });
    if (run.error) { results.push({ name, ok: false, detail: `could not run: ${run.error.message}` }); continue; }
    let out;
    try { out = JSON.parse(run.stdout); } catch { results.push({ name, ok: false, detail: `standard output is not JSON (exit ${run.status})` }); continue; }
    if (typeof out.ok !== 'boolean' || !Array.isArray(out.checks)) { results.push({ name, ok: false, detail: 'the JSON has no boolean "ok" and "checks" array' }); continue; }
    const failing = out.checks.filter((c) => c && c.ok === false).map((c) => c.name).sort();
    const want = [...exp.failing].sort();
    const same = out.ok === exp.ok && JSON.stringify(failing) === JSON.stringify(want);
    results.push({ name, ok: same, detail: same ? '' : `expected ok=${exp.ok} failing ${JSON.stringify(want)}; got ok=${out.ok} failing ${JSON.stringify(failing)}` });
  }
  return results;
}

const isMain = Boolean(process.argv[1]) && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const args = process.argv.slice(2);
  if (args.includes('--table')) { console.log(vectorTable()); process.exit(0); }
  const sep = args.indexOf('--');
  const command = sep >= 0 ? args.slice(sep + 1) : [];
  if (!command.length) { console.error('usage: node conformance-run.mjs -- <your verifier command>   (or --table)'); process.exit(2); }
  const results = runConformance(command);
  for (const r of results) console.log(`${r.ok ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? `  (${r.detail})` : ''}`);
  const bad = results.filter((r) => !r.ok).length;
  console.log(bad ? `\n${bad} of ${results.length} vectors differ: this verifier does not agree with the specification yet` : `\nall ${results.length} vectors agree`);
  process.exit(bad ? 1 : 0);
}
