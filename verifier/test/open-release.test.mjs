// PRO-20: the specification, the vectors and the verifiers are released together, and this test fails when they disagree. It also holds the
// boundary between what is open and what is private, and runs the conformance runner the way an outside implementer would.
//
// The checks that need the monorepo (the list of open files, the platform's exporter) skip themselves in the public repository, where
// they cannot apply; everything else runs in both.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { vectorTable, loadExpected, runConformance } from '../conformance-run.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8').replace(/\r\n/g, '\n'); // a checkout may use either line ending
const expected = loadExpected();
const manifestVersion = (dir) => JSON.parse(fs.readFileSync(path.join(root, 'vectors', dir, 'manifest.json'), 'utf8')).export_version;
const vectorDirs = [...new Set(Object.entries(expected).map(([name, e]) => e.dir ?? name))];
const cmp = (a, b) => a.split('.').map(Number).reduce((d, n, i) => d || n - Number(b.split('.')[i]), 0);

test('the specification, the version history and the vectors name the same versions', () => {
  const spec = /^# .*\(version (\d+\.\d+)\)/m.exec(read('FORMAT.md'));
  assert.ok(spec, 'FORMAT.md states its version in its title');
  const history = [...read('CHANGES.md').matchAll(/^## (\d+\.\d+)\b/gm)].map((m) => m[1]);
  assert.ok(history.length >= 1);
  assert.equal(history[0], spec[1], 'the newest entry in CHANGES.md is the specification\'s version');
  for (const dir of vectorDirs) {
    const v = manifestVersion(dir);
    assert.ok(history.includes(v), `vector ${dir} declares version ${v}, which CHANGES.md does not describe`);
    assert.ok(cmp(v, spec[1]) <= 0, `vector ${dir} declares a version newer than the specification`);
  }
  assert.ok(vectorDirs.some((d) => manifestVersion(d) === spec[1]), 'the current version has at least one vector');
});

test('a vector that carries a 1.1 file declares 1.1, and a 1.0 vector carries none', () => {
  for (const dir of vectorDirs) {
    const has11 = ['reconciliation.json', 'authority.jsonl', 'README.txt'].some((f) => fs.existsSync(path.join(root, 'vectors', dir, f)));
    if (has11) assert.equal(manifestVersion(dir), '1.1', `${dir} carries a 1.1 file`);
    if (manifestVersion(dir) === '1.0') assert.equal(has11, false, `${dir} declares 1.0 but carries a 1.1 file`);
  }
});

test('the vector table in CONFORMANCE.md is the one expected.json produces', () => {
  const md = read('CONFORMANCE.md');
  const m = /<!-- vectors:begin -->\n([\s\S]*?)\n<!-- vectors:end -->/.exec(md);
  assert.ok(m, 'CONFORMANCE.md has the table markers');
  assert.equal(m[1].trim(), vectorTable().trim(), 'regenerate it with: node conformance-run.mjs --table');
});

test('every directory under vectors/ is a vector in expected.json, or a named fixture', () => {
  const fixtures = new Set(['anchors']);
  const keyFiles = new Set(Object.values(expected).map((e) => e.emitter_keys).filter(Boolean));
  for (const e of fs.readdirSync(path.join(root, 'vectors'), { withFileTypes: true })) {
    if (e.name === 'expected.json' || keyFiles.has(e.name)) continue;
    if (e.isDirectory()) assert.ok(vectorDirs.includes(e.name) || fixtures.has(e.name), `vectors/${e.name} is not in expected.json`);
  }
  for (const dir of vectorDirs) assert.ok(fs.existsSync(path.join(root, 'vectors', dir, 'manifest.json')), `vector ${dir} has no manifest`);
});

test('the conformance runner passes both verifiers and fails one that does not check anything', (t) => {
  const node = runConformance(['node', 'verify-export.mjs']);
  assert.deepEqual(node.filter((r) => !r.ok), [], 'the Node verifier agrees on every vector');
  const py = ['python', 'python3'].find((c) => spawnSync(c, ['--version']).status === 0);
  if (py) assert.deepEqual(runConformance([py, 'python/verify_export.py']).filter((r) => !r.ok), [], 'the Python verifier agrees on every vector');
  else t.diagnostic('python not installed: the Python run was skipped');
  const lazy = runConformance(['node', '-e', 'console.log(JSON.stringify({ok:true,checks:[]}))', '--']);
  assert.ok(lazy.some((r) => !r.ok), 'a verifier that always says ok is caught');
  const silent = runConformance(['node', '-e', 'console.log("hello")', '--']);
  assert.ok(silent.every((r) => !r.ok), 'one that prints no JSON agrees with nothing');
});

test('the open files are licensed, say what is open and what is not, and name what is stable', () => {
  const lic = read('LICENSE');
  assert.match(lic, /Apache License\s+Version 2\.0/);
  const readme = read('README.md');
  assert.match(readme, /Licensed under the Apache License 2\.0/);
  assert.match(readme, /What is open, and what is not/);
  assert.match(readme, /Not open:/);
  assert.match(read('STABILITY.md'), /## Stable/);
  assert.match(read('CONTRIBUTING.md'), /both verifiers/, 'a format change must touch both verifiers');
});

test('what leaves is exactly the list, and nothing on it imports anything that is not on it', async (t) => {
  let boundary;
  try { boundary = await import('../../scripts/export-open-verifier.mjs'); } catch { t.skip('the list of open files lives in the monorepo'); return; }
  const files = boundary.openFiles();
  assert.equal(new Set(files).size, files.length, 'no file twice');
  for (const f of files) assert.ok(fs.existsSync(path.join(root, f)), `${f} is on the open list and does not exist`);
  const inList = new Set(files.map((f) => path.posix.normalize(f)));
  for (const f of files.filter((x) => x.endsWith('.mjs'))) {
    const src = read(f);
    for (const m of src.matchAll(/(?:from|import)\s*\(?\s*'(\.[^']+)'/g)) {
      // this test's own optional import of the monorepo list: guarded above, and skipped where it does not exist
      if (f === 'test/open-release.test.mjs' && m[1].endsWith('scripts/export-open-verifier.mjs')) continue;
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(f), m[1]));
      assert.ok(inList.has(target), `${f} imports ${m[1]}, which is not on the open list (it would not exist in the public repository)`);
    }
  }
  // none of it points into the private platform
  for (const f of files.filter((x) => /\.(mjs|py|md|yml)$/.test(x) && !x.startsWith('vectors/') && x !== 'test/open-release.test.mjs')) { // this file names the patterns
    const src = read(f);
    assert.doesNotMatch(src, /packages\/ingest|app\/server|\/etc\/provantix|PLATFORM_DATABASE_URL|LEDGER_PLATFORM_SECRET/, `${f} mentions the private platform's internals`);
  }
  assert.ok(files.includes('LICENSE') && files.includes('FORMAT.md') && files.includes('vectors/expected.json'));
  assert.equal(boundary.targetOf('conformance-github-workflow.yml'), '.github/workflows/conformance.yml');
});
