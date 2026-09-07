#!/usr/bin/env node
// VENDORED COPY. Source: ~/Github/agent-os/skills/launch-check/scripts/launch-scan.mjs, copied 2026-09-07 (sha256 6f86f935ba10cad1445fa83540da011182ec95366ed0af5a2453faaa053d6233).
// Upstream is the skill; edit there and re-vendor. See README.md in this folder.
/**
 * launch-check scanner — deterministic pre-filter for the pre-launch gate.
 *
 *   node ~/.claude/skills/launch-check/scripts/launch-scan.mjs [path] [flags]
 *
 *   --json          machine-readable findings on stdout
 *   --no-network    skip the npm registry existence check and npm audit
 *   --no-shell      skip everything that shells out (git, npm)
 *   --explain       print each rule's false-positive profile alongside findings
 *   --only <fam>    one family: wired placeholder suppression config crash boundary repo backend
 *   --quiet         findings only, no inventory notes
 *   --cap N          max findings per rule before the rest are announced and dropped (default 40)
 *
 * It reports. It never fixes, never writes to the repo, never runs a build, a
 * migration or a seed. Exit code is 0 unless the scan itself failed: the verdict
 * is a judgment call made after this, not a number computed here.
 *
 * Design note. This finds mechanical signatures only. Everything it reports is a
 * candidate, and the false-positive profile on each rule is part of the output
 * for that reason. Adjudication needs a model; detection does not.
 */

import fs from 'node:fs';
import path from 'node:path';
import { walkDir, applyInlineIgnores, makeFinding, TEST_PATH_RE } from './lib/vendored.mjs';
import { STATIC_RULES } from './lib/rules-static.mjs';
import { BACKEND_RULES } from './lib/rules-backend.mjs';
import {
  requireBinaries, probeGit, probeDependencies, probeAppRouter,
  probeDeadLinks, probeOrphans, probeClientRatio, probeClientBundle, probeInventory, probeUnusedDeps,
} from './lib/probes.mjs';

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const optval = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : null; };

const OPTS = {
  json: flag('--json'),
  network: !flag('--no-network') && !flag('--no-shell'),
  shell: !flag('--no-shell'),
  explain: flag('--explain'),
  only: optval('--only'),
  quiet: flag('--quiet'),
};

const positional = argv.filter((a, i) => !a.startsWith('--') && argv[i - 1] !== '--only');
const ROOT = path.resolve(positional[0] || process.cwd());

if (!fs.existsSync(ROOT)) {
  console.error(`launch-check: no such path: ${ROOT}`);
  process.exit(2);
}

// -- Fail loudly on a missing binary rather than silently reporting a clean repo.
if (OPTS.shell) {
  const missing = requireBinaries(['git', 'npm']);
  if (missing.length) {
    console.error(`launch-check: required binaries not found: ${missing.join(', ')}`);
    console.error('Re-run with --no-shell to scan files only, or install them.');
    process.exit(2);
  }
}

const ALL_RULES = [...STATIC_RULES, ...BACKEND_RULES];
const REGISTRY = Object.fromEntries(ALL_RULES.map((r) => [r.id, r]));

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** Blank out SQL line comments, preserving offsets so line numbers stay exact.
 *  Without this, a migration that documents a DELETE in a comment is reported as
 *  performing one. Real case: Obermatt-V5 0004_staging.sql:26. */
function maskSqlComments(text) {
  return text.replace(/--[^\n]*/g, (m) => ' '.repeat(m.length));
}

function runFileRules(relPath, text) {
  let found = [];
  const matchText = /\.sql$/i.test(relPath) ? maskSqlComments(text) : text;
  for (const rule of ALL_RULES) {
    if (OPTS.only && rule.family !== OPTS.only) continue;
    if (rule.include && !rule.include.test(relPath)) continue;
    if (rule.excludePath && rule.excludePath.test(relPath)) continue;
    if (rule.skipTests !== false && TEST_PATH_RE.test(relPath)) continue;
    // Whole-file suppression: context elsewhere in the file makes the match benign.
    if (rule.fileReject && rule.fileReject.test(matchText)) continue;
    // Whole-file precondition: the rule only applies to files of a certain kind.
    if (rule.fileRequire && !rule.fileRequire.test(matchText)) continue;
    if (rule.fileRequireFn && !rule.fileRequireFn(matchText)) continue;

    if (rule.kind === 'fileAbsence') {
      if (!rule.requirePresent.test(matchText)) continue;
      if (rule.requireAlsoPresent.test(matchText)) continue;
      found.push(makeFinding(REGISTRY, rule.id, relPath, 0, ''));
      continue;
    }

    if (!rule.pattern) continue;
    rule.pattern.lastIndex = 0;
    let m;
    let guard = 0;
    while ((m = rule.pattern.exec(matchText)) !== null && guard++ < 500) {
      const line = lineOf(matchText, m.index);
      // Line-level suppression: the surrounding line makes this match benign.
      if (rule.rejectLine) {
        const start = matchText.lastIndexOf('\n', m.index) + 1;
        let end = matchText.indexOf('\n', m.index);
        if (end === -1) end = matchText.length;
        if (rule.rejectLine.test(matchText.slice(start, end))) {
          if (m.index === rule.pattern.lastIndex) rule.pattern.lastIndex++;
          continue;
        }
      }
      found.push(makeFinding(REGISTRY, rule.id, relPath, line, m[0]));
      if (m.index === rule.pattern.lastIndex) rule.pattern.lastIndex++;
    }
  }
  return applyInlineIgnores(found, text);
}

async function main() {
  const files = walkDir(ROOT);
  const findings = [];
  const notes = [];

  for (const file of files) {
    const rel = path.relative(ROOT, file);
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    if (text.length > 2_000_000) continue; // a 2 MB source file is generated, not written
    findings.push(...runFileRules(rel, text));
  }

  const runProbe = (label, fn) => {
    try {
      const r = fn();
      if (r && r.findings) findings.push(...r.findings);
      if (r && r.note) notes.push(`${label}: ${r.note}`);
      return r;
    } catch (e) {
      notes.push(`${label}: probe failed (${e && e.message ? e.message : e})`);
      return null;
    }
  };

  runProbe('inventory', () => probeInventory(ROOT, files));
  const router = runProbe('routes', () => probeAppRouter(ROOT));
  if (!OPTS.only || OPTS.only === 'repo') {
    runProbe('links', () => probeDeadLinks(ROOT, files, router && router.routes, router && router.dynamic));
    runProbe('orphans', () => probeOrphans(ROOT, files));
    runProbe('components', () => probeClientRatio(files));
    runProbe('unused-deps', () => probeUnusedDeps(ROOT, files));
    runProbe('bundle', () => probeClientBundle(ROOT));
    if (OPTS.shell) runProbe('git', () => probeGit(ROOT));
  }
  if (OPTS.shell && (!OPTS.only || OPTS.only === 'repo')) {
    try {
      const r = await probeDependencies(ROOT, { network: OPTS.network });
      findings.push(...r.findings);
      notes.push(`deps: ${r.note}`);
    } catch (e) {
      notes.push(`deps: probe failed (${e && e.message ? e.message : e})`);
    }
  }

  // Stable ordering so two runs on an unchanged repo produce identical output.
  const RANK = { blocker: 0, 'should-fix': 1, advisory: 2 };
  findings.sort((a, b) =>
    (RANK[a.severity] - RANK[b.severity]) ||
    a.rule.localeCompare(b.rule) ||
    a.file.localeCompare(b.file) ||
    (a.line - b.line));

  // Per-rule cap. One noisy rule must never be able to drown the report: a
  // scraped-site mirror once produced 35,184 dead-href findings in a single
  // repo. The cap is announced, never silent, because a truncation you cannot
  // see reads as "covered everything" when it did not.
  const CAP = Number(optval('--cap') || 40);
  const seen = new Map();
  const capped = [];
  const suppressed = new Map();
  for (const f of findings) {
    const n = (seen.get(f.rule) || 0) + 1;
    seen.set(f.rule, n);
    if (n <= CAP) capped.push(f);
    else suppressed.set(f.rule, (suppressed.get(f.rule) || 0) + 1);
  }
  for (const [rule, n] of suppressed) {
    notes.push(`cap: ${rule} matched ${n} more time(s) beyond the first ${CAP}; raise with --cap N or narrow the rule`);
  }
  const total = findings.length;
  findings.length = 0;
  findings.push(...capped);

  if (OPTS.json) {
    process.stdout.write(JSON.stringify({ root: ROOT, notes, findings }, null, 2) + '\n');
    return;
  }

  const counts = findings.reduce((a, f) => (a[f.severity] = (a[f.severity] || 0) + 1, a), {});
  console.log(`\nlaunch-check  ${ROOT}`);
  console.log(`${findings.length} candidates${total > findings.length ? ` (of ${total}, capped)` : ''}  ·  ${counts.blocker || 0} blocker  ${counts['should-fix'] || 0} should-fix  ${counts.advisory || 0} advisory`);
  if (!OPTS.quiet && notes.length) {
    console.log('');
    for (const n of notes) console.log(`  · ${n}`);
  }

  let lastRule = null;
  for (const f of findings) {
    if (f.rule !== lastRule) {
      const rule = REGISTRY[f.rule] || {};
      const n = findings.filter((x) => x.rule === f.rule).length;
      console.log(`\n[${f.severity}] ${f.name}  (${f.rule}${f.catalog ? `, catalog ${f.catalog}` : ''})  ×${n}`);
      if (f.why) console.log(`  why: ${f.why}`);
      if (f.owner && f.owner !== 'launch-check') console.log(`  owner: ${f.owner}`);
      if (OPTS.explain && rule.fp) console.log(`  false positives: ${rule.fp}`);
      lastRule = f.rule;
    }
    console.log(`    ${f.file}${f.line ? ':' + f.line : ''}${f.snippet ? '  ' + f.snippet.replace(/\s+/g, ' ').slice(0, 100) : ''}`);
  }

  console.log('\nEvery line above is a candidate, not a verdict. Run with --explain for each');
  console.log('rule\'s false-positive profile. Suppress a deliberate one in place with');
  console.log('a `launch-check-disable-next-line <rule-id> -- reason` comment.\n');
}

main().catch((e) => {
  console.error('launch-check: scan failed:', e && e.stack ? e.stack : e);
  process.exit(2);
});
