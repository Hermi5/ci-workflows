// VENDORED COPY of ~/Github/agent-os/skills/launch-check/scripts/lib/probes.mjs, copied 2026-09-07.
/**
 * Repo-level probes: checks that need the whole tree, git, the package registry
 * or a build output rather than one file at a time.
 *
 * Every probe that shells out or touches the network is individually skippable
 * and declares itself in the security table in ../NOTICE.md. Nothing here
 * writes to the repo, and nothing here runs a build, a migration or a seed.
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildImportGraph, TEST_PATH_RE } from './vendored.mjs';

const sev = (s) => s;

function sh(cmd, args, cwd) {
  try {
    const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 30000, maxBuffer: 32 * 1024 * 1024 });
    if (r.error) return { ok: false, reason: r.error.code || String(r.error) };
    return { ok: r.status === 0, status: r.status, out: r.stdout || '', err: r.stderr || '' };
  } catch (e) {
    return { ok: false, reason: e.code || String(e) };
  }
}

/** Fail loudly on a missing binary instead of silently reporting a clean repo. */
export function requireBinaries(names) {
  const missing = [];
  for (const n of names) {
    const r = spawnSync(n, ['--version'], { encoding: 'utf8', timeout: 8000 });
    if (r.error && r.error.code === 'ENOENT') missing.push(n);
  }
  return missing;
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}

function finding(rule, name, severity, why, file, line, snippet, owner) {
  return {
    rule, catalog: null, name, family: 'repo', severity, why,
    owner: owner || 'launch-check', file, line: line || 0,
    snippet: String(snippet || '').slice(0, 200),
  };
}

// ---------------------------------------------------------------------------
// git: committed .env files, and whether .env is actually ignored
// ---------------------------------------------------------------------------

export function probeGit(root) {
  const out = [];
  const tracked = sh('git', ['ls-files'], root);
  if (!tracked.ok) return { findings: out, note: 'not a git repository, or git unavailable' };

  const files = tracked.out.split('\n').filter(Boolean);
  for (const f of files) {
    const base = path.basename(f);
    if (!base.startsWith('.env')) continue;
    if (/\.(example|sample|template)$/i.test(base) || base === '.env.example') continue;
    out.push(finding(
      'git-committed-env', 'Environment file committed to git', sev('blocker'),
      'The secret is in the history even after deletion. It must be rotated, not just removed.',
      f, 0, f, 'backend-review: security-05-web-security-baseline.md'
    ));
  }

  const gi = path.join(root, '.gitignore');
  if (fs.existsSync(gi)) {
    const body = fs.readFileSync(gi, 'utf8');
    if (!/^\s*\.env/m.test(body)) {
      out.push(finding('git-env-not-ignored', '.env not listed in .gitignore', sev('should-fix'),
        'Nothing prevents the next commit from adding it.', '.gitignore', 0, '', 'backend-review: security-05-web-security-baseline.md'));
    }
  } else {
    out.push(finding('git-no-gitignore', 'No .gitignore', sev('should-fix'),
      'Every build artefact and local file is one git add away from the repository.', '.gitignore', 0, ''));
  }
  return { findings: out, note: `${files.length} tracked files` };
}

// ---------------------------------------------------------------------------
// Dependencies: existence in the registry (hallucination check) + npm audit
// ---------------------------------------------------------------------------

export async function probeDependencies(root, { network = true } = {}) {
  const out = [];
  const pkgPath = path.join(root, 'package.json');
  const pkg = readJson(pkgPath);
  if (!pkg) return { findings: out, note: 'no package.json, dependency probes skipped' };

  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const names = Object.keys(deps);
  if (!network) return { findings: out, note: `${names.length} dependencies, registry check skipped (--no-network)` };

  let checked = 0;
  const unknown = [];
  await Promise.all(names.map(async (name) => {
    // Local protocols are not registry packages.
    const spec = String(deps[name] || '');
    if (/^(?:file:|link:|workspace:|git\+|github:|https?:)/i.test(spec)) return;
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}`, {
        method: 'HEAD', signal: controller.signal,
      });
      clearTimeout(t);
      checked++;
      if (res.status === 404) unknown.push(name);
    } catch { /* network failure is not a finding; reported in the note */ }
  }));

  for (const name of unknown) {
    out.push(finding(
      'dep-not-in-registry', 'Dependency does not exist in the npm registry', sev('blocker'),
      'A package name that resolves to nothing is either a typo or a hallucinated name. Attackers register the popular hallucinations, which is why backend-review calls this slopsquatting.',
      'package.json', 0, name, 'backend-review: security-05-web-security-baseline.md'
    ));
  }

  const audit = sh('npm', ['audit', '--json', '--audit-level=none'], root);
  let note = `${checked}/${names.length} dependencies resolved against the registry`;
  if (audit.out) {
    const data = (() => { try { return JSON.parse(audit.out); } catch { return null; } })();
    const v = data && data.metadata && data.metadata.vulnerabilities;
    if (v) {
      if (v.critical > 0 || v.high > 0) {
        out.push(finding('dep-vulnerable', `npm audit: ${v.critical} critical, ${v.high} high`, sev('should-fix'),
          'Known vulnerable dependencies. Review each before launch; not every advisory is reachable from your code.',
          'package.json', 0, JSON.stringify(v), 'backend-review: security-05-web-security-baseline.md'));
      }
      note += ` | audit: ${v.critical}C ${v.high}H ${v.moderate}M ${v.low}L`;
    }
  } else {
    note += ' | npm audit produced no parseable output (no lockfile?)';
  }
  return { findings: out, note };
}

// ---------------------------------------------------------------------------
// Next.js App Router structure: crash containment + dead internal links
// ---------------------------------------------------------------------------

function findAppDir(root) {
  for (const c of ['app', 'src/app']) {
    const p = path.join(root, c);
    if (fs.existsSync(p) && fs.statSync(p).isDirectory()) return p;
  }
  return null;
}

export function probeAppRouter(root) {
  const out = [];
  const appDir = findAppDir(root);
  if (!appDir) return { findings: out, note: 'no Next.js app directory, router probes skipped' };

  const rel = path.relative(root, appDir);
  const has = (n) => ['tsx', 'jsx', 'ts', 'js'].some((e) => fs.existsSync(path.join(appDir, `${n}.${e}`)));

  if (!has('not-found')) {
    out.push(finding('app-no-not-found', 'No custom not-found page', sev('should-fix'),
      'Users hitting a bad URL get the framework default. site-audit also checks that the response is a real 404 rather than a soft 200.',
      `${rel}/not-found.tsx`, 0, ''));
  }
  if (!has('error')) {
    out.push(finding('app-no-error-boundary', 'No error boundary at the app root', sev('should-fix'),
      'Any uncaught render error takes down the whole route segment with no recovery path and no branded page.',
      `${rel}/error.tsx`, 0, ''));
  }
  if (!has('global-error')) {
    out.push(finding('app-no-global-error', 'No global-error boundary', sev('advisory'),
      'An error thrown in the root layout itself is not caught by error.tsx. global-error.tsx is the only thing that catches it.',
      `${rel}/global-error.tsx`, 0, ''));
  }

  // Route inventory for the dead-link check.
  const routes = new Set(['/']);
  const walk = (dir, seg) => {
    let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (!e.isDirectory()) {
        if (/^page\.(tsx|jsx|ts|js|mdx)$/.test(e.name)) routes.add(seg || '/');
        continue;
      }
      if (e.name.startsWith('_') || e.name.startsWith('.')) continue;
      // Route groups (marketing) do not appear in the URL.
      if (/^\(.+\)$/.test(e.name)) { walk(path.join(dir, e.name), seg); continue; }
      // Parallel and intercepting routes are not plain URL segments.
      if (e.name.startsWith('@') || /^\(\.+\)/.test(e.name)) continue;
      walk(path.join(dir, e.name), `${seg}/${e.name}`);
    }
  };
  walk(appDir, '');

  const dynamic = [...routes].some((r) => r.includes('['));
  return { findings: out, note: `${routes.size} routes discovered${dynamic ? ' (dynamic segments present)' : ''}`, routes, dynamic };
}

/** Internal hrefs pointing at a route that does not exist. Skipped when the
 *  app uses dynamic segments, because a static tree cannot decide those. */
export function probeDeadLinks(root, files, routes, dynamic) {
  const out = [];
  if (!routes || dynamic) {
    return { findings: out, note: dynamic ? 'dead-link check skipped: dynamic route segments present' : 'dead-link check skipped: no route tree' };
  }
  const known = new Set([...routes].map((r) => (r === '' ? '/' : r)));
  const HREF = /\bhref\s*=\s*["'](\/[^"'#?]*)["']/g;
  for (const file of files) {
    if (!/\.(jsx|tsx|vue|svelte|astro)$/i.test(file)) continue;
    if (TEST_PATH_RE.test(file)) continue;
    let text; try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    HREF.lastIndex = 0;
    let m;
    while ((m = HREF.exec(text)) !== null) {
      const target = m[1].replace(/\/$/, '') || '/';
      if (known.has(target)) continue;
      const line = text.slice(0, m.index).split('\n').length;
      out.push(finding('dead-internal-link', 'Internal link to a route that does not exist', sev('should-fix'),
        'A 404 reachable from your own navigation. The single most common consequence of a page being renamed or never built.',
        path.relative(root, file), line, m[0]));
    }
  }
  return { findings: out, note: `${out.length} dead internal links` };
}

// ---------------------------------------------------------------------------
// Orphans and the client/server ratio
// ---------------------------------------------------------------------------

export function probeOrphans(root, files) {
  const out = [];
  const aliases = readAliases(root);
  const graph = buildImportGraph(files, aliases);
  const imported = new Set();
  for (const set of graph.values()) for (const f of set) imported.add(f);

  // Framework entry points are reachable by convention, not by import.
  const ENTRY = /(?:^|[/\\])(?:page|layout|template|loading|error|global-error|not-found|route|default|middleware|proxy|instrumentation|sitemap|robots|opengraph-image|twitter-image|icon|apple-icon|manifest)\.(?:tsx?|jsx?|mjs)$/i;
  const CONFIG = /\.config\.(?:m?[jt]s|cjs)$|(?:^|[/\\])(?:tailwind|postcss|next|vite|drizzle|eslint|playwright|vitest|jest)\./i;

  // "Imported by nothing" only means dead INSIDE the module graph's own
  // territory. A CLI script under scripts/, a browser-extension bundle, or a
  // .d.ts declaration is an entry point of a different kind and is supposed to
  // have no importer. Reporting those was the first version's worst noise
  // source: 130 findings on Personal-Portfolio, essentially all of them wrong.
  const SOURCE_ROOT = /(?:^|[/\\])(?:src|app|components?|lib|hooks?|features?|ui|utils?)[/\\]/i;

  // Anything named in a package.json script is an entry point by definition.
  const pkg = readJson(path.join(root, 'package.json'));
  const scriptText = pkg && pkg.scripts ? Object.values(pkg.scripts).join(' ') : '';

  for (const file of files) {
    if (imported.has(file)) continue;
    const rel = path.relative(root, file);
    if (!/\.(m?[jt]sx?)$/i.test(file)) continue;
    if (/\.d\.ts$/i.test(file)) continue;
    if (ENTRY.test(rel) || CONFIG.test(rel) || TEST_PATH_RE.test(rel)) continue;
    if (!SOURCE_ROOT.test(rel)) continue;
    if (scriptText.includes(path.basename(file)) || scriptText.includes(rel)) continue;
    // A shebang means it is executed directly, not imported.
    try { if (fs.readFileSync(file, 'utf8').startsWith('#!')) continue; } catch { /* fall through */ }

    out.push(finding('orphan-file', 'File imported by nothing', sev('advisory'),
      'Dead code from an abandoned approach. Harmless to run, but it misleads the next reader and inflates the surface you think you maintain.',
      rel, 0, ''));
  }
  return { findings: out, note: `${out.length} orphans inside the source tree, of ${files.length} files` };
}

function readAliases(root) {
  const tsconfig = readJson(path.join(root, 'tsconfig.json'));
  const paths = tsconfig && tsconfig.compilerOptions && tsconfig.compilerOptions.paths;
  if (!paths) return null;
  const baseUrl = (tsconfig.compilerOptions.baseUrl) || '.';
  const base = path.resolve(root, baseUrl);
  const out = [];
  for (const [k, v] of Object.entries(paths)) {
    const prefix = k.replace(/\*$/, '');
    const targets = (Array.isArray(v) ? v : [v]).map((t) => path.resolve(base, String(t).replace(/\*$/, '')));
    out.push([prefix, targets]);
  }
  return out;
}

/** Declared runtime dependencies that nothing imports. Agents install packages
 *  they then abandon; each one is install time, bundle risk and an advisory
 *  surface you did not choose to maintain. */
export function probeUnusedDeps(root, files) {
  const out = [];
  const pkg = readJson(path.join(root, 'package.json'));
  if (!pkg || !pkg.dependencies) return { findings: out, note: 'no dependencies block' };

  const BARE = /(?:import\s+(?:[\s\S]{0,200}?from\s+)?|require\(\s*|import\(\s*)['"]([^'".][^'"]*)['"]/g;
  const used = new Set();
  for (const file of files) {
    let text; try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    BARE.lastIndex = 0;
    let m;
    while ((m = BARE.exec(text)) !== null) {
      const spec = m[1];
      if (spec.startsWith('.') || spec.startsWith('/')) continue;
      used.add(spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]);
    }
  }

  // Packages that are legitimately never imported by name: the framework itself,
  // build-chain plugins resolved by config, and type-only packages.
  const IMPLICIT = /^(?:next|react|react-dom|typescript|@types\/|eslint|@eslint\/|postcss|autoprefixer|tailwindcss|@tailwindcss\/|sharp|encoding|bufferutil|utf-8-validate)/;

  for (const name of Object.keys(pkg.dependencies)) {
    if (used.has(name) || IMPLICIT.test(name)) continue;
    out.push(finding('unused-dependency', 'Declared dependency that nothing imports', sev('advisory'),
      'Install time, bundle risk and an advisory surface for a package the project does not use. Usually the residue of an approach that was tried and abandoned.',
      'package.json', 0, name));
  }
  return { findings: out, note: `${used.size} packages imported, ${out.length} declared but unused` };
}

export function probeClientRatio(files) {
  const out = [];
  const components = files.filter((f) => /\.(jsx|tsx)$/i.test(f) && !TEST_PATH_RE.test(f));
  if (components.length < 12) return { findings: out, note: 'too few components to judge the client ratio' };
  let client = 0;
  for (const f of components) {
    let head; try { head = fs.readFileSync(f, 'utf8').slice(0, 400); } catch { continue; }
    if (/^\s*['"]use client['"]/m.test(head)) client++;
  }
  const pct = Math.round((client / components.length) * 100);
  if (pct >= 70) {
    out.push(finding('use-client-everywhere', `"use client" on ${pct}% of components`, sev('advisory'),
      'The App Router defaults to server components. A ratio this high usually means the directive was added to fix an error rather than chosen, which forfeits the server rendering the framework exists to give you.',
      'app/', 0, `${client}/${components.length}`));
  }
  return { findings: out, note: `${pct}% of ${components.length} components are client components` };
}

// ---------------------------------------------------------------------------
// Client bundle: does a server-only env value appear in what ships?
// ---------------------------------------------------------------------------

export function probeClientBundle(root) {
  const out = [];
  const staticDir = path.join(root, '.next', 'static');
  if (!fs.existsSync(staticDir)) {
    return { findings: out, note: 'no .next/static build output; run a production build first for the bundle secret scan' };
  }

  // Values of every non-NEXT_PUBLIC_ variable found in a local env file.
  const secrets = new Map();
  for (const name of ['.env', '.env.local', '.env.production', '.env.production.local']) {
    const p = path.join(root, name);
    if (!fs.existsSync(p)) continue;
    let body; try { body = fs.readFileSync(p, 'utf8'); } catch { continue; }
    for (const line of body.split('\n')) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.+?)\s*$/i);
      if (!m) continue;
      const [, key, rawVal] = m;
      if (key.startsWith('NEXT_PUBLIC_')) continue;
      const val = rawVal.replace(/^["']|["']$/g, '');
      if (val.length < 12) continue; // too short to be distinctive
      secrets.set(val, key);
    }
  }
  if (secrets.size === 0) {
    return { findings: out, note: 'build output present, but no local env file with server-only values to search for' };
  }

  const bundleFiles = [];
  const walk = (d) => {
    let entries; try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (/\.(js|mjs|json|txt|map)$/i.test(e.name)) bundleFiles.push(full);
    }
  };
  walk(staticDir);

  for (const file of bundleFiles) {
    let text; try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    for (const [val, key] of secrets) {
      if (!text.includes(val)) continue;
      out.push(finding('secret-in-client-bundle', `Server-only value ${key} is present in the client bundle`, sev('blocker'),
        'This string ships to every visitor. If it is a key, it is compromised and must be rotated, not just removed.',
        path.relative(root, file), 0, key, 'backend-review: security-05-web-security-baseline.md'));
    }
  }
  return { findings: out, note: `${bundleFiles.length} bundle files searched for ${secrets.size} server-only values` };
}

// ---------------------------------------------------------------------------
// Inventory: things worth stating even when they are not findings
// ---------------------------------------------------------------------------

export function probeInventory(root, files) {
  const notes = [];
  const pkg = readJson(path.join(root, 'package.json'));
  const tests = files.filter((f) => /\.(test|spec)\.[jt]sx?$/i.test(f)).length;
  notes.push(`${files.length} scannable files, ${tests} test files`);
  if (pkg) {
    const next = (pkg.dependencies && pkg.dependencies.next) || (pkg.devDependencies && pkg.devDependencies.next);
    if (next) notes.push(`next ${next}`);
    if (!fs.existsSync(path.join(root, '.env.example')) && !fs.existsSync(path.join(root, '.env.sample'))) {
      notes.push('no .env.example: nobody else can configure this repo without asking you');
    }
  }
  if (tests === 0) notes.push('no test files found: the green gate has nothing to assert');
  return { findings: [], note: notes.join(' | ') };
}
