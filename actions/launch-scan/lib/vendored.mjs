// VENDORED COPY of ~/Github/agent-os/skills/launch-check/scripts/lib/vendored.mjs, copied 2026-09-07.
/**
 * Vendored from pbakaus/impeccable via ~/.claude/skills/ai-design-slop/scripts/detector/.
 * Apache-2.0. See ../NOTICE.md for provenance, license and the security audit.
 *
 * Three modules, copied because they are the only design-agnostic machinery in
 * that detector: the file walker + import graph, and the inline-ignore parser.
 * Adapted for launch-check:
 *   - directive token renamed impeccable-disable -> launch-check-disable
 *   - SCANNABLE_EXTENSIONS widened to config/data files a launch scan needs
 *   - buildImportGraph made fault-tolerant (upstream readFileSync could throw)
 *   - findings hydration takes the registry as an argument instead of importing it
 */

import fs from 'node:fs';
import path from 'node:path';

// ---------------------------------------------------------------------------
// File walker
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  'node_modules', 'dist', 'build', 'out', 'coverage', '__pycache__',
  'public', 'static', 'vendor',
  // Not authored source: scraped mirrors, frozen copies, generated snapshots.
  // obermatt-org keeps a full mirror of the old site under migration/mirror/,
  // which produced 35,184 dead-href findings before this line existed.
  'mirror', 'mirrors', 'snapshot', 'snapshots', 'legacy', 'archive', '_archive', 'fixtures',
]);

const HIDDEN_SOURCE_DIRS = new Set(['.vitepress', '.vuepress', '.storybook', '.github']);

const SCANNABLE_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.vue', '.svelte', '.astro',
  '.html', '.htm', '.json', '.sql', '.env', '.yml', '.yaml',
]);

// Paths whose findings are almost always intentional. Kept separate from
// SKIP_DIRS because a rule may explicitly want to look here.
const TEST_PATH_RE = /(^|[/\\])(__tests__|__mocks__|test|tests|e2e|cypress|playwright|fixtures?|mocks?|stories)([/\\]|$)|\.(test|spec|stories)\.[jt]sx?$/i;

function hasScannableExtension(filename) {
  return SCANNABLE_EXTENSIONS.has(path.extname(filename.toLowerCase()));
}

function walkDir(dir, depth = 0) {
  const files = [];
  if (depth > 12) return files;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return files; }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    if (entry.isDirectory() && entry.name.startsWith('.') && !HIDDEN_SOURCE_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...walkDir(full, depth + 1));
    else if (hasScannableExtension(entry.name) || entry.name.startsWith('.env')) files.push(full);
  }
  return files;
}

// ---------------------------------------------------------------------------
// Import graph — powers orphan-file detection (catalog family 5)
// ---------------------------------------------------------------------------

const IMPORT_SPECIFIER_PATTERNS = [
  /import\s+(?:[\s\S]*?from\s+)?['"]([^'"]+)['"]/g,
  /require\(\s*['"]([^'"]+)['"]\s*\)/g,
  /import\(\s*['"]([^'"]+)['"]\s*\)/g,
  /export\s+(?:[\s\S]*?from\s+)?['"]([^'"]+)['"]/g,
];

const RESOLVE_EXTS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro'];

function resolveImport(specifier, fromDir, fileSet, aliases) {
  let spec = specifier;
  // tsconfig-style path aliases, most commonly "@/..." -> src/ or repo root.
  if (aliases) {
    for (const [prefix, targets] of aliases) {
      if (!spec.startsWith(prefix)) continue;
      const rest = spec.slice(prefix.length);
      for (const target of targets) {
        // path.join, never string concatenation: path.resolve strips the
        // trailing slash off the alias target, so "src" + "components/x"
        // silently becomes "srccomponents/x" and every aliased import fails
        // to resolve. That produced 98 wrong orphan findings on the first run.
        const hit = resolveConcrete(path.join(target, rest), fileSet);
        if (hit) return hit;
      }
    }
  }
  if (!/^[./]/.test(spec)) return null; // bare specifier = a package, not a repo file
  return resolveConcrete(path.resolve(fromDir, spec), fileSet);
}

function resolveConcrete(base, fileSet) {
  if (fileSet.has(base)) return base;
  for (const ext of RESOLVE_EXTS) {
    if (fileSet.has(base + ext)) return base + ext;
  }
  for (const ext of RESOLVE_EXTS) {
    const idx = path.join(base, 'index' + ext);
    if (fileSet.has(idx)) return idx;
  }
  return null;
}

function buildImportGraph(files, aliases) {
  const fileSet = new Set(files);
  const graph = new Map();
  for (const file of files) {
    let content;
    try { content = fs.readFileSync(file, 'utf-8'); } catch { graph.set(file, new Set()); continue; }
    const dir = path.dirname(file);
    const imports = new Set();
    for (const pattern of IMPORT_SPECIFIER_PATTERNS) {
      pattern.lastIndex = 0;
      for (const match of content.matchAll(pattern)) {
        const resolved = resolveImport(match[1], dir, fileSet, aliases);
        if (resolved && resolved !== file) imports.add(resolved);
      }
    }
    graph.set(file, imports);
  }
  return graph;
}

// ---------------------------------------------------------------------------
// Inline ignore directives — launch-check-disable[-line|-next-line] <rule>...
// ---------------------------------------------------------------------------

const DIRECTIVE_RE = /launch-check-(disable-next-line|disable-line|disable)\b[ \t]*([^\n\r]*)/gi;
const TRAILING_CLOSER_RE = /\s*(?:\*\/\}?|--+>|\*\}|#\}|%>|\}\})\s*$/;

function normalizeRule(token) {
  return String(token || '').trim().toLowerCase();
}

function parseRuleList(remainder) {
  let text = String(remainder || '').replace(TRAILING_CLOSER_RE, '').trim();
  const reasonSep = text.match(/\s*(?:--+|:)\s*/);
  if (reasonSep) text = text.slice(0, reasonSep.index);
  const tokens = text.split(/[\s,]+/).map(normalizeRule).filter(Boolean);
  if (tokens.length === 0 || tokens.includes('*')) return ['*'];
  return tokens;
}

function getSet(map, key) {
  let set = map.get(key);
  if (!set) { set = new Set(); map.set(key, set); }
  return set;
}

function parseInlineIgnores(content) {
  const result = { file: new Set(), line: new Map(), nextLine: new Map() };
  const text = typeof content === 'string' ? content : '';
  if (!/launch-check-disable/i.test(text)) return result;
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    DIRECTIVE_RE.lastIndex = 0;
    let m;
    while ((m = DIRECTIVE_RE.exec(lines[i])) !== null) {
      const variant = m[1].toLowerCase();
      const rules = parseRuleList(m[2]);
      if (variant === 'disable') for (const r of rules) result.file.add(r);
      else if (variant === 'disable-line') for (const r of rules) getSet(result.line, i + 1).add(r);
      else for (const r of rules) getSet(result.nextLine, i + 2).add(r);
    }
  }
  return result;
}

function setMatches(set, rule) {
  return Boolean(set) && (set.has('*') || set.has(rule));
}

function hasDirectives(d) {
  return d.file.size > 0 || d.line.size > 0 || d.nextLine.size > 0;
}

function applyInlineIgnores(findings, content) {
  if (!Array.isArray(findings) || findings.length === 0) return findings;
  const d = parseInlineIgnores(content);
  if (!hasDirectives(d)) return findings;
  return findings.filter((f) => {
    const rule = normalizeRule(f && f.rule);
    if (!rule) return true;
    if (setMatches(d.file, rule)) return false;
    const line = Number(f && f.line) || 0;
    if (line > 0 && (setMatches(d.line.get(line), rule) || setMatches(d.nextLine.get(line), rule))) return false;
    return true;
  });
}

// ---------------------------------------------------------------------------
// Finding hydration — a rule id plus a location becomes a full record
// ---------------------------------------------------------------------------

function makeFinding(registry, id, file, line, snippet) {
  const meta = registry[id] || {};
  return {
    rule: id,
    catalog: meta.catalog || null,
    name: meta.name || id,
    family: meta.family || 'unknown',
    severity: meta.severity || 'advisory',
    why: meta.why || '',
    owner: meta.owner || 'launch-check',
    file,
    line: line || 0,
    snippet: (snippet || '').trim().slice(0, 200),
  };
}

export {
  SKIP_DIRS,
  SCANNABLE_EXTENSIONS,
  TEST_PATH_RE,
  hasScannableExtension,
  walkDir,
  resolveImport,
  buildImportGraph,
  parseInlineIgnores,
  applyInlineIgnores,
  makeFinding,
};
