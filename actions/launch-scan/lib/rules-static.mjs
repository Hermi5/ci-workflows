// VENDORED COPY of ~/Github/agent-os/skills/launch-check/scripts/lib/rules-static.mjs, copied 2026-09-07.
/**
 * launch-check static rules — the seven catalog families.
 *
 * Every rule carries its own metadata so there is one place to read and one
 * place to edit. Deliberately narrow: this file covers ONLY the "does the code
 * merely look finished" class. Security and data-correctness signatures live in
 * rules-backend.mjs, which executes what backend-review already documents.
 *
 * Rule shape:
 *   id        kebab-case, stable, used by launch-check-disable directives
 *   catalog   <family>.<item>, matches references/vibecode-catalog.md
 *   severity  blocker | should-fix | advisory
 *   include   RegExp on the file path; the rule only runs on matches
 *   pattern   RegExp with /g; each match is one finding
 *   skipTests true (default) drops matches under test/fixture/story paths
 *   fp        the false-positive profile, printed with --explain
 *
 * A rule with no honest false-positive profile is not finished. If a signature
 * cannot be written without unacceptable noise, the catalog entry says NONE and
 * there is no rule here. That is a real answer.
 */

const CODE = /\.(jsx?|tsx?|mjs|cjs|vue|svelte|astro)$/i;
const JSXISH = /\.(jsx|tsx|vue|svelte|astro|html?)$/i;

/**
 * True when the file's FIRST statement is the "use server" directive.
 *
 * Written as a linear scan, not a regex, deliberately. The regex form
 * `/^(?:\s*\/\/[^\n]*\n|\s*\/\*[\s\S]*?\*\/\s*|\s)*['"]use server['"]/` has
 * nested quantifiers and backtracks catastrophically: it hung a real repo scan
 * for over eight minutes before this replaced it. Any prologue matcher needs
 * bounded, single-pass behaviour.
 */
function hasUseServerPrologue(text) {
  const n = Math.min(text.length, 4000);
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ';') { i++; continue; }
    if (c === '/' && text[i + 1] === '/') {
      const nl = text.indexOf('\n', i);
      if (nl === -1) return false;
      i = nl + 1; continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      if (end === -1) return false;
      i = end + 2; continue;
    }
    break;
  }
  return /^['"]use server['"]/.test(text.slice(i, i + 16));
}

export const STATIC_RULES = [
  // -------------------------------------------------------------------------
  // Family 1 — Looks done, is not wired
  // -------------------------------------------------------------------------
  {
    id: 'form-no-handler',
    catalog: '1.1',
    family: 'wired',
    name: 'Form with nowhere to go',
    severity: 'blocker',
    why: 'The form renders and validates and submits into nothing. Users believe they contacted you.',
    include: JSXISH,
    pattern: /<form\b(?![^>]{0,500}?\b(?:action|onSubmit|onsubmit|method|handleSubmit)\s*=)[^>]{0,500}?>/gi,
    fp: 'Fires on a form whose handler is attached later by a ref or a library hook such as react-hook-form used without onSubmit on the element. Check the component before reporting.',
  },
  {
    id: 'empty-handler',
    catalog: '1.2',
    family: 'wired',
    name: 'Handler with an empty body',
    severity: 'blocker',
    why: 'The control looks interactive and does nothing at all when used.',
    include: JSXISH,
    pattern: /\bon[A-Z]\w+\s*=\s*\{\s*(?:async\s*)?\(\s*[^)]{0,60}\)\s*=>\s*\{\s*(?:\/\/[^\n]*|\/\*[\s\S]{0,200}?\*\/)?\s*\}\s*\}/g,
    fp: 'A deliberately empty handler used to swallow an event, for example stopping propagation on a wrapper. Rare, and usually written with a comment saying so.',
  },
  {
    id: 'handler-only-logs',
    catalog: '1.3',
    family: 'wired',
    name: 'Handler that only logs',
    severity: 'blocker',
    why: 'A console.log stands in for the real action. Ships as a dead button.',
    include: JSXISH,
    pattern: /\bon[A-Z]\w+\s*=\s*\{\s*(?:async\s*)?\(\s*[^)]{0,60}\)\s*=>\s*\{?\s*console\.\w+\([^)]{0,120}\)\s*;?\s*\}?\s*\}/g,
    fp: 'Almost none. A logging-only handler in shipped code is the finding.',
  },
  {
    id: 'submit-preventdefault-only',
    catalog: '1.4',
    family: 'wired',
    name: 'Submit handler that only calls preventDefault',
    severity: 'blocker',
    why: 'The form stops the browser from submitting and then does nothing with the data.',
    include: JSXISH,
    pattern: /onSubmit\s*=\s*\{\s*(?:async\s*)?\(?\s*(\w+)\s*\)?\s*=>\s*\{?\s*\1\.preventDefault\(\)\s*;?\s*\}?\s*\}/g,
    fp: 'None worth noting. If real work follows, the body is longer and this does not match.',
  },
  {
    id: 'dead-href',
    catalog: '1.5',
    family: 'wired',
    name: 'Link that goes nowhere',
    severity: 'should-fix',
    why: 'href="#" is the default placeholder. On a nav item or a CTA it is a dead end that also fails keyboard and screen-reader expectations.',
    include: JSXISH,
    pattern: /\bhref\s*=\s*["'](?:#|javascript:\s*void\s*\(\s*0\s*\))["']/g,
    fp: 'Legitimate on a control that is genuinely a button styled as a link, and on skip-links using a real fragment target. A bare "#" is still the wrong element choice.',
  },
  {
    id: 'placeholder-alert',
    catalog: '1.6',
    family: 'wired',
    name: 'alert() standing in for the feature',
    severity: 'blocker',
    why: 'A browser alert is the model\'s placeholder for a real flow. It is never the intended shipped behaviour.',
    include: CODE,
    pattern: /\balert\s*\(\s*["'`]/g,
    fp: 'Some genuinely simple internal tools use alert. On a client site it is a finding.',
  },
  {
    id: 'empty-named-handler',
    catalog: '1.8',
    family: 'wired',
    name: 'Named handler with an empty body',
    severity: 'blocker',
    why: 'The same dead control as 1.2, in the form that actually dominates generated code: the handler is a named function declared above and its body is empty.',
    include: JSXISH,
    // The inline-arrow rules miss `onClick={handleSubmit}` where handleSubmit is
    // an empty declaration. That is the majority form, so matching only inline
    // arrows leaves most of the family undetected.
    pattern: /(?:const|function)\s+(?:handle|on)[A-Z]\w*\s*(?:=\s*(?:async\s*)?\([^)]{0,60}\)\s*(?::[^=]{0,60})?=>|\([^)]{0,60}\))\s*\{\s*(?:\/\/[^\n]*|\/\*[\s\S]{0,200}?\*\/)?\s*\}/g,
    fp: 'A handler genuinely meant to absorb an event. Confirm the control it is bound to is supposed to do something.',
  },
  {
    id: 'trivial-export',
    catalog: '1.7',
    family: 'wired',
    name: 'Exported function that only returns a literal',
    severity: 'advisory',
    why: 'A stub left where real work was planned. Often an API helper returning hardcoded rows.',
    include: CODE,
    pattern: /export\s+(?:async\s+)?function\s+\w+\s*\([^)]{0,120}\)[^{]{0,80}\{\s*return\s+(?:\[[\s\S]{0,300}?\]|\{[\s\S]{0,300}?\}|true|false|null)\s*;?\s*\}/g,
    fp: 'High. Constant factories, default-config getters and feature-flag stubs all look identical. Advisory by design, never a blocker on its own.',
  },

  // -------------------------------------------------------------------------
  // Family 2 — Placeholder and fake content
  // -------------------------------------------------------------------------
  {
    id: 'lorem-ipsum',
    catalog: '2.1',
    family: 'placeholder',
    name: 'Lorem ipsum',
    severity: 'blocker',
    why: 'Placeholder copy visible to users, and indexable by search engines.',
    include: /\.(jsx?|tsx?|mjs|vue|svelte|astro|html?|json|md)$/i,
    pattern: /\blorem\s+ipsum\b/gi,
    fp: 'None, outside a fixture or a design-system demo page.',
  },
  {
    id: 'placeholder-credential',
    catalog: '2.2',
    family: 'placeholder',
    name: 'Placeholder credential left in place',
    severity: 'blocker',
    why: 'The integration cannot work. Worse, it usually fails silently rather than erroring.',
    include: /\.(jsx?|tsx?|mjs|cjs|json|ya?ml|env.*)$/i,
    pattern: /\b(?:your[-_ ]?(?:api[-_ ]?)?(?:key|token|secret)|YOUR_API_KEY|REPLACE_ME|CHANGE_?ME|<your[- ][^>]{0,40}>|sk_test_your|xxxxx+)\b/gi,
    fp: 'Legitimate inside .env.example and documentation, which is exactly where it belongs. Those paths are excluded.',
    excludePath: /\.env\.example$|\.env\.sample$|README|\.md$|docs?[/\\]/i,
  },
  {
    id: 'example-domain',
    catalog: '2.3',
    family: 'placeholder',
    name: 'Example domain in shipped code',
    severity: 'should-fix',
    why: 'example.com in a link, a canonical tag or an email address means the real value was never filled in.',
    include: /\.(jsx?|tsx?|mjs|vue|svelte|astro|html?|json)$/i,
    pattern: /\b(?:example\.(?:com|org|net)|yourdomain\.com|yoursite\.com|mysite\.com)\b/gi,
    fp: 'Genuinely correct in RFC-style documentation examples and in schema.org sample markup. Check the surrounding line.',
  },
  {
    id: 'placeholder-contact',
    catalog: '2.4',
    family: 'placeholder',
    name: 'Placeholder contact details',
    severity: 'should-fix',
    why: 'A 555 number or a test@ address on a live contact page loses every enquiry sent to it.',
    include: /\.(jsx?|tsx?|mjs|vue|svelte|astro|html?|json)$/i,
    pattern: /\b(?:\+?1?[-.\s]?\(?555\)?[-.\s]?\d{3}[-.\s]?\d{4}|123[-.\s]?456[-.\s]?7890|(?:test|foo|bar|john\.?doe|jane\.?doe)@(?:test|example|foo|bar)\.\w{2,})\b/gi,
    fp: 'The 555 range is reserved for fiction precisely so it is safe in examples, so it is a strong signal, not a certain one.',
  },
  {
    id: 'placeholder-image',
    catalog: '2.5',
    family: 'placeholder',
    name: 'Placeholder image service',
    severity: 'should-fix',
    why: 'A grey box or a random stock photo where the real asset belongs, served from a third party you do not control.',
    include: /\.(jsx?|tsx?|mjs|vue|svelte|astro|html?|json|css|scss)$/i,
    pattern: /\b(?:placehold\.(?:it|co)|placeholder\.com|via\.placeholder|picsum\.photos|unsplash\.it|dummyimage\.com|loremflickr)\b/gi,
    fp: 'Deliberate in a prototype or a storybook story. Those paths are skipped.',
  },
  {
    id: 'todo-marker',
    catalog: '2.6',
    family: 'placeholder',
    name: 'TODO on a shipped path',
    severity: 'advisory',
    why: 'Not a defect by itself, but a reliable index of where the work stopped. Read them before shipping.',
    include: CODE,
    pattern: /\b(?:TODO|FIXME|XXX|HACK)\b\s*[:(\-]/g,
    fp: 'Very high as a defect signal and that is fine. This rule exists to produce a reading list, which is why it is advisory.',
  },

  // -------------------------------------------------------------------------
  // Family 3 — Suppressions and silenced failure
  // -------------------------------------------------------------------------
  {
    id: 'next-ignore-build-errors',
    catalog: '3.1',
    family: 'suppression',
    name: 'TypeScript errors ignored at build',
    severity: 'blocker',
    why: 'The build is green because checking was switched off. Every type error in the repo ships. This is the purest form of looking finished.',
    include: /next\.config\.(m?[jt]s|cjs)$/i,
    pattern: /ignoreBuildErrors\s*:\s*true/g,
    fp: 'None. If it is deliberate it needs a stated reason and a launch-check-disable directive.',
    skipTests: false,
  },
  {
    id: 'next-ignore-eslint',
    catalog: '3.2',
    family: 'suppression',
    name: 'ESLint ignored at build',
    severity: 'should-fix',
    why: 'Lint findings, including the accessibility and hooks rules, never block anything again.',
    include: /next\.config\.(m?[jt]s|cjs)$/i,
    pattern: /ignoreDuringBuilds\s*:\s*true/g,
    fp: 'Sometimes set deliberately while migrating a legacy config. Needs a reason.',
    skipTests: false,
  },
  {
    id: 'ts-strict-off',
    catalog: '3.3',
    family: 'suppression',
    name: 'TypeScript strict mode off',
    severity: 'should-fix',
    why: 'Without strict, null and undefined stop being tracked, which is where most runtime crashes come from.',
    include: /tsconfig(\.\w+)?\.json$/i,
    pattern: /"strict"\s*:\s*false/g,
    fp: 'Expected in a repo mid-migration from JavaScript. Note it rather than block on it there.',
    skipTests: false,
  },
  {
    id: 'ts-suppression',
    catalog: '3.4',
    family: 'suppression',
    name: '@ts-ignore or @ts-nocheck',
    severity: 'should-fix',
    why: 'Silences a real type error at exactly the point the model could not make the types work. @ts-expect-error is the honest version because it fails when the error goes away.',
    include: CODE,
    pattern: /@ts-(?:ignore|nocheck)\b/g,
    fp: 'Occasionally unavoidable against a badly typed dependency. Each one should carry a reason on the same line.',
  },
  {
    id: 'explicit-any',
    catalog: '3.5',
    family: 'suppression',
    name: 'Explicit any',
    severity: 'advisory',
    why: 'A census, not an accusation. A sharp cluster of any in one module usually marks the part the model could not reason about.',
    include: /\.tsx?$/i,
    pattern: /(?::\s*any\b|\bas\s+any\b|<any>)/g,
    fp: 'Legitimate at genuine dynamic boundaries. Read the distribution, not the total.',
  },
  {
    id: 'test-only',
    catalog: '3.6',
    family: 'suppression',
    name: '.only left in a test',
    severity: 'blocker',
    why: 'Every other test in that file silently stops running. The suite still reports green.',
    include: CODE,
    pattern: /\b(?:describe|it|test|context)\.only\s*\(/g,
    fp: 'None. This is always a mistake in committed code.',
    skipTests: false,
  },
  {
    id: 'test-skip',
    catalog: '3.7',
    family: 'suppression',
    name: '.skip left in a test',
    severity: 'advisory',
    why: 'A disabled test reads as coverage in the count while asserting nothing.',
    include: CODE,
    pattern: /\b(?:describe|it|test|context)\.skip\s*\(/g,
    fp: 'Often deliberate and reasonable. Advisory so it surfaces without nagging.',
    skipTests: false,
  },

  // -------------------------------------------------------------------------
  // Family 4 — Environment and config drift
  // -------------------------------------------------------------------------
  {
    id: 'hardcoded-localhost',
    catalog: '4.1',
    family: 'config',
    name: 'Hardcoded localhost URL',
    severity: 'blocker',
    why: 'Works perfectly on the developer machine and is unreachable for every real user.',
    include: CODE,
    pattern: /["'`]https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^"'`]*["'`]/g,
    fp: 'Correct inside dev-only branches, test setup, and config that already reads NODE_ENV. Test paths are skipped; check for an env guard on the remaining hits.',
  },
  {
    id: 'env-fallback-secret',
    catalog: '4.2',
    family: 'config',
    name: 'Env var with a hardcoded fallback',
    severity: 'should-fix',
    why: 'process.env.X || "some-value" means a missing variable in production silently uses the fallback instead of failing loudly.',
    include: CODE,
    pattern: /process\.env\.\w+\s*(?:\|\||\?\?)\s*["'`][^"'`]{3,}["'`]/g,
    fp: 'Fine for genuinely optional settings with a sensible default, such as a port or a log level. Never fine for a URL, a key or a secret.',
  },

  // -------------------------------------------------------------------------
  // Family 6 — Crash containment
  // (Family 5 and the repo-level parts of 6 and 7 are computed in probes.mjs,
  //  because they need the whole tree rather than one file at a time.)
  // -------------------------------------------------------------------------
  {
    id: 'empty-catch',
    catalog: '6.4',
    family: 'crash',
    name: 'Swallowed error',
    severity: 'should-fix',
    why: 'The failure happens, nothing is recorded, and the code carries on with wrong state.',
    include: CODE,
    pattern: /catch\s*(?:\([^)]{0,40}\))?\s*\{\s*\}/g,
    fp: 'Deliberate when an optional operation is genuinely allowed to fail, which should be written as a comment inside the block rather than an empty one.',
    owner: 'backend-review: correctness-05-observability-and-testing.md',
  },

  // -------------------------------------------------------------------------
  // Family 7 — Client/server boundary confusion
  // -------------------------------------------------------------------------
  {
    id: 'hydration-nondeterminism',
    catalog: '6.5',
    family: 'crash',
    name: 'Non-deterministic value in a render path',
    severity: 'should-fix',
    why: 'Server and client compute different values, so React discards the mismatched subtree. It warns in development and blanks the section in production, which is why it survives to launch.',
    include: /\.(jsx|tsx)$/i,
    pattern: /\bMath\.random\s*\(\s*\)/g,
    fp: 'Fine inside an event handler, an effect, or a seeded generator that runs only on the client. It is never fine in the body of a component that also renders on the server, and using it for a React key is a separate bug.',
  },
  {
    id: 'server-action-no-revalidate',
    catalog: '7.3',
    family: 'boundary',
    name: 'Server action mutates without revalidating',
    severity: 'should-fix',
    why: 'The write succeeds and the user still sees the old data, because nothing told Next.js the cache is stale. Reads as "the save button does nothing", which is indistinguishable from an unwired button to the person using it.',
    kind: 'fileAbsence',
    include: /\.(m?ts|tsx)$/i,
    requirePresent: /['"]use server['"][\s\S]{0,4000}?\b(?:insert|update|delete|upsert)\s*\(/i,
    requireAlsoPresent: /revalidatePath|revalidateTag|router\.refresh|redirect\s*\(|revalidate/,
    fp: 'A mutation whose result is returned straight to an optimistic client update may not need revalidation. Most do.',
  },
  {
    id: 'use-server-non-async-export',
    catalog: '7.4',
    family: 'boundary',
    name: 'Non-async export from a "use server" file',
    severity: 'blocker',
    why: 'A "use server" file may export only async functions. A non-async value export, or a type RE-export that survives erasure, compiles, lints, builds and tests green, then returns a 500 from every server action in the file at runtime.',
    include: /\.(m?ts|tsx)$/i,
    // Two corrections, both forced by ground truth rather than by reasoning.
    //
    // 1. `export const submit = async () => {}` is the CORRECT idiom. The
    //    negative lookahead must sit immediately after `=` and swallow the
    //    whitespace itself: written as `=\s*(?!async\b)` the `\s*` backtracks to
    //    zero width, the lookahead then tests a space rather than the keyword,
    //    and the correct form gets flagged.
    // 2. A local `export type Foo = {...}` or `export interface` is ERASED by
    //    TypeScript and never reaches the runtime. Flagging those produced 36
    //    findings in Obermatt-V5, which is live and working, so they cannot be
    //    the defect. Only a type RE-export (`export type { X } from './y'`),
    //    which can emit a runtime binding, belongs here. That re-export is the
    //    form behind the real incident this rule exists for.
    pattern: /export\s+type\s*\{[^}]*\}\s*from|export\s+(?:const|let|var)\s+\w+\s*(?::[^=\n]{0,80})?=(?!\s*async\b)/g,
    // Must match the directive PROLOGUE, not the string anywhere in the file.
    // Obermatt-V5's mobile/src/lib/money/engine.ts opens with a comment reading
    // `NO "use server" (exports non-async consts/types)` — a file documenting why
    // it omits the directive was flagged for the exact defect it was avoiding.
    fileRequireFn: hasUseServerPrologue,
    fp: 'Only applies to a file whose first statement is the "use server" directive. Inside one there is no benign case: the framework rejects non-async exports at runtime.',
  },
  {
    id: 'useeffect-fetch',
    catalog: '7.2',
    family: 'boundary',
    name: 'Data fetched in useEffect',
    severity: 'advisory',
    why: 'In the App Router this usually means a server component was turned into a client component to fetch data that could have been fetched on the server. Costs a render pass, a loading state, and often a waterfall.',
    include: /\.(jsx|tsx)$/i,
    pattern: /useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[\s\S]{0,400}?\b(?:fetch|axios)\s*\(/g,
    fp: 'Correct for data that genuinely depends on client state or must poll. Advisory for that reason.',
  },
];

export const RULE_REGISTRY = Object.fromEntries(
  STATIC_RULES.map((r) => [r.id, r])
);
