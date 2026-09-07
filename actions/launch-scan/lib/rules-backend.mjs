// VENDORED COPY of ~/Github/agent-os/skills/launch-check/scripts/lib/rules-backend.mjs, copied 2026-09-07.
/**
 * backend-review's documented detection, made executable.
 *
 * backend-review carries roughly 90 detection commands across ten "How to
 * detect" sections. They are good patterns and they have never been runnable as
 * written: 64 of them invoke `rg` and one invokes `fd`, and neither binary
 * exists on this machine (`spawnSync('rg')` returns ENOENT; ripgrep is only a
 * Claude Code shell function). So the knowledge was there and the gate was not.
 *
 * This file translates them into dependency-free Node regex. It adds NO new
 * knowledge. Every rule cites the backend-review file that owns it, and every
 * finding routes the reader there rather than restating the guidance.
 *
 * NOT translated, and why:
 *   - patterns needing surrounding context (`rg -A4`, `rg -B1 -A4`) — a line
 *     regex cannot express "this within four lines of that" reliably enough
 *   - `xargs` pipelines expressing "files matching X that do NOT match Y" —
 *     these are implemented as fileAbsence rules below instead
 *   - live database introspection (the RLS policy SQL in security-02) — needs a
 *     connection, which a static scanner must not open
 *   - `ls drizzle/`, `fd -e test.ts | wc -l` — inventory, not detection; these
 *     are reported by probes.mjs as counts
 *
 * Severity follows backend-review's own P-scale: P0 -> blocker, P1 -> should-fix,
 * P2/P3 -> advisory. Its severities are explicitly scope-relative (IDOR is P0
 * multi-tenant and near-N/A single-user), so these are a starting position for
 * the adjudication pass, never a verdict.
 */

const TS = /\.tsx?$/i;
const CODE = /\.(m?[jt]sx?|cjs)$/i;
const SQL = /\.sql$/i;

const F = {
  c01: 'backend-review: correctness-01-data-modeling-and-migrations.md',
  c02: 'backend-review: correctness-02-database-performance-and-transactions.md',
  c03: 'backend-review: correctness-03-money-and-numeric-correctness.md',
  c04: 'backend-review: correctness-04-reliability-idempotency-and-jobs.md',
  c05: 'backend-review: correctness-05-observability-and-testing.md',
  s01: 'backend-review: security-01-authorization-and-idor.md',
  s02: 'backend-review: security-02-auth-sessions-and-rls.md',
  s03: 'backend-review: security-03-nextjs-server-actions-and-data.md',
  s04: 'backend-review: security-04-rate-limiting-and-search.md',
  s05: 'backend-review: security-05-web-security-baseline.md',
  s06: 'backend-review: security-06-ai-and-llm-features.md',
};

export const BACKEND_RULES = [
  // --- correctness-01: migrations -------------------------------------------
  { id: 'br-db-push', family: 'migrations', owner: F.c01, severity: 'blocker',
    name: 'drizzle-kit push present',
    why: 'Named in backend-review as the number one vibecoder migration disaster: a renamed column silently becomes DROP then ADD.',
    include: /package\.json$|\.ya?ml$|\.sh$/i, pattern: /drizzle-kit\s+push|["']db:push["']/g,
    fp: 'A push script scoped to a local dev database only. Read the script body.', skipTests: false },
  { id: 'br-destructive-migration', family: 'migrations', owner: F.c01, severity: 'should-fix',
    name: 'Destructive SQL in migration history',
    why: 'Drizzle migrations are forward-only with no down. Destructive statements need a verified backup first.',
    include: SQL, pattern: /\b(?:DROP\s+COLUMN|DROP\s+TABLE|ALTER\s+COLUMN\s+\w+\s+TYPE|RENAME\s+COLUMN|TRUNCATE|DELETE\s+FROM)\b/gi,
    // Not a blocker, because a static scan cannot tell an already-applied
    // migration from a pending one, and applied history is history. The pending
    // ones are the risk. Check `git status` on the migrations directory.
    fp: 'An expand-contract contract step is a legitimate DROP, and a data-cleanup DELETE inside a seed migration is routine. The question is whether the statement is PENDING and whether a backup exists.', skipTests: false },
  { id: 'br-volatile-default', family: 'migrations', owner: F.c01, severity: 'should-fix',
    name: 'Volatile default added to an existing table',
    why: 'DEFAULT gen_random_uuid() or now() on ALTER TABLE rewrites every row under ACCESS EXCLUSIVE.',
    include: SQL,
    // Only the ALTER path rewrites. The rule's own note said so while the
    // pattern matched CREATE TABLE too, which produced ten wrong findings on
    // the first real run. ADD COLUMN must appear on the same statement.
    pattern: /ALTER\s+TABLE[\s\S]{0,200}?ADD\s+COLUMN[\s\S]{0,120}?DEFAULT\s+(?:gen_random_uuid|now|uuid_generate\w*|clock_timestamp)\s*\(/gi,
    fp: 'Postgres 11 and later can add a column with a CONSTANT default without a rewrite. Volatile defaults still rewrite.', skipTests: false },
  { id: 'br-blocking-index', family: 'migrations', owner: F.c01, severity: 'advisory',
    name: 'Index built without CONCURRENTLY',
    why: 'Blocks writes for the duration on a live table.',
    include: SQL, pattern: /CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)/gi,
    // A migration that creates the table in the same file is building an index
    // on an empty table, where the lock is instant and meaningless.
    fileReject: /CREATE\s+TABLE/i,
    fp: 'Fine on an empty or brand-new table, which is why same-file CREATE TABLE suppresses it. Note that CONCURRENTLY cannot run inside a transaction and Drizzle wraps migrations in one.', skipTests: false },

  // --- correctness-02: performance and races --------------------------------
  { id: 'br-js-arithmetic-on-balance', family: 'races', owner: F.c02, severity: 'blocker',
    name: 'Read-modify-write arithmetic in JavaScript',
    why: 'The classic lost update. Two concurrent requests both read, both add, one result survives. Compute in SQL instead.',
    include: TS,
    // Deliberately TIGHTER than backend-review's documented pattern, which is
    // `(balance|amount|count|stock|quantity)\s*[-+]\s`. That version matched CSS
    // class names and string literals ("stock-photo", "credit-card") on the
    // first real run. This targets the actual lost-update signature instead:
    // self-referential assignment, x = x + n or x += n.
    pattern: /\b(\w*(?:balance|amount|count|stock|quantity|credits?|total))\s*=\s*\1\s*[-+]\s|\b\w*(?:balance|amount|count|stock|quantity|credits?)\s*[-+]=\s/gi,
    fp: 'Fires on legitimate local accumulators in a loop. The question is whether the starting value came from a database read and the result goes back to a write.' },
  { id: 'br-n-plus-one', family: 'performance', owner: F.c02, severity: 'should-fix',
    name: 'Query inside a loop',
    why: 'One query per row. Fine at ten rows, fatal at ten thousand.',
    include: TS, pattern: /(?:for\s*\([^)]{0,120}\)\s*\{[\s\S]{0,200}?await\s+db\.|\.map\s*\(\s*async[\s\S]{0,200}?\bdb\.)/g,
    fp: 'A bounded loop over a handful of known ids is acceptable. Check the collection size.' },
  { id: 'br-offset-pagination', family: 'performance', owner: F.c02, severity: 'should-fix',
    name: 'OFFSET pagination',
    why: 'OFFSET is O(n) and ?page=9999999 becomes a denial-of-service vector. Keyset pagination instead.',
    include: TS, pattern: /\.offset\s*\(|\bOFFSET\s+\$?\d/gi,
    fp: 'Acceptable on a small, bounded, authenticated list.' },
  { id: 'br-bare-select', family: 'performance', owner: F.c02, severity: 'advisory',
    name: 'Bare select() selects every column',
    why: 'Pulls columns you did not intend to expose and defeats covering indexes. Also the read-side of mass assignment.',
    include: TS, pattern: /\.select\s*\(\s*\)/g,
    fp: 'Fine when the row genuinely is the payload and it holds nothing sensitive.' },

  // --- correctness-03: money ------------------------------------------------
  { id: 'br-float-money-column', family: 'money', owner: F.c03, severity: 'blocker',
    name: 'Float column holding money',
    why: '0.1 plus 0.2 is not 0.3. Money in a float corrupts silently and the drift compounds.',
    include: /schema\w*\.ts$|\.sql$/i, pattern: /\b(?:real|doublePrecision|double\s+precision|float\d*)\s*\(?/gi,
    fp: 'Legitimate for genuinely approximate values such as a latitude or a score. Check the column name.', skipTests: false },
  { id: 'br-parsefloat-money', family: 'money', owner: F.c03, severity: 'blocker',
    name: 'parseFloat or unary plus on a money value',
    why: 'postgres-js returns numeric as a string on purpose. Converting it to a JS number reintroduces exactly the float bug the numeric type prevented.',
    include: TS, pattern: /(?:parseFloat|Number)\s*\(\s*[^)]{0,60}(?:amount|price|total|balance|rate|cents|fee|subtotal)/gi,
    fp: 'Low. Confirm the source column is numeric or an integer minor unit.' },
  { id: 'br-naive-cents', family: 'money', owner: F.c03, severity: 'should-fix',
    name: 'Hardcoded times-100 or divide-by-100',
    why: 'Minor-unit scale is not universally two decimals. JPY has none and KWD has three.',
    include: TS, pattern: /(?:amount|price|total|cents?|balance)\w*\s*[*/]\s*100\b|\b100\s*[*]\s*(?:amount|price|total)/gi,
    fp: 'Correct for a single-currency application that will stay single-currency. Say so explicitly rather than by omission.' },

  // --- correctness-04: idempotency and jobs ---------------------------------
  { id: 'br-webhook-no-dedupe', family: 'idempotency', owner: F.c04, severity: 'blocker',
    name: 'Webhook handler with no dedupe guard',
    why: 'Providers deliver at least once. Without a dedupe key a retry charges the customer twice.',
    kind: 'fileAbsence',
    include: /app[/\\]api[/\\][\s\S]*route\.tsx?$/i,
    requirePresent: /constructEvent|webhook|stripe-signature/i,
    requireAlsoPresent: /onConflict|processed|idempotenc|event\.id|unique/i,
    fp: 'A webhook that is genuinely read-only needs no dedupe. Check whether the handler mutates.' },
  { id: 'br-unauth-cron', family: 'idempotency', owner: F.c04, severity: 'blocker',
    name: 'Cron route with no secret check',
    why: 'A Vercel cron route is a public URL. Without CRON_SECRET verification anyone can trigger the job at will.',
    kind: 'fileAbsence',
    include: /app[/\\]api[/\\]cron[\s\S]*route\.tsx?$/i,
    requirePresent: /./,
    requireAlsoPresent: /CRON_SECRET|authorization|Authorization/,
    fp: 'None. Verify the Bearer token.' },
  { id: 'br-waituntil-critical', family: 'idempotency', owner: F.c04, severity: 'should-fix',
    name: 'waitUntil or after() used for work that must not be lost',
    why: 'Neither is durable. backend-review is explicit that they are never for payments or fulfillment.',
    include: TS, pattern: /\b(?:waitUntil|after)\s*\(/g,
    fp: 'Correct for genuinely best-effort work such as analytics. Read what is inside the callback.' },
  { id: 'br-fixed-retry', family: 'idempotency', owner: F.c04, severity: 'advisory',
    name: 'Fixed-interval retry with no jitter',
    why: 'Synchronised retries from many clients produce a thundering herd against a service that is already struggling.',
    include: TS, pattern: /setTimeout\s*\([^,]{0,60},\s*(?:1000|2000|3000|5000)\s*\)/g,
    fp: 'High. Most setTimeout calls are not retries. Confirm it sits in a retry path.' },

  // --- correctness-05: observability ----------------------------------------
  { id: 'br-log-secret', family: 'observability', owner: F.c05, severity: 'blocker',
    name: 'Logging a secret or PII',
    why: 'Log aggregators retain and replicate. A token in a log line is a leaked token.',
    include: CODE, pattern: /console\.(?:log|error|warn|info|debug)\s*\([^)]{0,160}\b(?:token|secret|password|passwd|apikey|api_key|session|credential|process\.env)\b/gi,
    // Usage banners and CLI help text name the argument without printing a
    // value. Six of the first run's hits on Personal-Portfolio were these.
    rejectLine: /\b[Uu]sage:|<new-password>|<password>|\bhelp\b.*--|process\.argv/,
    fp: 'Logging the NAME of a missing env var, or a CLI usage banner naming an argument, is fine. Logging a value is not. Read the line.' },

  // --- security-01: authorization and IDOR ----------------------------------
  { id: 'br-mass-assignment', family: 'authz', owner: F.s01, severity: 'blocker',
    name: 'Whole request object spread into a write',
    why: 'Over-posting. The caller sets userId, role, isAdmin or price because nothing whitelists the fields.',
    include: TS, pattern: /\.(?:set|values)\s*\(\s*(?:input|body|data|req|formData|payload)\s*\)/g,
    fp: 'Safe if the object was produced by a Zod .strict() parse immediately above. Check the line before.' },
  { id: 'br-as-any-payload', family: 'authz', owner: F.s01, severity: 'should-fix',
    name: 'as any on a request payload',
    why: 'backend-review flags this specifically because it masks an unvalidated payload reaching a write.',
    include: TS, pattern: /\b(?:input|body|data|req|formData|payload)\s+as\s+any\b|\bas\s+any\s*\)\s*(?:\.set|\.values)/g,
    fp: 'Distinct from the general explicit-any census. This one is scoped to write paths.' },
  { id: 'br-getsession-authz', family: 'authz', owner: F.s02, severity: 'blocker',
    name: 'getSession() used server-side',
    why: 'getSession reads the cookie without verifying it. Supabase says never trust it in server code. getUser or getClaims instead.',
    include: CODE, pattern: /\bgetSession\s*\(\s*\)/g,
    fp: 'Acceptable in client code purely for rendering, never for an authorization decision.' },
  { id: 'br-role-in-user-metadata', family: 'authz', owner: F.s01, severity: 'blocker',
    name: 'Authorization off user_metadata',
    why: 'user_metadata is user-editable through updateUser(). A role stored there is a role the user can grant themselves.',
    include: CODE, pattern: /user_metadata/g,
    fp: 'Fine for display preferences. A finding the moment it touches a permission check.' },

  // --- security-02 / 03: secrets and the client boundary --------------------
  { id: 'br-public-secret-name', family: 'secrets', owner: F.s03, severity: 'blocker',
    name: 'Secret-shaped NEXT_PUBLIC_ variable',
    why: 'NEXT_PUBLIC_ is inlined into the browser bundle at build time. The name pattern is usually a typo with a real secret behind it.',
    include: /\.(m?[jt]sx?|cjs|env.*|ya?ml)$/i,
    pattern: /NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|_SK_|SIGNING)[A-Z0-9_]*/g,
    fp: 'Near zero. NEXT_PUBLIC_SUPABASE_ANON_KEY and NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY are correct and do not match this pattern.', skipTests: false },
  { id: 'br-service-role-client', family: 'secrets', owner: F.s02, severity: 'blocker',
    name: 'service_role or DATABASE_URL in a client file',
    why: 'service_role bypasses RLS completely. In a client component it is a full database handout.',
    include: /\.(jsx|tsx)$/i, pattern: /\b(?:service_role|SERVICE_ROLE|SUPABASE_SERVICE|DATABASE_URL)\b/g,
    fp: 'A .tsx file that is server-only still matches. Confirm whether the file or its importers carry "use client".' },
  { id: 'br-sql-raw', family: 'injection', owner: F.s05, severity: 'blocker',
    name: 'sql.raw()',
    why: 'The one place the ORM stops parameterising. Every hit needs reading.',
    include: TS, pattern: /\bsql\s*\.\s*raw\s*\(|\.raw\s*\(\s*`/g,
    fp: 'Safe with a hardcoded string or an allow-listed identifier. Never safe with runtime input.' },
  { id: 'br-dangerous-html', family: 'injection', owner: F.s05, severity: 'blocker',
    name: 'dangerouslySetInnerHTML',
    why: 'Named in backend-review as the primary XSS vector. Sanitise with isomorphic-dompurify, not bare dompurify, which crashes in RSC.',
    include: /\.(jsx|tsx)$/i, pattern: /dangerouslySetInnerHTML/g,
    // Injecting a JSON.stringify'd JSON-LD blob into a ld+json script tag is
    // the standard React way to emit structured data and carries no XSS risk,
    // because the content never renders as HTML.
    fileReject: /application\/ld\+json/i,
    fp: 'Safe with genuinely trusted, build-time content such as compiled MDX, and for JSON-LD, which is excluded. Trace where the value comes from.' },
  { id: 'br-eval', family: 'injection', owner: F.s05, severity: 'blocker',
    name: 'eval or the Function constructor',
    why: 'Arbitrary code execution, and it defeats any Content Security Policy you set.',
    include: CODE, pattern: /\beval\s*\(|new\s+Function\s*\(/g,
    fp: 'Almost none in application code.' },
  { id: 'br-cors-wildcard', family: 'headers', owner: F.s05, severity: 'blocker',
    name: 'Wildcard CORS',
    why: 'Access-Control-Allow-Origin: * on a credentialed endpoint hands the API to any origin. backend-review notes the Next.js docs themselves ship this as a placeholder.',
    include: CODE, pattern: /["']Access-Control-Allow-Origin["']\s*[,:]\s*["']\*["']/g,
    fp: 'Genuinely fine on a public, uncredentialed, read-only endpoint. Rare.' },

  // --- security-04: rate limiting -------------------------------------------
  { id: 'br-wildcard-like', family: 'performance', owner: F.s04, severity: 'should-fix',
    name: 'Leading-wildcard LIKE search',
    why: "LIKE '%term%' cannot use an index and scans the table. Use tsvector full-text search or pg_trgm.",
    include: TS, pattern: /\b(?:like|ilike)\s*\(\s*[^,]{0,60},\s*[`'"]%/gi,
    fp: 'Acceptable on a small, bounded table.' },

  // --- security-06: AI features ---------------------------------------------
  { id: 'br-unbounded-agent', family: 'ai', owner: F.s06, severity: 'should-fix',
    name: 'Model call with no step or token bound',
    why: 'An unbounded agent loop is an unbounded bill, and OWASP LLM10 unbounded consumption.',
    kind: 'fileAbsence',
    include: CODE,
    requirePresent: /\b(?:streamText|generateText|WorkflowAgent)\s*\(/,
    requireAlsoPresent: /stopWhen|stepCountIs|maxOutputTokens|maxSteps/,
    fp: 'A single-shot generateText with no tools does not loop. Check whether tools are passed.' },
  { id: 'br-tool-no-approval', family: 'ai', owner: F.s06, severity: 'should-fix',
    name: 'Model tool that writes without approval',
    why: 'OWASP LLM06 excessive agency. A tool that mutates on the model\'s say-so needs needsApproval or a human step.',
    include: CODE, pattern: /\btool\s*\(\s*\{[\s\S]{0,600}?\b(?:insert|update|delete|drop)\b/gi,
    fp: 'Moderate. Confirm the matched verb is a database write rather than a word in the description.' },
];

export const BACKEND_REGISTRY = Object.fromEntries(BACKEND_RULES.map((r) => [r.id, r]));
