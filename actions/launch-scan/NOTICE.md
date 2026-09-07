# NOTICE — third-party code and security posture

## Vendored code

`lib/vendored.mjs` contains three modules adapted from **impeccable** by Paul Bakaus
(<https://github.com/pbakaus/impeccable>), taken via the copy already vendored in
`~/.claude/skills/ai-design-slop/scripts/detector/` at commit
`251135e1900662ed048dda391211f1895ab42d7e`.

- **License**: Apache-2.0, retained under its terms.
- **Copyright**: (c) 2026 Paul Bakaus.
- **Modules taken**: the file walker and import-graph builder (`node/file-system.mjs`),
  the inline-ignore directive parser (`shared/inline-ignores.mjs`), and the finding
  hydration helper (`findings.mjs`).
- **Why only these three**: they are the only design-agnostic machinery in that
  detector. Its other ~23,000 lines resolve CSS, typography and colour and carry
  zero transfer value for a code-quality scan. There is no plugin surface to
  extend, so this is a copy, not an import.

### Changes from upstream

| Change | Reason |
| --- | --- |
| Directive token `impeccable-disable` renamed to `launch-check-disable` | Two scanners sharing one token would silently waive each other's findings |
| `SCANNABLE_EXTENSIONS` widened to `.json`, `.sql`, `.yml`, `.env*` | A launch scan reads config and migrations, not just source |
| `buildImportGraph` made fault-tolerant | Upstream's `readFileSync` could throw and abort the whole graph |
| Alias resolution added, using `path.join` | tsconfig `paths` support. String concatenation here is a trap: `path.resolve` strips the trailing slash, so `src` + `components/x` becomes `srccomponents/x`. That bug produced 98 wrong orphan findings before it was caught |
| `findings` hydration takes the registry as an argument | Upstream imported a hardcoded registry module |

## Security posture

`ai-design-slop`'s vendored detector declares "no `child_process`, no `eval`, no
filesystem writes, one network call." **launch-check deliberately departs from
that**, and this is the full accounting.

| Behaviour | Present | Detail | How to disable |
| --- | --- | --- | --- |
| `child_process` | **Yes** | `git ls-files`, `npm audit`. Fixed argument lists, never a shell string, never interpolated user input | `--no-shell` |
| Network | **Yes** | HEAD requests to `registry.npmjs.org`, one per declared dependency, to detect hallucinated package names | `--no-network` |
| Filesystem writes | No | Reads only. Never writes to the scanned repo | n/a |
| `eval` / `new Function` | No | It detects these; it does not use them | n/a |
| Environment access | Reads `.env*` files in the scanned repo | Values are compared against build output to find leaked secrets. **Values are never printed** — findings name the variable, not its content | skip the bundle probe with `--only` |
| Builds, migrations, seeds | **Never run** | `backend-review` states the never-auto-run rule three times over. This scanner reports only | n/a |
| Third-party imports | None | Node builtins only. No `package.json`, no `node_modules` | n/a |

### Why truly zero-dependency matters here

`ai-design-slop`'s static-HTML engine wants `htmlparser2`, `css-select`, `css-tree`
and `domutils`. None are installed, so it prints a DEGRADED warning and falls back
to regex **on every single run in this environment**. A degraded path that is
always taken is a dead check wearing a fallback's clothes.

Relatedly, `rg` is **not a binary on this machine** — it exists only as a Claude Code
shell function, and `spawnSync('rg')` returns ENOENT. Nothing here depends on it.
This also means `backend-review`'s 64 documented `rg` detection commands and its one
`fd` command have never been runnable as written, which is why `lib/rules-backend.mjs`
reimplements them in Node regex.

## Calibration

Re-run these after changing any rule. A scanner that cries wolf gets ignored, which
is worse than no scanner.

Measured 2026-08-15, all with `--no-network`:

| Target | Result | Reading |
| --- | --- | --- |
| `Personal-Portfolio` | 81 candidates, 6 blocker | Lights up as expected; it carries two open security memories |
| `Obermatt-V5` | 416 candidates, 61 blocker | Large pnpm monorepo, scans in 0.74s. 56 of the blockers are `Number(t.amount)` across the money module, which is a true positive |
| `obermatt-org` | 28 candidates | Was 35,213 before `mirror` entered SKIP_DIRS |
| `SAK-Industries` · `StellaVie` · `solvena` | 9 to 14 candidates each | The quiet baseline. A working repo should look like this |
| No `package.json`, and no git history | Clean exit with a note | Never a stack trace |
| Two runs, unchanged repo | Byte-identical | Determinism holds |

### Scanning the scanner

Pointing `launch-scan.mjs` at its own directory reports 9 blockers. All nine are the rule definitions matching themselves: `lorem-ipsum` finds the string `lorem ipsum` inside the `lorem-ipsum` rule, `placeholder-credential` finds `YOUR_API_KEY` inside its own pattern, and so on. Expected, harmless, and a useful sanity check that the rules are wired at all. Exclude `~/.claude` when scanning a repo that vendors a detector.

### Known limitations

- **Monorepos resolve imports from one root.** `Obermatt-V5` reports 243 orphans because `web/` and `mobile/` carry their own `tsconfig.json` path aliases and the graph is built from the repo root only. Per-package alias resolution is not implemented. Treat orphan counts in a monorepo as unreliable, or scan each package separately.
- **The dead-link check skips any app with dynamic route segments**, because a static tree cannot decide `[slug]`. It says so in the notes rather than passing silently.
- **The bundle secret scan needs build output.** No `.next/static` means the highest-value check did not run, and the note says which.
- **One rule can be capped at 40 findings by default.** The cap is always announced with the exact number suppressed. Raise it with `--cap N`.

Three mechanisms must be verified by **injection**, never by reading the code:

1. Add a nonexistent package name to a temp `package.json`; it must be caught, and
   real packages including scoped ones must not be.
2. Plant a server-only env value, confirm the bundle probe is silent, then leak it
   into `.next/static` and confirm it fires.
3. Place two identical findings, suppress one with a `launch-check-disable-next-line`
   directive, and confirm exactly one survives.

All three were verified on 2026-08-15. This is the discipline from
`[[Verification-Driven AI Development]]`: both of Hermann's vault hooks read as
correct on every inspection while validating nothing for months. Checking by
reading is not checking.
