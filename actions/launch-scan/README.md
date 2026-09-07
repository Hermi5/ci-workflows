# launch-scan (vendored)

Deterministic pre-filter for the AI-code failure class where code looks finished
and is not: unwired forms, placeholder content, disabled build gates, orphans,
hallucinated dependencies.

## Source

| | |
| --- | --- |
| Upstream path | `~/Github/agent-os/skills/launch-check/scripts/` |
| Copied | 2026-09-07 |
| `launch-scan.mjs` sha256 at copy time | `6f86f935ba10cad1445fa83540da011182ec95366ed0af5a2453faaa053d6233` |

Vendored rather than checked out because `agent-os` is a private local repo and
`ci-workflows` is public: a public workflow cannot clone it, and making `agent-os`
public to satisfy CI would publish the whole setup. The cost is drift: upstream
is the skill, this is a copy. **Edit upstream, then re-vendor**, never the other
way round.

Re-vendor with:

```sh
SRC=~/Github/agent-os/skills/launch-check/scripts
DST=~/Github/ci-workflows/actions/launch-scan
cp "$SRC/launch-scan.mjs" "$DST/launch-scan.mjs"
cp "$SRC/NOTICE.md"       "$DST/NOTICE.md"
cp "$SRC/lib/"*.mjs       "$DST/lib/"
# then re-add the two-line VENDORED COPY header to each file and update this table
```

`NOTICE.md` travels with the copy: it documents the Apache-2.0 modules vendored
into `lib/vendored.mjs` and the exact `child_process` and network surface the
scanner touches. Read it before changing anything here.

## CLI

```
node launch-scan.mjs [path] [flags]

  --json          machine-readable findings on stdout
  --no-network    skip the npm registry existence check and npm audit
  --no-shell      skip everything that shells out (git, npm)
  --explain       print each rule's false-positive profile alongside findings
  --only <fam>    one family: wired placeholder suppression config crash boundary repo backend
  --quiet         findings only, no inventory notes
  --cap N         max findings per rule before the rest are announced and dropped (default 40)
```

**Exit code is 0 unless the scan itself failed** (2 on a missing path or a missing
binary). It reports candidates; it does not decide. That is why the composite
action wrapping it is advisory: a signature-only hit on a blocker-severity rule is
a reason to go and look, not a reason to fail a merge. Adjudication needs a model.
