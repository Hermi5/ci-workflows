# ci-workflows

Reusable GitHub Actions workflows, composite actions and the shared Renovate
preset for Hermann's repo fleet. **Public on purpose**: a reusable workflow in a
private personal-account repo is a support question nobody wants to have, and
nothing in here is a secret. Every credential arrives from the calling repo.

The model it implements: two Workers per site through wrangler environments,
**Workers Builds owns PR previews and staging on `main`**, and **GitHub Actions
owns production on a `v*` tag**. Actions never deploys staging and never runs
heavy gates on a push to `main`.

## Calling it

Ten lines in `.github/workflows/ci.yml`:

```yaml
name: CI
on:
  pull_request:
    branches: [main]
jobs:
  ci:
    uses: Hermi5/ci-workflows/.github/workflows/web-app.yml@v1
    with:
      run-e2e: true
      run-lhci: true
    secrets: inherit
```

And `.github/workflows/release.yml`:

```yaml
name: Release
on:
  push:
    tags: ["v*"]
jobs:
  deploy:
    uses: Hermi5/ci-workflows/.github/workflows/deploy-production.yml@v1
    with:
      has-db: true
      smoke-marker: "<html"
    secrets: inherit
```

`secrets: inherit` is deliberate. The alternative is naming five secrets in every
one of seventeen repos and re-editing all of them the day a sixth is added.

### Workflows

| File | For | Trigger the caller uses |
| --- | --- | --- |
| `web-app.yml` | Next app on Workers, with a database | `pull_request` |
| `static-site.yml` | Next site with no database (delegates to `web-app.yml`) | `pull_request` |
| `python-daemon.yml` | the uv/ruff/pytest daemons | `pull_request` |
| `deploy-production.yml` | release | `push: tags: v*` |
| `nightly-fleet.yml` | fleet watch, runs *in this repo*, not called | `schedule` |

### Composite actions

| Action | Does |
| --- | --- |
| `actions/setup-runtime` | reads `.nvmrc` / `mise.toml`, detects npm vs pnpm, caches, installs lockfile-exact |
| `actions/wait-for-preview` | reproduces Cloudflare's alias sanitizer, polls the preview URL with Access service-token headers |
| `actions/launch-scan` | runs the vendored launch-check scanner, annotates, applies `launch-check.budget.json` |

`actions/launch-scan/` holds a **vendored copy** of the agent-os `launch-check`
scanner: `agent-os` is private and a public workflow cannot check it out. Source
path, copy date and the re-vendor command are in `actions/launch-scan/README.md`.

## The gate matrix

| Gate | web-app | static-site | python-daemon | Phase 1 |
| --- | --- | --- | --- | --- |
| install (lockfile-exact) | ✓ | ✓ | ✓ (uv) | **block** |
| ESLint / ruff check | ✓ | ✓ | ✓ | **block** |
| Biome `format` / `ruff format --check` | ✓ | ✓ | ✓ | **block** |
| `tsc --noEmit` / mypy | ✓ | ✓ | ✓ | **block** / advisory |
| vitest / pytest | ✓ | ✓ | ✓ | **block**, warn on zero tests |
| `next build` | ✓ | ✓ | n/a | **block** |
| gitleaks, full history | ✓ | ✓ | ✓ | **block** |
| launch-scan + budget file | ✓ | ✓ | n/a | advisory → block in wave 3 |
| Playwright `e2e` vs the preview URL (axe rides here) | ✓ | ✓ | n/a | **block** where suites exist |
| `@hermann/site-checks` | ✓ | ✓ | n/a | advisory → block after 1 green week |
| LHCI budgets | ✓ | ✓ | n/a | SEO + CLS **block**, performance warns |
| link check, sitemap sample | ✓ | ✓ | n/a | advisory |
| `wrangler deploy --dry-run` Total Upload vs budget | ✓ | ✓ | n/a | advisory → block at 90% |
| `osv-scanner` | ✓ | ✓ | ✓ | advisory, **CRITICAL blocks** |

Lighthouse's blocking/warning split is not in this repo: it lives in each
caller's `lighthouserc.json`. SEO and CLS are `error`, performance is `warn`, and
that split is StellaVie's, adopted fleet-wide because it survived contact with a
real repo.

### The ratchet rule

**A gate flips to blocking after two consecutive green weeks on that repo.**
Not on a schedule, not on a feeling. After the repo has actually been green
twice running.

**Anything red on arrival gets `|| true` for at most one week.** A gate that is
red the day it lands is a gate somebody appends `|| true` to and never removes;
the one-week ceiling makes that suppression a dated, visible debt instead of a
permanent one. Every advisory step here carries `continue-on-error: true` with
the matrix column in a comment above it, so the ratchet is one line to delete.

### Flake policy

`retries: 1` on CI only, `fullyParallel`, `trace: 'on-first-retry'`. **A spec
that retries twice in one week is quarantined** into a `@flaky` project that runs
non-blocking, with a dated TODO next to it. No blanket retries, and no `retry: 3`
to make a red suite go away; that converts a real bug into an intermittent one.

## Pinning

Every third-party action is pinned to a **full commit SHA** with the human
version in a trailing comment, resolved 2026-09-07:

| Action | Version | SHA |
| --- | --- | --- |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-node` | v7.0.0 | `820762786026740c76f36085b0efc47a31fe5020` |
| `actions/upload-artifact` | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `actions/github-script` | v9.0.0 | `3a2844b7e9c422d3c10d287c895573f7108da1b3` |
| `cloudflare/wrangler-action` | v4.0.0 | `ebbaa1584979971c8614a24965b4405ff95890e0` |
| `gitleaks/gitleaks-action` | v3.0.0 | `e0c47f4f8be36e29cdc102c57e68cb5cbf0e8d1e` |
| `google/osv-scanner-action/osv-scanner-action` | v2.5.1 | `6e4298ebc4db23e847df9b2e2de2939d6f066c67` |
| `astral-sh/setup-uv` | v10.0.1 | `20cfd1bf945f4377ade1205e4dbc17946fc9a30d` |

Lighthouse runs through `npx --yes @lhci/cli@0.15.x`, not through an action:
that is the path StellaVie has run since 2026-08, and it is one fewer third-party
SHA to keep current.

The three `Hermi5/ci-workflows/actions/*@v1` references inside the workflows are
**tag references, not SHAs, and they are internal**. They must be bumped in the
same commit that moves the `v1` tag; a workflow calling `@v1` while the caller
pins `@v2` would silently mix two generations.

Renovate keeps the SHAs current through `helpers:pinGitHubActionDigests`, so a
pinned action is not a frozen one.

## Requirements this repo does not satisfy on its own

- **`@hermann/site-checks` must exist** for the site-checks gate and the nightly
  fleet run. Installed from git (`github:Hermi5/site-checks`), not a registry.
- **Cloudflare Access service token** with a Service Auth policy on each staging
  Worker, as `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`. Tokens expire
  after at most a year; put the expiry alert on.
- **Rulesets and environments on private repos need GitHub Pro.** `Hermi5` is a
  personal account and today no repo in the fleet has any branch protection. The
  required reviewer on `deploy-production.yml` is a no-op until that changes.
- **pnpm repos need a `packageManager` field** in `package.json`; corepack cannot
  pick a version without it, and `setup-runtime` fails loudly rather than
  installing whatever is newest.
