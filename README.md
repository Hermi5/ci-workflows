# ci-workflows

Reusable GitHub Actions workflows, composite actions and the shared Renovate
preset for Hermann's repo fleet. **Public on purpose**: a reusable workflow in a
private personal-account repo is a support question nobody wants to have, and
nothing in here is a secret. Every credential arrives from the calling repo.

The model it implements: two Workers per site through wrangler environments,
**Workers Builds owns PR previews and staging on `main`**, and **GitHub Actions
owns production on a `v*` tag**. Actions never deploys staging. Main push runs
establish acceptance for the exact merged commit before it can be released.

This remediation is opt-in. Publish and pin its reviewed commit in both the
caller `uses:` reference and the required `ci-ref` input; do not move fleet-wide
`v1`. The app must return `X-SAK-Build-SHA` with its actual build commit.

Run the isolated release-control regressions with
`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`.

## Calling it

Ten lines in `.github/workflows/ci.yml`:

```yaml
name: CI
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
jobs:
  ci:
    permissions:
      contents: read
      pull-requests: read
    uses: Hermi5/ci-workflows/.github/workflows/web-app.yml@<reviewed-commit-sha>
    with:
      ci-ref: <reviewed-commit-sha>
      run-e2e: true
      run-lhci: true
      # On main pushes, pass the canonical staging URL instead of a PR alias.
      site-url: ${{ github.event_name == 'push' && 'https://your-staging-host' || '' }}
    secrets:
      CF_ACCESS_CLIENT_ID: ${{ secrets.CF_ACCESS_CLIENT_ID }}
      CF_ACCESS_CLIENT_SECRET: ${{ secrets.CF_ACCESS_CLIENT_SECRET }}
      GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
      E2E_EMAIL: ${{ secrets.E2E_EMAIL }}
      E2E_PASSWORD: ${{ secrets.E2E_PASSWORD }}
```

And `.github/workflows/release.yml`:

```yaml
name: Release
on:
  push:
    tags: ["v*"]
jobs:
  deploy:
    permissions:
      contents: read
      actions: read
    uses: Hermi5/ci-workflows/.github/workflows/deploy-production.yml@<reviewed-commit-sha>
    with:
      ci-ref: <reviewed-commit-sha>
      has-db: true
      smoke-marker: "<html"
    secrets:
      CF_ACCESS_CLIENT_ID: ${{ secrets.CF_ACCESS_CLIENT_ID }}
      CF_ACCESS_CLIENT_SECRET: ${{ secrets.CF_ACCESS_CLIENT_SECRET }}
```

PR test credentials are passed by name. Production `CLOUDFLARE_API_TOKEN`,
`CLOUDFLARE_ACCOUNT_ID`, and `DATABASE_URL_PRODUCTION` belong only to the
production GitHub environment. Remove the production API token from repository
and organization secrets available to PRs; removing its caller line alone cannot
stop a changed PR workflow from requesting a repository secret. The release job
reads environment secrets directly after the separate eligibility job succeeds.

SAK's required TOTP fixture additionally needs `E2E_TOTP_EMAIL`,
`E2E_TOTP_PASSWORD`, and `E2E_TOTP_SECRET` passed by name. Use an isolated synthetic
staging identity; do not use a production account or a person's authenticator.

`secrets: inherit` was the
first draft, and on the first organisation repository it delivered EMPTY values
for every secret the called workflow declares under `workflow_call.secrets`,
while a plain job in the same pull request saw them all (SAK-Industries/sak-portal
PR #1, 2026-09-09). The caller job also grants `contents: read` and
`pull-requests: read`: a called workflow may not request more than its caller
holds, the organisation default is contents-read only, and gitleaks-action lists
the pull request's commits.

### Workflows

| File | For | Trigger the caller uses |
| --- | --- | --- |
| `web-app.yml` | Next app on Workers, with a database | `pull_request`, `push: main` |
| `static-site.yml` | Next site with no database (delegates to `web-app.yml`) | `pull_request` |
| `python-daemon.yml` | the uv/ruff/pytest daemons | `pull_request` |
| `deploy-production.yml` | release | `push: tags: v*` |
| `nightly-fleet.yml` | fleet watch, runs *in this repo*, not called | `schedule` |

### Composite actions

| Action | Does |
| --- | --- |
| `actions/setup-runtime` | reads `.nvmrc` / `mise.toml`, detects npm vs pnpm, caches, installs lockfile-exact |
| `actions/wait-for-preview` | polls an alias or staging URL until its build SHA equals the expected candidate; a second check rejects an alias that advanced during tests |
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

`retries: 1` on CI only, `fullyParallel`. **A spec
that retries twice in one week is quarantined** into a `@flaky` project that runs
non-blocking, with a dated TODO next to it. No blanket retries, and no `retry: 3`
to make a red suite go away; that converts a real bug into an intermittent one.

Authenticated suites must disable Playwright tracing. This workflow does not
upload Playwright HTML reports or test results: traces and API transport errors
can retain Access headers, passwords, and session cookies. Reintroducing report
uploads requires tested credential redaction. Both Playwright projects capture
raw JSON and stderr in private temporary files outside the checkout, then remove
them. CI receives only counts, failed test titles and source locations, and fixed
error categories. A failed command or invalid report still fails the gate. This
does not redact standard Playwright reports or arbitrary caller commands.
Lighthouse reports are retained only when Lighthouse is enabled.

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

The updated web/release workflows pin unchanged setup/scan actions to their
audited commit and check out changed helper code at the caller's immutable
`ci-ref`. Pin `uses:` and `ci-ref` to the same published revision. No mutable tag
needs to move. Other workflows remain on their existing release until migrated.

Renovate keeps the SHAs current through `helpers:pinGitHubActionDigests`, so a
pinned action is not a frozen one.

## Requirements this repo does not satisfy on its own

- **`@hermann/site-checks` must exist** for the site-checks gate and the nightly
  fleet run. Installed from git (`github:Hermi5/site-checks`), not a registry.
- **Cloudflare Access service token** with a Service Auth policy on each staging
  Worker, as `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`. Tokens expire
  after at most a year; put the expiry alert on.
- **Release authority remains an owner configuration step.** Private Team repos
  support environments and tag rules but not required environment reviewers.
  Separate agent credentials from owner/tag/deployment authority. The source
  guard proves main ancestry and successful exact-SHA CI, not human approval.
- **pnpm repos need a `packageManager` field** in `package.json`; corepack cannot
  pick a version without it, and `setup-runtime` fails loudly rather than
  installing whatever is newest.
