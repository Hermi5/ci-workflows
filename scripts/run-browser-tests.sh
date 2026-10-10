#!/usr/bin/env bash
set -euo pipefail

# Transport errors can contain dynamic session cookies that GitHub cannot mask.
umask 077
results_dir=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/playwright-results.XXXXXX")
trap 'rm -rf -- "$results_dir"' EXIT

set +e
npx --no-install playwright test --project="$1" --reporter=json \
  --output="$results_dir/test-results" \
  >"$results_dir/report.json" 2>"$results_dir/stderr.log"
runner_status=$?
python3 "$(dirname "$0")/summarize-browser-results.py" "$results_dir/report.json"
summary_status=$?
set -e

if [ "$runner_status" -ne 0 ]; then exit "$runner_status"; fi
exit "$summary_status"
