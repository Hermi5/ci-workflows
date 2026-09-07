#!/usr/bin/env node
/**
 * Turn launch-scan's --json into GitHub annotations, a job summary and outputs.
 *
 *   node report.mjs launch-scan.json
 *
 * Reads BUDGET_FILE and FAIL_ON_BLOCKER from the environment (the action passes
 * them). Written here rather than inline in the composite action because a
 * twenty-line `jq` pipeline inside YAML is unreadable and untestable.
 *
 * Annotations are capped: a repo with 40 advisory findings must not push 40
 * notices into the PR diff view, because that volume is what teaches people to
 * stop reading them.
 */

import fs from "node:fs";

const ANNOTATION_CAP = 12;

const file = process.argv[2];
if (!file) {
  console.error("usage: node report.mjs <launch-scan.json>");
  process.exit(2);
}

const { findings = [], notes = [] } = JSON.parse(fs.readFileSync(file, "utf8"));

const counts = { blocker: 0, "should-fix": 0, advisory: 0 };
for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

const out = process.env.GITHUB_OUTPUT;
if (out) {
  fs.appendFileSync(
    out,
    `blockers=${counts.blocker}\nshould-fix=${counts["should-fix"]}\nadvisory=${counts.advisory}\n`,
  );
}

/* Blockers annotate as warnings, not errors: the scanner found a signature, and
   a signature is not a confirmed defect. An `::error::` on a candidate is a lie
   about how much was verified. */
for (const f of findings.slice(0, ANNOTATION_CAP)) {
  const loc = f.line ? `,line=${f.line}` : "";
  const msg = `[${f.severity}] ${f.name} (${f.rule})${f.snippet ? `, ${String(f.snippet).replace(/\s+/g, " ").slice(0, 120)}` : ""}`;
  console.log(`::warning file=${f.file}${loc}::${msg}`);
}
if (findings.length > ANNOTATION_CAP) {
  console.log(
    `::notice::${findings.length - ANNOTATION_CAP} further launch-check candidate(s) in the uploaded launch-scan.json`,
  );
}

const summary = process.env.GITHUB_STEP_SUMMARY;
if (summary) {
  const rows = findings
    .slice(0, 40)
    .map(
      (f) =>
        `| ${f.severity} | ${f.rule} | \`${f.file}${f.line ? `:${f.line}` : ""}\` |`,
    )
    .join("\n");
  fs.appendFileSync(
    summary,
    [
      "## launch-check",
      "",
      `${counts.blocker} blocker · ${counts["should-fix"]} should-fix · ${counts.advisory} advisory`,
      "",
      "Candidates, not verdicts. Each one needs a human to read the code path before it is a defect.",
      "",
      rows ? "| severity | rule | location |\n| --- | --- | --- |\n" + rows : "_No candidates._",
      "",
      notes.length ? "<details><summary>Scanner notes</summary>\n\n" + notes.map((n) => `- ${n}`).join("\n") + "\n\n</details>" : "",
      "",
    ].join("\n"),
  );
}

/* The budget file is the repo's own ratchet. Absent, nothing is enforced. */
const budgetPath = process.env.BUDGET_FILE;
let budget = null;
if (budgetPath && fs.existsSync(budgetPath)) {
  try {
    budget = JSON.parse(fs.readFileSync(budgetPath, "utf8")).launchCheck ?? null;
  } catch (e) {
    console.log(`::warning::${budgetPath} is not valid JSON: ${e.message}`);
  }
}

let failed = false;
if (budget) {
  for (const [key, severity] of [
    ["maxBlockers", "blocker"],
    ["maxShouldFix", "should-fix"],
  ]) {
    if (typeof budget[key] === "number" && counts[severity] > budget[key]) {
      console.log(
        `::error::${counts[severity]} ${severity} candidate(s), budget ${key} is ${budget[key]}`,
      );
      failed = true;
    }
  }
}

if (process.env.FAIL_ON_BLOCKER === "true" && counts.blocker > 0) {
  console.log(`::error::${counts.blocker} blocker-severity candidate(s) and fail-on-blocker is on`);
  failed = true;
}

console.log(
  `launch-check: ${counts.blocker} blocker, ${counts["should-fix"]} should-fix, ${counts.advisory} advisory`,
);
process.exit(failed ? 1 : 0);
