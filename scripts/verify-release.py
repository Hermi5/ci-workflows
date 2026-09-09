#!/usr/bin/env python3
"""Read-only release eligibility: accepted exact commit, already on main."""

import json
import os
import re
import subprocess


def verify_release(repository, sha, ref, event, get):
    if event != "push" or not ref.startswith("refs/tags/v"):
        raise ValueError("release requires a v* tag push")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("release requires a full commit SHA")
    prefix = f"repos/{repository}"
    comparison = get(f"{prefix}/compare/{sha}...main")
    if comparison.get("status") not in {"ahead", "identical"} or comparison.get(
        "merge_base_commit", {}
    ).get("sha") != sha:
        raise ValueError("tagged commit is not on main")

    runs = get(
        f"{prefix}/actions/workflows/ci.yml/runs?branch=main&event=push&head_sha={sha}&per_page=100"
    ).get("workflow_runs", [])
    runs = [
        run for run in runs
        if run.get("head_sha") == sha
        and run.get("head_branch") == "main"
        and run.get("event") == "push"
    ]
    if not runs:
        raise ValueError("no main CI run exists for the tagged commit")
    run = max(runs, key=lambda item: item["id"])
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise ValueError("latest exact-commit main CI run did not succeed")

    jobs = get(f"{prefix}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100").get("jobs", [])
    for name in ["ci / fast", "ci / audit", "ci / preview-gates"]:
        matches = [job for job in jobs if job.get("name") == name]
        if len(matches) != 1 or matches[0].get("status") != "completed" or matches[0].get("conclusion") != "success":
            raise ValueError(f"required exact-commit job did not succeed: {name}")
    return run["id"]


def github_get(path):
    result = subprocess.run(
        ["gh", "api", "--method", "GET", path], check=True,
        text=True, capture_output=True,
    )
    return json.loads(result.stdout)


if __name__ == "__main__":
    try:
        run_id = verify_release(
            os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_SHA"],
            os.environ["GITHUB_REF"], os.environ["GITHUB_EVENT_NAME"], github_get,
        )
    except (ValueError, KeyError, subprocess.CalledProcessError):
        # API output can contain metadata that is irrelevant to the release log.
        raise SystemExit("::error::release eligibility failed; require a v* tag on main with successful exact-commit CI")
    print(f"Eligible commit {os.environ['GITHUB_SHA']}, main CI run {run_id}")
