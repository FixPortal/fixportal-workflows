#!/usr/bin/env python3
"""Fails when a job in the given workflow is not accounted for by the CI Gate.

The gate is a required status check, so it decides what can merge -- but it only
aggregates the jobs listed in its `needs:`. A quality job added later and never wired in
is silently not merge-blocking, and nothing about adding it prompts anyone to notice.
This asserts the wiring instead of trusting it.

A job is accounted for when it is in the gate's `needs:`, or named in GATE_EXEMPT.
Exemption is an explicit job-id list rather than an inferred rule, because a decision
that grants itself automatically is not reviewable.

Pure Python, invoked directly rather than through a shell wrapper. The wrapper used to be
bash, which cannot survive CRLF line endings: a repo whose .gitattributes checks the file
out with CRLF got `set: pipefail: invalid option name` and a permanently red required
check. Python does not care about CRLF, so the failure mode is designed out rather than
patched per repo.
"""
import os
import sys

try:
    import yaml
except ImportError:
    # Deliberately fails rather than installing PyYAML here. This script decides merge
    # eligibility for every pull request, so fetching an unpinned package from PyPI at
    # CI time would put an arbitrary-at-install-time dependency in the gating path.
    # PyYAML ships with GitHub's ubuntu images; a runner without it is a runner-image
    # problem, and should be loud.
    sys.exit(
        "python3 cannot import yaml. Provide PyYAML in the runner image rather than "
        "installing it at CI time -- this script gates merges."
    )


def main(argv):
    if len(argv) < 2:
        sys.exit("usage: assert_gate_coverage.py <workflow-file> [gate-job-id]")

    workflow_path = argv[1]
    gate_job = argv[2] if len(argv) > 2 else os.environ.get("GATE_JOB", "ci-gate")

    with open(workflow_path, encoding="utf-8") as handle:
        workflow = yaml.safe_load(handle)

    jobs = (workflow or {}).get("jobs") or {}
    if not jobs:
        sys.exit(f"{workflow_path}: no jobs found -- refusing to report coverage over nothing.")
    if gate_job not in jobs:
        sys.exit(f"{workflow_path}: no '{gate_job}' job found.")

    needs = (jobs[gate_job] or {}).get("needs") or []
    if isinstance(needs, str):
        needs = [needs]

    exempt = set(os.environ.get("GATE_EXEMPT", "").replace(",", " ").split())

    # A stale exemption is worse than a missing one: it reads as a deliberate decision
    # while covering nothing, and it survives the rename that made it meaningless.
    unknown = sorted(exempt - set(jobs))
    if unknown:
        sys.exit(f"{workflow_path}: GATE_EXEMPT names jobs that do not exist: {', '.join(unknown)}")

    missing = sorted(set(jobs) - set(needs) - exempt - {gate_job})
    if missing:
        sys.exit(
            f"{workflow_path}: not gated by '{gate_job}': {', '.join(missing)}.\n"
            f"Add each to the '{gate_job}' needs: list, or to GATE_EXEMPT if it is "
            "deliberately not merge-blocking."
        )

    print(f"{workflow_path}: all {len(jobs)} job(s) accounted for by '{gate_job}'.")


if __name__ == "__main__":
    main(sys.argv)
