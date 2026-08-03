#!/usr/bin/env bash
# Fails when a job in the given workflow is not accounted for by the CI Gate.
#
# The gate is a required status check, so it decides what can merge -- but it only
# aggregates the jobs listed in its `needs:`. A quality job added later and never wired
# in is silently not merge-blocking, and nothing about adding it prompts anyone to
# notice. This asserts the wiring instead of trusting it.
#
# A job is accounted for when it is in the gate's `needs:`, or named in GATE_EXEMPT.
# Exemption is an explicit job-id list rather than an inferred rule, because a decision
# that grants itself automatically is not reviewable.
set -euo pipefail

workflow="${1:?usage: assert-gate-coverage.sh <workflow-file>}"
gate_job="${GATE_JOB:-ci-gate}"

python3 - "$workflow" "$gate_job" <<'PY'
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

workflow_path, gate_job = sys.argv[1], sys.argv[2]

with open(workflow_path, encoding="utf-8") as handle:
    workflow = yaml.safe_load(handle)

jobs = workflow.get("jobs") or {}
if not jobs:
    sys.exit(f"{workflow_path}: no jobs found -- refusing to report coverage over nothing.")
if gate_job not in jobs:
    sys.exit(f"{workflow_path}: no '{gate_job}' job found.")

needs = jobs[gate_job].get("needs") or []
if isinstance(needs, str):
    needs = [needs]

exempt = set(os.environ.get("GATE_EXEMPT", "").replace(",", " ").split())

# A stale exemption is worse than a missing one: it reads as a deliberate decision while
# covering nothing, and it survives the rename that made it meaningless.
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
PY
