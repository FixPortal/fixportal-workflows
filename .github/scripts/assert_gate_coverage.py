#!/usr/bin/env python3
"""Fails when a job in the given workflow is not accounted for by the CI Gate.

The gate is a required status check, so it decides what can merge -- but it only
aggregates the jobs listed in its `needs:`. A quality job added later and never wired in
is silently not merge-blocking, and nothing about adding it prompts anyone to notice.
This asserts the wiring instead of trusting it.

A job is accounted for when it is in the gate's `needs:`, or named in GATE_EXEMPT.
Exemption is an explicit job-id list rather than an inferred rule, because a decision
that grants itself automatically is not reviewable.

Given a directory instead of a single file, every `*.yml`/`*.yaml` workflow in it is
checked: each must contain the gate job (and passes the per-file assertion above), or be
named in GATE_FILE_EXEMPT. The per-file exemption list is load-bearing, not optional --
this repo's product is `workflow_call` workflows whose jobs run in the CALLER and
correctly must not appear in this repo's gate. A workflow with no gate job and no
exemption is exactly the silent not-merge-blocking failure this script exists to close.

The gate job's `if:` must be `always()` (or `!cancelled()`): without it the gate is
SKIPPED when an upstream job fails, a skipped job emits no check run, and a required
context that never reports leaves the pull request permanently unmergeable. A cleanup
removing that line used to pass this script cleanly; it is asserted here now.

Pure Python, invoked directly rather than through a shell wrapper. The wrapper used to be
bash, which cannot survive CRLF line endings: a repo whose .gitattributes checks the file
out with CRLF got `set: pipefail: invalid option name` and a permanently red required
check. Python does not care about CRLF, so the failure mode is designed out rather than
patched per repo.
"""
import os
import sys
from pathlib import Path

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


GATE_IF_ACCEPTED = {"always()", "!cancelled()"}


def split_env(name):
    return set(os.environ.get(name, "").replace(",", " ").split())


def check_file(workflow_path, gate_job, exempt):
    """Assert one file's intra-workflow wiring. Returns True when the file contains
    the gate job (and the assertion ran), False when it does not."""

    with open(workflow_path, encoding="utf-8") as handle:
        workflow = yaml.safe_load(handle)

    jobs = (workflow or {}).get("jobs") or {}
    if not jobs:
        sys.exit(f"{workflow_path}: no jobs found -- refusing to report coverage over nothing.")
    if gate_job not in jobs:
        return False

    needs = (jobs[gate_job] or {}).get("needs") or []
    if isinstance(needs, str):
        needs = [needs]

    gate_if = str((jobs[gate_job] or {}).get("if") or "").replace(" ", "")
    if gate_if not in GATE_IF_ACCEPTED:
        sys.exit(
            f"{workflow_path}: '{gate_job}' must have `if: always()` (or `!cancelled()`); "
            f"found '{gate_if or '<none>'}'. Without it the gate skips when an upstream job "
            "fails, emits no check run, and a required context that never reports leaves the "
            "pull request permanently unmergeable."
        )

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
    return True


def main(argv):
    if len(argv) < 2:
        sys.exit("usage: assert_gate_coverage.py <workflow-file|workflow-dir> [gate-job-id]")

    target = argv[1]
    gate_job = argv[2] if len(argv) > 2 else os.environ.get("GATE_JOB", "ci-gate")
    exempt = split_env("GATE_EXEMPT")

    if not Path(target).is_dir():
        check_file(target, gate_job, exempt)
        return

    files = sorted(
        path.as_posix()
        for path in list(Path(target).glob("*.yml")) + list(Path(target).glob("*.yaml"))
    )
    if not files:
        sys.exit(f"{target}: no workflow files found -- refusing to report coverage over nothing.")

    file_exempt = {name.replace("\\", "/") for name in split_env("GATE_FILE_EXEMPT")}
    stale = sorted(file_exempt - set(files))
    if stale:
        sys.exit(f"GATE_FILE_EXEMPT names workflows that do not exist: {', '.join(stale)}")

    gated = 0
    for workflow_path in files:
        if check_file(workflow_path, gate_job, exempt):
            gated += 1
        elif workflow_path in file_exempt:
            print(f"{workflow_path}: exempt from '{gate_job}' coverage (GATE_FILE_EXEMPT).")
        else:
            sys.exit(
                f"{workflow_path}: no '{gate_job}' job and not in GATE_FILE_EXEMPT, so its jobs "
                "are not merge-blocking. Give the file its own gate job wired the same way, or "
                "exempt it deliberately. Reusable workflow_call workflows belong on the exempt "
                "list: their jobs run in the caller and must NOT be wired into this repo's gate."
            )

    if not gated:
        sys.exit(f"{target}: no file contains a '{gate_job}' job -- refusing to report coverage over nothing.")


if __name__ == "__main__":
    main(sys.argv)
