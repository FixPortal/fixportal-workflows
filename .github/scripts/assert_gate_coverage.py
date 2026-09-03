#!/usr/bin/env python3
"""Fails when a job in the given workflow is not accounted for by the CI Gate.

The gate is a required status check, so it decides what can merge -- but it only
aggregates the jobs listed in its `needs:`. A quality job added later and never wired in
is silently not merge-blocking, and nothing about adding it prompts anyone to notice.
This asserts the wiring instead of trusting it.

A job is accounted for when it is in the gate's `needs:`, or named in GATE_EXEMPT.
Exemption is an explicit job-id list rather than an inferred rule, because a decision
that grants itself automatically is not reviewable.

A job that feeds the gate must not carry a job-level `if:`: the gate counts `skipped`
as a pass, so a conditional quality job that skips reports green while checking
nothing. The only tolerated conditionals are the GATE_CONDITIONAL_EXEMPT jobs (e.g. a
secrets scan that legitimately runs on pull_request only) -- conditional exemption
does NOT exempt a job from gate membership; that is GATE_EXEMPT alone.

The GATE'S OWN semantics are asserted too, because `needs:` membership alone does not
make a gate real:

  * without `if: always()` the gate is SKIPPED when an upstream job fails, and a
    skipped required check cannot block a merge -- the one job whose whole purpose is
    to fail stops running exactly when it was needed;
  * without a step keyed on a `needs.<job>.result`, the gate aggregates nothing and
    reports success unconditionally.

Either way the required context goes green while deciding nothing, which is the same
fail-OPEN outcome as an ungated job and is invisible in a diff that keeps the job, its
name and its needs: list intact.

Given a directory instead of a single file, every `*.yml`/`*.yaml` workflow in it is
checked with the full contract above: each must contain the gate job (and pass every
assertion above), or be named in GATE_FILE_EXEMPT. The per-file exemption list is
load-bearing, not optional -- this repo's product is `workflow_call` workflows whose
jobs run in the CALLER and correctly must not appear in this repo's gate. A workflow
with no gate job and no exemption is exactly the silent not-merge-blocking failure
this script exists to close.

Pure Python, invoked directly rather than through a shell wrapper. The wrapper used to be
bash, which cannot survive CRLF line endings: a repo whose .gitattributes checks the file
out with CRLF got `set: pipefail: invalid option name` and a permanently red required
check. Python does not care about CRLF, so the failure mode is designed out rather than
patched per repo.
"""
import os
import re
import sys
from pathlib import Path


ID = r"[A-Za-z_][A-Za-z0-9_-]*"
# A job key may be quoted -- `"security-scan":` is valid Actions syntax. The previous
# unquoted-only pattern silently dropped such a job from the `jobs` dict, so it could
# never appear in `set(jobs) - set(needs)` and the gate reported full coverage over a
# quality job it was not gating. That is a fail-OPEN result, the one outcome this
# script exists to prevent, so anything unclassifiable at job indentation now exits.
JOB = re.compile(rf"""^\ \ (?:'({ID})'|"({ID})"|({ID}))\s*:\s*(?:\#.*)?$""", re.VERBOSE)
NEEDS = re.compile(r"^    needs\s*:\s*(.*?)\s*$")
# Block sequence items may sit at the key's own indentation (4) or be indented under it
# (6), and may be quoted. Both forms are valid YAML; accepting only unquoted 6-space
# items dropped entries, which ENLARGES `missing` and reddens a valid workflow.
BLOCK_NEED = re.compile(rf"""^\s{{4,}}-\s*(?:'({ID})'|"({ID})"|({ID}))\s*(?:\#.*)?$""", re.VERBOSE)
COMMENT_OR_BLANK = re.compile(r"^\s*(?:\#.*)?$")
# Job-level only: `if:` at job-body indentation (4). Step-level `if:` sits at 6+ and
# is out of scope -- a skipped step fails its job's own assertions, it does not make
# the gate report green over a missing check. The key may be quoted (`'if':`,
# `"if":`) -- that is valid YAML and must not slip past the check.
JOB_IF = re.compile(r"""^    (?:'if'|"if"|if)\s*:""")
# Same key, capturing its value, for the gate's own `if:`.
JOB_IF_VALUE = re.compile(r"""^    (?:'if'|"if"|if)\s*:\s*(.*?)\s*$""")
# A reference to an upstream job's outcome, in either the `needs.*.result` wildcard
# form or the per-job `needs.build.result` form. Requiring the literal wildcard would
# red a workflow that aggregates job by job, which is equally correct.
NEEDS_RESULT = re.compile(r"needs\.[A-Za-z0-9_*-]+\.result")
# A STEP-level `if:`, i.e. deeper than the four-space job-level one JOB_IF_VALUE matches,
# in either the plain form (`        if: ...`) or as a list item's first key
# (`      - if: ...`). Used to insist the gate's aggregation lives on a condition.
# Group 1 is everything before the key, so its length is the key's own COLUMN. A block
# scalar's continuation must out-indent THAT, not the line: measuring the line put the bar
# at the `- ` of a dash-form step, so the sibling `run:` and its body were swallowed into
# the condition (see step_conditions).
STEP_IF_VALUE = re.compile(r"""^(\s{5,}(?:-\s+)?)(?:'if'|"if"|if)\s*:\s*(.*?)\s*$""")
# A step `if:` may open a YAML block scalar and carry its condition on the following,
# more-indented lines. Those lines are part of the condition and must be searched too, or
# a perfectly good gate written as `if: >` reads as having no condition at all.
#
# The header is `|` or `>` followed by an indentation indicator and a chomping indicator
# in either order -- `|`, `>-`, `|2`, `>2-`, `|-2` are all valid. Matching only `[|>][+-]?`
# missed the digit forms, so `if: >2` looked like an ordinary truthy value, its
# continuation lines were never read, and the checker reported a spurious "no step
# conditioned on" failure. Rare shape, but the failure direction is a false RED on
# correct configuration.
BLOCK_SCALAR = re.compile(r"^[|>](?:[0-9][+-]?|[+-][0-9]?)?$")


def _first_group(match):
    return next(g for g in match.groups() if g is not None)


def strip_comment(line):
    """Drop a trailing comment. Naive by design: a '#' inside a quoted scalar is not a
    shape this file's job/needs grammar admits, and guessing at YAML quoting rules here
    would be less predictable than the explicit exit below."""
    return line.split("#", 1)[0]


def parse_need_ids(value):
    value = strip_comment(value).strip()
    if value.startswith("[") and value.endswith("]"):
        values = value[1:-1].split(",")
    else:
        values = [value]
    ids = [item.strip().strip("'\"") for item in values if item.strip()]
    if any(not re.fullmatch(ID, item) for item in ids):
        sys.exit(f"unsupported needs value: {value}")
    return ids


def read_gate_contract(lines, gate_job):
    try:
        # `jobs: # comment` is valid and used to fail the equality outright, returning no
        # jobs at all.
        jobs_start = next(
            i for i, line in enumerate(lines) if strip_comment(line).rstrip() == "jobs:"
        )
    except StopIteration:
        return {}, [], set()

    jobs = {}
    for i in range(jobs_start + 1, len(lines)):
        line = lines[i].rstrip("\r\n")
        if line.strip() and not line.startswith((" ", "#")):
            break
        if COMMENT_OR_BLANK.match(line):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent != 2:
            continue
        match = JOB.match(line)
        if not match:
            # Fail closed. An unrecognised construct at job indentation (an anchor, a
            # merge key, a multi-line key) means this parser does not understand the
            # workflow, and "does not understand" must never render as "all accounted
            # for".
            sys.exit(
                f"unparsable line at job indentation (line {i + 1}): {line.strip()}\n"
                "This gate refuses to report coverage it cannot verify. Simplify the job "
                "key, or extend assert_gate_coverage.py to understand this form."
            )
        jobs[_first_group(match)] = i

    if gate_job not in jobs:
        return jobs, [], set()

    gate_start = jobs[gate_job] + 1
    gate_end = min((i for i in jobs.values() if i >= gate_start), default=len(lines))
    for i in range(gate_start, gate_end):
        match = NEEDS.match(lines[i].rstrip("\r\n"))
        if not match:
            continue
        if strip_comment(match.group(1)).strip():
            return jobs, parse_need_ids(match.group(1)), conditional_jobs(lines, jobs)

        needs = []
        for line in lines[i + 1 : gate_end]:
            line = line.rstrip("\r\n")
            item = BLOCK_NEED.match(line)
            if item:
                needs.append(_first_group(item))
                continue
            # Skip comments and blanks BEFORE testing indentation: a comment sitting at
            # the key's own indentation used to end the sequence early and silently
            # truncate `needs`.
            if COMMENT_OR_BLANK.match(line):
                continue
            if len(line) - len(line.lstrip(" ")) <= 4:
                break
        return jobs, needs, conditional_jobs(lines, jobs)

    return jobs, [], set()


def conditional_jobs(lines, jobs):
    """The ids of jobs carrying a job-level `if:` condition."""
    starts = sorted(jobs.values())
    conditional = set()
    for job_id, start in jobs.items():
        end = min((i for i in starts if i > start), default=len(lines))
        if any(JOB_IF.match(lines[i].rstrip("\r\n")) for i in range(start + 1, end)):
            conditional.add(job_id)
    return conditional


def job_block(lines, jobs, job_id):
    """The lines of one job's body, from its key to the next job key."""
    start = jobs[job_id]
    end = min((i for i in sorted(jobs.values()) if i > start), default=len(lines))
    return [line.rstrip("\r\n") for line in lines[start + 1 : end]]


def normalise_condition(value):
    """`if:` value reduced to a comparable form.

    `always()`, `'always()'` and `${{ always() }}` are the same condition written three
    valid ways, and a check that accepted only one spelling would red a correct gate.
    Compound conditions survive normalisation as themselves (`always()&&x`) and so are
    correctly NOT equal to `always()` -- a gate that runs only sometimes is the defect
    being caught, not a spelling variant of the fix.
    """
    value = strip_comment(value).strip().strip("'\"").strip()
    if value.startswith("${{") and value.endswith("}}"):
        value = value[3:-2]
    return value.replace(" ", "")


def step_conditions(block):
    """Every step-level `if:` condition in a job body, block scalars included."""
    for index, line in enumerate(block):
        match = STEP_IF_VALUE.match(line)
        if not match:
            continue
        value = strip_comment(match.group(2)).strip()
        if value and not BLOCK_SCALAR.match(value):
            yield value
            continue
        # An empty value or a block-scalar indicator: the condition is on the following
        # lines, which are indented past the `if:` KEY -- its own column, not the line's.
        # Measuring the line put the bar at the dash of a `- if: >-` step, so the sibling
        # `run:` at the key's column and its whole body were absorbed into the condition. A
        # gate folded to `false` with the diagnostic echo of `join(needs.*.result, ', ')`
        # below it then passed, which is the fail-OPEN shape this check exists to reject.
        indent = len(match.group(1))
        continuation = []
        for following in block[index + 1 :]:
            if COMMENT_OR_BLANK.match(following):
                continue
            if len(following) - len(following.lstrip()) <= indent:
                break
            continuation.append(strip_comment(following).strip())
        yield " ".join(continuation)


def assert_gate_semantics(workflow_path, lines, jobs, gate_job):
    block = job_block(lines, jobs, gate_job)

    condition = next(
        (JOB_IF_VALUE.match(line).group(1) for line in block if JOB_IF_VALUE.match(line)),
        None,
    )
    if condition is None or normalise_condition(condition) != "always()":
        found = "no job-level 'if:'" if condition is None else f"'if: {condition}'"
        sys.exit(
            f"{workflow_path}: '{gate_job}' must carry `if: always()` -- found {found}.\n"
            "Without it the gate is skipped when an upstream job fails, and a skipped "
            "required check cannot block a merge."
        )

    # The reference must sit on a STEP CONDITION, not merely somewhere in the block.
    # Searching the whole block accepted a gate whose failing `if:` had been deleted, so
    # long as a diagnostic line survived -- and the house skeleton ships exactly such a
    # line right beside the condition:
    #
    #     - name: Fail if any upstream job did not succeed
    #       if: contains(needs.*.result, 'failure') || ...        <- the actual gate
    #       run: |
    #         echo "Upstream results: ${{ join(needs.*.result, ', ') }}"   <- matched too
    #
    # Delete the `if:` and the step runs unconditionally and never fails, while the echo
    # keeps this assertion green. That is precisely the "guts only the aggregation step"
    # neuter the function exists to catch, so the check was blind to its own subject.
    # Demonstrated 2026-09-02 on a fixture with the condition removed: exit 0, reported
    # as "aggregates its needs". Found by Gitar on fixportal-initiator#225.
    if not any(NEEDS_RESULT.search(condition) for condition in step_conditions(block)):
        sys.exit(
            f"{workflow_path}: '{gate_job}' has no step whose `if:` references a "
            "`needs.<job>.result`.\n"
            "The gate aggregates nothing and reports success unconditionally. A "
            "`needs.*.result` appearing only in a `run:` body -- an echo of the upstream "
            "results, say -- gates nothing."
        )


def check_file(workflow_path, gate_job, exempt, conditional_exempt):
    """Assert one file's full gate contract. Returns True when the file contains the
    gate job (and every assertion ran), False when it has no gate job at all."""

    with open(workflow_path, encoding="utf-8") as handle:
        lines = handle.readlines()
    jobs, needs, conditional = read_gate_contract(lines, gate_job)

    if not jobs:
        sys.exit(f"{workflow_path}: no jobs found -- refusing to report coverage over nothing.")
    if gate_job not in jobs:
        return False

    # A stale exemption is worse than a missing one: it reads as a deliberate decision
    # while covering nothing, and it survives the rename that made it meaningless.
    unknown = sorted((exempt | conditional_exempt) - set(jobs))
    if unknown:
        sys.exit(
            f"{workflow_path}: GATE_EXEMPT/GATE_CONDITIONAL_EXEMPT name jobs that do not "
            f"exist: {', '.join(unknown)}"
        )

    missing = sorted(set(jobs) - set(needs) - exempt - {gate_job})
    if missing:
        sys.exit(
            f"{workflow_path}: not gated by '{gate_job}': {', '.join(missing)}.\n"
            f"Add each to the '{gate_job}' needs: list, or to GATE_EXEMPT if it is "
            "deliberately not merge-blocking."
        )

    # The gate counts `skipped` as a pass, so a job feeding it must be unconditional:
    # a skipped conditional job reports green while checking nothing.
    unconditioned = sorted((conditional & set(needs)) - conditional_exempt - {gate_job})
    if unconditioned:
        sys.exit(
            f"{workflow_path}: job-level 'if:' on job(s) feeding '{gate_job}': "
            f"{', '.join(unconditioned)}.\n"
            "A skipped job passes the gate, so a conditional quality job can report "
            "green while checking nothing. Remove the condition, or name the job in "
            "GATE_CONDITIONAL_EXEMPT with a written rationale in the workflow."
        )

    assert_gate_semantics(workflow_path, lines, jobs, gate_job)

    print(
        f"{workflow_path}: all {len(jobs)} job(s) accounted for by '{gate_job}', "
        "which runs always() and aggregates its needs."
    )
    return True


def split_env(name):
    return set(os.environ.get(name, "").replace(",", " ").split())


def main(argv):
    if len(argv) < 2:
        sys.exit("usage: assert_gate_coverage.py <workflow-file|workflow-dir> [gate-job-id]")

    target = argv[1]
    gate_job = argv[2] if len(argv) > 2 else os.environ.get("GATE_JOB", "ci-gate")
    exempt = split_env("GATE_EXEMPT")
    conditional_exempt = split_env("GATE_CONDITIONAL_EXEMPT")

    if not Path(target).is_dir():
        check_file(target, gate_job, exempt, conditional_exempt)
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
        if check_file(workflow_path, gate_job, exempt, conditional_exempt):
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
