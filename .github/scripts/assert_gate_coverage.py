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

Pure Python, invoked directly rather than through a shell wrapper. The wrapper used to be
bash, which cannot survive CRLF line endings: a repo whose .gitattributes checks the file
out with CRLF got `set: pipefail: invalid option name` and a permanently red required
check. Python does not care about CRLF, so the failure mode is designed out rather than
patched per repo.
"""
import json
import math
import os
import re
import sys
from pathlib import Path


ID = r"[A-Za-z_][A-Za-z0-9_-]*"
COMMENT_OR_BLANK = re.compile(r"^\s*(?:\#.*)?$")
# A complete positive predicate over an upstream job's failure/cancellation outcome.
# The job id and outcome are CAPTURED rather than merely matched, because "some
# dependency is referenced" is not the assertion that matters: a gate declaring
# `needs: [build, lint]` whose condition names only `build` reports success while
# `lint` fails, and one naming only 'failure' reports success over a CANCELLED job.
#
# This replaced a bare `needs\.(\w+)\.result` search, which accepted
# `false && contains(...)` -- a condition that can never reach the failing step and
# leaves the required gate green.
# Conditions are accepted only as `||`-joined instances of this shape below. Merely
# finding `needs.*.result` inside a condition accepted `false && contains(...)`, which
# can never reach the failing step and leaves the required gate green.
FAILURE_CONDITION_ATOM = re.compile(
    rf"(?:contains\(needs\.({ID}|\*)\.result,['\"](failure|cancelled)['\"]\)|"
    rf"needs\.({ID})\.result(?:==['\"](failure|cancelled)['\"]|!=['\"]success['\"]))"
)
# A REFINEMENT, not a coverage atom: `needs.<job>.result != 'skipped'` narrows a
# `!= 'success'` atom about the same job rather than covering an outcome of its own.
#
# It exists because the house shape for a CONDITIONAL feeder is
# `needs.secrets.result != 'success' && needs.secrets.result != 'skipped'` -- a job that
# legitimately skips must not fail the gate by skipping, which is exactly what
# GATE_CONDITIONAL_EXEMPT is for. Refusing every residual conjunction rejected that, and
# fixportal-initiator's correct gate then read as "aggregates nothing". Found by running
# the reconciled checker over all 26 repositories BEFORE syncing it to any of them.
CONDITION_REFINEMENT = re.compile(rf"needs\.({ID})\.result!=['\"]skipped['\"]")
BACKSLASH = "\\"

# The gate step's failing command, in the forms this checker will vouch for. Anything
# else is REJECTED with a message naming these -- see ends_non_zero for why recognising
# a small set beats parsing arbitrary shell here.
#
# `$` is admitted inside the echo/message arms only, so `echo "::error::$msg"` works;
# the failing command itself takes no substitution, because a substituted exit code is
# exactly the shape whose value cannot be read from the file.
# A trailing redirection does not change whether the command fails. `exit 1 >&2` and
# `false 2>/dev/null` were rejected outright, and the failure direction of a rejection
# here is a PERMANENTLY RED required check on a correct gate, in every repo this asset is
# installed into. (CodeRabbit, PR #135.)
#
# THE REDIRECT TARGET CANNOT CONTAIN A SEPARATOR. `\S+` swallowed one, so
# `false >/tmp/gate;true` fullmatched and was accepted - and it exits ZERO. A gate body
# that can succeed is the one thing this function must never vouch for.
_REDIR = r"(?:\s*[12]?>>?\s*(?:&[12]|[^\s;|&]+))*"
# The message arm carries its own redirection for the same reason: the house one-liner is
# `echo "::error::..." >&2 && exit 1`, and an echo body that could swallow `>` or `&`
# would either miss the separator that follows or run past it.
# A LEADING redirection is as ordinary as a trailing one: `>&2 echo "upstream failed"` is
# the same command as `echo "upstream failed" >&2`, and refusing the first form reddened a
# gate whose body does fail. It cannot widen what the form VOUCHES for, because the failing
# command itself is still required separately by _FAIL.
_ECHO = rf"(?:{_REDIR}\s*)?(?:echo|printf)\s+[^\n|&;<>]*{_REDIR}"
_NONZERO_STATUS = r"0*(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
_FAIL = rf"(?:exit\s+{_NONZERO_STATUS}|false){_REDIR}\s*;?"
ACCEPTED_FAILING_FORMS = tuple(
    re.compile(pattern)
    for pattern in (
        # exit 1   (with any trailing redirection)
        _FAIL,
        # NO `||` / `&&` GUARD FORMS. An earlier round of this review asked for them as
        # "ordinary spellings of the house one-liner" and I added them; the next round
        # showed the widening was fail-OPEN, and it is right. `[ -z "$x" ] || exit 1`
        # exits ZERO whenever its test passes, and the gate step's own `if:` has ALREADY
        # established that an upstream job failed - so a second condition inside the body
        # can only re-decide that, in the direction of letting a failed lane report green.
        # A false RED here is an argument someone has to win; a false GREEN is a merge
        # nobody notices.
        #
        # echo "..." ; exit 1     (message then failure, either separator style)
        rf"{_ECHO}\s*(?:;|&&)\s*{_FAIL}",
        # PowerShell. `shell: pwsh` gate steps are house style in the .NET repos and
        # `throw 'upstream failed'` is how one fails, so rejecting it was a false RED
        # on a correct gate - the direction that gets a working control deleted to make
        # CI green. The trailing message is optional because mask_quoted has already
        # blanked the string by the time these patterns run. Admitting `throw` costs
        # nothing under bash either: it is not a builtin there, so the step still exits
        # non-zero (127), which is exactly what this function is asserting.
        # UNCONDITIONAL only. `if ($false) { throw "failed" }` was accepted and does not
        # throw, so the step exits 0 - the same fail-open as the `||` forms above.
        # THE TAIL CANNOT CARRY A SEPARATOR. It used to be `.*`, and mask_quoted blanks
        # the message, so `throw "upstream failed" || true` normalised to `throw || true`
        # and fullmatched - but under bash `-e` does not fire on a command whose status
        # `||` consumes, so the step exits 0. Excluding | & ; < > from the tail keeps the
        # message arm and refuses every guarded form, exactly as the block above does.
        r"throw(?:\s+[^|&;<>]*)?",
    )
)
# A MESSAGE line is the only thing a failing command may follow. It writes output
# and cannot re-decide the step's exit status, so vouching for it as a prefix does
# not vouch for a command that could make the step succeed. This is _ECHO with the
# argument made optional: mask_quoted has already blanked any quoted text by the
# time it runs, so `echo "Upstream results: ..."` reaches it as a bare `echo`.
_MESSAGE = re.compile(rf"(?:{_REDIR}\s*)?(?:echo|printf)(?:\s+[^\n|&;<>]*)?{_REDIR}")
# `set -euo pipefail` is the house prefix on run: blocks across this estate, and
# refusing it was a false RED waiting for the first gate written in the house style --
# the direction that gets a working control deleted to make CI green.
#
# NOT EVERY SHELL OPTION IS INERT, which is why this is an allowlist of four and not a
# ban on the dangerous ones. `set -n` (noexec) and `set -t` (onecmd) STOP the shell
# before the final command: `set -n` then `exit 1` reads the exit and never runs it, so
# the step exits ZERO while the checker vouches for the `exit 1` it can see. Both were
# accepted when this prefix was any word list. A blocklist of the forms known to be
# unsafe today is the wrong shape for a control that vouches -- it is open by default
# and one shell feature away from wrong -- so only `-e`, `-u`, `-x` and `-o` with
# pipefail/errexit/nounset/xtrace are recognised, in the short, combined and long
# spellings. Anything else, `set +e` and `set -o noexec` alike, is simply not a
# shell-option line. Separators and expansions cannot appear in either arm, so
# `set -e; exit 0` is not one either. (CodeRabbit, PR #176.)
_SAFE_SHORT_OPTIONS = r"-[eux]+"
_SAFE_LONG_OPTIONS = r"-[eux]*o\s+(?:pipefail|errexit|nounset|xtrace)"
_SHELL_OPTION = re.compile(
    rf"set(?:\s+(?:{_SAFE_LONG_OPTIONS}|{_SAFE_SHORT_OPTIONS}))+"
)
# An `if:` may open a YAML block scalar and carry its condition on the following,
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


# INDENTATION IS DERIVED, NEVER ASSUMED.
#
# YAML fixes no indentation step. `jobs:` children at three spaces and job bodies at
# six are both valid Actions syntax, and the hard-coded four-space job body these
# expressions used to carry was a fail-OPEN defect: a job whose `if:` sat at six
# spaces was not seen, so the job read as UNCONDITIONAL -- and because the gate counts
# `skipped` as a pass, a conditional quality job that skipped was accepted as a check
# that ran. Every pattern below therefore takes the indentation it must match, which
# mapping_indent() reads off the document.
# The top-level `jobs:` key, in every form YAML allows for it: quoted either way, and
# with whitespace before the colon. Exact string equality against "jobs:" rejected all
# of those, and a file that parses as having no jobs is printed by directory mode as
# "not a workflow, skipped" and counted GREEN -- so a whole workflow's jobs escaped
# gate coverage on how its key was punctuated. Same fail-OPEN class as the quoted job
# key below, one level up.
JOBS_KEY = re.compile(r"""^(?:'jobs'|"jobs"|jobs)\s*:\s*(?:$|\{)""")
JOBS_DECL = re.compile(r"""^(?:'jobs'|"jobs"|jobs)\s*:""")


def is_block_scalar_header(raw):
    """Whether a `run:` value is a BLOCK-SCALAR HEADER rather than an inline command.

    Asked of the RAW value only. `BLOCK_SCALAR.match` applied to the DECODED command read
    `run: ">&2 echo upstream failed; exit 1"` as a folded body, because decoding a quoted
    scalar leaves a string that opens with `>`. A quoted scalar is by definition inline, so
    it is excluded before the header test runs at all.
    """
    value = raw.strip()
    if value[:1] in ("'", '"'):
        return False
    return bool(BLOCK_SCALAR.match(strip_inline_comment(value).strip()))


def job_key_pattern(indent):
    """A job key at exactly `indent`, quoted or bare, capturing the job id.

    A job key may be quoted -- `"security-scan":` is valid Actions syntax. The previous
    unquoted-only pattern silently dropped such a job from the `jobs` dict, so it could
    never appear in `set(jobs) - set(needs)` and the gate reported full coverage over a
    quality job it was not gating. That is a fail-OPEN result, the one outcome this
    script exists to prevent, so anything unclassifiable at job indentation now exits.
    """
    return re.compile(rf"""^ {{{indent}}}(?:'({ID})'|"({ID})"|({ID}))\s*:\s*(?:\#.*)?$""")


def key_pattern(indent, key):
    """One mapping key at exactly `indent`, quoted or bare, capturing its value.

    Quoting is admitted for EVERY key read through here rather than a chosen few.
    `'needs': [build, lint]` is valid YAML that the bare-only expression read as an
    empty dependency list, producing a false RED on a correct workflow; `'if':` is the
    fail-OPEN direction of the identical omission, since a job whose condition is not
    seen reads as unconditional.
    """
    return re.compile(rf"""^ {{{indent}}}(?:'{key}'|"{key}"|{key})\s*:\s*(.*?)\s*$""")


def block_need_pattern(indent):
    """A `needs:` block sequence item.

    Items may sit at the key's own indentation or be indented under it, and may be
    quoted. Both forms are valid YAML; accepting only the unquoted deeper form dropped
    entries, which ENLARGES `missing` and reddens a valid workflow.
    """
    return re.compile(rf"""^\s{{{indent},}}-\s*(?:'({ID})'|"({ID})"|({ID}))\s*(?:\#.*)?$""")


def step_key_pattern(indent, key):
    """A STEP-level key -- deeper than the job body -- in either the plain form
    (`        if: ...`) or as a list item's first key (`      - if: ...`).

    Group 1 is everything before the key, so its length is the key's own COLUMN. A
    block scalar's continuation must out-indent THAT, not the line: measuring the line
    put the bar at the `- ` of a dash-form step, so the sibling `run:` and its body
    were swallowed into the condition (see step_conditions).

    THE FLUSH SEQUENCE FORM IS THE REASON FOR THE FIRST ALTERNATIVE. YAML lets a
    sequence sit at its key's own column:

        steps:
        - if: ${{ needs.build.result != 'success' }}
          run: |
            exit 1

    Here the dash is at the JOB BODY column, one less than `indent`, so
    `\\s{indent,}` never reaches it and the first key after the dash is invisible.
    Only the first key is affected -- later keys are indented past it -- which is
    what makes this easy to test wrongly: a fixture whose step opens `- name:` and
    carries `if:` on a later line passes either way. Measured 2026-09-05 on two
    files differing only in that indentation: flush exited 1 with "has no step whose
    `if:` references a needs.<job>.result", indented exited 0. Both directions are
    false REDs rather than fail-open -- the sibling shape (`- run: |` first, `if:`
    second) reports "that step has no `run:` body" -- but a repository writing its
    gate in this perfectly ordinary form gets a permanently red required check.
    Found by CodeRabbit on the upstream review, after an earlier pass on
    the upstream review had wrongly refuted the same claim against a fixture
    that did not carry the key in the affected position.
    """
    # indent - 2, not indent - 1: `-\s+` contributes at least two characters, so this
    # bound is exactly the one that still guarantees the KEY lands at column >= indent,
    # which is the property every caller relies on. One column tighter and the form
    # this alternative exists to admit is rejected whenever the caller passes the key's
    # own column rather than the step column.
    dash = max(indent - 2, 0)
    return re.compile(
        rf"""^(\s{{{dash},}}-\s+|\s{{{indent},}}(?:-\s+)?)"""
        rf"""(?:'{key}'|"{key}"|{key})\s*:\s*(.*?)\s*$"""
    )


def other_block_key_pattern(indent):
    """Any OTHER step-body key that opens a block scalar (`run: |`, `run: >-`, ...).

    Its payload is arbitrary text -- a heredoc/echo line shaped like
    `if: contains(...)` inside a `run:` body is not a real YAML key, but
    step_key_pattern(indent, "if") cannot tell the difference by itself. Used to skip
    such spans wholesale before they reach it. Group 1 is the key's own indent prefix,
    same convention as step_key_pattern, so the span ends the same way: content must
    out-indent it.

    A QUOTED key (`'run': |`) and a TRAILING COMMENT (`run: | # build log`) are both
    admitted, because either spelling is valid YAML that this expression previously
    failed to recognise -- and failing to recognise the OPENER means the payload IS
    scanned. An inert `run:` body line then supplies the `needs.*.result` condition
    this script looks for, so the real aggregation `if:` can be deleted with the
    checker still green. Fail-OPEN, on the one assertion that decides what can merge.

    The flush sequence form takes the same first alternative as step_key_pattern, and
    for a sharper reason: failing to recognise a block-scalar OPENER means its payload
    IS scanned, so a `- run: |` written flush left its body open to supplying the
    `needs.*.result` this script looks for.
    """
    # indent - 2, not indent - 1: `-\s+` contributes at least two characters, so this
    # bound is exactly the one that still guarantees the KEY lands at column >= indent,
    # which is the property every caller relies on. One column tighter and the form
    # this alternative exists to admit is rejected whenever the caller passes the key's
    # own column rather than the step column.
    dash = max(indent - 2, 0)
    return re.compile(
        rf"""^(\s{{{dash},}}-\s+|\s{{{indent},}}(?:-\s+)?)(?:'{ID}'|"{ID}"|{ID})\s*:\s*"""
        r"""[|>](?:[0-9][+-]?|[+-][0-9]?)?\s*(?:\#.*)?$"""
    )


def _first_group(match):
    return next(g for g in match.groups() if g is not None)


def strip_comment(line):
    """Drop a trailing comment. Naive by design: a '#' inside a quoted scalar is not a
    shape this file's job/needs grammar admits, and guessing at YAML quoting rules here
    would be less predictable than the explicit exit below."""
    return line.split("#", 1)[0]


def strip_inline_comment(value):
    """Drop a YAML inline comment from a `run:` value. Two rules, both load-bearing.

    A `#` opens a comment only after WHITESPACE, so the shell parameter length `${#x}`
    is not one. The naive strip_comment above truncated `if [ ${#x} -eq 0 ]; then exit
    1; fi` at the brace and reported a correct gate as unfailable.

    A `#` inside a QUOTED YAML scalar is data, not a comment, and the quoted form has to
    be recognised before any stripping happens. Getting this wrong broke in both
    directions at once, which is why it is fixed here rather than at either caller:

      * fail-OPEN through gate_script_paths. `run: "printf 'tag # audit'; python
        .github/scripts/probe.py"` executes probe.py, but truncating at the hash hid the
        path, so the script escaped the HIGH-tier requirement -- on the very control
        assert_gate_scripts exists to be;
      * false RED through step_can_fail. `run: 'echo " # progress"; exit 1' # gate`
        became an unterminated fragment, so a gate that does fail read as one that
        cannot. (Measured: exit 1 before this change, exit 0 after.)

    A PLAIN (unquoted) scalar is deliberately left to the regex. There YAML itself ends
    the value at ` #`, so `run: printf 'tag # audit'` really is truncated before the
    shell ever sees it -- SHELL quotes do not protect a hash from YAML, and pretending
    they do would vouch for a command the runner never receives.

    (CodeRabbit, fixportal-ci-backend#140 and fixportal-ci-frontend#163.)
    """
    quote = value[:1]
    if quote not in ("'", '"'):
        return re.sub(r"(?m)(?<!\S)#[^\n]*", "", value)

    index = 1
    while index < len(value):
        char = value[index]
        if quote == '"' and char == BACKSLASH:
            index += 2
            continue
        if char == quote:
            # `''` inside a single-quoted scalar is an escaped quote, not the end.
            if quote == "'" and value[index + 1:index + 2] == "'":
                index += 2
                continue
            return value[: index + 1]
        index += 1
    # Unterminated. That is broken YAML either way, and returning the value whole errs
    # toward rejecting the step rather than vouching for a fragment of it.
    return value


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


def mapping_indent(lines, start, end):
    """The indentation of a mapping's first child, i.e. the indent all its keys share.

    Read rather than assumed: see the note above job_key_pattern. Returns None when the
    range holds nothing but comments and blanks.
    """
    for i in range(start, end):
        line = lines[i].rstrip("\r\n")
        if COMMENT_OR_BLANK.match(line):
            continue
        return len(line) - len(line.lstrip(" "))
    return None


def job_body_indent(lines, jobs, job_id, job_indent):
    """The indentation of one job's own keys, or None when the job has no body."""
    start = jobs[job_id]
    end = min((i for i in sorted(jobs.values()) if i > start), default=len(lines))
    indent = mapping_indent(lines, start + 1, end)
    if indent is None or indent <= job_indent:
        return None
    return indent


def read_gate_contract(lines, gate_job):
    try:
        # `jobs: # comment` is valid and used to fail the equality outright, returning no
        # jobs at all. JOBS_KEY also admits the quoted forms and a space before the
        # colon -- see its definition for why matching only "jobs:" was fail-open.
        jobs_start = next(
            i for i, line in enumerate(lines) if JOBS_KEY.match(strip_comment(line).rstrip())
        )
    except StopIteration:
        return {}, [], set()

    jobs_end = len(lines)
    for i in range(jobs_start + 1, len(lines)):
        line = lines[i].rstrip("\r\n")
        if line.strip() and not line.startswith((" ", "#")):
            jobs_end = i
            break

    job_indent = mapping_indent(lines, jobs_start + 1, jobs_end)
    if job_indent is None or job_indent == 0:
        return {}, [], set()
    job_key = job_key_pattern(job_indent)

    jobs = {}
    for i in range(jobs_start + 1, jobs_end):
        line = lines[i].rstrip("\r\n")
        if COMMENT_OR_BLANK.match(line):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent != job_indent:
            continue
        match = job_key.match(line)
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

    body_indent = job_body_indent(lines, jobs, gate_job, job_indent)
    if body_indent is None:
        return jobs, [], conditional_jobs(lines, jobs, job_indent)
    needs_key = key_pattern(body_indent, "needs")
    block_need = block_need_pattern(body_indent)

    gate_start = jobs[gate_job] + 1
    gate_end = min((i for i in jobs.values() if i >= gate_start), default=len(lines))
    for i in range(gate_start, gate_end):
        match = needs_key.match(lines[i].rstrip("\r\n"))
        if not match:
            continue
        if strip_comment(match.group(1)).strip():
            return (
                jobs,
                parse_need_ids(match.group(1)),
                conditional_jobs(lines, jobs, job_indent),
            )

        needs = []
        for line in lines[i + 1 : gate_end]:
            line = line.rstrip("\r\n")
            item = block_need.match(line)
            if item:
                needs.append(_first_group(item))
                continue
            # Skip comments and blanks BEFORE testing indentation: a comment sitting at
            # the key's own indentation used to end the sequence early and silently
            # truncate `needs`.
            if COMMENT_OR_BLANK.match(line):
                continue
            if len(line) - len(line.lstrip(" ")) <= body_indent:
                break
        return jobs, needs, conditional_jobs(lines, jobs, job_indent)

    return jobs, [], conditional_jobs(lines, jobs, job_indent)


def conditional_jobs(lines, jobs, job_indent):
    """The ids of jobs carrying a job-level `if:` condition.

    Job-level only. A step-level `if:` sits deeper and is out of scope -- a skipped
    step does not make the gate report green over a missing check, but it is outside this
    job-level scan. Each job's own body indentation is read rather than assumed, so a
    valid deeper `if:` cannot disappear and leave the job looking unconditional.
    """
    starts = sorted(jobs.values())
    conditional = set()
    for job_id, start in jobs.items():
        end = min((i for i in starts if i > start), default=len(lines))
        indent = job_body_indent(lines, jobs, job_id, job_indent)
        if indent is None:
            continue
        job_if = key_pattern(indent, "if")
        for i in range(start + 1, end):
            match = job_if.match(lines[i].rstrip("\r\n"))
            if match and normalise_condition(match.group(1)) not in ("always()", "!cancelled()"):
                conditional.add(job_id)
    return conditional


def tolerant_jobs(lines, jobs, job_indent):
    """The ids of jobs carrying an effective job-level `continue-on-error`."""
    starts = sorted(jobs.values())
    tolerant = set()
    for job_id, start in jobs.items():
        end = min((i for i in starts if i > start), default=len(lines))
        indent = job_body_indent(lines, jobs, job_id, job_indent)
        if indent is None:
            continue
        tolerant_key = key_pattern(indent, "continue-on-error")
        for i in range(start + 1, end):
            match = tolerant_key.match(lines[i].rstrip("\r\n"))
            if not match:
                continue
            value = strip_comment(match.group(1)).strip()
            if not value or is_block_scalar_header(value):
                body, _ = continuation_lines(lines, i, indent)
                value = " ".join(strip_comment(line).strip() for line in body)
            value = normalise_condition(value)
            # Two shapes the bare membership test misread, both false REDs on a feeder
            # that tolerates nothing: a block-scalar spelling (`continue-on-error: >`
            # then `false`) never unfolded past the header, and a compound like
            # `${{ false && inputs.allow_failure }}` survives normalisation as itself
            # while static_truth folds it to False (mirror fixportal-claude-skills#110;
            # unit review 2026-09-21). UNKNOWN stays tolerant -- an expression this
            # checker cannot fold may still evaluate true at runtime, and that is the
            # conservative direction.
            if value not in ("false", "") and static_truth(value) is not False:
                tolerant.add(job_id)
                break
    return tolerant


def job_block(lines, jobs, job_id):
    """The lines of one job's body, from its key to the next job key."""
    start = jobs[job_id]
    end = min((i for i in sorted(jobs.values()) if i > start), default=len(lines))
    return [line.rstrip("\r\n") for line in lines[start + 1 : end]]


def job_needs(lines, jobs, job_id, job_indent):
    """The direct `needs:` ids for one job, including block-list form."""
    start = jobs[job_id]
    end = min((i for i in sorted(jobs.values()) if i > start), default=len(lines))
    indent = job_body_indent(lines, jobs, job_id, job_indent)
    if indent is None:
        return set()
    needs_key = key_pattern(indent, "needs")
    block_need = block_need_pattern(indent)
    for i in range(start + 1, end):
        match = needs_key.match(lines[i].rstrip("\r\n"))
        if not match:
            continue
        value = strip_comment(match.group(1)).strip()
        if value:
            return set(parse_need_ids(value))
        result = set()
        for line in lines[i + 1 : end]:
            item = block_need.match(line.rstrip("\r\n"))
            if item:
                result.add(item.group(1) or item.group(2) or item.group(3))
                continue
            if COMMENT_OR_BLANK.match(line):
                continue
            if len(line) - len(line.lstrip(" ")) <= indent:
                break
        return result
    return set()


def normalise_condition(value):
    """`if:` value reduced to a comparable form.

    `always()`, `'always()'` and `${{ always() }}` are the same condition written three
    valid ways, and a check that accepted only one spelling would red a correct gate.
    Compound conditions survive normalisation as themselves (`always()&&x`) and so are
    correctly NOT equal to `always()` -- a gate that runs only sometimes is the defect
    being caught, not a spelling variant of the fix.
    """
    # Strip a WRAPPING quote pair only, decoding YAML's doubled-single-quote escape
    # as it goes. `.strip("'\"")` peeled any leading or trailing quote, so
    # `needs.build.result == 'failure'` lost its closing quote and stopped matching
    # FAILURE_CONDITION_ATOM -- a correct per-job gate then read as gating nothing,
    # which is a false RED on the house shape. A plain `value[1:-1]` fixed that but
    # missed the escape: `if: 'needs.build.result != ''success'''` left
    # `needs.build.result != ''success''` behind, which ALSO fails to match. Reusing
    # decode_yaml_scalar (already relied on for `run:` values) decodes the escape
    # too, and it is a no-op whenever the whole value isn't quote-wrapped, which is
    # every ordinary `if:` -- see its own guard. Found by CodeRabbit on the upstream
    # review.
    value = strip_comment(value).strip()
    decoded = decode_yaml_scalar(value)
    if decoded != value:
        value = decoded.strip()
    if value.startswith("${{") and value.endswith("}}"):
        value = value[3:-2]
    value = strip_whitespace_outside_quotes(value)
    return value.lower() if value.lower() in ("true", "false", "always()") else value


def strip_whitespace_outside_quotes(value):
    """Remove every space OUTSIDE a quoted span, leaving quoted content untouched.

    A blanket `.replace(' ', '')` altered quoted literals too: `'not equal' ==
    'notequal'` normalised to `'notequal'=='notequal'`, which static_truth then folds
    to True as an identity comparison -- although GitHub compares the two DIFFERENT
    strings and gets False. Folding a conjunct to True drops it from failure_atoms'
    residual, crediting the atom beside it as real coverage for a step whose actual
    compound condition is always false. Found by CodeRabbit on the upstream review.

    A double-quoted literal can itself contain an escaped quote (`_LITERAL` matches
    `\\"(?:\\\\.|[^\\"])*\\"`, same as split_top_level/strip_inline_comment), and this
    loop originally had no escape handling: `"a\\" b"` closed the string at the
    escaped quote, re-entered quote mode at the bare quote that follows, and stripped
    the space that was actually inside the literal -- `"a\\"b"`, comparing against
    `ab` instead of the intended `a" b`. Skipping two characters on a backslash
    inside a double-quoted span, exactly as those sibling functions do, is what
    keeps the escape from being read as a close. Found by Gitar on the upstream
    review.
    """
    out = []
    quote = None
    index = 0
    while index < len(value):
        char = value[index]
        if quote == '"' and char == BACKSLASH and index + 1 < len(value):
            out.append(char)
            out.append(value[index + 1])
            index += 2
            continue
        if quote is not None:
            out.append(char)
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"":
            quote = char
            out.append(char)
            index += 1
            continue
        if char != " ":
            out.append(char)
        index += 1
    return "".join(out)


# YAML's double-quoted escape table (single-character forms only -- \xNN/\uNNNN/\UNNNNNNNN
# are handled separately below), from the spec's own list. json.loads recognises a strict
# SUBSET of this: it accepts \n \t \r \" \/ \\ but rejects \0 \a \v \e \  \N \_ \L \P outright,
# so a value using any of those round-tripped through decode_yaml_double_quoted's predecessor
# came back unchanged, quotes and all. Two independent instances of that, found by CodeRabbit
# on two different repos' upstream reviews: \  (escaped space) in a condition whose author
# split it across a line-continuation, and \x28\x29 spelling out "()" in "always\x28\x29".
_YAML_SINGLE_ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r",
    "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\",
    "N": "", "_": " ", "L": " ", "P": " ",
}


def decode_yaml_double_quoted(inner):
    """Decode the escapes inside a double-quoted YAML scalar's already-unwrapped body.

    Line-continuation escapes (a backslash at end-of-line, folding into the next) are
    deliberately unhandled -- decode_yaml_scalar's own docstring scopes this to
    SINGLE-LINE `run:`/`if:` values, which is what a workflow file's own condition ever
    is. An unrecognised escape is left as the literal backslash-plus-character pair
    rather than raising: this is a best-effort normalisation feeding a pattern match,
    not a validator, and a value that fails to decode should read as itself, not vanish.
    """
    out = []
    index = 0
    length = len(inner)
    while index < length:
        char = inner[index]
        if char == BACKSLASH and index + 1 < length:
            next_char = inner[index + 1]
            if next_char in _YAML_SINGLE_ESCAPES:
                out.append(_YAML_SINGLE_ESCAPES[next_char])
                index += 2
                continue
            width = {"x": 2, "u": 4, "U": 8}.get(next_char)
            code_point = None
            if width is not None and index + 2 + width <= length:
                try:
                    code_point = int(inner[index + 2 : index + 2 + width], 16)
                except ValueError:
                    code_point = None
            if code_point is not None and code_point > 0x10FFFF:
                code_point = None
            if code_point is not None:
                out.append(chr(code_point))
                index += 2 + width
            else:
                out.append(char)
                out.append(next_char)
                index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def decode_yaml_scalar(value):
    """Decode the quoted single-line YAML scalars used for `run:` and `if:` values."""
    if len(value) < 2 or value[0] != value[-1] or value[0] not in "'\"":
        return value
    if value[0] == "'":
        inner = value[1:-1]
        return value if "'" in inner.replace("''", "") else inner.replace("''", "'")
    return decode_yaml_double_quoted(value[1:-1])


def split_top_level(expression, operator):
    parts = []
    start = 0
    depth = 0
    quote = None
    index = 0
    while index < len(expression):
        char = expression[index]
        if quote == '"' and char == BACKSLASH and index + 1 < len(expression):
            index += 2
            continue
        if quote == "'" and char == "'" and index + 1 < len(expression) and expression[index + 1] == "'":
            index += 2
            continue
        if quote is not None:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and expression.startswith(operator, index):
            parts.append(expression[start:index])
            index += len(operator)
            start = index
            continue
        index += 1
    parts.append(expression[start:])
    return parts


def strip_outer_parentheses(expression):
    while expression.startswith("(") and expression.endswith(")"):
        depth = 0
        closes_at_end = True
        quote = None
        for index, char in enumerate(expression):
            if quote is not None:
                if char == quote and (quote == "'" or index == 0 or expression[index - 1] != BACKSLASH):
                    quote = None
                continue
            if char in "'\"":
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and index != len(expression) - 1:
                    closes_at_end = False
                    break
        if not closes_at_end:
            break
        expression = expression[1:-1].strip()
    return expression


_UNKNOWN = object()
_LITERAL = r"(?:true|false|null|-?[0-9]+(?:\.[0-9]+)?|'(?:''|[^'])*'|\"(?:\\.|[^\"])*\")"


def literal_value(value):
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered == "null":
        return None
    if value.startswith("'"):
        return value[1:-1].replace("''", "'")
    if value.startswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return _UNKNOWN
    try:
        return float(value)
    except ValueError:
        return _UNKNOWN


def github_equal(left, right):
    if type(left) is type(right):
        return left.casefold() == right.casefold() if isinstance(left, str) else left == right

    def to_number(value):
        if value is None:
            return 0.0
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, float):
            return value
        if isinstance(value, str):
            if not value:
                return 0.0
            try:
                parsed = json.loads(value)
                return float(parsed) if isinstance(parsed, (int, float)) and not isinstance(parsed, bool) else math.nan
            except (json.JSONDecodeError, ValueError, OverflowError):
                return math.nan
        return math.nan

    left_number = to_number(left)
    right_number = to_number(right)
    return not (math.isnan(left_number) or math.isnan(right_number)) and left_number == right_number


def static_truth(condition):
    """Fold only literal boolean branches; unknown GitHub context/function values stay unknown."""
    expression = decode_yaml_scalar(strip_comment(condition).strip()).strip()
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression[3:-2].strip()
    expression = strip_outer_parentheses(expression)

    parts = split_top_level(expression, "||")
    if len(parts) > 1:
        values = [static_truth(part) for part in parts]
        if any(value is True for value in values):
            return True
        return False if all(value is False for value in values) else _UNKNOWN

    parts = split_top_level(expression, "&&")
    if len(parts) > 1:
        values = [static_truth(part) for part in parts]
        if any(value is False for value in values):
            return False
        return True if all(value is True for value in values) else _UNKNOWN

    expression = strip_outer_parentheses(expression)
    if expression.startswith("!"):
        value = static_truth(expression[1:])
        return not value if value is True or value is False else _UNKNOWN
    if expression.lower() == "true":
        return True
    if expression.lower() == "false":
        return False
    # `always()` is unconditionally true in GitHub Actions, so it is a literal boolean here
    # in every sense that matters. Leaving it UNKNOWN made failure_atoms keep it as a
    # residual conjunct in the common `always() && contains(needs.*.result, 'failure')`,
    # return None, and report a correct gate as referencing no `needs.<job>.result` at all
    # -- a false RED on the shape the gate's own job-level condition uses.
    #
    # Only always(). success(), failure() and cancelled() depend on the run, so they stay
    # UNKNOWN: folding those would be the fail-OPEN direction.
    if re.fullmatch(r"always\(\s*\)", expression, re.IGNORECASE):
        return True
    match = re.fullmatch(rf"\s*({_LITERAL})\s*(==|!=|<=|>=|<|>)\s*({_LITERAL})\s*", expression, re.IGNORECASE)
    if match:
        left = literal_value(match.group(1))
        right = literal_value(match.group(3))
        if left is _UNKNOWN or right is _UNKNOWN:
            return _UNKNOWN
        operation = match.group(2)
        if operation in ("==", "!="):
            return github_equal(left, right) == (operation == "==")
        if not isinstance(left, float) or not isinstance(right, float):
            return _UNKNOWN
        return {
            "<": left < right,
            "<=": left <= right,
            ">": left > right,
            ">=": left >= right,
        }[operation]
    return _UNKNOWN


def failure_atoms(normalised):
    """The failure atoms a normalised step condition aggregates on, else None.

    A conjunct that is statically TRUE cannot change whether the step runs, so it is
    dropped before matching: `contains(needs.*.result,'failure') && 'VALUE' == 'value'`
    gates exactly what the `contains` alone gates -- GitHub's `==` is case-insensitive --
    and refusing it would be a false RED on a condition that does aggregate. A
    statically FALSE conjunct makes the whole condition false, which the caller's
    static_truth check already discards.

    What survives must be a single OR-expression of recognised atoms. A residual
    CONJUNCTION of UNKNOWNS is refused rather than guessed at: `contains(...) && <unknown>`
    runs only when that unknown also holds, so the outcomes it covers are not the atoms'
    outcomes, and crediting them would vouch for coverage the gate does not have.

    One conjunction IS accepted, per OR-branch: a coverage atom narrowed by
    `!= 'skipped'` guards about the SAME job. That is the house shape for a conditional
    feeder -- `needs.secrets.result != 'success' && needs.secrets.result != 'skipped'` --
    and it covers exactly {failure, cancelled} for that job, which is what the atom
    already claims. Refusing it rejected fixportal-initiator's correct gate outright.
    """
    residual = [
        part
        for part in split_top_level(normalised, "&&")
        if static_truth(part) is not True
    ]
    if not residual:
        return None
    atoms = split_top_level(strip_outer_parentheses("&&".join(residual)), "||")
    matches = []
    for atom in atoms:
        match = resolve_atom(strip_outer_parentheses(atom))
        if match is None:
            return None
        matches.append(match)
    if not matches:
        return None
    return matches


def resolve_atom(atom):
    """One OR-branch as a coverage atom, or None when it covers nothing provable.

    A bare atom resolves to itself. A conjunction resolves only when it holds exactly one
    coverage atom and every other conjunct is a `!= 'skipped'` refinement naming that SAME
    job: the refinement narrows the atom's outcome set rather than adding a condition the
    checker cannot read. A refinement about a DIFFERENT job is refused -- it makes the step
    depend on that job's state too, so the atom no longer describes when the gate fails.
    """
    # Index and property access name the same job. Normalize only that reference;
    # arbitrary string contents must not turn into additional coverage atoms.
    atom = re.sub(rf"\bneeds\[['\"]({ID})['\"]\]\.result", r"needs.\1.result", atom)
    direct = FAILURE_CONDITION_ATOM.fullmatch(atom)
    if direct is not None:
        return direct

    conjuncts = [strip_outer_parentheses(part) for part in split_top_level(atom, "&&")]
    if len(conjuncts) < 2:
        return None

    coverage = None
    refined_jobs = set()
    for conjunct in conjuncts:
        match = FAILURE_CONDITION_ATOM.fullmatch(conjunct)
        if match is not None:
            if coverage is not None:
                return None
            coverage = match
            continue
        refinement = CONDITION_REFINEMENT.fullmatch(conjunct)
        if refinement is None:
            return None
        refined_jobs.add(refinement.group(1))

    if coverage is None:
        return None
    job_id = coverage.group(1) or coverage.group(3)
    if refined_jobs - {job_id}:
        return None
    return coverage


def continuation_lines(block, index, indent):
    """The block-scalar body opened on `block[index]`, plus the index after it.

    Continuation belongs to the KEY's column, not the line's: a `- if: >` step opens at
    the key while the line starts at the dash two columns to its left. Lines are
    returned stripped but with comments intact, because a `run:` body's `#` is shell,
    not YAML; callers that read YAML values strip comments themselves.
    """
    body = []
    following_index = index + 1
    while following_index < len(block):
        following = block[following_index]
        if COMMENT_OR_BLANK.match(following):
            following_index += 1
            continue
        if len(following) - len(following.lstrip()) <= indent:
            break
        body.append(following.strip())
        following_index += 1
    return body, following_index


def step_span(block, index, key_indent):
    """The (start, end) line range of the step containing the key at `index`.

    Steps are a YAML sequence, so the step begins at the nearest `- ` at or above the
    key whose dash sits left of it, and ends before the next line at or left of that
    dash. Returns None when the key is not inside a sequence item at all.
    """
    start = None
    for i in range(index, -1, -1):
        line = block[i]
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if stripped.startswith("- ") and indent < key_indent:
            start = i
            break
        if i != index and not COMMENT_OR_BLANK.match(line) and indent < key_indent:
            # A shallower key that is not a sequence item: this is not a step list.
            return None
    if start is None:
        return None

    dash_indent = len(block[start]) - len(block[start].lstrip())
    end = len(block)
    for i in range(start + 1, len(block)):
        line = block[i]
        if COMMENT_OR_BLANK.match(line):
            continue
        if len(line) - len(line.lstrip()) <= dash_indent:
            end = i
            break
    return start, end


def mask_quoted(line):
    """`line` with the contents of every quoted span blanked out.

    A SCANNER, not a regex. A `"[^"]*"` alternation ends a double-quoted span at the
    first quote it meets, and an ESCAPED quote is not the end of one:
    `echo "then \\" ; exit 1"` is a single inert string, but blanking only as far as
    the escaped quote left `; exit 1"` looking like a real command, which
    ends_non_zero would then have accepted. That is the fail-OPEN direction, so it is
    worth the extra ten lines. POSIX single quotes have no escapes at all, so only the
    double-quoted arm consumes a backslash.

    An unterminated quote blanks the rest of the line. That is broken shell either
    way, and refusing to find an exit there errs toward rejecting the step rather than
    passing it.
    """
    out = []
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote != "'" and char == BACKSLASH and index + 1 < len(line):
            out.append("  ")
            index += 2
            continue
        if quote is None and char in "'\"":
            quote = char
            out.append(" ")
        elif quote == char:
            quote = None
            out.append(" ")
        elif quote is not None:
            out.append(" ")
        else:
            out.append(char)
        index += 1
    return "".join(out)


def ends_non_zero(body):
    """True when the gate body is a RECOGNISED failing form, as a WHOLE.

    This used to split a de-quoted, de-commented line on command separators and accept
    any segment starting `exit <n>` or `false`. Four independent escapes were found in
    that one heuristic, each producing a step that exits 0 while reading as failable:

      * `echo "\\n exit 1 \\n"` and a backslash-continued `echo \\ / exit 1` -- quote
        state was per physical line, so inert string content read as a command;
      * `echo then exit 1` -- `then` is a COMMAND_BOUNDARY, so the argument split the
        line and `exit 1` became a segment of its own;
      * `exit 1 | true` -- no single `|` in the boundary alternation, and the pattern
        matched on a prefix;
      * `false || true` -- same shape, opposite operator.

    Four escapes is a fact about the approach, not about the patches. So the checker no
    longer parses arbitrary shell: it recognises a small set of verified forms and
    rejects everything else with a message naming what it supports. A gate step is the
    one place in a workflow where an exotic shell body buys nothing.

    The verdict is over the COMPLETE body, not the first matching line. Accepting any
    matching segment validated `exit 0` followed by an unreachable `exit 1` -- the step
    exits ZERO at run time on the first line while the checker vouches for the second.
    So every line before the failing command must be a MESSAGE or a `set` SHELL-OPTION
    line -- the two prefixes that cannot re-decide the exit status -- and the final line
    must fullmatch an accepted form. Anything else is refused rather than parsed.

    `body` is the joined run: body, with backslash continuations already folded.
    """
    # A COMMAND SUBEXPRESSION CAN EXIT THE STEP BEFORE THE FAILING COMMAND RUNS. Under
    # `shell: pwsh`, `echo "$(exit 0)"` exits ZERO during expansion, and mask_quoted
    # blanks the string to a bare `echo` that reads as an ordinary message line -- so a
    # body of `echo "$(exit 0)"` then `throw` was vouched for while the step succeeds.
    # This predates the message-prefix rule: the same body passed the any-line rule on
    # its `throw` alone. What the subexpression does cannot be read from the file, which
    # is the basis on which this function vouches at all, so it is refused rather than
    # parsed. GitHub substitutes `${{ ... }}` textually before the shell parses
    # the body, so an expression can splice a separator or early exit into an
    # otherwise inert message line. Keep expressions in `env:` instead.
    # (CodeRabbit, PR #176.)
    if "$(" in body:
        return False
    if "${{" in body:
        return False
    if re.search(r"\bthrow\s+[@(]", body):
        return False
    if re.search(r"\bexit\s+[^\s\n;|&<>]*['\"]", body):
        return False
    text = mask_quoted(body)
    # Drop comments AFTER masking, so a `#` inside a string is not treated as one.
    text = re.sub(r"(?m)(?<!\S)#[^\n]*", "", text)
    # Normalise whitespace per logical line and drop the empties.
    segments = [
        segment
        for segment in (" ".join(logical.split()) for logical in text.split("\n"))
        if segment
    ]
    if not segments:
        return False
    for segment in segments[:-1]:
        if not (_MESSAGE.fullmatch(segment) or _SHELL_OPTION.fullmatch(segment)):
            return False
    return any(form.fullmatch(segments[-1]) for form in ACCEPTED_FAILING_FORMS)


def step_can_fail(block, span, key_indent):
    """(ok, reason) for the step spanning `span`: can it actually fail its job?

    A condition proves only that the aggregation step is REACHED. `continue-on-error:
    true`, or a body whose `exit 1` has been replaced by `true`, leaves the condition
    untouched while the required context stays green -- the same fail-OPEN outcome the
    condition check exists to prevent, and equally invisible in a diff that keeps the
    job, its name and its needs: list intact.

    CEILING, stated rather than implied: the `run:` body is read as COMMANDS, not
    executed, so an `exit 1` that is never reached at run time -- inside
    `if false; then exit 1; fi`, or after an early `exit 0` -- still counts. Closing
    that would mean evaluating arbitrary shell, which is unbounded; it is the same
    reasoning assert_workflow_hygiene's checkout scan states for its own shell gap.
    What is refused here is the shapes a neutering diff actually takes: delete the
    exit, swap in `true`, or add continue-on-error. Inert TEXT is not accepted --
    see ends_non_zero.
    """
    start, end = span
    # Keys are matched at the step's OWN column, so a `continue-on-error: true` line
    # sitting inside the `run:` payload -- shell text, not a YAML key -- is not read as
    # one. Same distinction other_block_key_pattern draws, for the same reason.
    tolerant_key = step_key_pattern(key_indent, "continue-on-error")
    for i in range(start, end):
        match = tolerant_key.match(block[i])
        if not match or len(match.group(1)) != key_indent:
            continue
        value = strip_comment(match.group(2)).strip()
        if not value or is_block_scalar_header(value):
            body, _ = continuation_lines(block, i, key_indent)
            value = " ".join(strip_comment(line).strip() for line in body)
        value = normalise_condition(value)
        # The job-level sibling consults static_truth for the same expression: a
        # compound like `${{ false && inputs.allow_failure }}` normalises to itself but
        # folds to False, and a step whose continue-on-error cannot evaluate true CAN
        # still fail the job. Without the consult the two levels disagreed about the
        # same expression (unit review 2026-09-21). UNKNOWN stays cannot-fail, the
        # conservative direction.
        if value not in ("false", "") and static_truth(value) is not False:
            return False, "carries `continue-on-error`, so it cannot fail the job"

    shell = "bash"
    shell_key = step_key_pattern(key_indent, "shell")
    for i in range(start, end):
        match = shell_key.match(block[i])
        if match and len(match.group(1)) == key_indent:
            shell = decode_yaml_scalar(strip_inline_comment(match.group(2)).strip()).strip()
            break
    if shell not in ("bash", "bash {0}", "pwsh", "pwsh {0}"):
        return False, f"uses unsupported shell `{shell}`"

    run_key = step_key_pattern(key_indent, "run")
    for i in range(start, end):
        match = run_key.match(block[i])
        if not match or len(match.group(1)) != key_indent:
            continue
        raw = match.group(2).strip()
        value = decode_yaml_scalar(raw)
        if value == raw:
            value = decode_yaml_scalar(strip_inline_comment(raw).strip())
        # Block-scalar-ness is a property of the RAW header, never of the decoded command.
        # Testing the decoded text read `run: ">&2 echo upstream failed; exit 1"` as a
        # FOLDED body, because decoding leaves a string opening with `>`. That step then
        # supplied no coverage and the gate went red over a command that does fail -- a
        # false RED. (CodeRabbit, fixportal-claude-skills#106.)
        if value and not is_block_scalar_header(raw):
            body = [value]
        else:
            body, _ = continuation_lines(block, i, key_indent)
        # A FOLDED body (`run: >`) joins its lines with spaces at run time, so the
        # command that actually executes is not any line in the file. Reading it
        # line-by-line would vouch for a command nobody wrote.
        #
        # Read off the RAW header, not the decoded command, for the same reason as above:
        # `run: ">&2 echo ...; exit 1"` decodes to a string opening with `>` and is not
        # folded at all.
        if is_block_scalar_header(raw) and raw.lstrip().startswith(">"):
            return False, "uses a folded `run:` body, whose executed command cannot be verified line-by-line"
        # JOIN first, then fold backslash continuations, so quote state and continued
        # commands are carried across line boundaries. Evaluating each physical line
        # with its own quote state is what let `echo "\n exit 1 \n"` and a
        # backslash-continued echo read as failable commands.
        joined = "\n".join(body)
        joined = re.sub(r"\\\n\s*", " ", joined)
        if shell.startswith("pwsh"):
            # STRIP COMMENTS BEFORE THE FULLMATCH, the way the bash path already does.
            # `continuation_lines` keeps comments intact deliberately, and ends_non_zero
            # masks then strips them (below). This arm did neither, so a pwsh
            # `throw "..." # note` inside a `run: |` block was refused outright while the
            # identical bash `exit 1 # note` was accepted and the same pwsh throw written
            # inline passed via strip_inline_comment. A false RED on a gate that does
            # fail. (Issue #232.)
            #
            # Located in the MASKED copy, not stripped by a blind re.sub: mask_quoted
            # preserves offsets exactly -- every branch emits as many characters as it
            # consumes -- so a span found there cuts the original at the right place,
            # while a `#` inside the throw's own quoted message stays masked and is left
            # alone. A blind sub would eat that message and fail the fullmatch for an
            # unrelated reason. Removed back-to-front so earlier offsets stay valid.
            probe = joined
            masked = mask_quoted(probe)
            for comment in reversed(list(re.finditer(r"(?m)(?<!\S)#[^\n]*", masked))):
                probe = probe[: comment.start()] + probe[comment.end() :]
            if not re.fullmatch(
                r"\s*throw(?:\s+(?:'[^'\n]*'|\"[^\"\n]*\"))?\s*", probe
            ):
                return False, "uses pwsh; only an unconditional throw with an optional static message is supported"
        if ends_non_zero(joined):
            return True, ""
        return False, (
            "its `run:` body is not a recognised failing form, so this checker will not "
            "vouch for it. Use one of: `exit 1`; `false`; `echo \"...\"; exit 1`; or, "
            "under `shell: pwsh`, an unconditional `throw`. Each may carry a trailing "
            "redirection, and may be preceded by message lines (`echo`/`printf`) and "
            "`set` shell-option lines only. A command subexpression `$(...)` anywhere "
            "in the body is refused: under pwsh it can exit the step before the failing "
            "command runs. "
            "A gate step is not the place for shell this checker has to guess about, "
            "and a body guarded by its own `||`/`&&`/`if` test is refused because it "
            "exits ZERO on the other branch"
        )
    return False, "has no `run:` body, so it cannot fail the job"


def step_conditions(block, indent):
    """Every step-level `if:` condition in a job body, block scalars included.

    Yields (condition, line index). The index is the caller's handle on the step the
    condition belongs to, which is what step_span/step_can_fail need to answer the
    separate question of whether that step can fail.

    A preceding step's own block scalar (`run: |`, `run: >-`, ...) is skipped
    wholesale before its lines ever reach the `if:` pattern: its payload is arbitrary
    text, and a heredoc/echo line shaped like `if: contains(needs.*.result, ...)`
    is not a real YAML key. Without this, deleting the actual step-level `if:`
    while a diagnostic `run:` body still echoed a `needs.*.result`-shaped string
    let the gate keep reporting a condition that no longer existed -- the same
    fail-OPEN shape assert_gate_semantics's own docstring already documents for a
    different line. Found by CodeRabbit on the upstream review.
    """
    step_if_value = step_key_pattern(indent, "if")
    other_block_key = other_block_key_pattern(indent)
    index = 0
    skip_until_indent = None
    while index < len(block):
        line = block[index]

        if skip_until_indent is not None:
            if COMMENT_OR_BLANK.match(line) or len(line) - len(line.lstrip()) > skip_until_indent:
                index += 1
                continue
            skip_until_indent = None
            # Fall through: this line is back at or above the opener's indent, so it
            # may itself be a real `if:` (or another block-scalar opener) and must be
            # examined normally rather than skipped.

        match = step_if_value.match(line)
        if match:
            key_column = len(match.group(1))
            for prior in range(index, -1, -1):
                prefix = block[prior].lstrip()
                prior_indent = len(block[prior]) - len(prefix)
                if prefix.startswith("- ") and prior_indent < key_column:
                    key_column = prior_indent + 2
                    break
            if len(match.group(1)) != key_column:
                index += 1
                continue
            value = strip_comment(match.group(2)).strip()
            if value and not BLOCK_SCALAR.match(value):
                yield value, index
                index += 1
                continue
            # An empty value or a block-scalar indicator: the condition is on the
            # following lines, indented past the `if:` KEY -- its own column, not the
            # line's. Measuring the line put the bar at the dash of a `- if: >-` step,
            # so the sibling `run:` at the key's column and its whole body were
            # absorbed into the condition.
            body, following_index = continuation_lines(block, index, len(match.group(1)))
            yield " ".join(strip_comment(entry).strip() for entry in body), index
            index = following_index
            continue

        other_block = other_block_key.match(line)
        if other_block:
            skip_until_indent = len(other_block.group(1))
        index += 1


def assert_gate_semantics(workflow_path, lines, jobs, gate_job, needs):
    block = job_block(lines, jobs, gate_job)
    gate_line = lines[jobs[gate_job]]
    job_indent = len(gate_line) - len(gate_line.lstrip(" "))
    body_indent = job_body_indent(lines, jobs, gate_job, job_indent)
    if body_indent is None:
        sys.exit(f"{workflow_path}: '{gate_job}' has an empty body -- it asserts nothing.")
    job_if_value = key_pattern(body_indent, "if")

    condition = None
    for i, line in enumerate(block):
        match = job_if_value.match(line)
        if not match:
            continue
        value = strip_comment(match.group(1)).strip()
        if value and not BLOCK_SCALAR.match(value):
            condition = value
        else:
            # `if: >` carrying `always()` on the following more-indented lines is the
            # same condition as the inline spelling, and valid YAML. Reading only the
            # header captured `>`, which normalises to itself and never equals
            # `always()` -- a false RED on a correct gate. The step-level scan has read
            # continuations all along; this is the job level catching up.
            body, _ = continuation_lines(block, i, body_indent)
            condition = " ".join(strip_comment(entry).strip() for entry in body)
        break

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
    # as "aggregates its needs". Found by Gitar on the upstream review.
    # ONE binding, used by both the scan below and the failure-capability check further
    # down. They were computed independently as `body_indent + 1` in two places, and they
    # must be equal: the second re-matches a line the first already matched, so a future
    # edit to one alone would make that re-match return None and raise AttributeError
    # instead of printing this script's own diagnostic. A crash is a worse signal than a
    # clean fail-closed exit. Found by CodeRabbit on the upstream review.
    step_indent = body_indent + 1

    referenced = {}
    failing = []
    for condition, index in step_conditions(block, step_indent):
        # A condition that is statically false never enforces anything, however
        # well-formed its atoms look, so it cannot count toward coverage.
        if static_truth(condition) is False:
            continue
        matches = failure_atoms(normalise_condition(condition))
        if matches is None:
            continue
        coverage = []
        for match in matches:
            job_id = match.group(1) or match.group(3)
            outcome = match.group(2) or match.group(4)
            outcomes = {outcome} if outcome else {"failure", "cancelled"}
            referenced.setdefault(job_id, set()).update(outcomes)
            coverage.append((job_id, outcomes))
        failing.append((condition, index, coverage))

    if not referenced:
        sys.exit(
            f"{workflow_path}: '{gate_job}' has no step whose `if:` references a "
            "`needs.<job>.result`.\n"
            "The gate aggregates nothing and reports success unconditionally. A "
            "`needs.*.result` appearing only in a `run:` body -- an echo of the upstream "
            "results, say -- gates nothing."
        )

    # EVERY declared dependency, not merely one of them. Accepting the first
    # `needs.<job>.result` it saw meant a gate declaring `needs: [build, lint]` whose
    # condition named only `build` passed this assertion while a lone `lint` failure
    # left the required context green -- the exact fail-OPEN shape the assertion
    # exists to refuse, reached by deleting half a condition rather than all of it.
    # The parser already had the full needs: set and simply was not consulting it.
    wildcard = referenced.get("*", set())
    uncovered = sorted(
        f"{job_id}:{outcome}"
        for job_id in needs
        for outcome in ("failure", "cancelled")
        if outcome not in wildcard and outcome not in referenced.get(job_id, set())
    )
    if uncovered:
        sys.exit(
            f"{workflow_path}: '{gate_job}' step conditions do not cover "
            f"{', '.join(uncovered)}.\n"
            "Every dependency must make the gate fail for both failure and cancellation. "
            "Use `needs.<job>.result != 'success'`, or cover both terminal results."
        )

    # A condition proves the step is REACHED, not that reaching it costs anything. See
    # step_can_fail: continue-on-error, or a body with no non-zero exit, keeps the
    # condition intact and the required context green.
    # ACCUMULATE the dependencies covered by steps that can actually fail, rather than
    # breaking on the first failable step. With a per-job gate -- the shape this script's
    # own docstring blesses -- one step could be neutered while another stayed failable,
    # and the `break` accepted the whole gate on that one survivor: the fail-open the
    # coverage assertion above closes, reopened one assertion later.
    reason = "could not be located as a step in the job body"
    reported = failing[0][0]
    covered = {}
    step_if_value = step_key_pattern(step_indent, "if")
    for condition, index, coverage in failing:
        reported = condition
        match = step_if_value.match(block[index])
        # Guarded rather than assumed. `index` came from a line this very pattern
        # matched, so None is unreachable while the two uses share step_indent above --
        # which is exactly the invariant a future edit could break, and the failure would
        # be an AttributeError rather than this script's own message.
        if match is None:
            continue
        span = step_span(block, index, len(match.group(1)))
        if span is None:
            continue
        ok, reason = step_can_fail(block, span, len(match.group(1)))
        if not ok:
            continue
        for job_id, outcomes in coverage:
            covered.setdefault(job_id, set()).update(outcomes)

    if not covered:
        sys.exit(
            f"{workflow_path}: '{gate_job}' aggregates on `if: {reported}` but that "
            f"step {reason}.\n"
            "A condition that is reached and then does nothing leaves the required "
            "context green over a failed dependency, exactly as a missing condition "
            "does. Give the step a `run:` body that exits non-zero, and do not mark it "
            "continue-on-error."
        )

    wildcard = covered.get("*", set())
    unenforced = sorted(
        f"{job_id}:{outcome}"
        for job_id in needs
        for outcome in ("failure", "cancelled")
        if outcome not in wildcard and outcome not in covered.get(job_id, set())
    )
    if unenforced:
        sys.exit(
            f"{workflow_path}: '{gate_job}' leaves {', '.join(unenforced)} referenced "
            "only by steps that cannot fail.\n"
            "A dependency outcome named in a condition whose step carries "
            "continue-on-error, or whose body cannot exit non-zero, is not gated at all."
        )

def parse_jobs(workflow_path):
    """The job-name set for one file, read once so callers can validate exemptions
    against it before (or across, in directory mode) running the full assertion.

    utf-8-sig, not utf-8: see the note on the main read in assert_gate_coverage.
    """
    with open(workflow_path, encoding="utf-8-sig") as handle:
        lines = handle.readlines()
    jobs, _, _ = read_gate_contract(lines, "")
    return set(jobs)


# A repo-local script invoked from a `run:` body. Deliberately a small, closed set of
# directory roots rather than "any path with a script extension": the point is to catch
# a checker the repository authored and wired into the merge barrier, and widening this
# to every path-shaped token would start matching tool arguments and report files.
#
# The candidate is only ever a CANDIDATE -- it must also exist on disk before anything
# is asserted about it (see gate_script_paths). That existence test is what keeps a
# script name inside an `echo` message, or a path that a later commit deleted, from
# reddening a repository over a file it does not have.
#
# BOTH SEPARATORS, EITHER CASE. Windows resolves a path case-insensitively and accepts
# `\` as well as `/`, so on a windows-latest runner `.\scripts\probe.ps1` and
# `./scripts/probe.PS1` run the repo-local script exactly as the POSIX spelling does.
# Admitting only `/` and lowercase extensions meant gate_script_paths never saw either,
# assert_gate_scripts asserted nothing, and a repo-authored gate script stayed editable
# in a NORMAL-tier pull request -- reachable by punctuation rather than by deleting
# anything, which is the precise hole assert_gate_scripts exists to close. Widening here
# widens DETECTION only: more scripts are required HIGH, never fewer. That is the
# opposite error direction from widening an accept-list, which is why it is safe to do
# and an ACCEPTED_FAILING_FORMS widening was not.
#
# Probed on a mini-repo (issue #230): `.\scripts\probe.ps1` and `./scripts/probe.PS1`
# both exited 0 -- green, ungated -- while the POSIX control `./scripts/probe.ps1`
# exited 1 with "not tiered HIGH".
GATE_SCRIPT = re.compile(
    # The extension set is deliberately closed: these are the gate-script languages
    # supported by the estate checker. Add a new extension here and to the policy
    # review before wiring it into a merge barrier. Spelled as character classes rather
    # than an inline `(?i:...)` group, which needs Python 3.11 -- this asset runs on
    # whatever python3 a consuming repository's runner provides.
    r"""(?<![\w.-])\.?[\\/]?((?:\.github[\\/]scripts|scripts|build|tools)[\\/]"""
    r"""[\w.\\/-]*\.(?:[Pp][Ss]1|[Pp][Yy]|[Ss][Hh]))\b"""
)
# A `run:` key at any depth. Group 1 is everything before the key, so its LENGTH is the
# key's own column -- which is what continuation_lines needs to find a block scalar's
# body. Same reasoning as step_key_pattern, and the same dash-form hazard: a `- run: |`
# opens at the key, two columns right of the dash.
RUN_KEY = re.compile(r"""^(\s*(?:-\s+)?)(?:'run'|"run"|run)\s*:\s*(.*?)\s*$""")
LOCAL_USES = re.compile(r"""^\s*(?:-\s+)?(?:'uses'|"uses"|uses)\s*:\s*['"]?((?:\./|\$/)[^\s#'"]+)""")
# The `runs:` key of an action's metadata, anchored at column ZERO like JOBS_KEY: that is
# where action metadata carries it, and the anchor keeps a `runs:`-shaped line inside a
# reusable workflow's (always indented) run: body from being read as metadata. The colon
# in the pattern is what keeps `runs-on:` from matching.
RUNS_KEY = re.compile(r"""^(?:'runs'|"runs"|runs)\s*:\s*(.*?)\s*$""")
def parse_flow_mapping(text):
    """The depth-1 entries of a `{...}` flow mapping as (key, value) pairs, or None.

    A hand parser, because the regex scan it replaces was wrong in both directions. A
    quoted span is data, not syntax: `{note: "{using: composite}", using: docker}` held
    the decoy first and a regex returned composite, so the real non-composite entry was
    never read -- fail-OPEN. And a naive strip_comment cut a quoted '#'
    (`{main: "x # y", using: ...}`), leaving an unterminated fragment that raised on
    valid YAML -- a false RED. (CodeRabbit, PR #228.) So quotes are tracked, a '#'
    opens a comment only outside quotes (after whitespace or at a line start, per the
    YAML rule), keys may be quoted exactly as key_pattern admits in block style, and a
    nested flow value is skipped with its own depth walk so its braces never move the
    outer count.

    None when the text is not a flow mapping or is unterminated -- the caller then
    raises, because "cannot classify" must never read as "composite".
    """
    length = len(text)

    def skip_gap(i):
        while i < length:
            if text[i] in " \t\r\n":
                i += 1
            elif text[i] == "#":
                newline = text.find("\n", i)
                i = length if newline == -1 else newline + 1
            else:
                break
        return i

    def read_quoted(i):
        quote = text[i]
        i += 1
        chars = []
        while i < length:
            char = text[i]
            if quote == '"' and char == BACKSLASH and i + 1 < length:
                chars.append(text[i + 1])
                i += 2
                continue
            if char == quote:
                if quote == "'" and i + 1 < length and text[i + 1] == "'":
                    chars.append("'")
                    i += 2
                    continue
                return "".join(chars), i + 1
            chars.append(char)
            i += 1
        return "".join(chars), i

    def read_bare(i):
        start = i
        while i < length and text[i] not in ",{}: \t\r\n":
            i += 1
        return text[start:i], i

    index = skip_gap(0)
    if index >= length or text[index] != "{":
        return None
    depth = 1
    index += 1
    entries = []
    while index < length and depth > 0:
        index = skip_gap(index)
        if index >= length:
            break
        char = text[index]
        if char == "{":
            depth += 1
            index += 1
            continue
        if char == "}":
            depth -= 1
            index += 1
            continue
        if char == ",":
            index += 1
            continue
        if depth != 1:
            # Inside a nested mapping: quoted spans stay atomic so their content
            # (braces, commas, colons) never reaches the outer walk.
            if char in "'\"":
                _, index = read_quoted(index)
            else:
                index += 1
            continue
        if char in "'\"":
            key, index = read_quoted(index)
        else:
            key, index = read_bare(index)
        index = skip_gap(index)
        if index >= length or text[index] != ":":
            continue
        index = skip_gap(index + 1)
        if index < length and text[index] in "'\"":
            value, index = read_quoted(index)
        elif index < length and text[index] == "{":
            nested_depth = 0
            while index < length:
                char = text[index]
                if char in "'\"":
                    _, index = read_quoted(index)
                    continue
                if char == "{":
                    nested_depth += 1
                elif char == "}":
                    nested_depth -= 1
                    if nested_depth == 0:
                        index += 1
                        break
                index += 1
            value = None
        else:
            value, index = read_bare(index)
        if value is not None:
            entries.append((key, value))
    if depth != 0:
        return None
    return entries


def resolve_runs_using(lines, target):
    """The action's `runs.using` value, or None when the file has no `runs:` key.

    Scoped to the `runs:` mapping. The whole-file regex this replaces matched the first
    `using:`-shaped line ANYWHERE, which was wrong in both directions:

      * a block scalar (a multi-line description, an embedded script) holding an
        indented `'using': javascript` line matched BEFORE the real mapping, so a valid
        composite action raised -- a false RED on a healthy action (CodeRabbit,
        fixportal-fixatdl#148);
      * a flow-style `runs: {using: node20, main: index.js}` never matched the
        line-anchored pattern at all, so `using` stayed unset and the non-composite
        guard was skipped -- fail-OPEN (issue #227).

    A `runs:` key holding no readable `using` entry RAISES rather than skipping the
    guard: "cannot classify" must never read as "composite". None (no `runs:` at all)
    remains the reusable-workflow path, which carries no such guard.
    """
    for start, line in enumerate(lines):
        match = RUNS_KEY.match(line)
        if match:
            break
    else:
        return None
    value = strip_comment(match.group(1)).strip()
    if value.startswith("{"):
        # A flow mapping is PARSED, not regexed (parse_flow_mapping for the why and the
        # mechanics). The regex scan this replaces read `using` out of quoted text and
        # without depth context: `{note: "{using: composite}", using: docker}` returned
        # composite because the decoy sat first -- fail-OPEN -- and the naive
        # strip_comment ahead of it cut a quoted '#', turning valid YAML into an
        # unterminated fragment that raised -- a false RED. (CodeRabbit, PR #228.) The
        # parser reads the RAW text (so a comment marker inside quotes survives), takes
        # `using` only from a depth-1 key, and returns None on an unterminated mapping,
        # which falls to the fail-closed raise below rather than classifying a fragment.
        entries = parse_flow_mapping("\n".join([match.group(1)] + list(lines[start + 1 :])))
        if entries is not None:
            for entry_key, entry_value in entries:
                if entry_key == "using":
                    return entry_value
    elif not value:
        # Block style: `using` is a child key of the mapping, at the indentation every
        # key in it shares -- read off the document, never assumed. The mapping ends at
        # the next line back at column zero.
        end = len(lines)
        for i in range(start + 1, len(lines)):
            candidate = lines[i]
            if candidate.strip() and not candidate.startswith((" ", "#")):
                end = i
                break
        child = mapping_indent(lines, start + 1, end)
        if child is not None:
            using_key = key_pattern(child, "using")
            for i in range(start + 1, end):
                entry = using_key.match(lines[i])
                if entry:
                    return decode_yaml_scalar(strip_comment(entry.group(1)).strip()).strip()
    raise ValueError(
        f"{target}: `runs:` is present but holds no readable `using:` entry, so whether "
        "the body is composite cannot be verified -- refusing to follow it"
    )


def glob_to_regex(pattern):
    """A gitignore-style policy glob as an anchored regex.

    A DELIBERATE MIRROR of glob_to_regex in the pr-review-policy hook, which is what
    actually tiers a pull request:

        **/  -> (.*/)?     **  -> .*     *  -> [^/]*     ?  -> [^/]

    Mirrored rather than approximated because the two must agree exactly. A checker
    stricter than the hook reports a false RED on a repository the hook already tiers
    HIGH -- for instance one covering its scripts with `scripts/**` instead of naming
    each file -- and a false RED on a required check is what gets a working control
    deleted to make CI green.

    Placeholders keep emitted output out of reach of later substitutions, for the same
    reason the shell version uses them: rewriting `**/` to `(.*/)?` first and then
    applying the `*` rule mangles the `*` that rule just emitted.
    """
    out = re.escape(pattern)
    # re.escape escapes the glob metacharacters too, so match them in escaped form.
    out = out.replace(r"\*\*/", "\x01").replace(r"\*\*", "\x02")
    out = out.replace(r"\*", "\x03").replace(r"\?", "\x04")
    out = out.replace("\x01", "(?:.*/)?").replace("\x02", ".*")
    out = out.replace("\x03", "[^/]*").replace("\x04", "[^/]")
    return re.compile(rf"^{out}$")


def matches_any(path, patterns):
    """The first pattern that tiers `path`, or None. Case-sensitive, like the hook."""
    for pattern in patterns:
        if glob_to_regex(pattern).match(path):
            return pattern
    return None


def policy_root(workflow_path):
    """The nearest ancestor directory holding `.claude/review-policy.json`, or None.

    Resolved by walking UP from the workflow file rather than from the process's working
    directory, so the check behaves the same whether CI runs it from the repository root
    or a test runs it against a workflow in a temporary directory. None means no policy
    is in scope and nothing is asserted -- a repository without a review policy tiers
    everything NORMAL, and review-policy-guard.yml is what owns that absence.
    """
    for parent in Path(workflow_path).resolve().parents:
        if (parent / ".claude" / "review-policy.json").is_file():
            return parent
        if (parent / ".git").exists():
            break
    return None


def run_payload_indexes(lines):
    """The line indexes consumed by block-scalar `run:` payloads in `lines`.

    A `run: |` body is SHELL TEXT at workflow indentation, and a LOCAL_USES scan over
    physical lines cannot tell it from syntax: an indented `uses: ./action` inside the
    payload -- a heredoc writing an action manifest, say -- matched and read as a local
    delegation. A missing target was silently ignored, but an EXISTING non-composite one
    raised the ValueError in delegated_run_bodies and failed gate coverage over a line
    the workflow never executes as a step. That is a false RED on a correct workflow --
    the direction that gets a working control deleted to make CI green. (CodeRabbit,
    fixportal-claude-skills#110.)

    Only BLOCK-SCALAR payloads are indexed. A single-line `run: foo` carries its command
    on the `run:` line itself, which starts with the key and so cannot match LOCAL_USES.
    The value test reads the COMMENT-STRIPPED value, exactly as the run-body loops in
    delegated_run_bodies and gated_run_bodies do -- `run: | # build log` is a real
    spelling, and BLOCK_SCALAR is anchored.
    """
    payloads = set()
    index = 0
    while index < len(lines):
        match = RUN_KEY.match(lines[index])
        if not match:
            index += 1
            continue
        value = strip_inline_comment(match.group(2)).strip()
        if BLOCK_SCALAR.match(value):
            _, following = continuation_lines(lines, index, len(match.group(1)))
            payloads.update(range(index + 1, following))
            index = following
        else:
            index += 1
    return payloads


# A `working-directory:` value, including the dash form a step's FIRST key takes
# (`- working-directory: sub`). Without the optional dash that spelling was invisible, so
# a gate script under `sub/` resolved against the repository root and went untiered --
# fail-open on ordinary YAML. (fixportal-agents-skills#263, item 6.)
WORKDIR = re.compile(r"""^\s*(?:-\s+)?(?:'working-directory'|"working-directory"|working-directory)\s*:\s*['"]?([^\s#'"]+)""")
# The composite action's own directory, spelled the three ways a run body can reach it.
ACTION_PATH = re.compile(r"\$\{\{\s*github\.action_path\s*\}\}|\$\{GITHUB_ACTION_PATH\}|\$GITHUB_ACTION_PATH\b")
STEPS_KEY = re.compile(r"""^(?:'steps'|"steps"|steps)\s*:""")


def working_directories(lines):
    """Every `working-directory:` value in `lines`, normalised to `/` without a trailing one."""
    found = set()
    for line in lines:
        match = WORKDIR.match(strip_comment(line))
        if match:
            found.add(match.group(1).replace("\\", "/").rstrip("/"))
    return found


def step_lines(block, run_index, key_indent):
    """The lines of the step whose `run:` key is at `run_index`.

    Scoping to the step is what keeps a SIBLING step's working-directory out of this
    step's candidate paths: it never applies here, and an unrelated file that happened to
    exist at that spelling was being required HIGH. (fixportal-agents-skills#263, item 3.)
    A run key that is not inside a sequence item falls back to the whole block -- more
    candidates, never fewer.
    """
    span = step_span(block, run_index, key_indent)
    if span is None:
        return block
    start, end = span
    return block[start:end]


def job_level_lines(block, body_indent):
    """A job's own lines OUTSIDE its `steps:` sequence -- where `defaults.run` lives.

    The sequence may be indented under `steps:` or flush with it (`- run:` at the key's
    own column), so a dash at exactly `body_indent` still belongs to the steps.
    """
    if body_indent is None:
        return []
    out = []
    in_steps = False
    for line in block:
        if COMMENT_OR_BLANK.match(line):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent <= body_indent:
            if in_steps and indent == body_indent and stripped.startswith("- "):
                continue
            in_steps = indent == body_indent and bool(STEPS_KEY.match(stripped))
            if in_steps:
                continue
        elif in_steps:
            continue
        out.append(line)
    return out


def delegated_run_bodies(root, ref, visited):
    """Yield run bodies and their action-level working directories."""
    relative = ref[2:]
    target = root / relative
    if target.is_dir():
        target = next((target / name for name in ("action.yml", "action.yaml") if (target / name).is_file()), None)
    if target is None or not target.is_file():
        return
    key = target.resolve().as_posix()
    if key in visited:
        return
    visited.add(key)
    # utf-8-sig, not utf-8: see the note on the main read in assert_gate_coverage. A
    # BOM'd local action manifest would otherwise read as having no `runs:` mapping,
    # and its delegated body would escape the scan entirely.
    lines = target.read_text(encoding="utf-8-sig").splitlines()
    # `using` is resolved INSIDE the `runs:` mapping by resolve_runs_using -- see its
    # docstring. Quoted keys ('using'/"using"/using) are admitted in both block and
    # flow style, as they were here. (CodeRabbit, fixportal-claude-skills#110.)
    using = resolve_runs_using(lines, target)
    if using is not None and using != "composite":
        raise ValueError(
            f"{target}: local action uses runs.using {using}; "
            "gate coverage only follows composite action bodies"
        )
    # A composite action reaches its OWN files through the action path. Rewriting that
    # expression to the action's repository-relative directory lets both a run body's
    # script reference and a `working-directory: ${{ github.action_path }}` resolve to
    # the file that actually runs, which is then required HIGH like any other gate
    # script. Before this, `"${{ github.action_path }}/scripts/gate.sh"` resolved against
    # the repository root and a script beside action.yml went untiered.
    # (fixportal-agents-skills#263, item 7.)
    try:
        action_dir = target.parent.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        action_dir = None
    index = 0
    while index < len(lines):
        match = RUN_KEY.match(lines[index])
        if not match:
            index += 1
            continue
        run_index = index
        value = strip_inline_comment(match.group(2)).strip()
        if BLOCK_SCALAR.match(value):
            body, index = continuation_lines(lines, index, len(match.group(1)))
        else:
            body, index = ([value] if value else []), index + 1
        if body:
            scoped = step_lines(lines, run_index, len(match.group(1)))
            if action_dir is not None:
                scoped = [ACTION_PATH.sub(action_dir, line) for line in scoped]
            directories = working_directories(scoped)
            if action_dir is not None and any(ACTION_PATH.search(line) for line in body):
                directories.add(action_dir)
                body = [ACTION_PATH.sub(action_dir, line) for line in body]
            yield body, directories
    payload_indexes = run_payload_indexes(lines)
    for index, line in enumerate(lines):
        if index in payload_indexes:
            continue
        match = LOCAL_USES.match(line)
        if match:
            yield from delegated_run_bodies(root, match.group(1), visited)


def gated_run_bodies(lines, jobs, needs, gate_job, root):
    """Every `run:` body line belonging to a job that can fail the gate, with its job id.

    Scoped to the gate's `needs:` plus the gate job itself, because that is exactly the
    set whose failure blocks a merge. A script run only by an exempt, non-merge-blocking
    job cannot neuter the barrier, so requiring it to be HIGH would be a cost with no
    control behind it.
    """
    job_indent = len(lines[jobs[gate_job]]) - len(lines[jobs[gate_job]].lstrip(" "))
    # Workflow-level lines end at the first job; only `defaults.run` there can set a
    # working directory for this job's steps.
    workflow_directories = working_directories(lines[:min(jobs.values())])
    pending = list(set(needs) | {gate_job})
    seen = set()
    while pending:
        job_id = pending.pop()
        if job_id in seen:
            continue
        seen.add(job_id)
        if job_id not in jobs:
            continue
        block = job_block(lines, jobs, job_id)
        # Directories that apply to EVERY step of this job: workflow- and job-level
        # `defaults.run.working-directory`. A step's own value is added per run body
        # below; a sibling step's is not (fixportal-agents-skills#263, item 3). Computed
        # once per job rather than once per script match (item 9).
        job_directories = workflow_directories | working_directories(
            job_level_lines(block, job_body_indent(lines, jobs, job_id, job_indent))
        )
        index = 0
        while index < len(block):
            match = RUN_KEY.match(block[index])
            if not match:
                index += 1
                continue
            run_index = index
            # Both tests read the COMMENT-STRIPPED value. `run: | # build log` is a real
            # spelling -- other_block_key_pattern documents it -- and BLOCK_SCALAR is
            # anchored, so testing the raw value made it miss: the else branch then
            # yielded the bare `|` and advanced one line, skipping the entire payload.
            # A script invoked from such a body was invisible to gate_script_paths and
            # escaped the HIGH-tier requirement, which is fail-open on the control this
            # function exists to feed. strip_inline_comment is the same helper
            # step_can_fail uses, so the two paths agree. (CodeRabbit, PR #140.)
            value = strip_inline_comment(match.group(2)).strip()
            if BLOCK_SCALAR.match(value):
                body, index = continuation_lines(block, index, len(match.group(1)))
            else:
                body, index = ([value] if value else []), index + 1
            directories = job_directories | working_directories(
                step_lines(block, run_index, len(match.group(1)))
            )
            for body_line in body:
                yield job_id, body_line, body, directories
        payload_indexes = run_payload_indexes(block)
        for index, line in enumerate(block):
            if index in payload_indexes:
                continue
            match = LOCAL_USES.match(line)
            if match:
                for delegated_body, directories in delegated_run_bodies(root, match.group(1), set()):
                    for body_line in delegated_body:
                        yield job_id, body_line, delegated_body, directories
        pending.extend(job_needs(lines, jobs, job_id, job_indent) - seen)


def resolve_committed_paths(root, relative):
    """The COMMITTED spelling(s) of `relative` under `root`; empty when it resolves to
    no file at all.

    Windows resolves a path case-insensitively, so a windows-latest job runs
    `./scripts/probe.PS1` against a file committed as `scripts/probe.ps1`. This checker
    runs on ubuntu, where the exact lookup fails -- so admitting the mixed-case spelling
    in GATE_SCRIPT without resolving it would capture the reference and then silently
    drop it. That is the same fail-open the widening exists to close, moved one step
    later and harder to see, because detection would LOOK correct.

    The COMMITTED spelling is what is returned, not what the workflow typed, because the
    review policy is matched against what is in the repository -- an exact policy entry
    like `scripts/assert-coverage-floor.ps1` would never match a key spelled `PS1`.

    EVERY case-insensitive match is returned, not the first. Two files differing only by
    case cannot both be what Windows ran, and picking one arbitrarily would vouch for a
    tier the other may not hold; requiring all of them is the fail-closed direction and
    matches the error direction of the rest of this check -- more scripts required HIGH,
    never fewer. An EXACT match still wins outright when one exists, which is the right
    disambiguation and the only case where two such files can be told apart.

    The walk is UNCONDITIONAL rather than a fallback behind an exact-path test. A
    fallback would never execute on Windows, whose filesystem matches case-insensitively
    -- so this resolution, and every fixture covering it, would be inert on the host it
    was written on and live only on the runner. That is the inert-test shape this file's
    own suite already carries a warning about. Walking always also makes the returned
    spelling identical on both platforms, so a fixture can assert on it.

    The cost is one `iterdir` per path segment per gate script found, and a repository
    has a handful of gate scripts at most.
    """
    # NORMALISE DOT COMPONENTS FIRST. `iterdir()` never yields `.` or `..`, so walking
    # them literally matches nothing and drops the candidate -- fail-open. The exact
    # `is_file()` this walk replaced did not have that problem for `.`, because pathlib
    # collapses a single dot on construction, so leaving it out was a REGRESSION rather
    # than an unchanged gap. `..` is resolved here too, and a path that climbs above the
    # repository root is refused outright rather than clamped: nothing outside the
    # checkout is a repo-local gate script. (CodeRabbit, on the review of this change.)
    parts = []
    climbed = False
    overclimbed = False
    for part in relative.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            climbed = True
            if not parts:
                # OVER-CLIMBED LEXICALLY. Returning here would be the same early-exit
                # mistake as the one below, one step earlier: `scripts/link/../../../gate.py`
                # escapes the checkout on paper, but if `link` targets a sufficiently deep
                # in-checkout directory the OS lands back INSIDE it, and the gate script
                # that actually runs would be omitted from coverage. Fall through to the
                # filesystem resolution instead; its `is_relative_to` containment check is
                # what excludes a genuinely external target, and it does so on the real
                # answer rather than the lexical one. (CodeRabbit.)
                overclimbed = True
                continue
            parts.pop()
            continue
        parts.append(part)

    normalised = "/".join(parts)

    # An over-climbed path has NO trustworthy lexical spelling -- the components left in
    # `parts` no longer describe where the path points -- so the component walk is skipped
    # entirely and only the filesystem answer is used.
    candidates = [] if (overclimbed or not parts) else [(root, [])]
    for part in (parts if candidates else []):
        following = []
        for base, resolved in candidates:
            try:
                entries = list(base.iterdir())
            except (OSError, ValueError):
                continue
            for entry in entries:
                if entry.name.lower() == part.lower():
                    following.append((entry, resolved + [entry.name]))
        candidates = following
        if not candidates:
            # BREAK, do not return. When the candidate CLIMBED, the lexical spelling is
            # not the only one worth trying: `scripts/link/../gate.ps1` reduces to
            # `scripts/gate.ps1`, and if that file does not exist a return here would
            # abandon the path before the filesystem resolution below ever ran -- leaving
            # the repository-root `gate.ps1` the runner actually executes untiered.
            # Fail-open, and invisible to a fixture that creates both targets. The empty
            # case is re-checked after the climbed block instead. (CodeRabbit.)
            break
    matches = sorted(
        "/".join(resolved) for path, resolved in candidates if path.is_file()
    ) if candidates else []

    # A `..` REDUCED LEXICALLY IS NOT WHAT THE RUNNER EXECUTES when a symlink precedes it.
    # `scripts/link/../gate.py` reduces here to `scripts/gate.py`, but the OS resolves
    # `link` first and then climbs from the TARGET's parent, so the file that actually
    # runs can be a different one -- and vouching for the lexical answer would require
    # HIGH on a path the gate never runs while the one it does run goes untiered.
    #
    # So when the candidate climbed, resolve it through the filesystem as well and keep
    # BOTH spellings. The error direction is the same as everywhere else in this check:
    # more scripts required HIGH, never fewer. A disagreement between the lexical and the
    # real answer can only ADD a requirement. A target outside the checkout is dropped
    # rather than clamped -- nothing out there is a repo-local gate script.
    #
    # Measured before writing this: zero committed symlinks across the estate, so the
    # hazard is unreachable today. It is closed because the cost is a dozen lines and the
    # direction is fail-open, not because it was observed. (CodeRabbit.)
    if climbed:
        try:
            real = (root / relative).resolve()
            if real.is_file() and real.is_relative_to(root.resolve()):
                spelled = real.relative_to(root.resolve()).as_posix()
                if spelled not in matches:
                    return sorted(matches + [spelled])
        except (OSError, ValueError):
            # Resolution can fail on a broken or circular link, a permission error, or a
            # path the platform rejects outright. Falling through leaves the LEXICAL
            # answer, which is already in `matches` and is what this function returned
            # before the filesystem check existed -- so a failure here costs the extra
            # requirement this block might have added and nothing else. Reporting no gate
            # script at all because a link could not be read would be the fail-open
            # direction, which is what this whole block exists to avoid.
            pass

    # The walk may have broken out with nothing, and the climbed block above may have
    # added nothing to it. Only now is "this path resolves to no file at all" true.
    if not matches:
        return []

    # The exact-match test uses the NORMALISED spelling: `scripts/./probe.py` resolves to
    # `scripts/probe.py`, and comparing against the raw text would never match it.
    return [normalised] if normalised in matches else matches


# A directory change at a COMMAND position: line start, after a separator, inside a
# subshell or brace group (`(cd x && ...)`, `{ cd x; ...; }`), after `!`, or after a
# compound keyword (`if cd x; then`). Those are ordinary ways to write one, so missing them
# let a gate script run from a directory the checker never considered.
# (fixportal-agents-skills#266 rollout review.)
# A compound keyword starts a command only when it is itself at a command position, so the
# keywords are an optional chain AFTER a real command start: `echo then cd sub` is an echo.
# `!` is the same: a separate token at a command position (`! cd x`), not a character
# inside an argument (`echo hi! cd x`).
_KEYWORDS = r"(?:(?:then|do|else|if|elif|while|until|!)\s+)*"
DIRECTORY_CHANGE = re.compile(r"(?:^|[;&|({])\s*" + _KEYWORDS + r"(?:cd|pushd|Set-Location)\b", re.IGNORECASE)
# A directory change as a command INSIDE a quoted string, which may span lines. An opening
# `$(` or backtick starts a command too: a substitution runs even inside printed text.
SEGMENT_DIRECTORY_CHANGE = re.compile(
    r"(?:^|[;&|\n(`{])\s*" + _KEYWORDS + r"(?:cd|pushd|Set-Location)\b",
    re.IGNORECASE,
)
# A single pipe (not `||`), which feeds printed text onward to another command.
PIPE = re.compile(r"(?<!\|)\|(?!\|)")
# The command a quoted string is an argument to, when that command only prints it.
MESSAGE_COMMAND = re.compile(
    r"(?:^|[;&|\n])\s*(?:echo|printf|Write-Host|Write-Output|Write-Warning|Write-Error|Write-Verbose)\b[^;&|\n]*$",
    re.IGNORECASE,
)


def quoted_segments(text):
    """(start, end, content) of every quoted ARGUMENT in `text`, by mask_quoted's rules.

    `start` is the opening quote's index and `end` the closing quote's.

    Spans that touch with nothing between them (`"cd sub; "'python3 x.py'`) are one shell
    argument, so they are returned as one segment. An unterminated quote runs to the end
    of the text, as it does in mask_quoted.
    """
    segments = []
    quote = None
    start = 0
    last_end = -2
    index = 0
    while index < len(text):
        char = text[index]
        if quote != "'" and char == BACKSLASH and index + 1 < len(text):
            index += 2
            continue
        if quote is None and char in "'\"":
            quote = char
            start = index
        elif quote == char:
            content = text[start + 1:index]
            if segments and start == last_end + 1:
                previous_start, _, previous = segments.pop()
                segments.append((previous_start, index, previous + content))
            else:
                segments.append((start, index, content))
            last_end = index
            quote = None
        index += 1
    if quote is not None:
        segments.append((start, len(text), text[start + 1:]))
    return segments


def changes_directory(body):
    """True when a run body may change directory before a gate script runs.

    Unquoted text is read line by line with quoted spans masked, so a `cd` inside
    `echo "step1; cd scripts is deprecated"` is not a directory change
    (fixportal-agents-skills#263, item 2).

    A quoted COMMAND string is different: `bash -c "cd sub; python3 scripts/gate.py"`
    really does run the script from `sub`, and masking it would resolve the path against
    the root instead -- the fail-open direction. So every quoted string in the WHOLE body
    is read as well (it may span lines of a block scalar), and one that both changes
    directory and names a gate script counts -- unless it is only the argument of a
    command that prints it (`echo`, `printf`, `Write-Host`, ...), where the same words are
    a message. The exemption covers PLAINLY printed text only: not a string holding a
    command substitution (`$(...)` or backticks), not one inside a substitution opened
    earlier on its line (`echo $(bash -c "cd sub; ...")`), and not one piped onward
    (`echo "cd sub; ..." | bash`) -- each of those runs the text. Adjacent quoted spans
    are read as the one argument they are. (Review follow-up on the
    fixportal-agents-skills#265 rollout.)

    THE BOUNDARY, stated so a pass is not read as more than it is: this is a line-level
    heuristic, not a shell parser. It covers the ways a workflow author ordinarily writes a
    directory change -- `cd`/`pushd`/`Set-Location` as a command, in a quoted `-c` string,
    or in a substitution. A deliberately obfuscated one (`eval "c""d sub"`, a variable
    holding the command, an alias, a nested interpreter reading a file) is out of scope:
    the workflow change that introduces it is itself HIGH-tier and reviewed, and review is
    the control for intent. Further spellings of that kind are declined, not chased.
    """
    for line in body:
        if DIRECTORY_CHANGE.search(mask_quoted(line)):
            return True
    text = "\n".join(body)
    masked = mask_quoted(text)
    for start, end, content in quoted_segments(text):
        if not (SEGMENT_DIRECTORY_CHANGE.search(content) and GATE_SCRIPT.search(content)):
            continue
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", end)
        # MASKED, so an earlier string that already closed on this line (`echo "$(date)";`)
        # cannot leak its `$(` into this one's test; an unquoted `$(` stays visible.
        before = masked[line_start:start]
        after = masked[end + 1:line_end if line_end != -1 else len(text)]
        executed = (
            "$(" in content or "`" in content          # a substitution inside the string
            or "$(" in before or "`" in before         # the string sits inside a substitution
            or PIPE.search(after) is not None          # the string is piped onward
        )
        if MESSAGE_COMMAND.search(masked[:start]) and not executed:
            continue
        return True
    return False


def gate_script_paths(lines, jobs, needs, gate_job, root):
    """Repo-local scripts a merge-blocking job runs from the checkout, path -> job id.

    Only paths that EXIST under `root` are returned. Nothing is asserted about a
    candidate that does not resolve to a file: the repository does not have it, so it
    cannot be edited to neuter anything.

    A Windows-spelled candidate is normalised to `/` here, once, before either use.
    Both downstream consumers need it: `Path("a\\b")` is a single filename on Linux, so
    the existence test would miss the file, and the review policy's globs are written
    with `/`, so a backslashed key would never match a tier and would report the script
    as untiered even where the policy covers it. Case is settled separately, against the
    disk, by resolve_committed_paths.
    """
    found = {}
    for job_id, body_line, body, directories in gated_run_bodies(lines, jobs, needs, gate_job, root):
        for match in GATE_SCRIPT.finditer(body_line):
            relative = match.group(1).replace("\\", "/")
            if changes_directory(body):
                sys.exit(f"{root}: cannot verify gate script paths after a directory change in job '{job_id}'; use working-directory:")
            # Every plausible spelling is kept -- the repository root, and each directory
            # that applies to this run body (workflow and job defaults, the body's own
            # step, a composite action's own directory). More scripts required HIGH,
            # never fewer.
            candidates = {relative} | {directory + "/" + relative for directory in directories if directory}
            for candidate in candidates:
                for committed in resolve_committed_paths(root, candidate):
                    found.setdefault(committed, job_id)
    # Local actions and reusable workflows execute from the PR checkout too. Their
    # own files therefore need HIGH coverage even when their run bodies contain no
    # directly named script.
    job_indent = len(lines[jobs[gate_job]]) - len(lines[jobs[gate_job]].lstrip(" "))
    pending = list(set(needs) | {gate_job})
    seen = set()
    while pending:
        job_id = pending.pop()
        if job_id in seen or job_id not in jobs:
            continue
        seen.add(job_id)
        block = job_block(lines, jobs, job_id)
        payload_indexes = run_payload_indexes(block)
        for index, line in enumerate(block):
            match = LOCAL_USES.match(line)
            if match and index not in payload_indexes and match.group(1).startswith(("./", "$/")):
                for relative in local_action_paths(root, match.group(1)):
                    found.setdefault(relative, job_id)
        pending.extend(job_needs(lines, jobs, job_id, job_indent) - seen)
    return found


def local_action_paths(root, ref, visited=None):
    """Action manifests reachable from a local composite action reference."""
    if visited is None:
        visited = set()
    target = root / ref[2:]
    if target.is_dir():
        target = next((target / name for name in ("action.yml", "action.yaml") if (target / name).is_file()), None)
    if target is None or not target.is_file():
        return set()
    target = target.resolve()
    if target in visited:
        return set()
    visited.add(target)
    try:
        relative = target.relative_to(root.resolve()).as_posix()
    except ValueError:
        sys.exit(f"{root}: local action escapes repository: {ref}")
    paths = {relative}
    lines = target.read_text(encoding="utf-8-sig").splitlines()
    using = resolve_runs_using(lines, target)
    if using is not None and using != "composite":
        return paths
    payload_indexes = run_payload_indexes(lines)
    for index, line in enumerate(lines):
        match = LOCAL_USES.match(line) if index not in payload_indexes else None
        if match and match.group(1).startswith(("./", "$/")):
            paths.update(local_action_paths(root, match.group(1), visited))
    return paths


def assert_gate_scripts(workflow_path, lines, jobs, needs, gate_job):
    """Every script a merge-blocking job runs must be tiered HIGH by the review policy.

    THE HOLE THIS CLOSES. The gate runs the pull request's OWN checkout, so a script it
    invokes decides what can merge in exactly the way the workflow does. The named-path
    list in review-policy-guard.yml protects the control plane that every scaffolded
    repository shares -- it cannot name a checker a single repository authored later,
    because a hard-coded path would red every repository that does not have that file.
    So a repo-authored gate script was protected by nothing: a pull request touching only
    `scripts/**` tiered NORMAL, and its own edited copy of the script is what ran. Change
    the failure path to `exit 0` and a neutered gate merges green.

    Derived rather than enumerated, which is what makes it general: the requirement
    follows from what the workflow actually invokes, so a gate script added to a
    repository years after it was scaffolded is covered on the day it is wired in.

    Verified in the field, not hypothesised: fixportal-fixatdl added
    `scripts/assert-coverage-floor.ps1` as a merge gate on 2026-08-24 and it sat outside
    both the policy and the guard until an adversarial review found it on 2026-09-08 --
    the third recurrence of this class in that repository, after the same hole had been
    closed for the two Python checkers three weeks earlier.
    """
    root = policy_root(workflow_path)
    if root is None:
        return
    policy_path = root / ".claude" / "review-policy.json"
    try:
        # utf-8-sig for the same reason as the workflow reads, and for one more: a BOM
        # makes json.loads raise, which the except below swallows as "no policy" -- so a
        # BOM'd policy file would disable the HIGH-tier assertion silently rather than
        # noisily. Not named in issue #231, which covered the workflow reads; it is the
        # same one-word defect in the same file and the same fail-open direction.
        policy = json.loads(policy_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        # An unreadable or malformed policy is review-policy-guard.yml's failure to
        # report, and it already does. Duplicating it here would print the same breach
        # twice and, worse, make THIS check the one that fails on a repository whose
        # actual problem is elsewhere.
        return
    if not isinstance(policy, dict):
        return
    high = policy.get("high")
    if not isinstance(high, list):
        return
    high = [pattern for pattern in high if isinstance(pattern, str)]

    scripts = gate_script_paths(lines, jobs, needs, gate_job, root)
    unprotected = sorted(path for path in scripts if matches_any(path, high) is None)
    if unprotected:
        detail = "\n".join(
            f"  {path}  (run by '{scripts[path]}')" for path in unprotected
        )
        sys.exit(
            f"{workflow_path}: script(s) run by a job feeding '{gate_job}' are not tiered "
            f"HIGH by {policy_path.name}:\n{detail}\n"
            "Each decides what can merge and runs from the pull request's own checkout, so "
            "an edit to one must draw the heavier review. Add each path to the policy's "
            "'high' array (or a glob that covers them), or stop the gate depending on it."
        )
    if scripts:
        print(
            f"{workflow_path}: {len(scripts)} gate script(s) tiered HIGH: "
            f"{', '.join(sorted(scripts))}."
        )


def check_file(workflow_path, gate_job, exempt, conditional_exempt, *, on_empty="fail"):
    """Assert one file's full gate contract. Returns True when the file contains the
    gate job (and every assertion ran), False when it has no gate job at all.

    Exemption-name validation is the CALLER's job, not this function's: in directory
    mode a job named in GATE_EXEMPT exists in exactly one workflow, so validating it
    against a single file's job set here reddened every OTHER workflow that also
    contains the gate job with a false "names jobs that do not exist". Found by
    CodeRabbit on the upstream review.

    READ AS utf-8-sig. A plain utf-8 read leaves a leading BOM in the first character,
    so `JOBS_KEY` -- anchored at `^` -- never matched a BOM'd file's `jobs:` line, and
    Windows editors add BOMs silently. The consequence split on invocation mode and was
    bad in both directions: in FILE mode (how the estate wires this) the file exited 1
    with "no jobs found", a permanently red required check over a valid workflow; in
    DIRECTORY mode it was written off as "not a workflow, skipped" and every job in it
    escaped coverage. A checker must not disagree with the runner about whether a file
    is a workflow. The canonical-asset hasher already tolerates a BOM, so the two now
    agree. (Issue #231, probed both modes.)
    """

    with open(workflow_path, encoding="utf-8-sig") as handle:
        lines = handle.readlines()
    jobs, needs, conditional = read_gate_contract(lines, gate_job)

    if not jobs:
        if any(JOBS_DECL.match(strip_comment(line).rstrip()) for line in lines):
            sys.exit(f"{workflow_path}: flow-style or empty 'jobs' mapping is unsupported; refusing to skip coverage.")
        if on_empty == "skip":
            return None
        sys.exit(f"{workflow_path}: no jobs found -- refusing to report coverage over nothing.")
    if gate_job not in jobs:
        return False

    # AFTER the gate-job test: a workflow with no gate job feeds nothing, so in directory
    # mode a file-exempt release.yml with `env: BASH_ENV:` no longer reddens the whole run
    # (fixportal-agents-skills#263, item 4). And block-scalar `run:` payloads are skipped:
    # a heredoc line starting `BASH_ENV:` is shell text, not an env key (item 1).
    payload_indexes = run_payload_indexes(lines)
    # Quoted keys admitted, as for every other key this checker reads: `"BASH_ENV":` is the
    # same env key, and missing it let the override through.
    if any(
        re.match(r"""^\s*(?:'BASH_ENV'|"BASH_ENV"|BASH_ENV)\s*:""", strip_comment(line))
        for index, line in enumerate(lines)
        if index not in payload_indexes
    ):
        sys.exit(
            f"{workflow_path}: BASH_ENV can load shell functions that override the gate's "
            "accepted exit command. Remove the override or use a separately verified gate shell."
        )

    gate_line = lines[jobs[gate_job]]
    job_indent = len(gate_line) - len(gate_line.lstrip(" "))

    missing = sorted(set(jobs) - set(needs) - exempt - {gate_job})
    if missing:
        sys.exit(
            f"{workflow_path}: not gated by '{gate_job}': {', '.join(missing)}.\n"
            f"Add each to the '{gate_job}' needs: list, or to GATE_EXEMPT if it is "
            "deliberately not merge-blocking."
        )

    # A typo in the gate's needs: would otherwise surface as a KeyError traceback from the
    # feeder lookup below. GitHub rejects such a workflow too, so say so plainly.
    undefined = sorted(set(needs) - set(jobs))
    if undefined:
        sys.exit(f"{workflow_path}: '{gate_job}' needs undefined job(s): {', '.join(undefined)}.")

    # A feeder can be skipped transitively when it depends on a conditional or
    # explicitly exempt job. Since the gate treats skipped as success, require an
    # always-running condition on that feeder before accepting the chain.
    def runs_regardless(job_id):
        """True when the job's own `if:` makes it run even after a skipped dependency."""
        start = jobs[job_id]
        end = min((i for i in jobs.values() if i > start), default=len(lines))
        indent = job_body_indent(lines, jobs, job_id, job_indent)
        pattern = key_pattern(indent, "if") if indent is not None else None
        condition = next((normalise_condition(match.group(1))
                          for i in range(start + 1, end)
                          if pattern and (match := pattern.match(lines[i].rstrip("\r\n")))), "")
        return condition in ("always()", "!cancelled()")

    unsafe_feeders = set()
    for feeder in set(needs) - {gate_job}:
        if runs_regardless(feeder):
            continue
        pending = list(job_needs(lines, jobs, feeder, job_indent))
        visited = set()
        while pending:
            dependency = pending.pop()
            if dependency in visited or dependency not in jobs:
                continue
            visited.add(dependency)
            if dependency in exempt or dependency in conditional:
                unsafe_feeders.add(feeder)
            # An intermediate that runs regardless of its own dependencies stops a skip
            # from propagating past it, so the chain behind it cannot skip this feeder.
            # The same always()/!cancelled() the feeder test above already accepts.
            # (fixportal-agents-skills#263, item 5.)
            if runs_regardless(dependency):
                continue
            pending.extend(job_needs(lines, jobs, dependency, job_indent) - visited)
    if unsafe_feeders:
        sys.exit(
            f"{workflow_path}: gate feeder dependency chain reaches conditional or exempt "
            f"job(s): {', '.join(sorted(unsafe_feeders))}. A skipped feeder passes the gate; "
            "add `if: always()` or `if: ${{ !cancelled() }}` to the dependent feeder, or remove "
            "the unsafe dependency."
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

    tolerant = sorted((tolerant_jobs(lines, jobs, job_indent) & (set(needs) | {gate_job})))
    if tolerant:
        sys.exit(
            f"{workflow_path}: job-level 'continue-on-error' on merge-blocking job(s): "
            f"{', '.join(tolerant)}.\n"
            "A tolerated job cannot provide a required check or serve as the aggregate gate."
        )

    assert_gate_semantics(workflow_path, lines, jobs, gate_job, needs)
    assert_gate_scripts(workflow_path, lines, jobs, needs, gate_job)

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
        if not Path(target).is_file():
            sys.exit(f"{target}: workflow path does not exist or is not a file.")
        unknown = sorted((exempt | conditional_exempt) - parse_jobs(target))
        if unknown:
            sys.exit(
                f"{target}: GATE_EXEMPT/GATE_CONDITIONAL_EXEMPT name jobs that do not "
                f"exist: {', '.join(unknown)}"
            )
        # The return value is the WHOLE assertion when the gate job is absent:
        # check_file reports every other breach by exiting, but answers "no gate job
        # here" with False and leaves the decision to its caller. Directory mode acts
        # on that (GATE_FILE_EXEMPT, or exit). File mode used to discard it and return,
        # so a workflow with jobs and NO gate job exited 0 in silence -- rename or
        # delete the gate job and the check that exists to notice said nothing.
        # Fail-OPEN, on the assertion that decides what can merge. Found by CodeRabbit
        # on the upstream review.
        if check_file(target, gate_job, exempt, conditional_exempt) is False:
            sys.exit(
                f"{target}: no '{gate_job}' job, so none of its jobs are merge-blocking. "
                f"Give the file a '{gate_job}' job wired to aggregate its needs, or point "
                "this check at the workflow directory and name the file in GATE_FILE_EXEMPT "
                "if it is deliberately not gated."
            )
        return

    files = sorted(
        path.as_posix()
        for path in list(Path(target).glob("*.yml")) + list(Path(target).glob("*.yaml"))
        if path.is_file()
    )
    if not files:
        sys.exit(f"{target}: no workflow files found -- refusing to report coverage over nothing.")

    file_exempt = {name.replace("\\", "/") for name in split_env("GATE_FILE_EXEMPT")}
    stale = sorted(file_exempt - set(files))
    if stale:
        sys.exit(f"GATE_FILE_EXEMPT names workflows that do not exist: {', '.join(stale)}")

    # Validate GATE_EXEMPT/GATE_CONDITIONAL_EXEMPT against the UNION of every
    # file's jobs, not any one file -- a job named in either list exists in
    # exactly one workflow, so checking it per-file reddened every other
    # workflow that also has a gate job. Found by CodeRabbit on
    # the upstream review.
    all_jobs = set()
    for workflow_path in files:
        all_jobs |= parse_jobs(workflow_path)
    unknown = sorted((exempt | conditional_exempt) - all_jobs)
    if unknown:
        sys.exit(
            f"{target}: GATE_EXEMPT/GATE_CONDITIONAL_EXEMPT name jobs that do not "
            f"exist in any workflow: {', '.join(unknown)}"
        )

    gated = 0
    for workflow_path in files:
        result = check_file(workflow_path, gate_job, exempt, conditional_exempt, on_empty="skip")
        if result is None:
            print(f"{workflow_path}: no jobs -- not a workflow, skipped.")
            continue
        if result:
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
