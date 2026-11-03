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

Pure Python, invoked directly rather than through a shell wrapper: bash cannot survive
CRLF line endings, and a repo whose .gitattributes checks the file out with CRLF gets
`set: pipefail: invalid option name` and a permanently red required check. Python does
not care about CRLF, so the failure mode is designed out rather than patched per repo.

YAML STRUCTURE IS READ THROUGH PyYAML, which assert_workflow_hygiene.py already requires
on the same runners. The line regexes below still read shell bodies and the job/needs/if
grammar, but which lines are TEXT and which are KEYS, and what `defaults:`, `env:` and
`working-directory:` actually hold, come from the parser -- see compose_yaml.
"""
import json
import math
import os
import posixpath
import re
import shlex
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    # `python -S` skips site-packages, and the test suites invoke this file that way for
    # start-up speed. Pull the site directories in before giving up: without PyYAML the
    # structural reads cannot run, and "cannot read" must exit non-zero, not vouch.
    import site

    site.main()
    try:
        import yaml
    except ImportError:
        print(
            "python3 cannot import yaml. Provide PyYAML in the runner image or a pinned "
            "isolated environment, and invoke this checker with that interpreter "
            "(assert_workflow_hygiene.py has the same requirement).",
            file=sys.stderr,
        )
        sys.exit(2)


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
# a correct gate of this shape then reads as "aggregates nothing".
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
# installed into.
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
#
# THE ARGUMENTS ARE PLAIN WORDS. `[^\n|&;<>]*` admitted `echo ([Environment]::Exit(0))`,
# which under pwsh exits the step ZERO while the echo is still being evaluated, before the
# failing command runs. Quoted strings never
# reach these patterns -- mask_quoted has blanked them by then -- so a word simply excludes
# every grouping, substitution and quoting character along with the separators the
# surrounding forms read.
# A braced NAME (`${x}`, `${#x}`) is admitted: it is a plain variable read under both
# shells, while every expanding form (`${x:-...}`, `${x@P}`, `${env:x}`) stays refused.
_WORD = r"(?:[^\s|&;<>()\[\]{}`'\"$]|\$(?!\{)|\$\{#?[A-Za-z_][A-Za-z0-9_]*\})+"
_ECHO = rf"(?:{_REDIR}\s*)?(?:echo|printf)(?:\s+{_WORD})*{_REDIR}"
_NONZERO_STATUS = r"0*(?:[1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
_FAIL_EXIT = rf"exit\s+{_NONZERO_STATUS}{_REDIR}\s*;?"
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
    )
)
# `false`, alone of the accepted failing forms, is not a builtin under BOTH
# candidate shells: under bash it is one, but under pwsh it is not a keyword,
# cmdlet, or alias, so it resolves through PATH -- the same GITHUB_PATH attack
# _THROW documents for `throw` under bash, with the shells swapped. With no
# readable shell the runner default may be pwsh on Windows, so a caller that has
# NOT resolved the effective shell drops every `false` arm and vouches for
# `exit` 1-255 alone, which is a builtin under either candidate.
ACCEPTED_FAILING_FORMS_NO_FALSE = tuple(
    re.compile(pattern)
    for pattern in (
        _FAIL_EXIT,
        rf"{_ECHO}\s*(?:;|&&)\s*{_FAIL_EXIT}",
    )
)
# `throw`, alone of the accepted failing forms, is not a bash builtin: bash resolves it
# through PATH, and PATH is writable from an earlier step in the same job (GITHUB_PATH),
# so a committed executable named `throw` that exits 0 turns a vouched gate green. The
# old defence -- "not a builtin, so exits 127" -- covers only the no-executable case
# (adversarial review 20260929T030431Z, X2). It is therefore accepted ONLY where it is a
# language keyword, which is when the EFFECTIVE shell is pwsh: a step-level
# `shell: pwsh`, or `defaults.run.shell` resolving to pwsh. With no shell key anywhere
# the runner default is bash off Windows, so `throw` stays refused there too -- use
# `exit 1-255`, or declare the shell. `shell: pwsh` gate steps are house style in the
# .NET repos and `throw 'upstream failed'` is how one fails, so it remains accepted
# there; the trailing message is optional because mask_quoted has already blanked the
# string by the time the pattern runs.
# UNCONDITIONAL only. `if ($false) { throw "failed" }` was accepted and does not
# throw, so the step exits 0 - the same fail-open as the `||` forms above.
# THE TAIL CANNOT CARRY A SEPARATOR: `.*` would let mask_quoted's blanked message
# admit `throw "upstream failed" || true`, normalising to `throw || true`, which
# fullmatches - but under bash `-e` does not fire on a command whose status
# `||` consumes, so the step exits 0. Excluding | & ; < > from the tail keeps the
# message arm and refuses every guarded form, exactly as the block above does.
_THROW = re.compile(r"throw(?:\s+[^|&;<>]*)?")
# A MESSAGE line is the only thing a failing command may follow. It writes output
# and cannot re-decide the step's exit status, so vouching for it as a prefix does
# not vouch for a command that could make the step succeed. It is _ECHO: mask_quoted
# has already blanked any quoted text by the time it runs, so
# `echo "Upstream results: ..."` reaches it as a bare `echo`.
_MESSAGE = re.compile(_ECHO)
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
# `set -e; exit 0` is not one either.
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
# six are both valid Actions syntax, and a hard-coded four-space job body in these
# expressions would be a fail-OPEN defect: a job whose `if:` sat at six spaces would
# not be seen, so the job would read as UNCONDITIONAL -- and because the gate counts
# `skipped` as a pass, a conditional quality job that skips would be accepted as a
# check that ran. Every pattern below therefore takes the indentation it must match, which
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
    admitted, because either spelling is valid YAML, and failing to recognise the
    OPENER means the payload IS scanned. An inert `run:` body line then supplies the
    `needs.*.result` condition this script looks for, so the real aggregation `if:`
    can be deleted with the checker still green. Fail-OPEN, on the one assertion that
    decides what can merge.

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
        # An exact equality against `jobs:` would fail on `jobs: # comment`, which is
        # valid YAML, and return no jobs at all. JOBS_KEY also admits the quoted forms
        # and a space before the colon -- see its definition for why matching only
        # "jobs:" was fail-open.
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

    # A flow mapping on a later line keeps the job header parseable, but its
    # fields are not block keys. Refuse it before scans can miss a job-level if.
    starts = sorted(jobs.values())
    for job_id, start in jobs.items():
        end = min((i for i in starts if i > start), default=jobs_end)
        for line in lines[start + 1 : end]:
            value = strip_inline_comment(line.strip()).strip()
            if not value:
                continue
            # YAML node properties can precede the value on this or their own
            # line. They must not hide a flow map from this block-only scanner.
            while value.startswith(("&", "!")):
                property_token = re.match(
                    r"^(?:&[^\s{}\[\],]+|!<[^>\r\n]+>|![^\s{}\[\],]*)(?:\s+|$)",
                    value,
                )
                if property_token is None:
                    sys.exit(f"unsupported YAML node property for job '{job_id}'")
                value = value[property_token.end() :].strip()
            if not value:
                continue
            if value.startswith("{"):
                sys.exit(
                    f"unsupported flow mapping value for job '{job_id}'\n"
                    "This gate refuses to report coverage it cannot verify. "
                    "Use a block mapping for the job."
                )
            break

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
            # the key's own indentation would end the sequence early and silently
            # truncate `needs`.
            if COMMENT_OR_BLANK.match(line):
                continue
            if len(line) - len(line.lstrip(" ")) <= body_indent:
                break
        return jobs, needs, conditional_jobs(lines, jobs, job_indent)

    return jobs, [], conditional_jobs(lines, jobs, job_indent)


def runs_unconditionally(condition):
    return condition == "!cancelled()" or (
        re.search(r"\balways\(\s*\)", mask_quoted(condition)) is not None
        and static_truth(condition) is True
    )


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
            if not match:
                continue
            # A block-scalar or empty `if:` (`if: >` then the expression on the next
            # lines) matched the header and read as an opaque condition -- the job was
            # counted conditional on the HEADER alone, so `if: >` / `always()` marked
            # an unconditional feeder conditional (a false RED), and worse, a folded
            # condition that is genuinely restrictive was never unfolded either.
            # Unfold exactly the way tolerant_jobs and assert_gate_semantics already do
            # for the same shapes.
            value = strip_comment(match.group(1)).strip()
            if not value or is_block_scalar_header(value):
                body, _ = continuation_lines(lines, i, indent)
                value = " ".join(strip_comment(line).strip() for line in body)
            if not runs_unconditionally(normalise_condition(value)):
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
            # while static_truth folds it to False. UNKNOWN stays tolerant -- an
            # expression this checker cannot fold may still evaluate true at runtime,
            # and that is the conservative direction.
            if value not in ("false", "") and static_truth(value) is not False:
                tolerant.add(job_id)
                break
    return tolerant


def job_block(lines, jobs, job_id):
    """The lines of one job's body, from its key to the next job key, as a Slice."""
    start = jobs[job_id]
    end = min((i for i in sorted(jobs.values()) if i > start), default=len(lines))
    return slice_of(lines, start + 1, end, transform=lambda line: line.rstrip("\r\n"))


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
    # every ordinary `if:` -- see its own guard.
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
    compound condition is always false.

    A double-quoted literal can itself contain an escaped quote (`_LITERAL` matches
    `\\"(?:\\\\.|[^\\"])*\\"`, same as split_top_level/strip_inline_comment). Without
    escape handling, this loop would close the string at the escaped quote in
    `"a\\" b"`, re-enter quote mode at the bare quote that follows, and strip
    the space that was actually inside the literal -- `"a\\"b"`, comparing against
    `ab` instead of the intended `a" b`. Skipping two characters on a backslash
    inside a double-quoted span, exactly as those sibling functions do, is what
    keeps the escape from being read as a close.
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
# came back unchanged, quotes and all. Two independent instances of that: \  (escaped
# space) in a condition whose author split it across a line-continuation, and
# \x28\x29 spelling out "()" in "always\x28\x29".
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
_LITERAL = r"(?:true|false|null|-?[0-9]+(?:\.[0-9]+)?|'(?:''|[^'])*'|\"(?:\\.|[^\"\\])*\")"


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


def static_truth(condition, _nested=False):
    """Fold only literal boolean branches; unknown GitHub context/function values stay unknown."""
    expression = (condition if _nested else decode_yaml_scalar(strip_comment(condition).strip())).strip()
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression[3:-2].strip()
    expression = strip_outer_parentheses(expression)

    parts = split_top_level(expression, "||")
    if len(parts) > 1:
        values = [static_truth(part, True) for part in parts]
        if any(value is True for value in values):
            return True
        return False if all(value is False for value in values) else _UNKNOWN

    parts = split_top_level(expression, "&&")
    if len(parts) > 1:
        values = [static_truth(part, True) for part in parts]
        if any(value is False for value in values):
            return False
        return True if all(value is True for value in values) else _UNKNOWN

    expression = strip_outer_parentheses(expression)
    if expression.startswith("!"):
        operand = expression[1:]
        # `!` is UNARY and binds tighter than a comparison, so `!1 == 2` is `(!1) == 2`,
        # not `!(1 == 2)`. Folding the latter credited coverage to a step that never runs
        # The precedence is UNVERIFIED against
        # the runner, so a negated comparison is left UNKNOWN rather than folded either way.
        if any(len(split_top_level(operand, operator)) > 1 for operator in ("==", "!=", "<=", ">=", "<", ">")):
            return _UNKNOWN
        value = static_truth(operand, True)
        return not value if value is True or value is False else _UNKNOWN
    if expression.startswith(("'", '"')) and re.fullmatch(_LITERAL, expression):
        literal = literal_value(expression)
        return bool(literal) if isinstance(literal, str) else _UNKNOWN
    if expression.lower() == "true":
        return True
    if expression.lower() == "false":
        return False
    # A bare number or null folds by GitHub truthiness: `0` and `null` are false, every
    # other number true. Left UNKNOWN, `if: ${{ 0 }}` on a feeder step never met the
    # always-skipped refusal.
    if re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?|null", expression, re.IGNORECASE):
        return bool(literal_value(expression.lower()))
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


def status_reachable_atoms(condition):
    """Adverse needs coverage independent of the current gate job's status.

    Step status functions read current job status, not upstream needs results.
    House policy requires the failing step to cover adverse needs while this job
    is Success, Failure or Cancelled: cancellation must not mask an upstream bad
    result. An explicit status function is a defensive override contract, not
    evidence that default success suppresses upstream failures on a healthy job.
    """
    normalised = normalise_condition(condition)
    unquoted = re.sub(_LITERAL, "''", normalised)
    status = r"\b(always|success|failure|cancelled)\(\s*\)"
    if not re.search(status, unquoted, re.IGNORECASE):
        return None
    def simplify(expression):
        expression = strip_outer_parentheses(expression)
        for operator in ("||", "&&"):
            parts = split_top_level(expression, operator)
            if len(parts) < 2:
                continue
            parts = [simplify(part) for part in parts]
            absorbing = operator == "||"
            if any(static_truth(part) is absorbing for part in parts):
                return str(absorbing).lower()
            parts = [part for part in parts if static_truth(part) is not (not absorbing)]
            if not parts:
                return str(not absorbing).lower()
            return operator.join(f"({part})" for part in parts)
        return expression

    projections = []
    for current_status in ("success", "failure", "cancelled"):
        values = {"always": True, "success": current_status == "success",
                  "failure": current_status == "failure",
                  "cancelled": current_status == "cancelled"}
        # Preserve literals; project actual calls using current-job state only.
        tokens = re.split(f"({_LITERAL})", normalised)
        for index in range(0, len(tokens), 2):
            tokens[index] = re.sub(
                status, lambda match: str(values[match.group(1).lower()]).lower(),
                tokens[index], flags=re.IGNORECASE,
            )
        simplified = simplify("".join(tokens))
        truth = static_truth(simplified)
        if truth is True:
            # success() is the healthy-run state: a step unconditional there fires on
            # every green run and aggregates nothing. failure()/cancelled() projections
            # are unreachable on a healthy run, so they cannot restrict coverage.
            if current_status == "success":
                return None
            continue
        if truth is False:
            return None
        matches = failure_atoms(simplified)
        if matches is None:
            return None
        projections.append(matches)
    # Require dependency-sensitive evidence; an always-true step aggregates nothing.
    if not projections:
        return None
    common = set(match.groups() for match in projections[0])
    for matches in projections[1:]:
        common.intersection_update(match.groups() for match in matches)
    return [match for match in projections[0] if match.groups() in common]


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
    already claims. Refusing it rejected a consumer's correct gate outright.
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


def mask_quoted(line, *, powershell=False):
    """`line` with the contents of every quoted span blanked out.

    A SCANNER, not a regex. A `"[^"]*"` alternation ends a double-quoted span at the
    first quote it meets, and an ESCAPED quote is not the end of one:
    `echo "then \\" ; exit 1"` is a single inert string, but blanking only as far as
    the escaped quote left `; exit 1"` looking like a real command, which
    ends_non_zero would then have accepted. That is the fail-OPEN direction, so it is
    worth the extra ten lines. In PowerShell mode, double quotes escape with a backtick
    and single quotes escape by doubling; in bash mode only double quotes consume a
    backslash.

    An unterminated quote blanks the rest of the line. That is broken shell either
    way, and refusing to find an exit there errs toward rejecting the step rather than
    passing it.
    """
    out = []
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if powershell and quote == "'" and char == "'" and line[index + 1:index + 2] == "'":
            out.append("  ")
            index += 2
            continue
        if (
            (powershell and quote == '"' and char == "`")
            or (not powershell and quote != "'" and char == BACKSLASH)
        ) and index + 1 < len(line):
            out.append(" \n" if line[index + 1] == "\n" else "  ")
            index += 2
            continue
        if quote is None and char in "'\"":
            quote = char
            out.append(" ")
        elif quote == char:
            quote = None
            out.append(" ")
        elif quote is not None:
            out.append("\n" if char == "\n" else " ")
        else:
            out.append(char)
        index += 1
    return "".join(out)


def ends_non_zero(body, *, allow_throw=False, allow_false=True, powershell=False):
    """True when the gate body is a RECOGNISED failing form, as a WHOLE.

    Splitting a de-quoted, de-commented line on command separators and accepting
    any segment starting `exit <n>` or `false` has four independent escapes in
    that one heuristic, each producing a step that exits 0 while reading as failable:

      * `echo "\\n exit 1 \\n"` and a backslash-continued `echo \\ / exit 1` -- quote
        state was per physical line, so inert string content read as a command;
      * `echo then exit 1` -- `then` is a COMMAND_BOUNDARY, so the argument split the
        line and `exit 1` became a segment of its own;
      * `exit 1 | true` -- no single `|` in the boundary alternation, and the pattern
        matched on a prefix;
      * `false || true` -- same shape, opposite operator.

    Four escapes is a fact about the approach, not about the patches. So this checker
    does not parse arbitrary shell: it recognises a small set of verified forms and
    rejects everything else with a message naming what it supports. A gate step is the
    one place in a workflow where an exotic shell body buys nothing.

    The verdict is over the COMPLETE body, not the first matching line. Accepting any
    matching segment validated `exit 0` followed by an unreachable `exit 1` -- the step
    exits ZERO at run time on the first line while the checker vouches for the second.
    So every line before the failing command must be a MESSAGE or a `set` SHELL-OPTION
    line -- the two prefixes that cannot re-decide the exit status -- and the final line
    must fullmatch an accepted form. Anything else is refused rather than parsed.

    `body` is the joined run: body, with backslash continuations already folded.
    `allow_throw` admits `_THROW` as a final form, and is for the caller that has
    RESOLVED the effective shell to pwsh -- the only place `throw` is a keyword
    rather than a PATH lookup (see _THROW). `allow_false=False` likewise drops
    every `false` arm for the caller that has NOT resolved the effective shell:
    `false` is a builtin only under bash, and an unknown shell may be pwsh on
    Windows, where it resolves through PATH (see ACCEPTED_FAILING_FORMS_NO_FALSE).
    `exit` 1-255 is a builtin under both candidate shells and stays accepted
    either way. `powershell` selects mask_quoted's quoting discipline, so a caller
    that does not know the shell can require the body to read as the same form under
    BOTH (see step_can_fail).
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
    if "$(" in body:
        return False
    if "${{" in body:
        return False
    if re.search(r"\bthrow\s+[@(]", body):
        return False
    if re.search(r"\bexit\s+[^\s\n;|&<>]*['\"]", body):
        return False
    text = mask_quoted(body, powershell=powershell)
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
    base = ACCEPTED_FAILING_FORMS if allow_false else ACCEPTED_FAILING_FORMS_NO_FALSE
    forms = base + ((_THROW,) if allow_throw else ())
    return any(form.fullmatch(segments[-1]) for form in forms)


def powershell_ends_non_zero(body, *, throw=True, echo=True):
    """Recognise a final PowerShell `throw`/nonzero `exit` after inert message lines.

    The accepted `exit` range is 1-255 on EVERY job, with no Windows arm. There was
    one, fed by a literal `runs-on:` scan, and it was wrong in both directions. The
    range itself matters: under pwsh on Linux `exit 256` exits ZERO (the status is
    truncated to 8 bits), so a body vouched for on a Windows assumption can succeed
    on the runner that actually executes it -- pwsh on ubuntu-latest is an ordinary,
    supported spelling. And the runner read was untrustworthy anyway:
    `runs-on: ${{ matrix.os }}` is invisible to a literal scan, and a
    `runs-on: windows-latest` line inside a `run:` payload is shell text, not a YAML
    key. The only sound direction is the range that is nonzero under pwsh on every
    OS, which is _NONZERO_STATUS -- the same 1-255 ends_non_zero accepts for bash.

    `throw=False` drops the bare-`throw` arm for a body whose shell is UNKNOWN (no
    step-level key, no `defaults.run.shell`): the runner default is bash off
    Windows, and under bash `throw` resolves through PATH -- see _THROW. `exit`
    1-255 is a builtin under both candidate shells and stays accepted either way.

    `echo=False` drops `echo` for the same unknown-shell body: unlike the cmdlets it RUNS
    under bash, with bash's quoting, so a body pwsh reads as messages then `exit 1` can
    hide an `exit 0` from bash (CodeRabbit, mirror PR #140). Such a body falls through to the
    both-disciplines check in step_can_fail instead.
    """
    string = r"(?:'(?:[^'\n]|'')*'|\"(?:[^`\"\n]|`.)*\")"
    # `echo` is pwsh's alias for Write-Output and the spelling the house one-liner uses,
    # so refusing it reddened a `shell: pwsh` gate that does fail (tax portal review
    # 20261101T004738Z, c02-C5). Admitted with a QUOTED argument or none, like the
    # cmdlets: an expression argument stays refused.
    words = "Write-Host|Write-Output|Write-Information" + ("|echo" if echo else "")
    message = re.compile(rf"(?:{words})(?:\s+{string})?", re.IGNORECASE)
    final = rf"throw(?:\s+{string})?|" if throw else ""
    failure = re.compile(rf"(?:{final}exit\s+{_NONZERO_STATUS})\s*", re.IGNORECASE)
    lines = [line.strip().rstrip(";").strip() for line in body.splitlines() if line.strip()]
    return bool(lines) and all(message.fullmatch(line) for line in lines[:-1]) and bool(failure.fullmatch(lines[-1]))


def step_can_fail(block, span, key_indent, default_shell=None):
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

    `default_shell` is the job/workflow `defaults.run.shell` the caller resolved.
    It applies when the step carries no `shell:` of its own, and it is held to the
    SAME allowlist a step-level spelling is: a default this checker does not
    recognise (`bash -n {0}` runs noexec -- the body is READ, never EXECUTED, and
    exits 0 over a visible `exit 1`) must be refused, not assumed away. Reading only
    the step key vouched for plain bash while the runner's actual shell did
    something else entirely (adversarial review 20260929T030431Z, X1).
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
        # still fail the job. Without the consult the two levels disagree about the
        # same expression. UNKNOWN stays cannot-fail, the conservative direction.
        if value not in ("false", "") and static_truth(value) is not False:
            return False, "carries `continue-on-error`, so it cannot fail the job"

    # None means NO `shell:` key, which is not the same as `shell: bash`: the runner
    # default is bash off Windows and pwsh on Windows, and `runs-on:` cannot be read
    # reliably (an expression value is invisible to a literal scan, and a `run:`
    # payload line can merely look like the key). A no-key body is therefore vouched
    # under EITHER shell's rules below -- accepted when bash or pwsh recognises it,
    # refused when neither does. A `defaults.run.shell` the caller resolved overrides
    # the runner default and is held to the same allowlist as a step-level spelling.
    shell = None
    shell_key = step_key_pattern(key_indent, "shell")
    for i in range(start, end):
        match = shell_key.match(block[i])
        if match and len(match.group(1)) == key_indent:
            shell = decode_yaml_scalar(strip_inline_comment(match.group(2)).strip()).strip()
            break
    shell_from_default = False
    if shell is None and default_shell is not None:
        shell = default_shell
        shell_from_default = True
    if shell is not None and shell not in (
        "bash",
        "bash {0}",
        "bash --noprofile --norc -eo pipefail {0}",
        "pwsh",
        "pwsh {0}",
        "pwsh -command . '{0}'",
        'pwsh -command ". \'{0}\'"',
    ):
        where = " from `defaults.run.shell`" if shell_from_default else ""
        return False, f"uses unsupported shell `{shell}`{where}"

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
        # false RED.
        if value and not is_block_scalar_header(raw):
            body = [value]
        elif not is_block_scalar_header(raw):
            # An EMPTY header opens a PLAIN scalar on the following lines, not a literal
            # block: YAML folds several lines with spaces, so `echo failed` / `exit 1` runs
            # as the ONE command `echo failed exit 1` and exits ZERO. A single line is just
            # the command written on the next line, so only more than one line is refused.
            plain, _ = continuation_lines(block, i, key_indent)
            plain = [strip_inline_comment(line).strip() for line in plain]
            plain = [line for line in plain if line]
            if not plain:
                return False, "has an empty `run:` body"
            if len(plain) > 1:
                return False, (
                    "has a plain multi-line `run:` body, which YAML folds into one command; "
                    "write `run: |`"
                )
            body = [decode_yaml_scalar(plain[0])]
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
        if shell is None or shell.startswith("pwsh"):
            # STRIP COMMENTS BEFORE THE FULLMATCH, the way the bash path already does.
            # `continuation_lines` keeps comments intact deliberately, and ends_non_zero
            # masks then strips them (below). This arm did neither, so a pwsh
            # `throw "..." # note` inside a `run: |` block was refused outright while the
            # identical bash `exit 1 # note` was accepted and the same pwsh throw written
            # inline passed via strip_inline_comment. A false RED on a gate that does
            # fail.
            #
            # Located in the MASKED copy, not stripped by a blind re.sub: mask_quoted
            # preserves offsets exactly -- every branch emits as many characters as it
            # consumes -- so a span found there cuts the original at the right place,
            # while a `#` inside the throw's own quoted message stays masked and is left
            # alone. A blind sub would eat that message and fail the fullmatch for an
            # unrelated reason. Removed back-to-front so earlier offsets stay valid.
            probe = joined
            masked = mask_quoted(probe, powershell=True)
            for comment in reversed(list(re.finditer(r"(?m)(?<!\S)#[^\n]*", masked))):
                probe = probe[: comment.start()] + probe[comment.end() :]
            if "$(" in probe or "${{" in probe:
                return False, "carries a command subexpression or GitHub expression the checker cannot verify"
            if powershell_ends_non_zero(probe, throw=shell is not None, echo=shell is not None):
                return True, ""
            if shell is not None:
                where = " (from `defaults.run.shell`)" if shell_from_default else ""
                return False, (
                    f"uses pwsh{where}; only inert Write-Host/Write-Output/Write-Information "
                    "lines followed by throw or `exit` 1-255 are supported"
                )
            # No `shell:` key, and pwsh does not recognise the body: bash may. The
            # accepted pwsh forms bar `throw` fail under bash as well -- measured with
            # `bash --noprofile --norc -eo pipefail` (the runner's bash wrapper): a
            # Write-Host/Write-Output/Write-Information line is `command not found`
            # (127) and `-e` ends the step there, and a bare `exit N` exits N. So an
            # accept above is never a body bash would pass, and falling through here
            # cannot vouch for a step that succeeds. `throw` itself is the exception
            # and was excluded above: bash resolves it through PATH, and an earlier
            # step in this job can write PATH (GITHUB_PATH), so a committed executable
            # named `throw` that exits 0 would turn the gate green -- it is accepted
            # only when the effective shell is explicitly pwsh (see _THROW).
        # `false` is the mirror image, excluded under an UNKNOWN shell: it is a
        # builtin only under bash, and with no shell key the runner may be pwsh on
        # Windows, where `false` resolves through the same writable PATH. It is
        # therefore admitted only once the allowlist above has resolved the shell
        # to a POSIX spelling -- explicit pwsh never reaches this line (it returns
        # from the probe arm), so `shell is not None` here means bash.
        # With NO shell key the body must read as the same failing form under BOTH
        # quoting disciplines. `echo "foo\`"` / `exit 1` / `#"` is a message then an exit
        # under bash, but under pwsh the backtick escapes the quote and the string runs
        # on to the `"` on the last line, swallowing `exit 1`: the step exits ZERO on a
        # Windows runner while the bash reading vouched for it (adversarial review
        # 20261031T213036Z, M1). Same both-disciplines rule changes_directory applies.
        disciplines = (False,) if shell is not None else (False, True)
        if all(
            ends_non_zero(
                joined,
                allow_throw=shell is not None and shell.startswith("pwsh"),
                allow_false=shell is not None,
                powershell=powershell,
            )
            for powershell in disciplines
        ):
            return True, ""
        where = f" The effective shell `{shell}` came from `defaults.run.shell`." if shell_from_default else ""
        return False, (
            "its `run:` body is not a recognised failing form, so this checker will not "
            "vouch for it." + where + " Under bash use `exit 1`; `false`; or `echo \"...\"; exit 1`. "
            "Under `shell: pwsh` use inert Write-Host/Write-Output/Write-Information "
            "lines followed by an unconditional `throw` or `exit` 1-255. With no "
            "`shell:` key the body must satisfy one of those two minus `throw` and "
            "`false`, because the runner default is bash off Windows and pwsh on "
            "Windows, `runs-on:` cannot be read reliably, and each is only a builtin "
            "under one of the two candidate shells -- under the other it resolves "
            "through PATH, which an earlier step in the job can write via GITHUB_PATH. "
            "Declare `shell: pwsh` to use `throw`, or `shell: bash` to use `false`. "
            "Each bash form may "
            "carry a trailing redirection, and may be "
            "preceded by message lines (`echo`/`printf`) and `set` shell-option lines "
            "only. A command subexpression `$(...)` anywhere in the body is refused: "
            "under pwsh it can exit the step before the failing command runs. "
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
    let the gate keep reporting a condition that no longer exists -- the same
    fail-OPEN shape assert_gate_semantics's own docstring already documents for a
    different line.
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
    # The effective `defaults.run.shell` for the gate job's steps: the job's own first,
    # then the workflow's. Both are read from the parsed document, so a `defaults:` after
    # `jobs:` is found (missing it re-opens the X1 noexec-shell bypass one key lower in
    # the file) and one nested under matrix data or inside a block scalar is not.
    try:
        document, _, _ = parsed_document(lines, workflow_path)
        default_shell = default_run_shell(job_node(document, gate_job))
        if default_shell is None:
            default_shell = default_run_shell(document)
    except ValueError as error:
        sys.exit(str(error) if str(error).startswith(str(workflow_path)) else f"{workflow_path}: {error}")
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
    #       if: always() && (contains(needs.*.result, 'failure') || ...)   <- the actual gate
    #       run: |
    #         echo "Upstream results: ${{ join(needs.*.result, ', ') }}"   <- matched too
    #
    # Delete the `if:` and the step runs unconditionally and never fails, while the echo
    # keeps this assertion green. That is precisely the "guts only the aggregation step"
    # neuter the function exists to catch, so the check was blind to its own subject.
    # Demonstrated 2026-09-02 on a fixture with the condition removed: exit 0, reported
    # as "aggregates its needs".
    # ONE binding, used by both the scan below and the failure-capability check further
    # down. They were computed independently as `body_indent + 1` in two places, and they
    # must be equal: the second re-matches a line the first already matched, so a future
    # edit to one alone would make that re-match return None and raise AttributeError
    # instead of printing this script's own diagnostic. A crash is a worse signal than a
    # clean fail-closed exit.
    step_indent = body_indent + 1

    referenced = {}
    failing = []
    for condition, index in step_conditions(block, step_indent):
        # A condition that is statically false never enforces anything, however
        # well-formed its atoms look, so it cannot count toward coverage.
        if static_truth(condition) is False:
            continue
        coverage = []
        matches = status_reachable_atoms(condition)
        if matches is None:
            continue
        for adverse in ("failure", "cancelled"):
            for match in matches:
                job_id = match.group(1) or match.group(3)
                outcome = match.group(2) or match.group(4)
                if outcome and outcome != adverse:
                    continue
                outcomes = {adverse}
                referenced.setdefault(job_id, set()).update(outcomes)
                coverage.append((job_id, outcomes))
        if coverage:
            failing.append((condition, index, coverage))

    if not referenced:
        sys.exit(
            f"{workflow_path}: '{gate_job}' has no step whose `if:` references a "
            "reachable `needs.<job>.result` for an adverse outcome.\n"
            "Use an explicit status override such as `always() && (...)`. A bare "
            "`contains(needs.*.result, ...)` step condition does fail on a healthy gate job, "
            "but it is refused by policy: without a status function it carries an implicit "
            "success(), so a cancelled gate job, or one whose earlier step failed, skips the "
            "step and the required check does not fail. A `needs.*.result` appearing only "
            "in a `run:` body -- an echo of the upstream results, say -- gates nothing."
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
        ok, reason = step_can_fail(block, span, len(match.group(1)), default_shell)
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
# Probed on a mini-repo: `.\scripts\probe.ps1` and `./scripts/probe.PS1`
# both exited 0 -- green, ungated -- while the POSIX control `./scripts/probe.ps1`
# exited 1 with "not tiered HIGH".
GATE_SCRIPT = re.compile(
    # The extension set is deliberately closed: these are the gate-script languages
    # supported by the estate checker. Add a new extension here and to the policy
    # review before wiring it into a merge barrier. Spelled as character classes rather
    # than an inline `(?i:...)` group, which needs Python 3.11 -- this asset runs on
    # whatever python3 a consuming repository's runner provides.
    #
    # `.mjs`/`.js` are admitted on review evidence: a JavaScript gate script
    # (`node scripts/gate.mjs`) matched nothing here, so gate_script_paths never saw
    # it and the script stayed editable in a NORMAL-tier pull request. Widening here
    # widens DETECTION only -- more scripts required HIGH, never fewer. The trailing
    # `\b` is what keeps `.jsx` out: `js` followed by a word character never matches.
    r"""(?<![\w.-])(?:\.[\\/])?[\\/]?((?:[\w.-]+[\\/])*(?:\.github[\\/]scripts|scripts|build|tools)[\\/]"""
    r"""[\w.\\/-]*\.(?:[Pp][Ss][Mm]1|[Pp][Ss]1|[Pp][Yy]|[Ss][Hh]|[Bb][Aa][Ss][Hh]|[Mm][Jj][Ss]|[Cc][Jj][Ss]|[Jj][Ss]|[Tt][Ss]))\b"""
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
    valid YAML -- a false RED. So quotes are tracked, a '#'
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
        composite action raised -- a false RED on a healthy action;
      * a flow-style `runs: {using: node20, main: index.js}` never matched the
        line-anchored pattern at all, so `using` stayed unset and the non-composite
        guard was skipped -- fail-OPEN.

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
        # unterminated fragment that raised -- a false RED. The parser reads the RAW
        # text (so a comment marker inside quotes survives), takes
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


class Slice(list):
    """A contiguous run of a document's lines that remembers where it came from.

    The line scanners work on slices -- a job's block, one step's lines -- but the YAML
    parser can only read a WHOLE document: a job that is an alias (`repeated: *build`)
    names an anchor defined in another job's block, and composing the slice alone fails
    on the undefined alias. So a slice carries its document and its offset, and every
    parsed answer about it is read off the document by absolute line. A plain list is its
    own document at offset 0; a slice of a slice composes the offsets.
    """

    def __init__(self, lines, document, offset):
        super().__init__(lines)
        self.document = document
        self.offset = offset

    # Equality stays list equality on purpose: document and offset are provenance, and a
    # slice must compare equal to the plain list of the same lines.
    def __eq__(self, other):
        return list.__eq__(self, other)

    __hash__ = None


def slice_of(lines, start, end, transform=None):
    document = getattr(lines, "document", lines)
    offset = getattr(lines, "offset", 0)
    body = lines[start:end]
    if transform is not None:
        body = [transform(line) for line in body]
    return Slice(body, document, offset + start)


MERGE_TAG = "tag:yaml.org,2002:merge"


def compose_yaml(lines, name=None):
    """(root node, text) for a whole file's lines, from PyYAML's composer.

    STRUCTURE IS READ FROM A PARSER, NOT A LINE REGEX. Every structural scan in this file
    used to recognise YAML by line shape, and every valid spelling the shape missed was a
    hole: block-scalar text read as keys, a `defaults:` whose flow mapping sat on the next
    line, an anchored or aliased `env:`, an escaped key (adversarial review
    20261031T213036Z, T1/H3; simulator-frontend 20261101T004730Z, S1/S2). The composer
    resolves aliases to the nodes they name and marks every node with the lines it
    occupies, which is exactly what those scans need.

    Raises ValueError on anything PyYAML cannot read. "Cannot parse" must never render as
    "nothing to check"; every caller turns the error into a fail-closed exit.
    """
    text = "\n".join(line.rstrip("\r\n") for line in lines)
    try:
        return yaml.compose(text, Loader=yaml.SafeLoader), text
    except yaml.YAMLError as error:
        where = f"{name}: " if name else ""
        raise ValueError(f"{where}cannot parse as YAML, so coverage cannot be verified: {error}") from None


def iter_nodes(node, seen=None):
    """Every node reachable from `node`, each once (an alias shares its anchor's node)."""
    if seen is None:
        seen = set()
    if node is None or id(node) in seen:
        return
    seen.add(id(node))
    yield node
    if isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            yield from iter_nodes(key, seen)
            yield from iter_nodes(value, seen)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            yield from iter_nodes(item, seen)


def mapping_entries(node):
    """(key text, value node) pairs of a MappingNode; empty for anything else."""
    if not isinstance(node, yaml.MappingNode):
        return []
    return [(key.value, value) for key, value in node.value if isinstance(key, yaml.ScalarNode)]


def mapping_get(node, key):
    for name, value in mapping_entries(node):
        if name == key:
            return value
    return None


def job_node(root, job_id):
    """The parsed mapping of one job, or None."""
    return mapping_get(mapping_get(root, "jobs"), job_id)


def step_node_at(scope, line):
    """The step (or other mapping) under `scope` whose `run:` key sits on absolute `line`."""
    for node in iter_nodes(scope):
        if not isinstance(node, yaml.MappingNode):
            continue
        for key, _ in node.value:
            if isinstance(key, yaml.ScalarNode) and key.value == "run" and key.start_mark.line == line:
                return node
    return None


def assert_readable_shapes(root, text, name=None):
    """Refuse the YAML shapes the LINE scanners in this file do not model.

    Each is valid YAML that a regex over lines reads wrongly, and wrongly in the fail-OPEN
    direction: the construct hides a key, a step or a value from a scan that then reports
    it covered.

      * a merge key (`<<: *base`) splices in keys no scan sees;
      * a double-quoted key with an escape (`"sh\\x65ll"`) is `shell` to GitHub and nothing
        to key_pattern (tax portal review 20261101T004738Z, M13);
      * a flow-style `steps:` or a flow-mapping step item carries `run:` text no RUN_KEY
        line ever matches (adversarial review 20261031T213036Z, M5);
      * a flow collection on the line AFTER its key reads as an empty value, so `needs:`
        loses its list (XM1; simulator-frontend 20261101T004730Z, S2).

    Anchors, aliases and tags are NOT refused: the composer resolves them, the parsed
    reads below see through them, and the job-level forms are accepted by existing
    fixtures. Raises ValueError, which every caller turns into a fail-closed exit.
    """
    where = f"{name}: " if name else ""
    for node in iter_nodes(root):
        if not isinstance(node, yaml.MappingNode):
            continue
        for key, value in node.value:
            line = key.start_mark.line + 1
            if key.tag == MERGE_TAG:
                raise ValueError(f"{where}line {line}: YAML merge key `<<` is unsupported; spell the keys out")
            raw_key = text[key.start_mark.index : key.end_mark.index]
            if isinstance(key, yaml.ScalarNode) and key.style == '"' and "\\" in raw_key:
                raise ValueError(f"{where}line {line}: escaped double-quoted key {raw_key} is unsupported; write the key plainly")
            if isinstance(value, (yaml.MappingNode, yaml.SequenceNode)) and value.flow_style and value.start_mark.line > key.start_mark.line:
                raise ValueError(f"{where}line {line}: a flow-style value for `{key.value}` must start on the key's own line")
            if isinstance(key, yaml.ScalarNode) and key.value == "steps" and isinstance(value, yaml.SequenceNode):
                if value.flow_style and value.value:
                    raise ValueError(f"{where}line {line}: flow-style `steps:` is unsupported; write each step as a `- ` block item")
                for item in value.value:
                    if isinstance(item, yaml.MappingNode) and item.flow_style:
                        raise ValueError(f"{where}line {item.start_mark.line + 1}: a flow-mapping step `{{...}}` is unsupported; write the step as a block mapping")


def scalar_payload_indexes(root):
    """The line indexes that hold TEXT rather than structure: the continuation lines of
    every multi-line scalar and the inside of every multi-line flow collection."""
    payloads = set()

    def add(owner_line, node):
        if not (isinstance(node, yaml.ScalarNode) or getattr(node, "flow_style", False)):
            return
        end = node.end_mark
        last = end.line - 1 if end.column == 0 else end.line
        payloads.update(range(owner_line + 1, last + 1))

    for node in iter_nodes(root):
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                add(key.start_mark.line, value)
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                add(item.start_mark.line, item)
    return payloads


_PARSED = {}


def parsed_document(lines, name=None):
    """(root, text, payload indexes) of a whole file, parsed and shape-checked once."""
    document = getattr(lines, "document", lines)
    cached = _PARSED.get(id(document))
    if cached is not None and cached[0] is document:
        return cached[1:]
    root, text = compose_yaml(document, name)
    assert_readable_shapes(root, text, name)
    payload = scalar_payload_indexes(root)
    _PARSED[id(document)] = (document, root, text, payload)
    return root, text, payload


def run_payload_indexes(lines):
    """The indexes of `lines` that are TEXT rather than structure.

    Previously only block-scalar `run:` payloads were indexed, so a `defaults:`, `shell:`,
    `BASH_ENV:` or `working-directory:` line inside ANY OTHER block scalar -- an `env:`
    value, a `with:` input, a `run-name:` -- was read as a real key: fail-OPEN when it
    spelled a shell the checker then trusted, false RED when it spelled a key the checker
    refuses (adversarial review 20261031T213036Z, H3; tax portal 20261101T004738Z, M35).
    The parser now decides what is text: the body of every multi-line scalar and the
    inside of every multi-line flow collection, anywhere in the document. `lines` may be
    a whole file or a Slice of one; the answer is relative to `lines`.
    """
    offset = getattr(lines, "offset", 0)
    _, _, payload = parsed_document(lines)
    return {index - offset for index in payload if offset <= index < offset + len(lines)}


# The composite action's own directory, spelled the three ways a run body can reach it.
ACTION_PATH = re.compile(r"\$\{\{\s*github\.action_path\s*\}\}|\$\{GITHUB_ACTION_PATH\}|\$GITHUB_ACTION_PATH\b")


def working_directories(node, exclude=(), rewrite=None):
    """Every working directory under the parsed `node`, resolving github.workspace and
    refusing unknown expressions.

    Read from the PARSED document rather than from `working-directory:` lines. The line
    read missed the flow spelling `defaults: {run: {working-directory: sub}}` outright, so
    a feeder's relative script path resolved from the root, failed to resolve, and was
    dropped -- untiered (adversarial review 20261031T213036Z, M3) -- and it read a
    `working-directory:` line inside an `env:` block scalar as a real key, reddening a
    correct workflow over text it never executes (H3). The parser sees every spelling the
    same way and never reads text as a key.

    `exclude` names top-level keys of `node` whose subtree belongs to a different scope:
    `jobs` when `node` is the workflow root, `steps` when it is a job. At those two scopes
    only `defaults.run.working-directory` reaches a step, so only it is read: scanning
    every other subtree read `on.workflow_call.inputs.working-directory` (an input
    declaration), `strategy.matrix` keys and `with:` inputs as directories, and the input
    mapping's not-a-string sentinel reddened a valid reusable workflow (CodeRabbit, PR
    #425). `node` itself is scanned whole when `exclude` is empty. `rewrite` is applied
    to each value before classification (a composite action rewrites its action-path
    expression to its own directory).

    `${{ github.workspace }}` is honoured only at the START of the value -- the one
    position where it names the checkout root this checker resolves against. A
    mid-string occurrence is left in place so the generic expression sentinel below
    refuses it. And a relative value whose `..` segments climb above the root --
    workspace-rooted or plain -- is refused with its own sentinel: gate_script_paths
    joins directories to script candidates lexically, and a climb above the root
    resolves outside the checkout, where nothing can be tiered HIGH. An interior `..`
    that never climbs past the root (`sub/../other`) stays allowed.
    """
    found = set()
    if node is None:
        return found
    if exclude:
        run_defaults = mapping_get(mapping_get(node, "defaults"), "run")
        roots = [run_defaults] if run_defaults is not None else []
    else:
        roots = [node]
    for scope in roots:
        for inner in iter_nodes(scope):
            for name, value_node in mapping_entries(inner):
                if name != "working-directory":
                    continue
                if not isinstance(value_node, yaml.ScalarNode):
                    found.add("!unsupported working-directory value that is not a string")
                    continue
                value = " ".join(value_node.value.split())
                if rewrite is not None:
                    value = rewrite(value)
                workspace_rooted = bool(re.match(r"\$\{\{\s*github\.workspace\s*\}\}", value, re.IGNORECASE))
                if workspace_rooted:
                    value = re.sub(r"\$\{\{\s*github\.workspace\s*\}\}", "", value, count=1, flags=re.IGNORECASE)
                if "${{" in value:
                    found.add(f"!unsupported working-directory expression: {value}")
                    continue
                value = value.replace("\\", "/").strip()
                if (value.startswith("/") and not workspace_rooted) or re.match(r"^[A-Za-z]:", value):
                    found.add(f"!unsupported absolute working-directory: {value}")
                    continue
                value = value.strip("/")
                # Every RELATIVE value gets the climb check, not only workspace-rooted
                # ones: a plain `..` resolves against the workspace and escapes the
                # checkout by the same lexical join, and the bare-candidate suspension
                # in gate_script_paths would let the script that runs go unchecked.
                depth = 0
                for segment in value.split("/"):
                    if segment == "..":
                        depth -= 1
                    elif segment and segment != ".":
                        depth += 1
                    if depth < 0:
                        break
                if depth < 0:
                    found.add(f"!unsupported working-directory climbing above the workspace root: {value}")
                    continue
                if value:
                    found.add(value.rstrip("/"))
    return found


def step_lines(block, run_index, key_indent):
    """The lines of the step whose `run:` key is at `run_index`, as a Slice.

    Scoping to the step is what keeps a SIBLING step's working-directory out of this
    step's candidate paths: it never applies here, and an unrelated file that happened to
    exist at that spelling was being required HIGH.
    A run key that is not inside a sequence item falls back to the whole block -- more
    candidates, never fewer.
    """
    span = step_span(block, run_index, key_indent)
    if span is None:
        return block
    start, end = span
    return slice_of(block, start, end)


def step_directories(scope, block, run_index, rewrite=None):
    """The working directories that apply to the `run:` at `block[run_index]`: the step's
    own, read from the parsed step; or the whole `scope` when the key is not in a step."""
    step = step_node_at(scope, getattr(block, "offset", 0) + run_index)
    return working_directories(step if step is not None else scope, rewrite=rewrite)


def default_run_shell(node):
    """The `defaults.run.shell` of the parsed mapping `node`, or None when unset.

    Read from the PARSED document and only at the mapping's own top level: a `defaults:`
    nested under `strategy.matrix.include` is matrix data, not the job default
    (adversarial review 20261031T213036Z, XL2), and text shaped like one inside an `env:`
    block scalar is a string (H3). The flow, block, anchored, aliased, next-line-flow and
    quoted spellings all resolve the same way because the parser reads them, not a regex
    (M4, XM1; simulator-frontend 20261101T004730Z, S2, S13). `run:` also appears as a
    STEP key; the scoped descent is why a step's own `run:` is never read here
    (adversarial review 20260929T030431Z, X1).

    A `defaults:` or `run:` that is present but not a mapping, or a `shell:` that is not a
    string, RAISES: "cannot resolve defaults.run.shell" must never read as "no default",
    because the body would then be vouched under a shell the runner does not use.
    """
    defaults = mapping_get(node, "defaults")
    if defaults is None:
        return None
    if not isinstance(defaults, yaml.MappingNode):
        raise ValueError("cannot resolve defaults.run.shell: `defaults:` is not a mapping")
    run = mapping_get(defaults, "run")
    if run is None:
        return None
    if not isinstance(run, yaml.MappingNode):
        raise ValueError("cannot resolve defaults.run.shell: `defaults.run:` is not a mapping")
    shell = mapping_get(run, "shell")
    if shell is None:
        return None
    if not isinstance(shell, yaml.ScalarNode):
        raise ValueError("cannot resolve defaults.run.shell: `shell:` is not a string")
    return " ".join(shell.value.split())


def delegated_run_bodies(root, ref, visited, include_directories=True):
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
    # flow style.
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
    # script. Without it, `"${{ github.action_path }}/scripts/gate.sh"` would resolve
    # against the repository root and a script beside action.yml would go untiered.
    try:
        action_dir = target.parent.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        action_dir = None
    index = 0
    document, _, _ = parsed_document(lines, target)
    payload_indexes = run_payload_indexes(lines)
    rewrite = (lambda value: ACTION_PATH.sub(action_dir, value)) if action_dir is not None else None
    while index < len(lines):
        if index in payload_indexes:
            index += 1
            continue
        match = RUN_KEY.match(lines[index])
        if not match:
            index += 1
            continue
        run_index = index
        value = strip_inline_comment(match.group(2)).strip()
        if not value or BLOCK_SCALAR.match(value):
            body, index = continuation_lines(lines, index, len(match.group(1)))
        else:
            body, index = ([value] if value else []), index + 1
        if body:
            directories = step_directories(document, lines, run_index, rewrite) if include_directories else set()
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
            yield from delegated_run_bodies(root, match.group(1), visited, include_directories)


def delegated_workflow_run_bodies(root, ref, visited, include_directories=True):
    """Yield run bodies from a local reusable workflow with its own defaults applied."""
    target = root / ref[2:]
    if not target.is_file():
        return
    key = target.resolve().as_posix()
    if key in visited:
        return
    visited.add(key)
    lines = target.read_text(encoding="utf-8-sig").splitlines()
    jobs, _, _ = read_gate_contract(lines, "__coverage_no_gate__")
    if not jobs:
        # `jobs: {build: {...}}` parses to NO jobs, and returning here let every script
        # the reusable workflow runs escape tiering. check_file refuses the same spelling
        # for the calling workflow; the callee gets the same refusal (adversarial review
        # 20261031T213036Z, M6).
        if any(JOBS_DECL.match(strip_comment(line).rstrip()) for line in lines):
            raise ValueError(
                f"{target}: flow-style or empty 'jobs' mapping in a reusable workflow is "
                "unsupported; refusing to skip its scripts."
            )
        return
    document, _, _ = parsed_document(lines, target)
    workflow_directories = working_directories(document, exclude={"jobs"}) if include_directories else set()
    for job_id in jobs:
        block = job_block(lines, jobs, job_id)
        job = job_node(document, job_id)
        job_directories = set(workflow_directories)
        if include_directories:
            job_directories |= working_directories(job, exclude={"steps"})
        payload_indexes = run_payload_indexes(block)
        index = 0
        while index < len(block):
            match = RUN_KEY.match(block[index])
            if not match:
                index += 1
                continue
            run_index = index
            value = strip_inline_comment(match.group(2)).strip()
            if not value or BLOCK_SCALAR.match(value):
                body, index = continuation_lines(block, index, len(match.group(1)))
            else:
                body, index = ([value] if value else []), index + 1
            directories = set(job_directories)
            if include_directories:
                directories |= step_directories(job, block, run_index)
            if body:
                yield body, directories
        for line_index, line in enumerate(block):
            if line_index in payload_indexes:
                continue
            local = LOCAL_USES.match(line)
            if not local:
                continue
            nested = local.group(1)
            if nested[2:].startswith(".github/workflows/"):
                yield from delegated_workflow_run_bodies(root, nested, visited, include_directories)
            else:
                yield from delegated_run_bodies(root, nested, set(), include_directories)


def gated_run_bodies(lines, jobs, needs, gate_job, root, include_directories=True):
    """Every `run:` body line belonging to a job that can fail the gate, with its job id.

    Scoped to the gate's `needs:` plus the gate job itself, because that is exactly the
    set whose failure blocks a merge. A script run only by an exempt, non-merge-blocking
    job cannot neuter the barrier, so requiring it to be HIGH would be a cost with no
    control behind it.
    """
    job_indent = len(lines[jobs[gate_job]]) - len(lines[jobs[gate_job]].lstrip(" "))
    document, _, _ = parsed_document(lines)
    # Only workflow-level `defaults.run` -- outside the jobs mapping, before or after
    # it -- can set a working directory for this job's steps.
    workflow_directories = working_directories(document, exclude={"jobs"}) if include_directories else set()
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
        job = job_node(document, job_id)
        # Directories that apply to EVERY step of this job: workflow- and job-level
        # `defaults.run.working-directory`. A step's own value is added per run body
        # below; a sibling step's is not. Computed once per job rather than once per
        # script match.
        job_directories = set(workflow_directories)
        if include_directories:
            job_directories |= working_directories(job, exclude={"steps"})
        payload_indexes = run_payload_indexes(block)
        index = 0
        while index < len(block):
            if index in payload_indexes:
                index += 1
                continue
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
            # step_can_fail uses, so the two paths agree.
            value = strip_inline_comment(match.group(2)).strip()
            if not value or BLOCK_SCALAR.match(value):
                body, index = continuation_lines(block, index, len(match.group(1)))
            else:
                body, index = ([value] if value else []), index + 1
            directories = set(job_directories)
            if include_directories:
                directories |= step_directories(job, block, run_index)
            for body_line in body:
                yield job_id, body_line, body, directories
        payload_indexes = run_payload_indexes(block)
        for index, line in enumerate(block):
            if index in payload_indexes:
                continue
            match = LOCAL_USES.match(line)
            if match:
                if match.group(1)[2:].startswith(".github/workflows/"):
                    delegated = delegated_workflow_run_bodies(root, match.group(1), set(), include_directories)
                else:
                    delegated = delegated_run_bodies(root, match.group(1), set(), include_directories)
                for delegated_body, directories in delegated:
                    for body_line in delegated_body:
                        yield job_id, body_line, delegated_body, directories
        pending.extend(job_needs(lines, jobs, job_id, job_indent) - seen)


def resolve_committed_paths(root, relative, allow_outside_repository=False):
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

    `allow_outside_repository` suspends the outside-repository exit for a candidate
    that is only a SPECULATIVE spelling of a reference a working directory already
    anchored -- see gate_script_paths. A resolved-outside file is then simply not
    returned (nothing outside the checkout can be tiered HIGH), and the exit keeps
    its force for the only spelling there is.
    """
    # NORMALISE DOT COMPONENTS FIRST. `iterdir()` never yields `.` or `..`, so walking
    # them literally matches nothing and drops the candidate -- fail-open. The exact
    # `is_file()` this walk replaced did not have that problem for `.`, because pathlib
    # collapses a single dot on construction, so leaving it out was a REGRESSION rather
    # than an unchanged gap. `..` is resolved here too, and a path that climbs above the
    # repository root is refused outright rather than clamped: nothing outside the
    # checkout is a repo-local gate script.
    parts = []
    overclimbed = False
    for part in relative.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                # OVER-CLIMBED LEXICALLY. Returning here would be the same early-exit
                # mistake as the one below, one step earlier: `scripts/link/../../../gate.py`
                # escapes the checkout on paper, but if `link` targets a sufficiently deep
                # in-checkout directory the OS lands back INSIDE it, and the gate script
                # that actually runs would be omitted from coverage. Fall through to the
                # filesystem resolution instead; its `is_relative_to` containment check is
                # what excludes a genuinely external target, and it does so on the real
                # answer rather than the lexical one.
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
            # case is re-checked after the climbed block instead.
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
    # Resolve through the filesystem as well as by committed spelling, and keep BOTH
    # spellings. A symlink target is the script whose contents can be edited; tiering only
    # the link would leave that target outside review. The error direction is:
    # more scripts required HIGH, never fewer. A disagreement between the lexical and the
    # real answer can only ADD a requirement. A target outside the checkout is refused.
    #
    # Measured before writing this: zero committed symlinks across the estate, so the
    # hazard is unreachable today. It is closed because the cost is a dozen lines and the
    # direction is fail-open, not because it was observed.
    resolved_matches = []
    try:
        real = (root / relative).resolve()
        if real.is_file() and real.is_relative_to(root.resolve()):
            spelled = real.relative_to(root.resolve()).as_posix()
            if spelled not in matches:
                resolved_matches.append(spelled)
        elif real.is_file() and not allow_outside_repository:
            sys.exit(f"{root}: gate script resolves outside the repository: {relative}")
    except (OSError, ValueError):
        # A broken or circular link cannot be read by the runner either. Keep the
        # committed lexical spelling, which is still subject to HIGH tiering.
        pass

    # The walk may have broken out with nothing and filesystem resolution may have added
    # nothing. Only now is "this path resolves to no file at all" true.
    if not matches and not resolved_matches:
        return []

    # The exact-match test uses the NORMALISED spelling: `scripts/./probe.py` resolves to
    # `scripts/probe.py`, and comparing against the raw text would never match it.
    if normalised in matches:
        return sorted({normalised, *resolved_matches})
    return sorted({*matches, *resolved_matches})


# A directory change at a COMMAND position: line start, after a separator, inside a
# subshell or brace group (`(cd x && ...)`, `{ cd x; ...; }`), after `!`, or after a
# compound keyword (`if cd x; then`). Those are ordinary ways to write one, so missing them
# let a gate script run from a directory the checker never considered.
# A compound keyword starts a command only when it is itself at a command position, so the
# keywords are an optional chain AFTER a real command start: `echo then cd sub` is an echo.
# `!` is the same: a separate token at a command position (`! cd x`), not a character
# inside an argument (`echo hi! cd x`).
_KEYWORDS = r"(?:(?:then|do|else|if|elif|while|until|!)\s+)*"
# The command word ends where a shell word ends, at whitespace or a metacharacter, not at
# any `\b`: `${cd:-x}`, `${cd}` and `{cd,ls}` name a `cd` without running one, and a `{`
# anchor followed by `\b` read all three as a directory change. A redirection ends the word
# too (`cd>log` is `cd` to $HOME); `#` does not, since `cd#x` is one word, not a comment.
# A `$` expansion does end it, in effect: `cd$X`, `cd${SUB}` and `cd$(...)` run `cd` when
# the expansion is empty or begins with whitespace (word splitting), so they fail closed.
# An assignment prefix. The BARE value alternative admits EMPTY (`*`, not `+`):
# mask_quoted blanks a quoted value to spaces, so `A="x y" B=1 cd sub` reads as
# `A=      B=1 cd sub` in the masked copy DIRECTORY_CHANGE runs against -- with `+`
# the first assignment failed to parse there, the whole prefix chain collapsed, and
# the directory change was missed. Empty is also REAL shell: `A= cd sub` runs cd with
# A empty. The masked read now covers every spelling, so the raw-line second pattern
# that used to paper over this (QUOTED_ASSIGNMENT_DIRECTORY_CHANGE) is gone -- keeping
# two patterns in agreement was a cost with no coverage behind it.
_ASSIGNMENT_WORD = r"[A-Za-z_][A-Za-z0-9_]*=(?:'(?:[^']|'')*'|\"(?:\\.|[^\"])*\"|[^\s;&|]*)"
# `sl` and `chdir` are pwsh's built-in aliases for Set-Location, so a Windows gate can
# change directory without spelling `cd`.
_DIRECTORY_COMMAND = r"(?:(?:command|builtin)\s+|" + _ASSIGNMENT_WORD + r"\s+)*(?P<directory>cd|chdir|sl|pushd|Push-Location|Set-Location)(?=[\s;&|()`<>$]|$)"
# An unquoted backtick opens a command substitution just as `$(` does, so it anchors too.
DIRECTORY_CHANGE = re.compile(r"(?:^|[;&|(`{])\s*" + _KEYWORDS + _DIRECTORY_COMMAND, re.IGNORECASE)
# A directory change as a command INSIDE a quoted string, which may span lines. An opening
# `$(` or backtick starts a command too: a substitution runs even inside printed text.
SEGMENT_DIRECTORY_CHANGE = re.compile(
    r"(?:^|[;&|\n(`{])\s*" + _KEYWORDS + _DIRECTORY_COMMAND,
    re.IGNORECASE,
)
# A single pipe (not `||`), which feeds printed text onward to another command.
PIPE = re.compile(r"(?<!\|)\|(?!\|)")
# The command a quoted string is an argument to, when that command only prints it.
MESSAGE_COMMAND = re.compile(
    r"(?:^|[;&|\n])\s*(?:echo|printf|Write-Host|Write-Output|Write-Warning|Write-Error|Write-Verbose)\b[^;&|\n]*$",
    re.IGNORECASE,
)


def quoted_segments(text, powershell=False):
    """(start, end, content) of every quoted ARGUMENT in `text`, by mask_quoted's rules.

    `start` is the opening quote's index and `end` the closing quote's.

    Spans that touch with nothing between them (`"cd sub; "'python3 x.py'`) are one shell
    argument, so they are returned as one segment. An unterminated quote runs to the end
    of the text, as it does in mask_quoted.

    The escape rules are mask_quoted's and must stay in step with it: in PowerShell
    mode a backtick escapes inside `"..."` and a doubled `''` escapes inside `'...'`;
    in bash mode a backslash escapes anywhere outside single quotes. The caller cuts
    `before`/`after` spans out of mask_quoted's output at THESE offsets, so a drift
    between the two would cut the original at the wrong place.
    """
    segments = []
    quote = None
    start = 0
    last_end = -2
    index = 0
    while index < len(text):
        char = text[index]
        if powershell and quote == "'" and char == "'" and text[index + 1:index + 2] == "'":
            index += 2
            continue
        if (
            (powershell and quote == '"' and char == "`")
            or (not powershell and quote != "'" and char == BACKSLASH)
        ) and index + 1 < len(text):
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


def opening_backticks_only(text):
    """`text` with every CLOSING backtick blanked, so only an opening one anchors a command.

    Backticks pair up, and only the first of each pair starts a substitution: in
    `` echo `pwd` cd sub `` the second `cd` is an argument to echo, not a command.
    The placeholder is not whitespace: a substitution closing at the start of a later line
    must not leave that line's `cd` looking like the first word of a command.
    """
    parts = text.split("`")
    return "".join(part + ("`" if index % 2 == 0 else "_") for index, part in enumerate(parts[:-1])) + parts[-1]


def changes_directory(body):
    """True when a run body may change directory before a gate script runs.

    Unquoted text is read line by line with quoted spans masked, so a `cd` inside
    `echo "step1; cd scripts is deprecated"` is not a directory change.

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
    are read as the one argument they are.

    BOTH quoting disciplines are tried, bash and PowerShell, and either verdict counts.
    Which shell runs a body is not reliably known here -- a step with no `shell:` key
    runs bash off Windows and pwsh on it -- and the disciplines differ exactly where it
    matters: pwsh does not treat `\"` as an escape, so bash masking never closes
    `Write-Host "cache: C:\" ; Set-Location sub` and the real directory change after the
    string stays masked. Testing both can only ADD a detection; a wrong positive costs a
    refused workflow while a wrong negative costs an untiered gate script, and those are
    not symmetric.

    THE BOUNDARY, stated so a pass is not read as more than it is: this is a line-level
    heuristic, not a shell parser. It covers the ways a workflow author ordinarily writes a
    directory change -- `cd`/`pushd`/`Set-Location` as a command, in a quoted `-c` string,
    or in a substitution. A deliberately obfuscated one (`eval "c""d sub"`, a variable
    holding the command, an alias, a nested interpreter reading a file) is out of scope:
    the workflow change that introduces it is itself HIGH-tier and reviewed, and review is
    the control for intent. Further spellings of that kind are declined, not chased.
    """
    # Backtick pairs are counted across the whole body, not per line: a substitution may
    # close on a later line, and its closing backtick must not read as an opening one.
    for powershell in (False, True):
        unquoted = opening_backticks_only(
            mask_quoted("\n".join(body), powershell=powershell)
        )
        for visible in unquoted.split("\n"):
            if DIRECTORY_CHANGE.search(visible):
                return True
    text = "\n".join(body)
    for powershell in (False, True):
        masked = mask_quoted(text, powershell=powershell)
        for start, end, content in quoted_segments(text, powershell=powershell):
            if not (SEGMENT_DIRECTORY_CHANGE.search(opening_backticks_only(content)) and GATE_SCRIPT.search(content)):
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


def _recognised_suffixes(relative):
    """Every suffix of `relative` starting at a segment GATE_SCRIPT recognises.

    GATE_SCRIPT's prefix classes are greedy, so a reference like
    `$GITHUB_WORKSPACE/scripts/gate.py` is captured WITH its prefix
    (`GITHUB_WORKSPACE/scripts/gate.py`), and finditer never retries inside a consumed
    match -- the suffix that actually exists in the checkout is never seen, and the
    prefixed spelling resolves to nothing and is dropped. Yielding each suffix that
    begins at a `scripts`/`build`/`tools` segment (or a `.github` segment followed by
    `scripts`, mirroring the regex) recovers it. More candidates, never fewer.

    A prefix that CLIMBS ABOVE ITS OWN START disqualifies every later suffix:
    `scripts/../../scripts/probe.ps1` escapes the checkout, and its `scripts/probe.ps1`
    suffix is a DIFFERENT file at run time -- one the repository may legitimately carry.
    Asserting it would redden the checkout over a script that never runs, which is the
    false-RED direction. A BALANCED climb does not disqualify: in
    `$GITHUB_WORKSPACE/x/../scripts/gate.py` the `..` only undoes `x`, and the suffix
    names exactly the file that runs. A flag that stayed set after ANY `..` yielded
    nothing there, so the script was never required HIGH (adversarial review
    20261031T213036Z, H4). Depth is tracked instead, and the suffix is refused only once
    the prefix has gone below where it started.
    """
    segments = relative.split("/")
    depth = 0
    escaped = False
    for index, segment in enumerate(segments):
        if segment == "..":
            depth -= 1
            escaped = escaped or depth < 0
            continue
        if escaped:
            continue
        if segment in ("scripts", "build", "tools") or (
            segment == ".github" and segments[index + 1:index + 2] == ["scripts"]
        ):
            yield "/".join(segments[index:])
        if segment and segment != ".":
            depth += 1


# `npm run <name>` (or `run-script`), with any `--flag` before the script name.
NPM_COMMAND = re.compile(r"\bnpm\s+")
NPM_NAME = re.compile(r"[\w:.@/-]*")
NPM_RUN_COMMANDS = {"run", "run-script", "rum", "urn"}
# Lifecycle commands run the package script of their own name, pre/post hooks included.
# `npm restart` runs `restart`, or `stop` then `start` when the package has none; that choice
# is made per package in npm_script_commands.
NPM_LIFECYCLE_COMMANDS = {
    "test": ("test",), "t": ("test",), "tst": ("test",), "start": ("start",), "stop": ("stop",),
    "restart": ("restart",),
    "install-test": ("test",), "it": ("test",),
    "install-ci-test": ("test",), "clean-install-test": ("test",), "cit": ("test",), "sit": ("test",),
}
# Options that move npm into another package. Each is resolved to that package's directory
# by npm_package_dirs; a value it cannot resolve statically is refused.
NPM_DIRECTORY_OPTIONS = ("--prefix", "-C", "--workspace", "-w", "--workspaces", "-ws", "--ws")
# The directory options that take a separate value, which is not the subcommand.
NPM_VALUED_DIRECTORY_OPTIONS = ("--prefix", "-C", "--workspace", "-w")


def npm_selectors(npm_args):
    """(option, value) for each directory option among npm's own arguments, in order."""
    selectors, index = [], 0
    while index < len(npm_args):
        option, _, value = npm_args[index].partition("=")
        if option in ("--include-workspace-root", "--iwr"):
            selectors.append(("--include-workspace-root", value))
        elif option in NPM_DIRECTORY_OPTIONS:
            if option in NPM_VALUED_DIRECTORY_OPTIONS and not value:
                value = npm_args[index + 1] if index + 1 < len(npm_args) else ""
                index += 1
            selectors.append((option, value))
        index += 1
    return selectors


def npm_workspace_dirs(root, base):
    """Repository-relative directories of the workspaces the package at `base` declares."""
    package = root / base / "package.json" if base else root / "package.json"
    try:
        declared = json.loads(package.read_text(encoding="utf-8-sig")).get("workspaces")
    except (OSError, ValueError, AttributeError):
        return []
    if isinstance(declared, dict):
        declared = declared.get("packages")
    if not isinstance(declared, list):
        return []
    found = set()
    for pattern in declared:
        if not isinstance(pattern, str) or pattern.startswith("!") or ".." in pattern.split("/"):
            continue
        for candidate in (root / base).glob(pattern.rstrip("/")):
            if (candidate / "package.json").is_file():
                found.add(candidate.relative_to(root).as_posix())
    return sorted(found)


def npm_package_dirs(root, base, selectors):
    """(directories, refusal) for an npm command run from `base` with `selectors`.

    `--prefix`/`-C` name a directory relative to the current package; `--workspace`/`-w`
    name a workspace of it by package name or by path (a parent path selects every
    workspace under it); `--workspaces`/`--ws` select all of them. Each was refused
    outright, which reddened every consumer whose gate runs `npm test` over workspaces.
    A value read from an expression, a path leaving the repository and a workspace the
    root package does not declare are still refused, since the script npm runs is unknown.
    The prefix is applied first and the workspaces are those of the prefixed package;
    `--workspaces=false` selects none; `--include-workspace-root` adds the package itself.
    """
    if not selectors:
        return [base], None
    current = base
    prefixes = [(option, value) for option, value in selectors if option in ("--prefix", "-C")]
    if prefixes:
        # npm keeps the last value of a repeated option.
        option, value = prefixes[-1]
        if not value or re.search(r"[$`{%]", value):
            return None, f"npm directory option `{option} {value}` is not a literal path"
        raw = value.replace("\\", "/")
        target = posixpath.normpath(posixpath.join(base or ".", raw))
        # A drive-absolute `C:/x` is not absolute to posixpath, and joined to a subdirectory it
        # reads `sub/C:/x`, so the drive is checked on the raw value.
        if target == ".." or target.startswith("../") or posixpath.isabs(target) or re.match(r"[A-Za-z]:", raw):
            return None, f"npm directory option `{option} {value}` leaves the repository"
        current = "" if target == "." else target
    include_root = any(option == "--include-workspace-root" and value.lower() in ("", "true") for option, value in selectors)
    chosen_selectors = [
        (option, value) for option, value in selectors
        if option in ("--workspace", "-w") or (option in ("--workspaces", "-ws", "--ws") and value.lower() != "false")
    ]
    if not chosen_selectors:
        return [current], None
    directories = [current] if include_root else []
    workspaces = npm_workspace_dirs(root, current)
    for option, value in chosen_selectors:
        if option in ("--workspaces", "-ws", "--ws"):
            if not workspaces:
                return None, f"npm option `{option}` selects no workspace the package at `{current or '.'}` declares"
            directories.extend(workspaces)
            continue
        if not value or re.search(r"[$`{%]", value):
            return None, f"npm workspace option `{option} {value}` is not a literal name or path"
        path = posixpath.normpath(posixpath.join(current or ".", value.replace("\\", "/")))
        chosen = []
        for directory in workspaces:
            try:
                name = json.loads((root / directory / "package.json").read_text(encoding="utf-8-sig")).get("name")
            except (OSError, ValueError, AttributeError):
                name = None
            if name == value or directory == path or directory.startswith(path + "/"):
                chosen.append(directory)
        if not chosen:
            return None, f"npm workspace `{value}` is not a workspace the package at `{current or '.'}` declares"
        directories.extend(chosen)
    return sorted(set(directories)), None


def npm_invocations(text):
    """(offset, script name, selectors) for each `npm` command in `text` that runs a package script.

    `npm test` / `npm t` run `scripts.test` with its hooks just as `npm run test` does, and
    reading only `run` left the most common gate command unfollowed. A directory option
    (`--prefix`, `-C`, `--workspace`, `-w`) was read as a flag and its VALUE as the script
    name, so the real script went untiered (CodeRabbit, mirror PR #140). The options are
    returned as `selectors` for npm_package_dirs to resolve to the package npm runs in.
    """
    for match in NPM_COMMAND.finditer(text):
        rest = text[match.end():]
        end = COMMAND_END.search(mask_quoted(rest))
        tokens = _interpreter_tokens(rest[:end.start()] if end else rest)
        npm_args = tokens[:tokens.index("--")] if "--" in tokens else tokens
        index, command = 0, None
        while index < len(tokens):
            token = tokens[index]
            if token.startswith("-"):
                # `npm --prefix frontend run lint`: the option's value is not the subcommand.
                index += 2 if token in NPM_VALUED_DIRECTORY_OPTIONS else 1
                continue
            # The leading name characters only, so `$(npm run lint)` still reads `lint`.
            command = NPM_NAME.match(token).group(0)
            previous = tokens[index - 1] if index else ""
            if command in NPM_RUN_COMMANDS or command in NPM_LIFECYCLE_COMMANDS or not previous.startswith("-") or "=" in previous:
                break
            # `npm --loglevel warn run gate`: an unknown word straight after a bare option is
            # read as that option's value, so the real subcommand after it is still found.
            index, command = index + 1, None
        if command is None:
            continue
        if command not in NPM_LIFECYCLE_COMMANDS and command not in NPM_RUN_COMMANDS:
            # `npm ci --prefix frontend` runs no package script this reading follows.
            continue
        selectors = npm_selectors(npm_args)
        if command in NPM_LIFECYCLE_COMMANDS:
            for name in NPM_LIFECYCLE_COMMANDS[command]:
                yield match.start(), name, selectors
        elif command in NPM_RUN_COMMANDS:
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
            name = NPM_NAME.match(tokens[index]).group(0) if index < len(tokens) else ""
            if name:
                yield match.start(), name, selectors
            # `npm run --loglevel warn gate`: after a bare option the first word may be its
            # value, so the next word is followed too. A missing script is skipped, so this
            # only adds candidates.
            previous = tokens[index - 1] if 0 < index < len(tokens) else ""
            if name and previous.startswith("-") and "=" not in previous:
                index += 1
                while index < len(tokens) and tokens[index].startswith("-"):
                    index += 1
                following = NPM_NAME.match(tokens[index]).group(0) if index < len(tokens) else ""
                if following:
                    yield match.start(), following, selectors


def printed_only(line, start):
    """True when the text at `start` of `line` is merely the ARGUMENT of a printing command.

    `echo "see scripts/report.py"` names a script it never runs. Reading the path out of
    raw text forced that file HIGH and, beside a `cd`, reddened the required check
    outright (tax portal review 20261101T004738Z, M18). The exemption is the one
    changes_directory already applies to quoted strings: the command must be echo/printf/
    Write-*, nothing before the text may open a substitution, and nothing after it may
    pipe the text onward -- each of those EXECUTES the text. An unquoted `(` in the
    printing command's own arguments counts as a substitution too: `echo (cmd)` and
    `Write-Host (cmd)` run cmd under pwsh, `echo <(cmd)` runs it under bash (CodeRabbit,
    PR #425).
    """
    masked = mask_quoted(line)
    before, after = masked[:start], masked[start:].split("\n", 1)[0]
    if "$(" in line or "`" in line or PIPE.search(after):
        return False
    command = MESSAGE_COMMAND.search(before)
    return command is not None and "(" not in command.group(0)


def npm_script_commands(root, bases, name, visited):
    """(package directory, command) for every package.json script `npm run <name>` runs.

    Resolved from each `base` directory's package.json, with the `pre<name>` and
    `post<name>` hooks npm runs around it, and followed transitively through nested
    `npm run` calls. A script reached only this way was invisible to the checker: the
    frontend's `npm run lint:ratchet` ran `scripts/lintRatchet.mjs`, the file that
    enforces a HIGH-tiered ratchet, and nothing required the script itself to be HIGH
    (simulator-frontend review 20261101T004730Z, S7).
    """
    commands = []
    for base in bases:
        package = root / base / "package.json" if base else root / "package.json"
        try:
            scripts = json.loads(package.read_text(encoding="utf-8-sig")).get("scripts")
        except (OSError, ValueError, AttributeError):
            continue
        if not isinstance(scripts, dict):
            continue
        if name == "restart" and not isinstance(scripts.get("restart"), str):
            # With no `restart` script, `npm restart` runs `stop` then `start` (its own
            # pre/post hooks still run around them).
            for fallback in ("stop", "start"):
                commands.extend(npm_script_commands(root, [base], fallback, visited))
        for hook in (f"pre{name}", name, f"post{name}"):
            command = scripts.get(hook)
            if not isinstance(command, str) or (base, hook) in visited:
                continue
            visited.add((base, hook))
            commands.append((base, command, None))
            for _, nested, selectors in npm_invocations(command):
                directories, refusal = npm_package_dirs(root, base, selectors)
                if refusal:
                    commands.append((base, None, refusal))
                else:
                    commands.extend(npm_script_commands(root, directories, nested, visited))
    return commands


def script_references(body, directories, root):
    """(relative path, applicable directories) for every gate-script reference `body`
    makes, directly or through `npm run`.

    Three readings, each only ADDING candidates (more scripts required HIGH, never fewer):
    each physical line, as before; the body with bash line continuations folded, because
    `scripts/ga\\` + newline + `te.py` is `scripts/gate.py` to bash and matched nothing
    per line (adversarial review 20261031T213036Z, XL1); and the package.json commands
    behind each `npm run <name>`, resolved against the package's own directory as well
    as the body's. A reference that is only PRINTED is skipped -- see printed_only.
    """
    text = "\n".join(body)
    folded = re.sub(r"\\\n[ \t]*", "", text)
    for source in {text, folded}:
        for match in GATE_SCRIPT.finditer(source):
            if printed_only(source, match.start(1)):
                continue
            yield match.group(1).replace("\\", "/"), directories
    bases = [""] + sorted(directory for directory in directories if directory and not directory.startswith("!"))
    # Unsupported working-directory markers travel with every interpreter reference, so
    # `working-directory: ${{ matrix.path }}` + `python gate.py` is refused, not resolved at the root.
    markers = {directory for directory in directories if directory.startswith("!")}
    for relative, extra in interpreter_references(folded, bases, root):
        yield relative, extra | markers
    for offset, name, selectors in npm_invocations(folded):
        if printed_only(folded, offset):
            continue
        packages, refusals = [], []
        for base in bases:
            resolved, refusal = npm_package_dirs(root, base, selectors)
            if refusal:
                refusals.append(refusal)
            else:
                packages.extend(directory for directory in resolved if directory not in packages)
        # The root is always a candidate beside a working-directory, so a selector is refused
        # only when it resolves from none of them (`--prefix ../x` leaves the root, not `sub`).
        if not packages:
            for refusal in refusals:
                yield _refusal(refusal)
        for base, command, nested_refusal in npm_script_commands(root, packages, name, set()):
            if nested_refusal:
                yield _refusal(nested_refusal)
                continue
            for script in GATE_SCRIPT.finditer(command):
                yield script.group(1).replace("\\", "/"), directories | ({base} if base else set())
            # `"gate": "python3 gate.py"` runs a root-level script GATE_SCRIPT cannot see (CodeRabbit, PR #426).
            # npm runs it from the package's own directory.
            for relative, extra in interpreter_references(command, [base], root):
                yield relative, extra | markers


# A Python interpreter as a command word. The target after it is read by
# interpreter_references; GATE_SCRIPT alone saw none of `-m`, `unittest discover -s` or a
# root-level `python3 gate.py` (tax portal review 20261101T004738Z, M36).
# A path prefix is allowed (`.venv/bin/python`, `/usr/bin/python3`; CodeRabbit, PR #426).
# A closing quote may follow (`"C:\Program Files\Python\python.exe" gate.py`).
PYTHON_COMMAND = re.compile(r"(?<![\w.-])python(?:3(?:\.\d+)*)?(?:\.exe)?(?=[\"']?[ \t])")
# Spellings of the checkout root in a target path, read as the repository root.
WORKSPACE_PREFIX = re.compile(r"^(?:\$\{?GITHUB_WORKSPACE\}?|\$\{\{\s*github\.workspace\s*\}\}|\$env:GITHUB_WORKSPACE)/")
# A shell redirection token: complete on its own (`2>&1`, `>out.txt`), or one that takes the next
# token as its file (`>`, `2>>`). Neither is an interpreter argument.
REDIRECT_COMPLETE = re.compile(r"\d*>&(?:\d+|-)|&>>?\S+|\d*>>?\S+|\d*<\S+")
REDIRECT_OPEN = re.compile(r"\d*>>?|&>>?|\d*<")
# Interpreter options that consume the next token.
PYTHON_VALUE_OPTIONS = {"-X", "-W", "-Q"}
# pytest options whose value is a separate token, so it is not read as a path.
PYTEST_VALUE_OPTIONS = {"-k", "-m", "-c", "-p", "-o", "-n", "-W", "-r", "--rootdir", "--confcutdir", "--basetemp", "--junitxml", "--cov", "--cov-report", "--ignore", "--deselect"}
# unittest options whose value is a separate token (`-k smoke`), so it is not read as a target (Gitar, PR #426).
UNITTEST_VALUE_OPTIONS = {"-k"}
# Shell separators that end one command, searched in quote-masked text.
COMMAND_END = re.compile(r";|&&|\|\||\||\n")


def _resolve_under_bases(root, bases, relative):
    """Root-relative committed paths of `relative` under each base directory."""
    found = []
    for base in bases:
        candidate = f"{base}/{relative}" if base else relative
        found.extend(resolve_committed_paths(root, candidate, allow_outside_repository=True))
    return found


def _files_matching(root, bases, start, patterns):
    """(start resolved, files): every file under `start` (per base) matching a pattern.

    Recursive. unittest discovery only descends into importable packages, so this can name
    more files than ever run -- the fail-closed direction, more scripts required HIGH.
    """
    resolved_start = False
    files = set()
    root_resolved = root.resolve()
    for base in bases:
        directory = (root / base / start) if base else (root / start)
        try:
            directory = directory.resolve()
        except OSError:
            continue
        if not directory.is_dir() or not directory.is_relative_to(root_resolved):
            continue
        resolved_start = True
        for pattern in patterns:
            for path in directory.rglob(pattern):
                if path.is_file() and ".git" not in path.relative_to(root_resolved).parts:
                    files.add(path.relative_to(root_resolved).as_posix())
    return resolved_start, files


def interpreter_references(text, bases, root):
    """(relative path, directories) for every repo file a `python ...` command runs.

    Covers what GATE_SCRIPT's path pattern cannot see: `python -m unittest discover -s D
    -p P` (every file the pattern matches under D), `python -m pytest <paths>` (each
    file, or each test module and conftest.py under a directory), `python -m pkg.mod`
    when `pkg/mod.py` or its package is in the checkout, and `python <file>.py` at any
    path, root level included.

    FAIL-CLOSED where the target names repository content that cannot be resolved: a
    discover start directory or a pytest path that does not exist, or a `-m` module whose
    top-level package is in the checkout but whose file is not. Those are refused rather
    than passed, because an unresolved target is a gate script nobody can require HIGH
    (owner decision, PR #425 M36). A module with no trace in the checkout (`pip`, `venv`,
    `pytest` itself) is an installed tool, not repo code, and passes.

    THE BOUNDARY: a module reached only through PYTHONPATH or an installed editable
    package is read as a tool. Review of the workflow change is the control there.
    """
    for match in PYTHON_COMMAND.finditer(text):
        if printed_only(text, match.start()) or _in_shell_comment(text, match.start()):
            continue
        rest = text[match.end():].lstrip("\"'")
        end = COMMAND_END.search(mask_quoted(rest))
        segment = rest[:end.start()] if end else rest
        # A shell comment is not an argument (`python -m pytest ci # run tests`).
        comment = re.search(r"(?:^|[ \t])#", mask_quoted(segment))
        if comment:
            segment = segment[:comment.start()]
        tokens = _interpreter_tokens(segment)
        index = 0
        while index < len(tokens) and tokens[index].startswith("-") and tokens[index] not in ("-m", "-c"):
            index += 2 if tokens[index] in PYTHON_VALUE_OPTIONS else 1
        if index >= len(tokens) or tokens[index] == "-c":
            continue
        if tokens[index] != "-m":
            target, rooted = WORKSPACE_PREFIX.subn("", tokens[index].replace("\\", "/"))
            if target.endswith(".py"):
                # A workspace-rooted target names the root file only, whatever working-directory says (CodeRabbit, PR #426).
                found = _resolve_under_bases(root, [""] if rooted else bases, target)
                for relative in found:
                    yield relative, set()
                # Unresolved here, a relative target is still yielded raw so gate_script_paths
                # applies its directory-change refusal: `cd sub` then `python3 gate.py` runs
                # sub/gate.py, which nothing above resolves (CodeRabbit, PR #426). An absolute,
                # home or variable path is outside the checkout and is not a repo gate script,
                # and a workspace-rooted one that is absent is not in the checkout at all.
                if not found and not rooted and not re.match(r"^(?:[/~$]|[A-Za-z]:)", target):
                    yield target, {base for base in bases if base}
            continue
        if index + 1 >= len(tokens):
            continue
        module, args = tokens[index + 1], tokens[index + 2:]
        if module == "unittest":
            yield from _unittest_references(root, bases, args)
        elif module in ("pytest", "py.test"):
            yield from _pytest_references(root, bases, args)
        else:
            yield from _module_references(root, bases, module)


def _in_shell_comment(text, start):
    """True when `start` follows an unquoted `#` on its line: `# python3 -m pytest ci` runs nothing (CodeRabbit, PR #426)."""
    line_start = text.rfind("\n", 0, start) + 1
    return re.search(r"(?:^|[ \t])#", mask_quoted(text[line_start:start])) is not None


def _interpreter_tokens(segment):
    """The words of one interpreter command, quotes stripped, redirections dropped.

    Non-POSIX shlex, because POSIX mode treats a backslash as an escape and turns
    `.\\ci\\gate.py` into `.cigate.py` (CodeRabbit, PR #426). Quotes are stripped per
    token, which also cleans a token cut from inside `bash -c "python3 gate.py"`.
    """
    try:
        raw = shlex.split(segment, posix=False)
    except ValueError:
        raw = segment.split()
    # A word ending in one backslash escaped the space after it (`gate\ script.py` in bash). Not
    # before an option: `tests\ -q` is a Windows trailing separator, not an escape (Gitar, PR #426).
    words = []
    for word in raw:
        if words and words[-1].endswith("\\") and not words[-1].endswith("\\\\") and not word.startswith("-"):
            words[-1] = words[-1][:-1] + " " + word
        else:
            words.append(word)
    tokens, skip = [], False
    for token in (word.strip("\"'") for word in words):
        if skip:
            skip = False
            continue
        # A redirection attached to an argument (`gate.py>out.txt`) is split off it.
        attached = re.search(r"[<>]", token)
        if attached and attached.start() > 0 and not token[:attached.start()].isdigit() and token[attached.start() - 1] != "&":
            token, redirect = token[:attached.start()], token[attached.start():]
            skip = bool(REDIRECT_OPEN.fullmatch(redirect))
        elif REDIRECT_COMPLETE.fullmatch(token):
            continue
        elif REDIRECT_OPEN.fullmatch(token):
            skip = True
            continue
        if token:
            tokens.append(token)
    return tokens


def _refusal(message):
    return "", {"!unsupported " + message}


def _unittest_references(root, bases, args):
    if args and args[0] == "discover":
        start, pattern, positional, index = ".", "test*.py", [], 1
        while index < len(args):
            arg = args[index]
            if arg in UNITTEST_VALUE_OPTIONS:
                index += 2
                continue
            if arg in ("-s", "--start-directory", "-p", "--pattern", "-t", "--top-level-directory") and index + 1 < len(args):
                if arg in ("-s", "--start-directory"):
                    start = args[index + 1]
                elif arg in ("-p", "--pattern"):
                    pattern = args[index + 1]
                index += 2
                continue
            if not arg.startswith("-"):
                positional.append(arg)
            index += 1
        if positional:
            start = positional[0]
        if len(positional) > 1:
            pattern = positional[1]
        resolved, files = _files_matching(root, bases, start.replace("\\", "/"), [pattern])
        if not resolved:
            yield _refusal(f"cannot resolve the unittest discover start directory '{start}'; run the gate's tests from a directory in the checkout")
        for relative in sorted(files):
            yield relative, set()
        return
    names, index = [], 0
    while index < len(args):
        if args[index] in UNITTEST_VALUE_OPTIONS:
            index += 2
            continue
        if not args[index].startswith("-"):
            names.append(args[index])
        index += 1
    if not names:
        yield from _unittest_references(root, bases, ["discover"])
        return
    for name in names:
        relative = name.replace("\\", "/") if name.endswith(".py") or "/" in name else name.replace(".", "/") + ".py"
        found = _resolve_under_bases(root, bases, relative)
        if not found:
            # A dotted name may stop at a class or method: try each shorter prefix as a module.
            parts = name.split(".")
            for cut in range(len(parts) - 1, 0, -1):
                found = _resolve_under_bases(root, bases, "/".join(parts[:cut]) + ".py")
                if found:
                    break
        if not found:
            yield _refusal(f"cannot resolve the unittest target '{name}' to a file in the checkout")
        for relative in found:
            yield relative, set()


def _pytest_references(root, bases, args):
    paths, index = [], 0
    while index < len(args):
        arg = args[index]
        if arg.startswith("-"):
            index += 2 if arg in PYTEST_VALUE_OPTIONS else 1
            continue
        paths.append(arg.split("::", 1)[0].replace("\\", "/"))
        index += 1
    for path in paths or ["."]:
        if path.endswith(".py"):
            found = _resolve_under_bases(root, bases, path)
            if not found:
                yield _refusal(f"cannot resolve the pytest target '{path}' to a file in the checkout")
            for relative in found:
                yield relative, set()
            continue
        resolved, files = _files_matching(root, bases, path, ["test_*.py", "*_test.py", "conftest.py"])
        if not resolved:
            yield _refusal(f"cannot resolve the pytest target '{path}' in the checkout")
        for relative in sorted(files):
            yield relative, set()


def _module_references(root, bases, module):
    parts = module.split(".")
    stem = "/".join(parts)
    for relative in (stem + ".py", stem + "/__main__.py"):
        found = _resolve_under_bases(root, bases, relative)
        if found:
            for item in found:
                yield item, set()
            return
    head = parts[0]
    if _resolve_under_bases(root, bases, head + ".py") or any(
        (root / base / head if base else root / head).is_dir() for base in bases
    ):
        yield _refusal(f"cannot resolve `python -m {module}` to a file in the checkout, though '{head}' is repository content")


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
    seen_bodies = set()
    for job_id, _, body, body_directories in gated_run_bodies(lines, jobs, needs, gate_job, root):
        body_key = (job_id, tuple(body), tuple(sorted(body_directories)))
        if body_key in seen_bodies:
            continue
        seen_bodies.add(body_key)
        for relative, directories in script_references(body, body_directories, root):
            unsupported = next((directory for directory in directories if directory.startswith("!unsupported ")), None)
            if unsupported:
                sys.exit(f"{root}: {unsupported[1:]}")
            if changes_directory(body):
                sys.exit(f"{root}: cannot verify gate script paths after a directory change in job '{job_id}'; use working-directory:")
            full_references = {relative} | {
                directory + "/" + relative
                for directory in directories
                if directory and not directory.startswith("!unsupported ")
            }
            direct = any(
                resolve_committed_paths(root, candidate, allow_outside_repository=True)
                for candidate in full_references
            )
            # Recover prefixed spellings only if the complete reference is absent.
            # Otherwise a nested script also captures an unrelated root suffix.
            relatives = {relative}
            if not direct:
                relatives.update(_recognised_suffixes(relative))
            # Every plausible spelling is kept -- the repository root, and each directory
            # that applies to this run body (workflow and job defaults, the body's own
            # step, a composite action's own directory). More scripts required HIGH,
            # never fewer.
            qualified = {
                directory + "/" + suffix
                for directory in directories
                if directory and not directory.startswith("!unsupported ")
                for suffix in relatives
            }
            # A BARE candidate is the same reference read from the repository root. When
            # a working directory anchors the reference the qualified candidates are the
            # real resolution and the bare one is speculative -- a `..` in it can then
            # resolve outside the checkout with nothing being wrong (`working-directory:
            # sub` plus `run: python3 ../scripts/gate.py`), so the outside-repository
            # exit is suspended for it. With NO working directory the bare spelling is
            # the only evidence there is and the exit still fires -- fail-closed exactly
            # where it matters.
            allow_outside = bool(qualified)
            for candidate in qualified:
                for committed in resolve_committed_paths(root, candidate):
                    found.setdefault(committed, job_id)
            for candidate in relatives:
                for committed in resolve_committed_paths(
                    root, candidate, allow_outside_repository=allow_outside
                ):
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

    Verified in the field: a consumer added
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
        # noisily. This is the same one-word defect in the same file and the same
        # fail-open direction as the workflow reads.
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


# Environment keys that can neutralise the gate's accepted exit command before it runs.
# BASH_ENV and ENV name a start-up file bash/sh sources, SHELLOPTS and BASHOPTS set shell
# options such as noexec at start-up, and BASH_FUNC_name%% imports a function over a
# builtin. Refusing BASH_ENV alone left every other route open (adversarial review
# 20261031T213036Z, M2; tax portal 20261101T004738Z, M16).
STARTUP_ENV_KEYS = ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS")
# The same routes spelled inside a GATE JOB run body -- a GITHUB_ENV write, or a write to
# pwsh's `$PROFILE`, which the runner loads because its pwsh template omits -NoProfile.
STARTUP_OVERRIDE_TOKEN = re.compile(
    r"(?i)\b(?:BASH_ENV|SHELLOPTS|BASHOPTS|BASH_FUNC_\w*)\b|(?<![\w$:])ENV(?=\s*[=<])|\$(?:env:)?PROFILE\b"
)


def startup_env_keys(mapping):
    """The keys of a parsed `env:` mapping that can neutralise the gate's exit command."""
    if mapping is None:
        return []
    if not isinstance(mapping, yaml.MappingNode):
        raise ValueError("`env:` is not a mapping this checker can read, so a start-up override cannot be ruled out")
    return [name for name, _ in mapping_entries(mapping) if name in STARTUP_ENV_KEYS or name.startswith("BASH_FUNC_")]


def assert_feeder_steps(workflow_path, lines, jobs, feeders, step_exempt, used_exempt, label=""):
    """Refuse a feeder step that can never fail its job or never runs.

    `continue-on-error: true` on a step is the step-level spelling of a tolerated job:
    the step's failure is swallowed and the feeder reports green. An `if:` that is
    statically false never runs the step at all. Either leaves a check the gate believes
    in doing nothing.

    Keys are matched at the step's OWN column, the guard step_can_fail already applies:
    an action INPUT named `if` or `continue-on-error` under `with:` is a value, not a step
    control, and reading it as one reddened a correct workflow (adversarial review
    20261031T213036Z, L3; tax portal 20261101T004738Z, M20).

    A best-effort step is exempted by naming `<job>/<step id>` in GATE_STEP_EXEMPT -- an
    explicit, reviewable list, as GATE_EXEMPT is for jobs. Fail-closed with no exemption
    reddened the first consumer with a best-effort step (simulator-frontend review
    20261101T004730Z, S12). `label` prefixes the job id when the jobs belong to a called
    reusable workflow, in messages and in exemption entries alike.
    """
    executable = re.compile(r"""^(\s*(?:-\s+)?)(?:'run'|"run"|run|'uses'|"uses"|uses)\s*:""")
    for feeder in sorted(feeders):
        block = job_block(lines, jobs, feeder)
        payloads = run_payload_indexes(block)
        seen = set()
        for index, line in enumerate(block):
            match = executable.match(line) if index not in payloads else None
            if not match:
                continue
            indent = len(match.group(1))
            span = step_span(block, index, indent)
            if span is None or span in seen:
                continue
            seen.add(span)
            kind = "run step" if "run" in line[indent:].split(":", 1)[0] else "step"

            def own_key(key):
                pattern = step_key_pattern(indent, key)
                for offset in range(*span):
                    entry = pattern.match(block[offset]) if offset not in payloads else None
                    if entry and len(entry.group(1)) == indent:
                        value = strip_comment(entry.group(2)).strip()
                        if not value or is_block_scalar_header(value):
                            body, _ = continuation_lines(block, offset, indent)
                            value = " ".join(strip_comment(part).strip() for part in body)
                        return value
                return None

            tolerance = own_key("continue-on-error")
            if tolerance is not None and static_truth(tolerance) is not False:
                step_id = own_key("id")
                entry = f"{label}{feeder}/{decode_yaml_scalar(step_id)}" if step_id else None
                if entry in step_exempt:
                    used_exempt.add(entry)
                else:
                    sys.exit(
                        f"{workflow_path}: feeder '{label}{feeder}' has a tolerated {kind}"
                        + (f" (id '{decode_yaml_scalar(step_id)}')" if step_id else "")
                        + ". A step whose failure is swallowed checks nothing the gate can see. "
                        "Remove `continue-on-error`, or give the step an `id:` and name "
                        "`<job>/<step id>` in GATE_STEP_EXEMPT with a written rationale."
                    )
            condition = own_key("if")
            if condition is not None and static_truth(condition) is False:
                sys.exit(f"{workflow_path}: feeder '{label}{feeder}' has an always-skipped {kind}.")


def reusable_workflow_feeder(lines, jobs, job_id, job_indent, root):
    """(path, lines, jobs, job indent) of the LOCAL reusable workflow `job_id` calls, or None."""
    indent = job_body_indent(lines, jobs, job_id, job_indent)
    if indent is None:
        return None
    uses_key = key_pattern(indent, "uses")
    for line in job_block(lines, jobs, job_id):
        match = uses_key.match(line)
        if not match:
            continue
        ref = decode_yaml_scalar(strip_comment(match.group(1)).strip())
        # `./` and `$/` are the two local spellings LOCAL_USES admits.
        if not (ref.startswith(("./", "$/")) and ref[2:].startswith(".github/workflows/")):
            return None
        target = root / ref[2:]
        if not target.is_file():
            return None
        callee_lines = target.read_text(encoding="utf-8-sig").splitlines()
        callee_jobs, _, _ = read_gate_contract(callee_lines, "")
        if not callee_jobs:
            return None  # delegated_workflow_run_bodies refuses the flow spelling
        parsed_document(callee_lines, target)
        first = min(callee_jobs.values())
        return target, callee_lines, callee_jobs, len(callee_lines[first]) - len(callee_lines[first].lstrip(" "))
    return None


def check_file(workflow_path, gate_job, exempt, conditional_exempt, *, on_empty="fail", step_exempt=frozenset(), step_usage=None):
    """Assert one file's full gate contract. Returns True when the file contains the
    gate job (and every assertion ran), False when it has no gate job at all.

    Exemption-name validation is the CALLER's job, not this function's: in directory
    mode a job named in GATE_EXEMPT exists in exactly one workflow, so validating it
    against a single file's job set here reddened every OTHER workflow that also
    contains the gate job with a false "names jobs that do not exist".

    The same holds for a stale GATE_STEP_EXEMPT entry. `step_usage` is directory mode's
    (used entries, feeder job ids) pair, shared by every file and judged once after the
    loop: judged per file, `build/lint` used by ci.yml's `build` read as stale in a
    release.yml whose own `build` has no tolerated step (CodeRabbit, mirror PR #140; issue #429). Without it
    (file mode) the file is judged on its own.

    READ AS utf-8-sig. A plain utf-8 read leaves a leading BOM in the first character,
    so `JOBS_KEY` -- anchored at `^` -- never matched a BOM'd file's `jobs:` line, and
    Windows editors add BOMs silently. The consequence split on invocation mode and was
    bad in both directions: in FILE mode (how the estate wires this) the file exited 1
    with "no jobs found", a permanently red required check over a valid workflow; in
    DIRECTORY mode it was written off as "not a workflow, skipped" and every job in it
    escaped coverage. A checker must not disagree with the runner about whether a file
    is a workflow. The canonical-asset hasher already tolerates a BOM, so the two now
    agree.
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
    # mode a file-exempt release.yml with `env: BASH_ENV:` does not redden the whole run.
    #
    # THE START-UP ENVIRONMENT IS READ FROM THE PARSED DOCUMENT, at the three scopes that
    # reach the gate job's shell: the workflow's `env:`, the gate job's, and its steps'.
    # Text scanning the whole file would redden the gate for a feeder-only `BASH_ENV:`
    # (job-level env does not cross jobs), read `BASH_ENV:` text inside a non-`run:` block
    # scalar as a key, and miss an override behind an anchored or aliased `env:`
    # (`env: &shared`). The composer resolves aliases and knows what is text.
    try:
        document, _, _ = parsed_document(lines, workflow_path)
        gate = job_node(document, gate_job)
        overrides = startup_env_keys(mapping_get(document, "env")) + startup_env_keys(mapping_get(gate, "env"))
        steps = mapping_get(gate, "steps")
        for step in (steps.value if isinstance(steps, yaml.SequenceNode) else []):
            overrides += startup_env_keys(mapping_get(step, "env"))
    except ValueError as error:
        sys.exit(str(error) if str(error).startswith(str(workflow_path)) else f"{workflow_path}: {error}")
    root = policy_root(workflow_path) or Path(workflow_path).resolve().parent.parent.parent
    if not overrides:
        seen_run_bodies = set()
        for job_id, _, body, _ in gated_run_bodies(
            lines, jobs, needs, gate_job, root, include_directories=False
        ):
            # GITHUB_ENV is per-JOB, so a feeder's BASH_ENV override never reaches the
            # gate job's shell -- scanning feeder bodies reddened harmless text, and
            # the gate job's bodies are the only ones whose later steps run under the
            # override. Delegated action bodies arrive under the CALLING job's id, so
            # the gate job's own local actions stay in scope.
            if job_id != gate_job:
                continue
            body_key = (job_id, tuple(body))
            if body_key in seen_run_bodies:
                continue
            seen_run_bodies.add(body_key)
            # The bare token, refused outright. The conjunction this replaces -- an
            # assignment AND a redirection AND a `$GITHUB_ENV` spelling -- missed real
            # overrides: `echo "BASH_ENV<<EOF" >> "$GITHUB_ENV"` writes heredoc syntax
            # THROUGH the env file and carries no `=`, and pwsh's
            # `Out-File -FilePath $env:GITHUB_ENV -Append` matches neither the
            # redirection nor the `$GITHUB_ENV` spelling. What the override attacks is
            # the gate's accepted failing forms, so ANY mention is refused here, even
            # in an echo: a gate step is not the place for text this checker has to
            # classify.
            match = STARTUP_OVERRIDE_TOKEN.search("\n".join(body))
            if match:
                overrides.append(match.group(0))
                break
    if overrides:
        sys.exit(
            f"{workflow_path}: {', '.join(sorted(set(overrides)))} can neutralise the gate's "
            "accepted exit command: BASH_ENV/ENV load a start-up file, SHELLOPTS/BASHOPTS set "
            "shell options such as noexec, BASH_FUNC_* imports a function over a builtin, and "
            "$PROFILE is loaded by the runner's pwsh. Remove the override or use a separately "
            "verified gate shell."
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
        if indent is None:
            return False
        pattern = key_pattern(indent, "if")
        for i in range(start + 1, end):
            match = pattern.match(lines[i].rstrip("\r\n"))
            if not match:
                continue
            # Unfold a block-scalar or empty `if:` before judging it, the same
            # unfold conditional_jobs above and assert_gate_semantics both do: an
            # `if: >` whose folded text is `always()` otherwise normalises from the
            # bare header to something unrecognised and the feeder is treated as
            # skippable -- a false RED on a chain that does run regardless.
            value = strip_comment(match.group(1)).strip()
            if not value or is_block_scalar_header(value):
                body, _ = continuation_lines(lines, i, indent)
                value = " ".join(strip_comment(line).strip() for line in body)
            return runs_unconditionally(normalise_condition(value))
        return False

    unsafe_feeders = set()
    # A feeder that is ITSELF conditional-exempt is allowed to skip, so a conditional or
    # exempt job behind it is no new hole; walking its chain reddened a correct workflow.
    for feeder in set(needs) - {gate_job} - conditional_exempt:
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

    used_step_exempt, step_feeders = step_usage if step_usage is not None else (set(), set())
    step_feeders |= set(needs) - {gate_job}
    assert_feeder_steps(workflow_path, lines, jobs, set(needs) - {gate_job}, step_exempt, used_step_exempt)

    # A feeder that is a LOCAL REUSABLE WORKFLOW runs that file's jobs, and the caller
    # reports success when every callee job succeeds OR SKIPS. A conditional, tolerated or
    # step-neutered job inside the callee is therefore the same hole as the same thing on
    # the feeder itself, and nothing looked inside.
    # The callee's jobs get the feeder's own checks; a feeder named in
    # GATE_CONDITIONAL_EXEMPT may skip, so its callee may be conditional too.
    for feeder in sorted(set(needs) - {gate_job}):
        callee = reusable_workflow_feeder(lines, jobs, feeder, job_indent, root)
        if callee is None:
            continue
        callee_path, callee_lines, callee_jobs, callee_indent = callee
        if feeder not in conditional_exempt:
            skippable = sorted(conditional_jobs(callee_lines, callee_jobs, callee_indent))
            if skippable:
                sys.exit(
                    f"{workflow_path}: feeder '{feeder}' calls {callee_path}, whose job(s) "
                    f"{', '.join(skippable)} carry a job-level 'if:'. A skipped callee job passes the "
                    "caller and so the gate; remove the condition, or name the feeder in "
                    "GATE_CONDITIONAL_EXEMPT with a written rationale."
                )
        tolerated = sorted(tolerant_jobs(callee_lines, callee_jobs, callee_indent))
        if tolerated:
            sys.exit(
                f"{workflow_path}: feeder '{feeder}' calls {callee_path}, whose job(s) "
                f"{', '.join(tolerated)} carry 'continue-on-error'. A tolerated callee job cannot fail "
                "the feeder."
            )
        assert_feeder_steps(callee_path, callee_lines, callee_jobs, set(callee_jobs), step_exempt, used_step_exempt, label=f"{feeder}/")

    if step_usage is None:
        assert_step_exempt_used(workflow_path, step_exempt, used_step_exempt, step_feeders)

    assert_gate_semantics(workflow_path, lines, jobs, gate_job, needs)
    assert_gate_scripts(workflow_path, lines, jobs, needs, gate_job)

    print(
        f"{workflow_path}: all {len(jobs)} job(s) accounted for by '{gate_job}', "
        "which runs always() and aggregates its needs."
    )
    return True


def assert_step_exempt_used(where, step_exempt, used, feeders):
    """Refuse a GATE_STEP_EXEMPT entry for a gated feeder that exempted no tolerated step."""
    stale = sorted(
        entry for entry in step_exempt
        if entry.split("/", 1)[0] in feeders and entry not in used
    )
    if stale:
        sys.exit(
            f"{where}: GATE_STEP_EXEMPT names step(s) that do not exist or are not "
            f"tolerated: {', '.join(stale)}. Each entry is `<job>/<step id>` for a feeder step "
            "carrying `continue-on-error`."
        )


def split_env(name):
    return set(os.environ.get(name, "").replace(",", " ").split())


def main(argv):
    if len(argv) < 2 or len(argv) > 3:
        # A third positional was silently ignored, so a stale call that still passed one
        # exited 0 with that argument unread.
        sys.exit("usage: assert_gate_coverage.py <workflow-file|workflow-dir> [gate-job-id]")

    target = argv[1]
    gate_job = argv[2] if len(argv) > 2 else os.environ.get("GATE_JOB", "ci-gate")
    exempt = split_env("GATE_EXEMPT")
    conditional_exempt = split_env("GATE_CONDITIONAL_EXEMPT")
    step_exempt = split_env("GATE_STEP_EXEMPT")
    malformed = sorted(entry for entry in step_exempt if not all(entry.split("/")) or "/" not in entry)
    if malformed:
        sys.exit(f"GATE_STEP_EXEMPT entries are `<job>/<step id>`; malformed: {', '.join(malformed)}")
    step_jobs = {entry.split("/", 1)[0] for entry in step_exempt}

    if not Path(target).is_dir():
        if not Path(target).is_file():
            sys.exit(f"{target}: workflow path does not exist or is not a file.")
        unknown = sorted((exempt | conditional_exempt | step_jobs) - parse_jobs(target))
        if unknown:
            sys.exit(
                f"{target}: GATE_EXEMPT/GATE_CONDITIONAL_EXEMPT/GATE_STEP_EXEMPT name jobs that do "
                f"not exist: {', '.join(unknown)}"
            )
        # The return value is the WHOLE assertion when the gate job is absent:
        # check_file reports every other breach by exiting, but answers "no gate job
        # here" with False and leaves the decision to its caller. Directory mode acts
        # on that (GATE_FILE_EXEMPT, or exit). Discarding that False in file mode and
        # returning would let a workflow with jobs and NO gate job exit 0 in silence --
        # renaming or deleting the gate job would leave the check that exists to notice
        # saying nothing. Fail-OPEN, on the assertion that decides what can merge.
        # A ValueError out of the local-action follow (a non-composite action, or a
        # `runs:` mapping with no readable `using:`) is a REFUSAL, not a crash: it says
        # coverage cannot be verified over this file. Exit with its message -- a bare
        # traceback reads as a broken checker, and a broken checker is what gets a
        # working control deleted to make CI green.
        try:
            no_gate = check_file(target, gate_job, exempt, conditional_exempt, step_exempt=step_exempt) is False
        except ValueError as error:
            sys.exit(str(error))
        if no_gate:
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
    # workflow that also has a gate job.
    all_jobs = set()
    for workflow_path in files:
        all_jobs |= parse_jobs(workflow_path)
    unknown = sorted((exempt | conditional_exempt | step_jobs) - all_jobs)
    if unknown:
        sys.exit(
            f"{target}: GATE_EXEMPT/GATE_CONDITIONAL_EXEMPT/GATE_STEP_EXEMPT name jobs that do "
            f"not exist in any workflow: {', '.join(unknown)}"
        )

    gated = 0
    step_usage = (set(), set())
    for workflow_path in files:
        # Same ValueError-to-refusal translation as file mode: a delegated action the
        # checker cannot classify must redden the run with a message, not a traceback.
        try:
            result = check_file(
                workflow_path, gate_job, exempt, conditional_exempt,
                on_empty="skip", step_exempt=step_exempt, step_usage=step_usage,
            )
        except ValueError as error:
            sys.exit(str(error))
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
    assert_step_exempt_used(target, step_exempt, *step_usage)


if __name__ == "__main__":
    main(sys.argv)
