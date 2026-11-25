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

SCRIPTS A GATED JOB RUNS must be HIGH in .claude/review-policy.json. They are found by a
word rule, not a shell parser: every word in a gated run body, or in a package script that
body runs, that names a tracked repository script is required HIGH. A script named in a
comment, an echo or an argument counts too; that over-approximation is accepted. A body or
package script with a directory command at command position that names a script is
refused (see DIRECTORY_CHANGE). A script reached only
through a variable, a dynamic launch, or code a gate script imports is not derived. See
ScriptWords and scaffold-ci/references/review-policy.md.
"""
import fnmatch
import json
import math
import os
import posixpath
import re
import shlex
import subprocess
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
    rf"needs\.({ID})\.result(?:==['\"](failure|cancelled)['\"]|!=['\"]success['\"]))",
    # GitHub compares strings case-insensitively (github_equal below does too), so
    # `contains(needs.*.result, 'Failure')` is a correct gate. Callers casefold the
    # captured outcome before comparing it with the lowercase adverse names.
    re.IGNORECASE,
)
# A REFINEMENT, not a coverage atom: `needs.<job>.result != 'skipped'` narrows a
# `!= 'success'` atom about the same job rather than covering an outcome of its own.
#
# It exists because the house shape for a CONDITIONAL feeder is
# `needs.secrets.result != 'success' && needs.secrets.result != 'skipped'` -- a job that
# legitimately skips must not fail the gate by skipping, which is exactly what
# GATE_CONDITIONAL_EXEMPT is for. Refusing every residual conjunction rejected that, and
# a correct gate of this shape then reads as "aggregates nothing".
CONDITION_REFINEMENT = re.compile(rf"needs\.({ID})\.result!=['\"]skipped['\"]", re.IGNORECASE)
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
    # `always() && !cancelled()` runs exactly when `!cancelled()` does: judge what is left once
    # the conjuncts that fold to true are dropped (consumer review, C1-F4).
    rest = [part for part in split_top_level(strip_outer_parentheses(condition), "&&") if static_truth(part, True) is not True]
    if [strip_outer_parentheses(part) for part in rest] == ["!cancelled()"]:
        return True
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
_LITERAL = r"(?:true|false|null|-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|'(?:''|[^'])*'|\"(?:\\.|[^\"\\])*\")"


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


_DECIMAL_STRING = re.compile(r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
# The runner's ParseNumber knows only lowercase `0x` and `0o`. `0X10`, `0b11` and signed hex are NaN there, so the
# comparison is False (issue #506 A13; ExpressionUtility.cs).
_HEX_STRING = re.compile(r"0x[0-9a-fA-F]+")
_OCTAL_STRING = re.compile(r"0o[0-7]+")
# .NET's Double.TryParse (observed, InvariantCulture) accepts `NaN` and `Infinity` in any case with an optional sign, and
# rejects `Inf`, `-inf` and the infinity glyph. All of them are determinate: NaN compares false, never unknown.
_NAN_STRING = re.compile(r"[+-]?nan", re.IGNORECASE)
_INFINITY_STRING = re.compile(r"[+-]?infinity", re.ASCII | re.IGNORECASE)  # ASCII: IGNORECASE alone folds U+0130/U+0131 onto i


def github_equal(left, right):
    """True/False for a comparison the runner's coercion makes certain, `_UNKNOWN` for one it does not."""
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
            # The runner trims before converting, so ' ' is 0, not NaN (code review).
            value = value.strip()
            if not value:
                return 0.0
            # A leading sign is accepted (`'+0'` is 0) and so is a `0x` hex prefix (ExpressionUtility.ParseNumber).
            if _DECIMAL_STRING.fullmatch(value):
                try:
                    return float(value)
                except (ValueError, OverflowError):
                    return math.nan
            if _HEX_STRING.fullmatch(value):
                # Int32.TryParse(AllowHexSpecifier): eight digits read as two's complement, more is out of range (NaN).
                number = int(value, 16)
                if number > 0xFFFFFFFF:
                    return math.nan
                return float(number - 0x100000000 if number >= 0x80000000 else number)
            if _OCTAL_STRING.fullmatch(value):
                # Convert.ToInt32(s, 8): the same 32-bit two's-complement range, and out of range is NaN.
                number = int(value[2:], 8)
                if number > 0xFFFFFFFF:
                    return math.nan
                return float(number - 0x100000000 if number >= 0x80000000 else number)
            if _NAN_STRING.fullmatch(value):
                return math.nan
            if _INFINITY_STRING.fullmatch(value):
                return -math.inf if value.startswith("-") else math.inf
            return math.nan
        return math.nan

    left_number = to_number(left)
    right_number = to_number(right)
    if left_number is _UNKNOWN or right_number is _UNKNOWN:
        return _UNKNOWN
    return not (math.isnan(left_number) or math.isnan(right_number)) and left_number == right_number


def negated_literal_readings(operand):
    """(`(!lhs) op rhs`, `!(lhs op rhs)`) for a negated comparison of two LITERALS, else None.

    Both are folded with the same literal rules as an un-negated comparison. A side that
    is not a literal, or whose fold is unknown, makes the pair unreadable (None).
    """
    match = re.fullmatch(rf"\s*({_LITERAL})\s*(==|!=|<=|>=|<|>)\s*({_LITERAL})\s*", operand, re.IGNORECASE)
    if not match:
        return None
    # A string operand is coerced to a number by the runner (`' '` is 0, `'1'` is 1) and
    # github_equal does not model every such conversion, so a string comparison is left UNKNOWN
    # rather than folded on a coercion this checker may get wrong.
    if match.group(1)[:1] in ("'", '"') or match.group(3)[:1] in ("'", '"'):
        return None
    left_truth = static_truth(match.group(1), True)
    whole = static_truth(operand, True)
    if left_truth is _UNKNOWN or whole is _UNKNOWN:
        return None
    negated = not left_truth
    # `(!lhs)` is a boolean; an ordered comparison coerces it to 1 or 0 first.
    operand_text = ("1" if negated else "0") if match.group(2) in ("<", "<=", ">", ">=") else ("true" if negated else "false")
    unary_first = static_truth(f"{operand_text} {match.group(2)} {match.group(3)}", True)
    if unary_first is _UNKNOWN:
        return None
    return unary_first, not whole


def ambiguous_negated_literal(condition):
    """True for a literal-only negated comparison whose two precedence readings disagree.

    `!1 == 2` is `(!1) == 2` (false) or `!(1 == 2)` (true). The runner's precedence is
    UNVERIFIED here, so static_truth leaves it UNKNOWN; on a feeder step that would pass an
    expression no real workflow writes on purpose, so assert_feeder_steps refuses it.
    """
    if static_truth(condition) is not _UNKNOWN:
        # Folded already (`true || !1 == 2` is true), so the ambiguous branch cannot affect the result.
        return False

    def ambiguous(expression):
        expression = strip_outer_parentheses(expression.strip())
        for operator in ("||", "&&"):
            parts = split_top_level(expression, operator)
            if len(parts) > 1:
                return any(ambiguous(part) for part in parts)
        if not expression.startswith("!"):
            return False
        readings = negated_literal_readings(expression[1:])
        return readings is not None and readings[0] is not readings[1]

    expression = decode_yaml_scalar(strip_inline_comment(condition).strip()).strip()
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression[3:-2].strip()
    return ambiguous(expression)


def static_truth(condition, _nested=False):
    """Fold only literal boolean branches; unknown GitHub context/function values stay unknown."""
    expression = (condition if _nested else decode_yaml_scalar(strip_inline_comment(condition).strip())).strip()
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
        # the runner, so a negated comparison folds only when BOTH readings agree: `!1 == 1`
        # is false as `(!1) == 1` and as `!(1 == 1)`, so a step guarded by it never runs and
        # must meet the always-skipped refusal. Where they disagree it stays UNKNOWN.
        if any(len(split_top_level(operand, operator)) > 1 for operator in ("==", "!=", "<=", ">=", "<", ">")):
            readings = negated_literal_readings(operand)
            if readings is not None and readings[0] is readings[1]:
                return readings[0]
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
    if re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|null", expression, re.IGNORECASE):
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
            equal = github_equal(left, right)
            return _UNKNOWN if equal is _UNKNOWN else equal == (operation == "==")
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


def continuation_lines(block, index, indent, keep_comments=False):
    """The block-scalar body opened on `block[index]`, plus the index after it.

    Continuation belongs to the KEY's column, not the line's: a `- if: >` step opens at
    the key while the line starts at the dash two columns to its left. Lines are
    returned stripped but with comments intact, because a `run:` body's `#` is shell,
    not YAML; callers that read YAML values strip comments themselves.

    `keep_comments` returns a `#` line indented inside the block as body text. In a
    literal block it is content, and it can sit inside a multi-line shell string
    (`echo "` / `# "; exit 0; echo "` / `"`), where dropping it makes the checker read a
    different command than the shell runs.
    """
    body = []
    following_index = index + 1
    while following_index < len(block):
        following = block[following_index]
        if COMMENT_OR_BLANK.match(following):
            if (
                keep_comments
                and following.strip()
                and len(following) - len(following.lstrip()) > indent
            ):
                body.append(following.strip())
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


# U+2018-U+201B and U+201C-U+201E. PowerShell treats every one of these as a quote
# character, so `Write-Host "a<U+201C>; exit 0; <U+201C>b"` closes its string at the curly
# quote and runs `exit 0`, while an ASCII-only reading sees one harmless string. Refusing the
# characters fails closed and costs nothing: a gate body has no reason to carry them.
TYPOGRAPHIC_QUOTES = re.compile("[‘-„]")


def comment_hides_code(text, disciplines=(False, True)):
    """True when an UNQUOTED `#` comment contains a quote or ends in a backslash.

    A shell ends a comment at the newline, so a trailing `\\` continues nothing and a quote
    inside it opens nothing. The checker folds backslash-newline and masks quotes BEFORE it
    drops comments, so a hidden line (`echo x # see logs \\` / `exit 0`) or a quote that
    appears to span lines can make a body read as a failing form when it exits zero. Rather
    than re-implement each shell's comment rules, refuse the two spellings that expose the
    ordering: a comment that ends in a backslash or holds a quote character.

    Scanned left to right with the quote state of each discipline in `disciplines` in turn
    (False is bash, True is PowerShell). A caller that has resolved the effective shell passes
    only that one: reading `\\"` as an escape in a body pwsh runs, or a backtick as one in a body
    bash runs, mis-tracks the quotes. With the shell unknown both are tried and either counts.
    """
    for powershell in disciplines:
        quote = None
        i = 0
        while i < len(text):
            char = text[i]
            if quote is not None:
                if char == ("`" if powershell else "\\") and quote == '"':
                    i += 2
                    continue
                if char == quote:
                    quote = None
            elif char in "'\"":
                quote = char
            elif char == ("`" if powershell else "\\"):
                i += 2
                continue
            elif char == "#" and (i == 0 or text[i - 1].isspace()):
                end = text.find("\n", i)
                end = len(text) if end == -1 else end
                comment = text[i:end]
                if comment.rstrip().endswith("\\") or "'" in comment or '"' in comment:
                    return True
                i = end
                continue
            i += 1
    return False


# Characters a shell or str.splitlines() may treat as a line break or separator that a
# `\n`-only reading does not: C0 controls other than tab, LF and CR (form feed and
# vertical tab among them), DEL, NEL, and U+2028/U+2029 (C1-F4).
_FOREIGN_LINE_BREAK = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\x85\u2028\u2029]")


def has_foreign_line_break(text):
    return bool(_FOREIGN_LINE_BREAK.search(text))


def is_within(path, parent):
    """Whether `path` sits under `parent`. Path.is_relative_to needs Python 3.9; on 3.8
    it raised AttributeError in place of this checker's fail-closed exit (C1-CX5)."""
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def read_manifest_lines(target):
    """The lines of a delegated manifest (local action or reusable workflow).

    str.splitlines() breaks on form feed, vertical tab, FS/GS/RS, NEL and U+2028/9, so a
    file holding one would be split before the YAML parser could refuse it, and the line
    indexes the scans share with the parser would disagree with GitHub's reading (C1-F5).
    """
    text = Path(target).read_text(encoding="utf-8-sig")
    if has_foreign_line_break(text):
        raise ValueError(
            f"{target}: carries a control character or Unicode line separator, which "
            "YAML parsers and line readers split differently; remove it"
        )
    return text.splitlines()


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
    # Quoting forms the masker does not model: ANSI-C `$'..'` and locale `$".."` strings
    # end at a different quote than a plain pair, and a backtick is command substitution
    # under bash. Under pwsh the backtick is the escape character and mask_quoted
    # handles it. A gate body has no use for any of them (C1-F3).
    if "$'" in body or '$"' in body or (not powershell and "`" in body):
        return False
    if has_foreign_line_break(body):
        return False
    # A pwsh here-string (`@"` ... `"@`) ends only at its terminator, whatever quotes sit
    # between, so the pair-by-pair masker reads a different command than pwsh runs (C1-CX3).
    if powershell and ('@"' in body or "@'" in body):
        return False
    if re.search(r"\bthrow\s+[@(]", body):
        return False
    text = mask_quoted(body, powershell=powershell)
    # The exit argument is judged in the RAW text but located in the MASKED copy, so an
    # `exit` inside a message string is not an exit (C1-CX6), while `exit 2\5\6` -- which
    # bash runs as `exit 256`, status 0 -- and `exit "1"` are refused (C1-F1).
    for exit_word in re.finditer(r"\bexit\b", text):
        argument = re.match(r"[ \t]+[^\s;|&<>]*", body[exit_word.end():])
        if argument and re.search(r"['\"\\]", argument.group(0)):
            return False
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
    hide an `exit 0` from bash (code review). Such a body falls through to the
    both-disciplines check in step_can_fail instead.
    """
    string = r"(?:'(?:[^'\n]|'')*'|\"(?:[^`\"\n]|`.)*\")"
    # `echo` is pwsh's alias for Write-Output and the spelling the house one-liner uses,
    # so refusing it reddened a `shell: pwsh` gate that does fail (consumer review
    # 20261101T004738Z, c02-C5). Admitted with a QUOTED argument or none, like the
    # cmdlets: an expression argument stays refused.
    words = "Write-Host|Write-Output|Write-Information" + ("|echo" if echo else "")
    message = re.compile(rf"(?:{words})(?:\s+{string})?", re.IGNORECASE)
    final = rf"throw(?:\s+{string})?|" if throw else ""
    failure = re.compile(rf"(?:{final}exit\s+{_NONZERO_STATUS})\s*", re.IGNORECASE)
    if has_foreign_line_break(body):
        return False
    lines = [line.strip().rstrip(";").strip() for line in body.split("\n") if line.strip()]
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
    #
    # The continuation lines of a multi-line scalar are text too, whatever key owns them:
    # a quoted `name:` spanning lines can hold a line shaped like `run: exit 1` at this
    # column, and a first-match scan would take it over the real key below it (C1-F6).
    payloads = run_payload_indexes(block)
    tolerant_key = step_key_pattern(key_indent, "continue-on-error")
    for i in range(start, end):
        if i in payloads:
            continue
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
        match = None if i in payloads else shell_key.match(block[i])
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
        match = None if i in payloads else run_key.match(block[i])
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
            body, _ = continuation_lines(block, i, key_indent, keep_comments=True)
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
        if TYPOGRAPHIC_QUOTES.search(joined):
            return False, (
                "carries a typographic quote (U+2018-U+201E), which PowerShell reads as a "
                "string delimiter and an ASCII-only reading does not; use ASCII quotes"
            )
        comment_disciplines = (False, True) if shell is None else ((True,) if shell.startswith("pwsh") else (False,))
        if comment_hides_code(joined, comment_disciplines):
            return False, (
                "has a `#` comment that contains a quote or ends in a backslash, which the "
                "checker and the shell read differently; move the quote out of the comment "
                "and do not end a comment line with a backslash"
            )
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
        # 20261031T213036Z, M1).
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
            "A GitHub expression `${{ ... }}` in the body is refused as well, because it "
            "is substituted before the shell parses the line: pass the value through `env:`. "
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
    # The parser knows which lines are TEXT: the continuation lines of any multi-line scalar.
    # A multi-line quoted `name:` can hold a line shaped like `if: <condition>` at the step's
    # own key column; read as a key it was credited to a step whose real `if:` is narrower.
    payloads = run_payload_indexes(block)
    index = 0
    skip_until_indent = None
    while index < len(block):
        if index in payloads:
            index += 1
            continue
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
                    # The step's keys start at the first non-space after the dash, not
                    # always two columns on: `-   if: ...` is valid YAML. A dash that
                    # carries only a comment (`-  # note`) puts its keys on the next
                    # lines, two columns in, so the comment's own column is not one.
                    rest = prefix[1:].lstrip()
                    if rest and not rest.startswith("#"):
                        key_column = prior_indent + len(prefix) - len(rest)
                    else:
                        # The keys follow on later lines, at whatever column the first of
                        # them uses: read it, rather than assuming two columns in.
                        key_column = prior_indent + 2
                        for follower in block[prior + 1 :]:
                            if follower.strip() and not follower.lstrip().startswith("#"):
                                key_column = len(follower) - len(follower.lstrip())
                                break
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
    # Scalar continuation lines are text: a multi-line quoted `name:` holding a line shaped
    # like `if: always()` must not stand in for the job's real, narrower `if:` (C1-F6).
    job_payloads = run_payload_indexes(block)
    for i, line in enumerate(block):
        match = None if i in job_payloads else job_if_value.match(line)
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
    #       env:
    #         RESULTS: ${{ join(needs.*.result, ', ') }}                   <- matched too
    #       run: |
    #         echo "Upstream results: $RESULTS"
    #
    # (The skeleton once spelled the expression inside the echo itself. A `${{ }}` in a
    # gate body is now refused outright -- see ends_non_zero -- so it lives in `env:`.)
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
    # Only an item of the job's own `steps:` is a step: a `- if:`/`run:` pair under
    # strategy.matrix.include is data, and was credited as the failing step (consumer review, C1-F7).
    steps = mapping_get(job_node(document, gate_job), "steps")
    step_lines = range(steps.start_mark.line, steps.end_mark.line + 1) if isinstance(steps, yaml.SequenceNode) else range(0)
    for condition, index in step_conditions(block, step_indent):
        if getattr(block, "offset", 0) + index not in step_lines:
            continue
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
                if outcome and outcome.casefold() != adverse:
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
    20261031T213036Z, T1/H3; a consumer 20261101T004730Z, S1/S2). The composer
    resolves aliases to the nodes they name and marks every node with the lines it
    occupies, which is exactly what those scans need.

    Raises ValueError on anything PyYAML cannot read. "Cannot parse" must never render as
    "nothing to check"; every caller turns the error into a fail-closed exit.
    """
    text = "\n".join(line.rstrip("\r\n") for line in lines)
    where = f"{name}: " if name else ""
    # PyYAML counts NEL, U+2028 and U+2029 as line breaks; the line readers do not. One
    # such character shifts every later node's line number by one against `lines`, so a
    # payload index lands on a real key or a real key reads as text (C1-F5).
    if has_foreign_line_break(text):
        raise ValueError(
            f"{where}carries a control character or Unicode line separator, which YAML "
            "parsers and line readers split differently; remove it"
        )
    try:
        return yaml.compose(text, Loader=yaml.SafeLoader), text
    except yaml.YAMLError as error:
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
        to key_pattern (consumer review 20261101T004738Z, M13);
      * a flow-style `steps:` or a flow-mapping step item carries `run:` text no RUN_KEY
        line ever matches (adversarial review 20261031T213036Z, M5);
      * a flow collection on the line AFTER its key reads as an empty value, so `needs:`
        loses its list (XM1; a consumer 20261101T004730Z, S2).

    Also refused:

      * a PLAIN (unquoted) multi-line value for `if`, `run`, `shell` or `continue-on-error`:
        YAML folds the continuation lines into one value (`if: always()` then `&& false`
        is `always() && false`), while every line reader takes the first line as the whole
        value. Write the value on one line or as a block scalar;
      * a step that is an ALIAS of another step or of a whole `steps:` sequence: the alias
        line carries no `run:`/`uses:` key, so a scan over lines never examines the step
        it stands for (a tolerated or skipped step hides there).

      * a job that is an ALIAS of another job, and a mapping that repeats a key.

    Anchors, aliases and tags are otherwise NOT refused: the composer resolves them, the
    parsed reads below see through them, and the job-level forms are accepted by existing
    fixtures. Raises ValueError, which every caller turns into a fail-closed exit.
    """
    where = f"{name}: " if name else ""
    # A job whose whole value is an alias written on the line AFTER its key (`twin:` then
    # `*template`) passes the job-key pattern, and every line scan then reads an empty job:
    # no `if:`, no `needs:`, no steps (C1-F13). Same position/identity test as for steps.
    job_nodes_seen = set()
    jobs_node = mapping_get(root, "jobs")
    for key, value in (jobs_node.value if isinstance(jobs_node, yaml.MappingNode) else []):
        if id(value) in job_nodes_seen or value.start_mark.index < key.end_mark.index:
            raise ValueError(
                f"{where}line {key.start_mark.line + 1}: a job that is an alias of another "
                "job is unsupported; write the job out"
            )
        job_nodes_seen.add(id(value))
    step_nodes_seen = set()
    # The mappings under `with:` and `env:` hold caller data: a key named `uses` there is an input
    # or a variable, not an action reference. The `jobs:` mapping is skipped, because its keys are
    # job ids and a job may be named `with` or `env` (code review).
    data_mappings = {
        id(value)
        for node in iter_nodes(root) if isinstance(node, yaml.MappingNode) and node is not jobs_node
        for key, value in node.value if isinstance(key, yaml.ScalarNode) and key.value in ("with", "env")
        # Only a mapping written in place: `env: *step` aliases an executable mapping, and exempting
        # it hid that step's off-line `uses` and the action it calls.
        and value.start_mark.index > key.end_mark.index
    }
    # Everything under a `matrix:` is data too: a `uses` there names no action (code review).
    data_mappings |= {id(inner) for node in iter_nodes(root) if isinstance(node, yaml.MappingNode) and node is not jobs_node
                      for key, value in node.value if isinstance(key, yaml.ScalarNode) and key.value == "matrix"
                      for inner in iter_nodes(value) if isinstance(inner, yaml.MappingNode)}
    for node in iter_nodes(root):
        if not isinstance(node, yaml.MappingNode):
            continue
        keys_seen = set()
        for key, value in node.value:
            line = key.start_mark.line + 1
            # The composer keeps a repeated key without complaint and every read here takes
            # the first one, so `run: exit 1` above `run: exit 0` was vouched for. Refused
            # whichever occurrence the runner would honour (C1-F15).
            if isinstance(key, yaml.ScalarNode):
                if key.value in keys_seen:
                    raise ValueError(f"{where}line {line}: duplicate key `{key.value}` is unsupported; write each key once")
                keys_seen.add(key.value)
            if (
                isinstance(key, yaml.ScalarNode)
                and key.value in ("if", "run", "shell", "continue-on-error")
                and isinstance(value, yaml.ScalarNode)
                and value.style is None
                and value.end_mark.line > value.start_mark.line
            ):
                raise ValueError(
                    f"{where}line {line}: a plain multi-line value for `{key.value}` is unsupported; "
                    "YAML folds it into one value that a line scan reads as its first line. "
                    "Write it on one line, or as a block scalar (`|` or `>-`)"
                )
            # `uses:` then the path on the next line is a valid scalar GitHub runs (actionlint
            # accepts it, observed 2026-11-21), but every reader takes `uses` from the key's own
            # line, so the called workflow or action was never walked (consumer review, RV-41).
            if (
                isinstance(key, yaml.ScalarNode)
                and key.value == "uses"
                and id(node) not in data_mappings
                and isinstance(value, yaml.ScalarNode)
                and (value.start_mark.line != key.start_mark.line or value.end_mark.line > value.start_mark.line)
            ):
                # An alias lands here too: it resolves to the node at its anchor, on another line.
                raise ValueError(
                    f"{where}line {line}: a `uses` value must be written on the key's own line, on one line"
                    + (", not as a block scalar" if value.style in ("|", ">") else ", not as an alias or on a later line")
                )
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
                # An alias resolves to the node where its ANCHOR was written, so a node that
                # sits outside the span it is used in is an alias, wherever the anchor lives
                # (matrix data, another job). A node met twice is an alias within the same
                # span. Position catches the first, identity the second.
                if id(value) in step_nodes_seen or value.start_mark.index < key.end_mark.index:
                    raise ValueError(f"{where}line {line}: a `steps:` sequence that is an alias of another is unsupported; write the steps out")
                step_nodes_seen.add(id(value))
                for item in value.value:
                    # A step that is also a `with:`/`env:` mapping (`env: &x` ... `- *x`) is an alias the
                    # data exemption would hide from the `uses` check.
                    if id(item) in step_nodes_seen or id(item) in data_mappings or not (value.start_mark.index <= item.start_mark.index <= value.end_mark.index):
                        raise ValueError(f"{where}line {item.start_mark.line + 1}: a step that is an alias of another step is unsupported; write the step out")
                    step_nodes_seen.add(id(item))
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
    refuses (adversarial review 20261031T213036Z, H3; a consumer 20261101T004738Z, M35).
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
    mapping's not-a-string sentinel reddened a valid reusable workflow (code review).
    `node` itself is scanned whole when `exclude` is empty. `rewrite` is applied
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
    (M4, XM1; a consumer 20261101T004730Z, S2, S13). `run:` also appears as a
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


def run_body_at(scope, block, index, match):
    """(body lines, next index) for the `run:` key RUN_KEY matched on `block[index]`.

    A QUOTED value is taken from the parsed node, not the line: GitHub hands the shell the
    DECODED scalar, so `run: "python3 scripts/g\\u0061te.py"` runs scripts/gate.py while
    the raw text names a file that does not exist and the script escaped tiering
    (C1-CX1). The node also covers a quoted value written on the line after the key.
    """
    step = step_node_at(scope, getattr(block, "offset", 0) + index)
    node = mapping_get(step, "run")
    if isinstance(node, yaml.ScalarNode) and node.style in ("'", '"'):
        return (node.value.split("\n") if node.value else []), index + 1
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
        # `#` lines are kept: one can close a string opened on the line above, and
        # dropping it leaves the commands after it reading as part of that string.
        return continuation_lines(block, index, len(match.group(1)), keep_comments=True)
    return [value], index + 1


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
    lines = read_manifest_lines(target)
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
        body, index = run_body_at(document, lines, index, match)
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
    lines = read_manifest_lines(target)
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
            # A `run:`-shaped line inside a multi-line scalar is text, not a step (C1-F18).
            if index in payload_indexes:
                index += 1
                continue
            match = RUN_KEY.match(block[index])
            if not match:
                index += 1
                continue
            run_index = index
            body, index = run_body_at(job, block, index, match)
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
    document, _, _ = parsed_document(lines)
    # Only workflow-level `defaults.run` -- outside the jobs mapping, before or after
    # it -- can set a working directory for this job's steps.
    workflow_directories = working_directories(document, exclude={"jobs"}) if include_directories else set()
    for job_id in gated_jobs_in_order(lines, jobs, needs, gate_job):
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
            body, index = run_body_at(job, block, index, match)
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


def gated_jobs_in_order(lines, jobs, needs, gate_job):
    """The gate job and every job it transitively needs, in the order the workflow declares them.

    Workflow order, not set order: the report names the first job that runs a script, and a set of
    job ids iterates in hash-seed order, so the same scripts were reported under a different job
    from run to run.
    """
    job_indent = len(lines[jobs[gate_job]]) - len(lines[jobs[gate_job]].lstrip(" "))
    reachable, pending = set(), [gate_job, *needs]
    while pending:
        job_id = pending.pop()
        if job_id in reachable:
            continue
        reachable.add(job_id)
        if job_id in jobs:
            pending.extend(job_needs(lines, jobs, job_id, job_indent) - reachable)
    return sorted((job_id for job_id in reachable if job_id in jobs), key=jobs.get)


def resolve_committed_paths(root, relative, allow_outside_repository=False):
    """The COMMITTED spelling(s) of `relative` under `root`; empty when it resolves to
    no file at all.

    Windows resolves a path case-insensitively, so a windows-latest job runs
    `./scripts/probe.PS1` against a file committed as `scripts/probe.ps1`. This checker
    runs on ubuntu, where the exact lookup fails -- so a mixed-case word that was not
    resolved here would be read and then silently dropped, which is fail-open.

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
        if real.is_file() and is_within(real, root.resolve()):
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


# Gate script discovery: the WORD RULE. Every word in a gated run body, or in a package
# script that body runs, that names a repository script must be HIGH. There is no shell
# parser and no interpreter option table, so a word in a comment, an echo or an argument
# counts too. That over-approximation is the accepted cost: more scripts required HIGH,
# never fewer.
SCRIPT_EXTENSIONS = (".ps1", ".psm1", ".py", ".sh", ".bash", ".mjs", ".cjs", ".js")
# `.ts` is a script only under a script-root segment (`tsx scripts/x.ts`), so a config file
# such as `vitest.config.ts` is not.
SCRIPT_ROOTS = ("scripts", "build", "tools")
WORD = re.compile(r"""[^\s'"`;|&()<>=,]+""")
TEST_RUNNERS = {"unittest", "pytest", "py.test"}
# pytest options whose value is the next argument (core options and aliases, plus the common
# xdist/cov ones), so `pytest -k smoke` or `pytest --maxfail 1` names no collection target.
PYTEST_VALUE_OPTIONS = {
    "-k", "-m", "-c", "-p", "-o", "-n", "-W", "-r", "--rootdir", "--confcutdir", "--basetemp", "--junitxml",
    "--junit-xml", "--junit-prefix", "--cov", "--cov-report", "--ignore", "--ignore-glob", "--deselect", "--maxfail",
    "--capture", "--tb", "--durations", "--durations-min", "--color", "--code-highlight", "--pastebin",
    "--show-capture", "--import-mode", "--override-ini", "--config-file", "--inifile", "--pythonwarnings",
    "--doctest-glob", "--doctest-report", "--assert", "--log-level", "--log-format", "--log-date-format",
    "--log-cli-level", "--log-cli-format", "--log-cli-date-format", "--log-file", "--log-file-mode", "--log-file-level",
    "--log-file-format", "--log-file-date-format", "--log-auto-indent", "--verbosity", "--numprocesses",
    "--maxprocesses", "--dist", "--tx", "--rsyncdir", "--deselect", "--last-failed-no-failures", "--lfnf",
}
SHELL_OPERATOR = re.compile(r"[();|&]+")
# shlex merges adjacent punctuation, so `&>`, `&>>`, `>|` and `>&` arrive as one token.
REDIRECTION = re.compile(r"&?[<>]+[&|]?")
# Words that run the next word as the command (`command pytest`, `env CI=1 pytest`).
COMMAND_WRAPPERS = {"command", "exec", "env", "time"}


def pytest_targets(arguments):
    """The collection targets among a pytest command's arguments: option values are not targets."""
    targets, index = [], 0
    while index < len(arguments):
        argument = arguments[index]
        if argument.startswith("-"):
            index += 2 if argument in PYTEST_VALUE_OPTIONS else 1
            continue
        targets.append(argument)
        index += 1
    return targets


def strip_shell_comment(line):
    """The line without its shell comment: a `#` starts one only at the start of a word, outside quotes
    (`--user-agent=ci#build` keeps its `#`). Not `strip_comment`, which is the YAML job/needs grammar's own cut."""
    quote, index, word_start = None, 0, True
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and quote == '"':
                index += 1
            elif char == quote:
                quote = None
        elif char == "#" and word_start:
            return line[:index]
        elif char == "\\":
            index += 1  # an escaped character, even a space, belongs to the current word
            word_start = False
        elif char in "'\"":
            quote = char
            word_start = False
        else:
            word_start = char.isspace() or char in ";&|()"
        index += 1
    return line


def shell_commands(line):
    """A line's commands as token lists, split at unquoted `; | & && || ( )` as the shell splits them.
    A redirection and its target (`> out.txt`, `2>&1`) are dropped. None when the quoting is unbalanced."""
    lexer = shlex.shlex(strip_shell_comment(line), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""  # shlex would end a token at an in-word `#`; strip_shell_comment applies the shell's rule
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    commands, current, index = [], [], 0
    while index < len(tokens):
        token = tokens[index]
        if REDIRECTION.fullmatch(token):
            if current and current[-1].isdigit():
                current.pop()  # the fd of `2>&1`
            index += 1  # and its target
        elif SHELL_OPERATOR.fullmatch(token):
            commands.append(current)
            current = []
        else:
            current.append(token)
        index += 1
    return [command for command in commands + [current] if command]


def pytest_invocations(commands):
    """The argument list of each command that runs pytest (by basename, at command position, after
    assignments or a wrapper, or after `-m`)."""
    for command in commands:
        for index, token in enumerate(command):
            if posixpath.basename(token) not in ("pytest", "py.test"):
                continue
            leading = command[:index]
            if all(re.match(r"[A-Za-z_]\w*=", word) or word in COMMAND_WRAPPERS for word in leading) or (leading and leading[-1] == "-m"):
                yield command[index + 1:]


UNITTEST_VALUE_OPTIONS = {"-s", "--start-directory", "-p", "--pattern", "-t", "--top-level-directory", "-k", "--durations"}


def is_unittest_command(command):
    """True when `unittest` is the command word or the module of `<python> -m unittest`, not just an argument
    (`echo unittest discover`, `git log --grep unittest`)."""
    if "unittest" not in command:
        return False
    position = command.index("unittest")
    if position == 0:
        return True
    return command[position - 1] == "-m" and has_python_interpreter(command, position - 1)


def unittest_discover_without_start(command):
    """True for `unittest discover` with no start directory: unittest then starts at `.` (issue #506 A3).
    A start directory is `-s DIR`, `--start-directory DIR` (or `=DIR`) or the first positional argument."""
    if not is_unittest_command(command):
        return False
    rest = command[command.index("unittest") + 1:]
    if not rest or rest[0] != "discover":
        return False
    skip = False
    for argument in rest[1:]:
        if skip:
            skip = False
        elif argument in UNITTEST_VALUE_OPTIONS:
            if argument in ("-s", "--start-directory"):
                return False
            skip = True
        elif argument.startswith(("-s=", "--start-directory=")) or (argument.startswith("-s") and len(argument) > 2 and not argument.startswith("--")):
            return False
        elif argument.startswith("-"):
            continue
        else:
            return False  # the first positional argument is the start directory
    return True


def runs_pytest_from_root(commands):
    """True when a command is pytest with no target."""
    return any(not pytest_targets(arguments) and not {"--version", "-V"} & set(arguments) for arguments in pytest_invocations(commands))


def pytest_option_values(commands):
    """The values pytest options take (`--ignore-glob '*slow*'`, `-k=x`): never discovery patterns."""
    values = set()
    for arguments in pytest_invocations(commands):
        for index, argument in enumerate(arguments):
            option, equals, value = argument.partition("=")
            if equals and option in PYTEST_VALUE_OPTIONS:
                values.add(value)
            elif argument in PYTEST_VALUE_OPTIONS and index + 1 < len(arguments):
                values.add(arguments[index + 1])
    return values
PACKAGE_MANAGERS = {"npm", "npx", "pnpm", "yarn"}
NPM_LIFECYCLE = {"test": "test", "t": "test", "tst": "test", "start": "start", "stop": "stop", "restart": "restart"}
NPM_INSTALL = {"ci", "install", "i"}
NPM_ELSEWHERE = {"-w", "--workspace", "--workspaces", "-ws", "--ws", "--prefix", "-C"}
# A directory command at COMMAND position: line start; after ; & | ( { or a backtick; opening
# a `-c`/`-Command` string; then optional shell keywords, `command`/`builtin` and assignment
# prefixes. Not quote- or comment-aware, so `echo "a; cd b"` and `# ; cd b` count. The word
# ends at whitespace, a separator, a redirection or `$` (`cd$X` runs cd when X is empty).
# An assignment value is a run of disjoint pieces, each told apart by its first character: a quoted
# string (escapes honoured inside double quotes), a backslash escape (`X=\" cd sub`), or one plain
# character. An unquoted branch that could also eat quotes backtracked exponentially (CodeQL
# py/redos, consumer review; escapes, code review).
DIRECTORY_CHANGE = re.compile(
    r"(?:^|[;&|({`]|(?<![\w-])-c(?:ommand)?[ \t]+[\"'])[ \t]*"
    r"(?:(?:then|do|else|if|elif|while|until|!)[ \t]+)*"
    r"(?:(?:command|builtin)[ \t]+|[A-Za-z_][A-Za-z0-9_]*=(?:\"(?:[^\"\\\n]|\\.)*\"|'[^'\n]*'|\\.|[^\s;&|\"'\\])*[ \t]+)*"
    r"(?:cd|chdir|pushd|sl|set-location|push-location)(?=[\s;&|()`<>$]|$)",
    re.IGNORECASE | re.MULTILINE,
)
WORKSPACE_PREFIX = re.compile(r"^(?:\$\{?GITHUB_WORKSPACE\}?|\$env:GITHUB_WORKSPACE)/", re.IGNORECASE)


def is_script(path):
    lowered = path.lower()
    if lowered.endswith(".ts"):
        return any(part in SCRIPT_ROOTS for part in lowered.split("/")[:-1])
    return lowered.endswith(SCRIPT_EXTENSIONS)


def repository_files(root):
    """Repository-relative files: git's tracked and not-ignored files in a work tree, else a walk.

    Untracked files count: the rollout runs this on assets it has just copied in, before any
    commit. Ignored files do not: a local build output is not reviewable content.
    """
    if (root / ".git").exists():
        try:
            listed = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                                    capture_output=True, check=True).stdout
            return {path for path in listed.decode("utf-8", "replace").split("\0") if path}
        except (OSError, subprocess.CalledProcessError):
            pass  # not readable as a repository here (no git, unsafe ownership): walk instead
    files = set()
    for directory, subdirectories, names in os.walk(root):
        subdirectories[:] = [name for name in subdirectories if name not in (".git", "node_modules")]
        base = Path(directory).relative_to(root).as_posix()
        files.update(name if base == "." else f"{base}/{name}" for name in names)
    return files


def changes_directory(text):
    """True when `text` runs a directory command at command position (see DIRECTORY_CHANGE)."""
    return DIRECTORY_CHANGE.search(text) is not None


def npm_flag_value(args, names):
    """npm's effective value for a Boolean option spelled as any of `names`: the last of `--x`,
    `--x true|false` (WORD splits `--x=false` the same way) or `--no-x` wins. An unknown value
    reads False, so the hooks are followed."""
    value = False
    for index, arg in enumerate(args):
        if arg in names:
            following = args[index + 1] if index + 1 < len(args) else ""
            value = following.lower() != "false"
        elif arg.startswith("--no-") and "--" + arg[5:] in names:
            value = False
    return value


# The interpreter in a `python -m <module>` launch (`python`, `python3.12`, `py`, `pypy3`, with an optional .exe).
# POSIX shell parsing eats the backslashes of an unquoted Windows path (`.venv\Scripts\python` arrives as
# `.venvScriptspython`), so a token that merely ENDS in the interpreter name counts, as does a bare `py`/`pypy`.
PYTHON_EXECUTABLE = re.compile(r"(?:.*python[0-9.]*(?:td?|d|w)?|(?:.*[/\\])?(?:py|pypy[0-9.]*))(?:\.exe)?", re.IGNORECASE)

# Commands that print or search their arguments and run none of them (`echo python3 -m unittest`).
NON_LAUNCHING_COMMANDS = {"echo", "printf", "cat", "grep", "egrep", "fgrep", "rg", "test", "which", "type", "ls"}
# `git <subcommand>` that prints or searches. Any other subcommand may run its arguments (`git bisect run <cmd>`).
NON_LAUNCHING_GIT_SUBCOMMANDS = {"log", "grep", "show", "diff", "blame", "describe", "status", "shortlog"}
# `git` and `env` options that take a separate value.
GIT_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}
ENV_VALUE_OPTIONS = {"-u", "--unset", "-C", "--chdir", "-a", "--argv0"}


def command_word_index(command):
    """Where the command word is: after assignments and known wrappers (by basename, so `/usr/bin/env` counts) and
    after the options of `env`, which would otherwise be read as the command (`env -i echo ...`)."""
    index = 0
    while index < len(command):
        word = command[index]
        if re.match(r"[A-Za-z_]\w*=", word):
            index += 1
        elif posixpath.basename(word) in COMMAND_WRAPPERS:
            is_env = posixpath.basename(word) == "env"
            index += 1
            while is_env and index < len(command) and command[index].startswith("-"):
                index += 2 if command[index] in ENV_VALUE_OPTIONS else 1
        else:
            return index
    return 0


def prints_instead_of_launching(command):
    """True when the command word only prints or searches its arguments (`echo python3 ...`, `git log --grep python3`)."""
    index = command_word_index(command)
    # `env -S '<command line>'` splits its operand into the command and its arguments, so what follows is unknown.
    if any(word.startswith(("-S", "--split-string")) for word in command[:index]):
        return False
    name = posixpath.basename(command[index])
    if name != "git":
        return name in NON_LAUNCHING_COMMANDS
    index += 1
    while index < len(command) and command[index].startswith("-"):
        index += 2 if command[index] in GIT_VALUE_OPTIONS else 1
    return index < len(command) and command[index] in NON_LAUNCHING_GIT_SUBCOMMANDS


def has_python_interpreter(command, end):
    """True when a word before `end` is a Python interpreter, so `-m` there names a module. Any such word counts,
    so a wrapper this checker does not know (`poetry run python -m x`, `xvfb-run python -m x`) still launches it;
    only a command that merely prints or searches its arguments does not, whether or not an assignment or a known
    wrapper (`FOO=1 echo ...`, `env -i echo ...`) comes first."""
    return not prints_instead_of_launching(command) and any(PYTHON_EXECUTABLE.fullmatch(earlier) for earlier in command[:end])


# Modules `python -m <module>` runs that are tools, not a repository script (issue #506 A5).
NON_REPOSITORY_MODULES = {
    "pip", "venv", "ensurepip", "build", "twine", "setuptools", "wheel", "pipx", "virtualenv", "black", "ruff",
    "mypy", "flake8", "isort", "pylint", "coverage", "tox", "nox", "http", "json", "zipfile", "tarfile",
    "compileall", "py_compile", "site", "sysconfig", "platform", "timeit", "trace", "cProfile", "pdb",
    "unittest", "pytest",
}


class ScriptWords:
    """The repository scripts that the words of run bodies and package scripts name."""

    def __init__(self, root):
        self.root = root
        self.files = repository_files(root)
        self.directories = {path.lower().rsplit("/", 1)[0] for path in self.files if "/" in path}
        for directory in list(self.directories):
            while "/" in directory:
                directory = directory.rsplit("/", 1)[0]
                self.directories.add(directory)

    def committed(self, relative, allow_outside):
        # Only repository files: an untracked build output on the host is not reviewable.
        return [path for path in resolve_committed_paths(self.root, relative, allow_outside) if is_script(path) and path in self.files]

    def beneath(self, directory, wanted):
        prefix = "" if directory == "." else directory.lower() + "/"
        return {path for path in self.files if path.lower().startswith(prefix) and wanted(path)}

    def attempt(self, text, bases, testing, patterns, speculative):
        found = set()
        for base in bases:
            joined = posixpath.join(base, text) if base else text
            path = posixpath.normpath(joined)
            absolute = path.startswith("/") or re.match(r"[A-Za-z]:", path) is not None
            # Only the bare relative spelling with no working directory is the sole evidence
            # there is, so only it keeps resolve_committed_paths' outside-repository exit.
            allow_outside = speculative or absolute or bool(base) or len(bases) > 1
            if absolute or path == ".." or path.startswith("../"):
                if text.lower().endswith(SCRIPT_EXTENSIONS + (".ts",)):
                    found.update(self.committed(joined, allow_outside))
                continue
            # A single-segment glob (`pytest test_*.py`) expands too, for a test runner's targets (issue #506 A9).
            if any(char in text for char in "*?[") and ("/" in text or (testing and not text.startswith("-"))):
                # `*` and `?` stay inside one path segment, as the shell reads them. A brace
                # list is split at its comma into separate words, so `{...` widens to `*`.
                segments = re.sub(r"\{[^/]*", "*", path).split("/")
                found.update(
                    script for script in self.files
                    if len(script.split("/")) == len(segments)
                    and all(fnmatch.fnmatchcase(part, pattern) for part, pattern in zip(script.split("/"), segments))
                    and is_script(script)
                )
                if testing:
                    # `pytest checks/*` also runs each directory the glob names (code review).
                    for directory in self.directories:
                        if len(directory.split("/")) == len(segments) and all(
                                fnmatch.fnmatchcase(part, pattern.lower()) for part, pattern in zip(directory.split("/"), segments)):
                            found |= self.beneath(directory, lambda script: script.endswith(".py") and (
                                not patterns or any(fnmatch.fnmatchcase(posixpath.basename(script), p) for p in patterns)))
            elif path.lower() in self.directories or path == ".":
                if testing:
                    found |= self.beneath(path, lambda script: script.endswith(".py") and (
                        not patterns or any(fnmatch.fnmatchcase(posixpath.basename(script), p) for p in patterns)))
                elif "/" in text and any(part in SCRIPT_ROOTS for part in path.lower().split("/")):
                    found |= self.beneath(path, is_script)
            elif text.lower().endswith(SCRIPT_EXTENSIONS + (".ts",)):
                found.update(self.committed(joined, allow_outside))
        return {committed for path in found for committed in resolve_committed_paths(self.root, path, True) if committed in self.files}

    def named(self, word, bases, testing=False, patterns=()):
        """Repository scripts one word names, read from each base directory."""
        word = word.replace("\\", "/")
        rooted, count = WORKSPACE_PREFIX.subn("", word)
        if count:
            word, bases = rooted, [""]
        hits = self.attempt(word, bases, testing, patterns, False)
        # A prefixed spelling (`$PWD/ci/gate.sh`, `sub/scripts/x.py`) names its longest suffix
        # of two or more segments. A prefix that climbs above its own start names a file
        # outside the checkout, so its suffixes are not tried.
        parts, depth = word.split("/"), 0
        for index in range(1, len(parts) - 1):
            depth += -1 if parts[index - 1] == ".." else 0 if parts[index - 1] in ("", ".") else 1
            if hits or depth < 0:
                break
            if ".." in parts[index:]:
                continue  # a climb in the suffix is resolved by the full spelling, not guessed
            hits = self.attempt("/".join(parts[index:]), bases, testing, patterns, True)
        return hits

    def scan(self, text, bases, found, job_id, seen):
        """Record every script `text` names, following the package scripts it runs.

        Returns True when the text names, or may run, a script: a resolved script, a
        script-shaped word, a path glob, or a package-manager word. A directory change in such a text
        exits, because the paths after it resolve from a directory nothing here knows.
        """
        refers = False
        for line in re.sub(r"\\\r?\n[ \t]*", "", text).splitlines():
            spans = list(WORD.finditer(line))
            words = [span.group() for span in spans]
            # Each shell command on the line, quotes honoured and split at `; | & ( )`, so a later
            # command's words are not the runner's arguments (code review).
            parsed_commands = shell_commands(line)
            commands = parsed_commands or [words]
            # A shell token WORD splits (`python3 "scripts/quality checks.py"`, `python 'scripts/check,fast.py'`,
            # `"scripts/check(quick).py"`) is a word too (code review; issue #506 A8).
            words = words + [token for command in commands for token in command if token not in words and token.strip()]
            # A runner by its basename too (`.venv/bin/pytest tests`), and a pytest run with no target
            # collects from the root (`pytest`, `python3 -m pytest -q`; consumer review, C1-F9). So does
            # `python -m unittest discover` with no start directory (issue #506 A3).
            root_run = runs_pytest_from_root(commands)
            discover_run = any(unittest_discover_without_start(command) for command in commands)
            if root_run or discover_run:
                words = words + ["."]
            pytest_line = root_run or any(posixpath.basename(token) in ("pytest", "py.test") for command in commands for token in command)
            testing = pytest_line or bool(TEST_RUNNERS & set(words))
            # A discovery pattern (`-p 'test_*.py'`) narrows which files of a named directory run, and only
            # the targets of the command that supplies it: `pytest tests && echo 'release-*'` hands pytest
            # no pattern (issue #506 A1). A pytest option's value (`--ignore-glob '*slow*'`) is not one
            # (code review). A word no runner command owns is unfiltered: that only widens.
            option_values = pytest_option_values(commands)
            patterns_by_word = {}
            runner_patterns = []
            for command in commands:
                if not (any(posixpath.basename(token) in ("pytest", "py.test") for token in command) or TEST_RUNNERS & set(command)):
                    continue
                # A discovery pattern is the value of unittest's `-p`/`--pattern`. A glob among pytest's targets
                # (`pytest checks*`) is a TARGET, never a filename filter for another one, and an option token
                # (`--ignore-glob=*slow*`) is never a pattern.
                own_patterns = []
                if is_unittest_command(command):
                    for position, token in enumerate(command):
                        if token in ("-p", "--pattern") and position + 1 < len(command):
                            own_patterns.append(command[position + 1])
                        elif token.startswith("--pattern="):
                            own_patterns.append(token.split("=", 1)[1])
                    # `unittest discover START PATTERN`: the second positional argument is the pattern.
                    after = command[command.index("unittest") + 1:]
                    if after[:1] == ["discover"]:
                        positionals, skip = [], False
                        for argument in after[1:]:
                            if skip:
                                skip = False
                            elif argument in UNITTEST_VALUE_OPTIONS:
                                skip = True
                            elif not argument.startswith("-"):
                                positionals.append(argument)
                        if len(positionals) >= 2:
                            own_patterns.append(positionals[1])
                own_patterns = [pattern for pattern in own_patterns if "*" in pattern and "/" not in pattern and pattern not in option_values]
                runner_patterns.append(own_patterns)
                for token in command:
                    # A word two runner commands both name (`-s checks` twice) keeps the union of their patterns, and an
                    # unfiltered occurrence leaves it unfiltered: a later command must not inherit an earlier one's filter.
                    if token not in patterns_by_word:
                        patterns_by_word[token] = own_patterns
                    elif not patterns_by_word[token] or not own_patterns:
                        patterns_by_word[token] = []
                    else:
                        patterns_by_word[token] = sorted(set(patterns_by_word[token]) | set(own_patterns))
            # The implicit `.` belongs to every runner that supplied it; one without a pattern leaves it unfiltered.
            patterns_by_word["."] = [] if not runner_patterns or any(not own for own in runner_patterns) else sorted({p for own in runner_patterns for p in own})
            for index, word in enumerate(words):
                # A pytest node id names its module before the `::` (issue #506 A2).
                target = word.split("::")[0] if pytest_line and "::" in word and not word.startswith("-") else word
                hits = self.named(target, bases, testing and not word.startswith("-"), patterns_by_word.get(word, []))
                if word == "-m" and index + 1 < len(words):
                    module = words[index + 1].replace(".", "/")
                    hits |= self.named(module + ".py", bases) | self.named(module + "/__main__.py", bases)
                    package = module.split("/")
                    for depth in range(1, len(package) + 1):
                        hits |= self.attempt("/".join(package[:depth]) + "/__init__.py", bases, False, (), True)
                if pytest_line:
                    # pytest also imports every conftest.py above a target, up to the root, and
                    # pytest 9.1.1 did so for a target directory holding no test module at all.
                    targets = [posixpath.join(hit, "_") for hit in (posixpath.normpath(posixpath.join(base, word) if base else word) for base in bases)
                               if hit.lower() in self.directories]
                    for hit in list(hits) + targets:
                        directory = posixpath.dirname(hit)
                        while True:
                            conftest = posixpath.join(directory, "conftest.py") if directory else "conftest.py"
                            if conftest in self.files:
                                hits.add(conftest)
                            if not directory:
                                break
                            directory = posixpath.dirname(directory)
                for hit in hits:
                    found.setdefault(hit, job_id)
                # A path glob may expand to a script from a directory a `cd` moved to (`cd ci && node --test checks/*`).
                glob = "/" in word and any(char in word for char in "*?[")
                # A recognised pytest or unittest invocation counts even when its target resolves to nothing from
                # here (`cd app` then `pytest tests`): the paths after a `cd` are unknown (issue #506 A4).
                runner_word = word == "unittest" or posixpath.basename(word) in ("pytest", "py.test")
                refers = refers or bool(hits) or glob or runner_word or word in PACKAGE_MANAGERS or word.lower().endswith(SCRIPT_EXTENSIONS + (".ts",))
                # (package-manager and `python -m` handling follows the word loop, per parsed command.) A package-manager
                # word the parsed commands do not account for (one inside a trailing comment) is still followed, with no
                # trusted flag: the word rule counts a script named in a comment (over-approximation by design).
                if word in PACKAGE_MANAGERS and sum(1 for earlier in words[:index] if earlier == word) >= sum(command.count(word) for command in commands):
                    self.package_scripts(words[index:], bases, found, job_id, seen, [])
            # Package-manager invocations and `python -m` launches are read from each PARSED command, with that
            # command's own arguments. Ownership is never rebuilt from raw-word occurrence counts: `n\pm ci
            # --ignore-scripts; npm ci` has one literal `npm` word but two npm commands (code review).
            for command in commands:
                for position, token in enumerate(command):
                    if token == "-m" and position + 1 < len(command):
                        # A literal `python -m <module>` may run a repository module even when it does not resolve from
                        # here (`cd qa && python3 -m quality`), so it is script-bearing (issue #506 A5). Well-known tool
                        # modules are not, and `-m` outside a Python command (`git commit -m`) is not a module at all.
                        module = command[position + 1]
                        if (has_python_interpreter(command, position)
                                and not module.startswith("-") and module.split(".")[0] not in NON_REPOSITORY_MODULES):
                            refers = True
                    if token in PACKAGE_MANAGERS:
                        refers = True
                        # The command's own arguments are its flags: a redirection target (`npm ci > --ignore-scripts`,
                        # `2>--ignore-scripts`) is a file name and shell_commands has already dropped it. npm stops
                        # reading options at `--` (npm 11.18.0 ran the hooks for `npm ci -- --ignore-scripts`), and
                        # `--x=false` reads as `--x false`, the way npm_flag_value expects it. Quotes that could not
                        # be parsed leave no trusted flag, so the hooks are followed.
                        # shlex discards whether a token was quoted or escaped, so a quoted `'>'` argument reads as a
                        # redirection and swallows a later `--ignore-scripts=false`. Any quote or escape on the line makes
                        # the flags untrusted and the hooks are followed (code review).
                        quoted = re.search(r"[\"'`\\]", line) is not None
                        flags = [part for argument in command[position + 1:] for part in argument.split("=", 1)] if parsed_commands and not quoted else []
                        flags = flags[:flags.index("--")] if "--" in flags else flags
                        # WORD split `--workspace=@x/app` into the option and its value; the options npm_scripts
                        # looks for (`--workspace`, `--prefix`) must still be found as whole words.
                        invocation = [part for argument in command[position:] for part in argument.split("=", 1)]
                        self.package_scripts(invocation, bases, found, job_id, seen, flags)
        return refers

    def package_scripts(self, words, bases, found, job_id, seen, flags=()):
        # `working-directory: ./web` is the package at `web` (issue #506 A6).
        bases = ["" if posixpath.normpath(base) == "." else posixpath.normpath(base) if base else "" for base in bases]
        elsewhere = any(word in NPM_ELSEWHERE for word in words)
        if elsewhere:
            packages = {path for path in self.files if posixpath.basename(path) == "package.json"}
        else:
            packages = {posixpath.join(base, "package.json") if base else "package.json" for base in bases} & self.files
            # npm runs from the nearest ancestor holding a package.json: `npm test` in web/src reads
            # web/package.json (code review).
            for base in bases:
                directory = base
                while directory and posixpath.join(directory, "package.json") not in self.files:
                    directory = posixpath.dirname(directory)
                    manifest = posixpath.join(directory, "package.json") if directory else "package.json"
                    if manifest in self.files:
                        packages.add(manifest)
                        break
        command = words[1] if len(words) > 1 else ""
        if words[0] != "npm" or elsewhere:
            names = None  # any other spelling: every script of the package is in play
        elif command in ("run", "run-script"):
            # Every later bare word may be the name: `npm run --loglevel warn lint`.
            names = [word for word in words[2:] if not word.startswith("-")]
        elif command in NPM_LIFECYCLE:
            names = [NPM_LIFECYCLE[command]]
        elif command in NPM_INSTALL:
            # An install runs these hooks in the root package and in every workspace package. npm
            # 11.18.0 also ran pre/post/`dependencies` on `npm ci`, and ran every hook for
            # `--ignore-scripts false`: only an effective true value skips them. It ran `prepublish` too.
            names = [] if npm_flag_value(list(flags), ("--ignore-scripts",)) else ["preinstall", "install", "postinstall", "prepublish", "prepare", "dependencies"]
            packages = {path for path in self.files if posixpath.basename(path) == "package.json"}
        else:
            names = None
        for package in sorted(packages):
            try:
                scripts = json.loads((self.root / package).read_text(encoding="utf-8-sig")).get("scripts")
            except (OSError, ValueError, AttributeError):
                continue
            if not isinstance(scripts, dict):
                continue
            chosen = list(scripts) if names is None else list(names)
            if chosen == ["restart"] and not isinstance(scripts.get("restart"), str):
                # npm restart with no restart script runs stop then start, still inside prerestart/postrestart (issue #506 A11).
                chosen = ["restart", "stop", "start"]
            for name in (chosen if names is None else [hook for name in chosen for hook in ("pre" + name, name, "post" + name)]):
                if isinstance(scripts.get(name), str) and (package, name) not in seen:
                    seen.add((package, name))
                    directory = posixpath.dirname(package)
                    if self.scan(scripts[name], [directory], found, job_id, seen) and changes_directory(scripts[name]):
                        sys.exit(f"{self.root}: cannot verify gate script paths after a directory change in job '{job_id}'; use working-directory:")


def gate_script_paths(lines, jobs, needs, gate_job, root):
    """Repo-local scripts a merge-blocking job runs from the checkout, path -> job id.

    Discovery is the word rule (see ScriptWords). Only paths that EXIST under `root` are
    returned: a name that resolves to no file cannot be edited to neuter anything.
    resolve_committed_paths is the final resolver for every candidate, so the committed
    spelling is returned and a target outside the repository exits.

    THE BOUNDARY: a script reached only through a variable, a dynamic launch, or code a
    gate script itself imports is not derived. Review of the workflow change is the
    control there.
    """
    found = {}
    words = ScriptWords(root)
    seen_bodies = set()
    seen_scripts = set()
    for job_id, _, body, body_directories in gated_run_bodies(lines, jobs, needs, gate_job, root):
        body_key = (job_id, tuple(body), tuple(sorted(body_directories)))
        if body_key in seen_bodies:
            continue
        seen_bodies.add(body_key)
        text = "\n".join(body)
        bases = [""] + sorted(directory for directory in body_directories if directory and not directory.startswith("!"))
        if not words.scan(text, bases, found, job_id, seen_scripts):
            continue
        unsupported = next((directory for directory in body_directories if directory.startswith("!unsupported ")), None)
        if unsupported:
            sys.exit(f"{root}: {unsupported[1:]}")
        if changes_directory(text):
            sys.exit(f"{root}: cannot verify gate script paths after a directory change in job '{job_id}'; use working-directory:")
    # Local actions and reusable workflows execute from the PR checkout too. Their
    # own files therefore need HIGH coverage even when their run bodies contain no
    # directly named script.
    for job_id in gated_jobs_in_order(lines, jobs, needs, gate_job):
        block = job_block(lines, jobs, job_id)
        payload_indexes = run_payload_indexes(block)
        for index, line in enumerate(block):
            match = LOCAL_USES.match(line)
            if match and index not in payload_indexes and match.group(1).startswith(("./", "$/")):
                for relative in local_action_paths(root, match.group(1)):
                    found.setdefault(relative, job_id)
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
    lines = read_manifest_lines(target)
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
# BASH_ENV names a start-up file bash sources, SHELLOPTS and BASHOPTS set shell
# options such as noexec at start-up, and BASH_FUNC_name%% imports a function over a
# builtin. Refusing BASH_ENV alone left every other route open (adversarial review
# 20261031T213036Z, M2; a consumer 20261101T004738Z, M16).
#
# `ENV` is NOT one of them. Bash reads it only when interactive in POSIX mode; a step runs
# a script file non-interactively. Observed 2026-11-19 with bash 5.3 under the runner's
# own flags (`ENV=file bash --noprofile --norc -eo pipefail body.sh`): the file is not
# sourced, while the same command with BASH_ENV sources it. Refusing the name made an
# ordinary `env: ENV: prod` a permanent false red (C1-F9). Every accepted gate shell is bash
# or pwsh, so `sh` never runs a gate step.
STARTUP_ENV_KEYS = ("BASH_ENV", "SHELLOPTS", "BASHOPTS")
# The same routes spelled inside a GATE JOB run body -- a GITHUB_ENV write, or a write to
# pwsh's `$PROFILE`, which the runner loads because its pwsh template omits -NoProfile.
# `GITHUB_PATH` is the same route by another door: an earlier step that prepends a directory
# holding a fake `bash` or `pwsh` replaces the shell the failing step then runs under.
STARTUP_OVERRIDE_TOKEN = re.compile(
    r"(?i)\b(?:BASH_ENV|SHELLOPTS|BASHOPTS|BASH_FUNC_\w*|GITHUB_PATH)\b|\$(?:env:)?PROFILE\b"
)


def startup_env_keys(mapping):
    """The keys of a parsed `env:` mapping that can neutralise the gate's exit command."""
    if mapping is None:
        return []
    if not isinstance(mapping, yaml.MappingNode):
        raise ValueError("`env:` is not a mapping this checker can read, so a start-up override cannot be ruled out")
    return [name for name, _ in mapping_entries(mapping) if name in STARTUP_ENV_KEYS or name.startswith("BASH_FUNC_")]


def assert_composite_steps(workflow_path, root, ref, feeder, step_exempt, used_exempt, visited):
    """Hold the steps of a LOCAL composite action to the feeder-step rules.

    A feeder whose check lives in `uses: ./.github/actions/quality` was judged on the
    calling step alone, which carries neither `continue-on-error` nor a false `if:`. The
    action's own steps could swallow the failure or never run and the feeder still reported
    success. The action's manifest is in the checkout, so it is read here: a step with
    `continue-on-error` (unless it is exempted like a workflow step, by `<job>/<step id>`)
    or a statically false `if:` is refused, and a nested local composite is followed.
    """
    target = root / ref[2:]
    if target.is_dir():
        target = next((target / name for name in ("action.yml", "action.yaml") if (target / name).is_file()), None)
    if target is None or not target.is_file():
        return
    key = target.resolve().as_posix()
    if key in visited:
        return
    visited.add(key)
    manifest_lines = read_manifest_lines(target)
    document, _, _ = parsed_document(manifest_lines, target)
    steps = mapping_get(mapping_get(document, "runs"), "steps")
    if not isinstance(steps, yaml.SequenceNode):
        return
    for step in steps.value:
        if not isinstance(step, yaml.MappingNode):
            continue
        step_id = mapping_get(step, "id")
        identifier = step_id.value if isinstance(step_id, yaml.ScalarNode) else None
        tolerance = mapping_get(step, "continue-on-error")
        if isinstance(tolerance, yaml.ScalarNode) and static_truth(tolerance.value) is not False:
            entry = f"{feeder}/{identifier}" if identifier else None
            if entry in step_exempt:
                used_exempt.add(entry)
            else:
                sys.exit(
                    f"{workflow_path}: feeder '{feeder}' runs local action '{ref}', whose step"
                    + (f" (id '{identifier}')" if identifier else "")
                    + " has `continue-on-error`. A step whose failure is swallowed checks nothing "
                    "the gate can see. Remove it, or give the step an `id:` and name "
                    "`<job>/<step id>` in GATE_STEP_EXEMPT with a written rationale."
                )
        condition = mapping_get(step, "if")
        if isinstance(condition, yaml.ScalarNode) and static_truth(condition.value) is False:
            sys.exit(f"{workflow_path}: feeder '{feeder}' runs local action '{ref}', which has an always-skipped step.")
        if isinstance(condition, yaml.ScalarNode) and ambiguous_negated_literal(condition.value):
            sys.exit(
                f"{workflow_path}: feeder '{feeder}' runs local action '{ref}', which has a step whose `if:` "
                "negates a literal comparison. Its two precedence readings disagree, so the checker cannot "
                "say whether the step runs. Write the intended comparison with explicit parentheses."
            )
        used = mapping_get(step, "uses")
        if isinstance(used, yaml.ScalarNode):
            nested = decode_yaml_scalar(used.value)
            if nested.startswith(("./", "$/")):
                assert_composite_steps(workflow_path, root, nested, feeder, step_exempt, used_exempt, visited)


def step_runs_unconditionally(condition):
    """True when a step `if:` cannot skip the step on a healthy run: what is left once the
    conjuncts that fold to true are dropped is only `!cancelled()` or `success()`, the
    condition every step already has."""
    value = normalise_condition(condition)
    rest = [part for part in split_top_level(strip_outer_parentheses(value), "&&") if static_truth(part, True) is not True]
    return all(strip_outer_parentheses(part) in ("!cancelled()", "success()") for part in rest)


# GATE_STEP_IF_EXEMPT entry -> the workflows in which it exempted a runtime `if:`. An entry is `<job>/<step id>`
# with no workflow, so directory mode refuses one that is doing that in more than one file (issue #506 A14).
IF_EXEMPT_WORKFLOWS = {}


def assert_feeder_steps(workflow_path, lines, jobs, feeders, step_exempt, used_exempt, label="", root=None, step_if_exempt=frozenset()):
    """Refuse a feeder step that can never fail its job or never runs.

    `continue-on-error: true` on a step is the step-level spelling of a tolerated job:
    the step's failure is swallowed and the feeder reports green. An `if:` that is
    statically false never runs the step at all. Either leaves a check the gate believes
    in doing nothing.

    A runtime `if:` (`github.event_name == 'push'`) is refused too, unless the step's
    `<job>/<step id>` is named in GATE_STEP_IF_EXEMPT: it skips the step on some runs while
    the job, and so the gate, still reports success (owner decision, consumer review
    C1-D-G2). Only a condition that folds to unconditional -- `always()`, `!cancelled()`,
    `success()`, a conjunction of those -- passes unlisted. A step with no `id:` cannot be
    listed, so the refusal asks for one. A local composite action's own steps are not held
    to this rule.

    Keys are matched at the step's OWN column, the guard step_can_fail already applies:
    an action INPUT named `if` or `continue-on-error` under `with:` is a value, not a step
    control, and reading it as one reddened a correct workflow (adversarial review
    20261031T213036Z, L3; a consumer 20261101T004738Z, M20).

    A best-effort step is exempted by naming `<job>/<step id>` in GATE_STEP_EXEMPT -- an
    explicit, reviewable list, as GATE_EXEMPT is for jobs. Fail-closed with no exemption
    reddened the first consumer with a best-effort step (consumer review
    20261101T004730Z, S12). `label` prefixes the job id when the jobs belong to a called
    reusable workflow, in messages and in exemption entries alike.
    """
    document, _, _ = parsed_document(lines, workflow_path)
    for feeder in sorted(feeders):
        block = job_block(lines, jobs, feeder)
        payloads = run_payload_indexes(block)
        # Only an item of the job's own `steps:` is a step: a `run:` under strategy.matrix.include is
        # data, and its sibling `if:` was refused as a step condition (code review; cf. C1-F7).
        # Its `run` and `uses` keys are read from the step MAPPING, never by a line match: an action
        # input named `run` under `with:` placed before `uses:` was taken for the step's own key, and the
        # step's real `if:` was never read (issue #506 A12).
        steps = mapping_get(job_node(document, feeder), "steps")
        executable_keys = {}
        if isinstance(steps, yaml.SequenceNode):
            for item in steps.value:
                if isinstance(item, yaml.MappingNode):
                    for key_node, _value in item.value:
                        if isinstance(key_node, yaml.ScalarNode) and key_node.value in ("run", "uses"):
                            executable_keys[key_node.start_mark.line - getattr(block, "offset", 0)] = (key_node.start_mark.column, key_node.value)
        seen = set()
        for index, line in enumerate(block):
            key = executable_keys.get(index) if index not in payloads else None
            if key is None:
                continue
            indent = key[0]
            span = step_span(block, index, indent)
            if span is None or span in seen:
                continue
            seen.add(span)
            kind = "run step" if key[1] == "run" else "step"

            def own_key(key):
                pattern = step_key_pattern(indent, key)
                for offset in range(*span):
                    entry = pattern.match(block[offset]) if offset not in payloads else None
                    if entry and len(entry.group(1)) == indent:
                        value = strip_inline_comment(entry.group(2)).strip()
                        if not value or is_block_scalar_header(value):
                            body, _ = continuation_lines(block, offset, indent)
                            value = " ".join(strip_inline_comment(part).strip() for part in body)
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
            if condition is not None and ambiguous_negated_literal(condition):
                sys.exit(
                    f"{workflow_path}: feeder '{label}{feeder}' has a {kind} whose `if:` negates a literal "
                    "comparison. Its two precedence readings disagree, so the checker cannot say whether "
                    "the step runs. Write the intended comparison with explicit parentheses."
                )
            if condition is not None and not step_runs_unconditionally(condition):
                step_id = own_key("id")
                entry = f"{label}{feeder}/{decode_yaml_scalar(step_id)}" if step_id else None
                if entry in step_if_exempt:
                    used_exempt.add(("if", entry))
                    IF_EXEMPT_WORKFLOWS.setdefault(entry, set()).add(str(workflow_path))
                else:
                    sys.exit(
                        f"{workflow_path}: feeder '{label}{feeder}' has a {kind}"
                        + (f" (id '{decode_yaml_scalar(step_id)}', entry '{entry}')" if step_id
                           else f" (name '{decode_yaml_scalar(own_key('name'))}')" if own_key("name") else "")
                        + f" whose `if: {condition}` can skip it on a healthy run. A skipped step "
                        "checks nothing, and its job still reports success to the gate. Remove the "
                        "condition, or "
                        + ("name" if step_id else "give the step an `id:` and name")
                        + " `<job>/<step id>` in GATE_STEP_IF_EXEMPT with a written rationale."
                    )
            used_ref = own_key("uses")
            if used_ref is not None and root is not None:
                composite = decode_yaml_scalar(used_ref)
                # A STEP-level local `uses:` is never a reusable-workflow call (that is job
                # level), so the `.github/workflows/` carve-out does not apply: a composite
                # action may live there.
                if composite.startswith(("./", "$/")):
                    assert_composite_steps(
                        workflow_path, root, composite, f"{label}{feeder}", step_exempt, used_exempt, set()
                    )


def reusable_workflow_feeder(lines, jobs, job_id, job_indent, root, workflow_path=None):
    """(path, lines, jobs, job indent) of the LOCAL reusable workflow `job_id` calls, or None."""
    indent = job_body_indent(lines, jobs, job_id, job_indent)
    if indent is None:
        return None
    uses_key = key_pattern(indent, "uses")
    for line in job_block(lines, jobs, job_id):
        match = uses_key.match(line)
        if not match:
            continue
        raw_ref = strip_comment(match.group(1)).strip()
        if is_block_scalar_header(raw_ref):
            sys.exit(
                f"{workflow_path}: job '{job_id}' spells `uses:` as a block scalar, so this checker cannot follow the "
                "reusable workflow it calls and would skip its jobs. Write the path on the `uses:` line."
            )
        ref = decode_yaml_scalar(raw_ref)
        # `./` and `$/` are the two local spellings LOCAL_USES admits.
        if not (ref.startswith(("./", "$/")) and ref[2:].startswith(".github/workflows/")):
            return None
        target = root / ref[2:]
        if not target.is_file():
            return None
        callee_lines = read_manifest_lines(target)
        callee_jobs, _, _ = read_gate_contract(callee_lines, "")
        if not callee_jobs:
            return None  # delegated_workflow_run_bodies refuses the flow spelling
        parsed_document(callee_lines, target)
        first = min(callee_jobs.values())
        return target, callee_lines, callee_jobs, len(callee_lines[first]) - len(callee_lines[first].lstrip(" "))
    return None


def check_file(workflow_path, gate_job, exempt, conditional_exempt, *, on_empty="fail", step_exempt=frozenset(), step_usage=None, step_if_exempt=frozenset()):
    """Assert one file's full gate contract. Returns True when the file contains the
    gate job (and every assertion ran), False when it has no gate job at all.

    Exemption-name validation is the CALLER's job, not this function's: in directory
    mode a job named in GATE_EXEMPT exists in exactly one workflow, so validating it
    against a single file's job set here reddened every OTHER workflow that also
    contains the gate job with a false "names jobs that do not exist".

    The same holds for a stale GATE_STEP_EXEMPT entry. `step_usage` is directory mode's
    (used entries, feeder job ids) pair, shared by every file and judged once after the
    loop: judged per file, `build/lint` used by ci.yml's `build` read as stale in a
    release.yml whose own `build` has no tolerated step (code review; issue #429). Without it
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
            "accepted exit command: BASH_ENV loads a start-up file, SHELLOPTS/BASHOPTS set "
            "shell options such as noexec, BASH_FUNC_* imports a function over a builtin, and "
            "$PROFILE is loaded by the runner's pwsh, and GITHUB_PATH can put a fake shell "
            "ahead of the real one. Remove the override or use a separately verified gate shell."
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
            "green while checking nothing. Remove the condition (or write "
            "`${{ !cancelled() }}`), or name the job in "
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
    assert_feeder_steps(workflow_path, lines, jobs, set(needs) - {gate_job}, step_exempt, used_step_exempt, root=root, step_if_exempt=step_if_exempt)

    # A feeder that is a LOCAL REUSABLE WORKFLOW runs that file's jobs, and the caller
    # reports success when every callee job succeeds OR SKIPS. A conditional, tolerated or
    # step-neutered job inside the callee is therefore the same hole as the same thing on
    # the feeder itself, and nothing looked inside.
    # The callee's jobs get the feeder's own checks; a feeder named in
    # GATE_CONDITIONAL_EXEMPT may skip, so its callee may be conditional too.
    # A callee job can itself call another local reusable workflow, and the same hole
    # reopens one hop down, so the walk recurses with a visited set (a cycle ends it).
    def check_callee(caller_path, caller_lines, caller_jobs, caller_indent, feeder, label, exempt, visited):
        callee = reusable_workflow_feeder(caller_lines, caller_jobs, feeder, caller_indent, root, caller_path)
        if callee is None:
            return
        callee_path, callee_lines, callee_jobs, callee_indent = callee
        if callee_path in visited:
            return
        visited = visited | {callee_path}
        if not exempt:
            skippable = sorted(conditional_jobs(callee_lines, callee_jobs, callee_indent))
            if skippable:
                sys.exit(
                    f"{workflow_path}: feeder '{label}{feeder}' calls {callee_path}, whose job(s) "
                    f"{', '.join(skippable)} carry a job-level 'if:'. A skipped callee job passes the "
                    "caller and so the gate; remove the condition, or name the feeder in "
                    "GATE_CONDITIONAL_EXEMPT with a written rationale."
                )
        tolerated = sorted(tolerant_jobs(callee_lines, callee_jobs, callee_indent))
        if tolerated:
            sys.exit(
                f"{workflow_path}: feeder '{label}{feeder}' calls {callee_path}, whose job(s) "
                f"{', '.join(tolerated)} carry 'continue-on-error'. A tolerated callee job cannot fail "
                "the feeder."
            )
        assert_feeder_steps(callee_path, callee_lines, callee_jobs, set(callee_jobs), step_exempt, used_step_exempt, label=f"{label}{feeder}/", root=root, step_if_exempt=step_if_exempt)
        for nested in sorted(callee_jobs):
            check_callee(callee_path, callee_lines, callee_jobs, callee_indent, nested, f"{label}{feeder}/", exempt, visited)

    for feeder in sorted(set(needs) - {gate_job}):
        check_callee(workflow_path, lines, jobs, job_indent, feeder, "", feeder in conditional_exempt, frozenset({workflow_path}))

    if step_usage is None:
        assert_step_exempt_used(workflow_path, step_exempt, used_step_exempt, step_feeders)
        assert_step_if_exempt_used(workflow_path, step_if_exempt, used_step_exempt)

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


def assert_step_if_exempt_used(where, step_if_exempt, used):
    """Refuse a GATE_STEP_IF_EXEMPT entry that exempted no runtime feeder step `if:`.

    Any job, not only a feeder: an entry naming the gate job's own failure step, or a job outside
    the gate, exempts nothing and was accepted in silence (code review).
    """
    stale = sorted(entry for entry in step_if_exempt if ("if", entry) not in used)
    if stale:
        sys.exit(
            f"{where}: GATE_STEP_IF_EXEMPT names step(s) that do not exist or carry no runtime "
            f"`if:`: {', '.join(stale)}. Each entry is `<job>/<step id>` for a feeder step whose "
            "`if:` can skip it."
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
    step_if_exempt = split_env("GATE_STEP_IF_EXEMPT")
    malformed = sorted(entry for entry in step_if_exempt if not all(entry.split("/")) or "/" not in entry)
    if malformed:
        sys.exit(f"GATE_STEP_IF_EXEMPT entries are `<job>/<step id>`; malformed: {', '.join(malformed)}")
    step_jobs = {entry.split("/", 1)[0] for entry in step_exempt | step_if_exempt}

    if not Path(target).is_dir():
        if not Path(target).is_file():
            sys.exit(f"{target}: workflow path does not exist or is not a file.")
        unknown = sorted((exempt | conditional_exempt | step_jobs) - parse_jobs(target))
        if unknown:
            sys.exit(
                f"{target}: GATE_EXEMPT/GATE_CONDITIONAL_EXEMPT/GATE_STEP_EXEMPT/GATE_STEP_IF_EXEMPT name jobs that do"
                f" not exist: {', '.join(unknown)}"
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
            no_gate = check_file(target, gate_job, exempt, conditional_exempt, step_exempt=step_exempt, step_if_exempt=step_if_exempt) is False
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
            f"{target}: GATE_EXEMPT/GATE_CONDITIONAL_EXEMPT/GATE_STEP_EXEMPT/GATE_STEP_IF_EXEMPT name jobs that do"
            f" not exist in any workflow: {', '.join(unknown)}"
        )

    gated = 0
    step_usage = (set(), set())
    for workflow_path in files:
        # Same ValueError-to-refusal translation as file mode: a delegated action the
        # checker cannot classify must redden the run with a message, not a traceback.
        try:
            result = check_file(
                workflow_path, gate_job, exempt, conditional_exempt,
                on_empty="skip", step_exempt=step_exempt, step_usage=step_usage, step_if_exempt=step_if_exempt,
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
    assert_step_if_exempt_used(target, step_if_exempt, step_usage[0])
    shared = sorted((entry, sorted(paths)) for entry, paths in IF_EXEMPT_WORKFLOWS.items() if len(paths) > 1)
    if shared:
        entry, paths = shared[0]
        sys.exit(
            f"{target}: GATE_STEP_IF_EXEMPT entry '{entry}' exempts a runtime `if:` in {len(paths)} workflows "
            f"({', '.join(paths)}). An entry names a job and a step id, not a workflow, so one rationale would "
            "cover steps nobody reviewed. Give the steps distinct ids, or remove the condition from all but one."
        )


if __name__ == "__main__":
    main(sys.argv)
