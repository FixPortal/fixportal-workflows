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
import os
import re
import sys
from pathlib import Path


ID = r"[A-Za-z_][A-Za-z0-9_-]*"
COMMENT_OR_BLANK = re.compile(r"^\s*(?:\#.*)?$")
# A reference to an upstream job's outcome, in either the `needs.*.result` wildcard
# form or the per-job `needs.build.result` form. Requiring the literal wildcard would
# red a workflow that aggregates job by job, which is equally correct. The job id is
# CAPTURED rather than merely matched, because "some dependency is referenced" is not
# the assertion that matters: a gate declaring `needs: [build, lint]` whose condition
# names only `build` reports success while `lint` fails.
NEEDS_RESULT = re.compile(r"needs\.([A-Za-z0-9_*-]+)\.result")
# A `run:` command that ends the shell non-zero. `exit 0`, `true`, or no exit at all
# leaves the step incapable of failing whatever its condition says.
NONZERO_EXIT = re.compile(r"^(?:exit\s+0*[1-9][0-9]*|false)\b")
# Where one shell command ends and the next begins. Matching NONZERO_EXIT only at the
# start of a line rejected the ordinary one-liner `if [ -n "$x" ]; then exit 1; fi`,
# which is a false RED on a correct gate.
COMMAND_BOUNDARY = re.compile(r"(?:;|&&|\|\||\bthen\b|\belse\b|\bdo\b|\{)")
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
_ECHO = rf"(?:echo|printf)\s+[^\n|&;<>]*{_REDIR}"
_FAIL = rf"(?:exit\s+0*[1-9][0-9]*|false){_REDIR}"
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
        # RESIDUAL, stated rather than quietly carried: the two `if <test>; then exit 1;
        # fi` forms below have the same property - they exit 0 when their test fails. They
        # predate this change, are the shipped house shape, and removing them would red
        # every repo running it, so they stay. Narrowing them is a separate, estate-wide
        # change with its own rollout. (CodeRabbit, PR #135.)
        #
        # echo "..." ; exit 1     (message then failure, either separator style)
        rf"{_ECHO}\s*(?:;|&&)\s*exit\s+0*[1-9][0-9]*",
        # if <test>; then <echo>; exit 1; fi   -- the house one-liner
        rf"if\s+.+?;\s*then\s+(?:{_ECHO};\s*)?exit\s+0*[1-9][0-9]*;\s*fi",
        # if <test>; then exit 1; fi   with the echo inside on its own already covered
        r"if\s+.+?;\s*then\s+exit\s+0*[1-9][0-9]*;\s*fi",
        # PowerShell. `shell: pwsh` gate steps are house style in the .NET repos and
        # `throw 'upstream failed'` is how one fails, so rejecting it was a false RED
        # on a correct gate - the direction that gets a working control deleted to make
        # CI green. The trailing message is optional because mask_quoted has already
        # blanked the string by the time these patterns run. Admitting `throw` costs
        # nothing under bash either: it is not a builtin there, so the step still exits
        # non-zero (127), which is exactly what this function is asserting.
        # UNCONDITIONAL only. `if ($false) { throw "failed" }` was accepted and does not
        # throw, so the step exits 0 - the same fail-open as the `||` forms above.
        r"throw(?:\s+.*)?",
    )
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
JOBS_KEY = re.compile(r"""^(?:'jobs'|"jobs"|jobs)\s*:\s*$""")


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
    Found by CodeRabbit on fixportal-claude-skills#102, after an earlier pass on
    fixportal-agents-skills#131 had wrongly refuted the same claim against a fixture
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
    step fails its job's own assertions, it does not make the gate report green over a
    missing check. Each job's own body indentation is read rather than assumed, so a
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
        if any(job_if.match(lines[i].rstrip("\r\n")) for i in range(start + 1, end)):
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
        if quote == '"' and char == BACKSLASH and index + 1 < len(line):
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
    """True when the gate body is a RECOGNISED failing form.

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

    `body` is the joined run: body, with backslash continuations already folded.
    """
    text = mask_quoted(body)
    # Drop comments AFTER masking, so a `#` inside a string is not treated as one.
    text = re.sub(r"#[^\n]*", "", text)
    # Normalise whitespace per logical line, then test each against the accepted forms.
    for logical in text.split("\n"):
        segment = " ".join(logical.split())
        if not segment:
            continue
        for form in ACCEPTED_FAILING_FORMS:
            if form.fullmatch(segment):
                return True
    return False


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
        if normalise_condition(match.group(2)) not in ("false", ""):
            return False, "carries `continue-on-error`, so it cannot fail the job"

    run_key = step_key_pattern(key_indent, "run")
    for i in range(start, end):
        match = run_key.match(block[i])
        if not match or len(match.group(1)) != key_indent:
            continue
        value = strip_comment(match.group(2)).strip()
        if value and not BLOCK_SCALAR.match(value):
            body = [value]
        else:
            body, _ = continuation_lines(block, i, key_indent)
        # JOIN first, then fold backslash continuations, so quote state and continued
        # commands are carried across line boundaries. Evaluating each physical line
        # with its own quote state is what let `echo "\n exit 1 \n"` and a
        # backslash-continued echo read as failable commands.
        joined = "\n".join(body)
        joined = re.sub(r"\\\n\s*", " ", joined)
        if ends_non_zero(joined):
            return True, ""
        return False, (
            "its `run:` body is not a recognised failing form, so this checker will not "
            "vouch for it. Use one of: `exit 1`; `false`; `echo \"...\"; exit 1`; "
            "`if <test>; then echo \"...\"; exit 1; fi`; or, under `shell: pwsh`, an "
            "unconditional `throw`. Each may carry a trailing redirection. A gate step "
            "is not the place for shell this checker has to guess about, and a body "
            "guarded by its own `||`/`&&` test is refused because it exits ZERO on the "
            "other branch"
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
    different line. Found by CodeRabbit on fixportal-quickfixn#68.
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
    # as "aggregates its needs". Found by Gitar on fixportal-initiator#225.
    # ONE binding, used by both the scan below and the failure-capability check further
    # down. They were computed independently as `body_indent + 1` in two places, and they
    # must be equal: the second re-matches a line the first already matched, so a future
    # edit to one alone would make that re-match return None and raise AttributeError
    # instead of printing this script's own diagnostic. A crash is a worse signal than a
    # clean fail-closed exit. Found by CodeRabbit on fixportal-agents-skills#131.
    step_indent = body_indent + 1

    referenced = set()
    failing = []
    for condition, index in step_conditions(block, step_indent):
        ids = NEEDS_RESULT.findall(condition)
        if not ids:
            continue
        referenced.update(ids)
        failing.append((condition, index))

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
    if "*" not in referenced:
        uncovered = sorted(set(needs) - referenced)
        if uncovered:
            sys.exit(
                f"{workflow_path}: '{gate_job}' step conditions reference "
                f"{', '.join(sorted(referenced))} but not {', '.join(uncovered)}.\n"
                "A dependency whose result is never referenced can fail while the gate "
                "still reports success. Use `needs.*.result`, or reference every job in "
                f"the '{gate_job}' needs: list."
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
    covered = set()
    wildcard_covered = False
    step_if_value = step_key_pattern(step_indent, "if")
    for condition, index in failing:
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
        ids = set(NEEDS_RESULT.findall(condition))
        if "*" in ids:
            wildcard_covered = True
        covered.update(ids - {"*"})

    if not wildcard_covered and not covered:
        sys.exit(
            f"{workflow_path}: '{gate_job}' aggregates on `if: {reported}` but that "
            f"step {reason}.\n"
            "A condition that is reached and then does nothing leaves the required "
            "context green over a failed dependency, exactly as a missing condition "
            "does. Give the step a `run:` body that exits non-zero, and do not mark it "
            "continue-on-error."
        )

    if not wildcard_covered:
        unenforced = sorted(set(needs) - covered)
        if unenforced:
            sys.exit(
                f"{workflow_path}: '{gate_job}' references "
                f"{', '.join(sorted(covered))} from a step that can fail, but "
                f"{', '.join(unenforced)} is referenced only by steps that cannot.\n"
                "A dependency named in a condition whose step carries continue-on-error, "
                "or whose body cannot exit non-zero, is not gated at all: it can fail "
                "while the required context stays green."
            )


def parse_jobs(workflow_path):
    """The job-name set for one file, read once so callers can validate exemptions
    against it before (or across, in directory mode) running the full assertion."""
    with open(workflow_path, encoding="utf-8") as handle:
        lines = handle.readlines()
    jobs, _, _ = read_gate_contract(lines, "")
    return set(jobs)


def check_file(workflow_path, gate_job, exempt, conditional_exempt, *, on_empty="fail"):
    """Assert one file's full gate contract. Returns True when the file contains the
    gate job (and every assertion ran), False when it has no gate job at all.

    Exemption-name validation is the CALLER's job, not this function's: in directory
    mode a job named in GATE_EXEMPT exists in exactly one workflow, so validating it
    against a single file's job set here reddened every OTHER workflow that also
    contains the gate job with a false "names jobs that do not exist". Found by
    CodeRabbit on fixportal-workflows#26.
    """

    with open(workflow_path, encoding="utf-8") as handle:
        lines = handle.readlines()
    jobs, needs, conditional = read_gate_contract(lines, gate_job)

    if not jobs:
        if on_empty == "skip":
            return None
        sys.exit(f"{workflow_path}: no jobs found -- refusing to report coverage over nothing.")
    if gate_job not in jobs:
        return False

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

    assert_gate_semantics(workflow_path, lines, jobs, gate_job, needs)

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
        # on fixportal-claude-skills#102.
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
    # fixportal-workflows#26.
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
