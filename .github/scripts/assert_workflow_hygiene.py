#!/usr/bin/env python3
"""Assert workflow hygiene structurally: no target-context trigger, no blanket
write token, third-party actions pinned to an immutable ref.

This replaces three line-anchored `grep` assertions. They were bypassable by
ORDINARY block-style YAML, not by any evasion technique: a value may sit on the
line after its key, so

    permissions:
      write-all

resolves to exactly what `permissions: write-all` resolves to, while matching
neither the key-anchored `permissions:.*write-all` pattern nor anything else the
guard looked for. The same held for a `uses:` split across two lines, which never
reached the pin check at all. Demonstrated 2026-08-22: both greps returned no
match on a file PyYAML resolves to `permissions: 'write-all'` and
`uses: 'third/party@v1'`.

Parsing also removes the self-match hazard the greps carried. They needed a
`^[^#]*` prefix so the guard's own comments describing the rules did not trip it
(that bit on the fixportal-venue pilot). A parser reads values, so prose about a
rule cannot be mistaken for the rule.

Composite actions under `.github/actions/*/action.yml` are scanned for pinning too:
a workflow-side `uses: ./...` ref is this repository's own reviewed code and is
skipped, but the composite action's own steps can name mutable third-party actions,
making the local ref an unscanned indirection layer without this. The trigger and
permissions assertions stay workflow-only -- they have no meaning in an action.

Exit codes: 0 clean, 1 a hard violation, 2 the checker could not run.
"""

import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    # Same policy as assert_gate_coverage.py: fail legibly rather than installing
    # PyYAML at CI time. This gates merges, so an arbitrary-at-install-time
    # dependency must not enter the gating path.
    #
    # sys.exit(2), not sys.exit(<str>): the string form prints to stderr and exits 1,
    # which is the code this module documents for a real violation. Both fail the step,
    # but a consumer branching on 2 ("infra problem, retry") versus 1 ("violation, do
    # not retry") would misclassify a missing interpreter dependency as a bad workflow.
    print(
        "PyYAML is not available to this runner. Install it in the image rather "
        "than at gate time, or restore '.github/workflows/**' to the review "
        "policy's high tier so a reviewer sees these diffs.",
        file=sys.stderr,
    )
    sys.exit(2)

WORKFLOWS = Path(".github/workflows")
ACTIONS = Path(".github/actions")
SHA_LEN = 40
DIGEST_LEN = 64


def load(path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def triggers(document):
    """The event names in `on:`, whatever spelling was used.

    YAML 1.1 reads a bare `on` as the boolean True, which is why the key is
    looked up both ways -- `document["on"]` alone silently finds nothing in every
    workflow that writes the key unquoted, i.e. all of them.
    """
    section = document.get("on", document.get(True))
    if isinstance(section, str):
        return [section]
    if isinstance(section, list):
        return [event for event in section if isinstance(event, str)]
    if isinstance(section, dict):
        return [event for event in section if isinstance(event, str)]
    return []


def permission_blocks(document):
    """Every `permissions:` value in the file: workflow level, then each job.

    KNOWN GAP, stated so this is not mistaken for full coverage: only the literal
    `write-all` scalar is flagged (see main()). A mapping that grants every scope
    `write` individually carries the same privilege and passes. Not closed here because
    the test cannot be written soundly -- "every scope is write" needs the complete set
    of scopes GitHub defines, which changes as GitHub adds them, and an omitted scope is
    a *narrower* grant, not a broader one. A heuristic on scope count would fail
    workflows that legitimately need three or four write scopes.

    This is the same scope as the grep it replaces, so it is not a regression; the
    bypass this file closes is the block-style spelling of `write-all`, not the
    enumerated equivalent.
    """
    blocks = []
    if "permissions" in document:
        blocks.append(("workflow", document["permissions"]))
    jobs = document.get("jobs")
    if isinstance(jobs, dict):
        for name, job in jobs.items():
            if isinstance(job, dict) and "permissions" in job:
                blocks.append((f"job '{name}'", job["permissions"]))
    return blocks


def action_refs(document):
    """Every `uses:` value in the file, with the job it came from."""
    refs = []
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return refs
    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        # A reusable-workflow call carries `uses:` on the job itself.
        if isinstance(job.get("uses"), str):
            refs.append((name, job["uses"]))
        steps = job.get("steps")
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict) and isinstance(step.get("uses"), str):
                    refs.append((name, step["uses"]))
    return refs


def composite_refs(document):
    """Every `uses:` value in a composite action's `runs.steps`."""
    refs = []
    runs = document.get("runs")
    if isinstance(runs, dict):
        steps = runs.get("steps")
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict) and isinstance(step.get("uses"), str):
                    refs.append(("composite step", step["uses"]))
    return refs


def is_pinned(ref):
    """True when the ref names an immutable revision.

    Both forms the estate actually uses are accepted. The previous `sed`-based
    scanner kept surrounding quotes in the extracted value, so a correctly pinned
    `uses: "actions/checkout@<40-hex>"` failed the hex test and was reported as an
    unpinned third-party action; and a digest-pinned `docker://` ref could never
    pass it at all. Parsed values carry no quotes, and the digest form is now
    recognised explicitly.
    """
    if ref.startswith("./"):
        return True  # A local action is this repository's own reviewed code.
    if "@" not in ref:
        return False
    revision = ref.rsplit("@", 1)[1]
    if ref.startswith("docker://"):
        algorithm, _, digest = revision.partition(":")
        return algorithm == "sha256" and len(digest) == DIGEST_LEN and all(
            char in "0123456789abcdef" for char in digest
        )
    return len(revision) == SHA_LEN and all(char in "0123456789abcdef" for char in revision)


def report_pin(path, where, ref):
    """Print the verdict for one `uses:` ref. Returns None when pinned, else
    'notice' (unpinned first-party) or 'error' (unpinned third-party)."""
    if is_pinned(ref):
        return None
    # actions/* is GitHub's own namespace, and a mutable tag there means
    # trusting GitHub -- which every workflow already does by running on
    # their runners. A third-party mutable tag means trusting that owner
    # forever, with no re-review when they move it. Only the second is
    # gated. Flip this to a failure once a pinning sweep lands.
    if ref.startswith("actions/"):
        print(
            f"::notice file={path}::'{ref}' ({where}) is not SHA-pinned. First-party "
            "(GitHub) action, so not failed -- pin it when convenient."
        )
        return "notice"
    print(
        f"::error file={path}::Third-party action '{ref}' ({where}) is not pinned to "
        "an immutable revision. A mutable tag can change after review."
    )
    return "error"


def main():
    if not WORKFLOWS.is_dir():
        print(f"::error::{WORKFLOWS} does not exist; the guard cannot assert anything.")
        return 2

    failed = False
    unpinned_first_party = 0

    for path in sorted(list(WORKFLOWS.glob("*.yml")) + list(WORKFLOWS.glob("*.yaml"))):
        try:
            document = load(path)
        except yaml.YAMLError as error:
            print(f"::error file={path}::Not parseable as YAML: {error}")
            failed = True
            continue
        if not isinstance(document, dict):
            print(f"::error file={path}::Workflow does not parse to a mapping.")
            failed = True
            continue

        for event in triggers(document):
            # This trigger runs with a write token and repository secrets in the
            # base repo's context, while able to check out attacker-controlled head
            # code. It has legitimate uses; none should land without being argued
            # for, so it is refused here rather than reviewed by glob.
            if event == "pull_request_target":
                print(
                    f"::error file={path}::This workflow uses the target-context trigger, which grants "
                    "a write token and repository secrets to a workflow that can check out untrusted "
                    "head code. Use the plain pull_request trigger, or remove this assertion "
                    "deliberately with a written rationale."
                )
                failed = True

        for scope, value in permission_blocks(document):
            if isinstance(value, str) and value.strip() == "write-all":
                print(
                    f"::error file={path}::A write-all token at {scope} scope discards least "
                    "privilege. Declare the specific permissions each job needs."
                )
                failed = True

        for job, ref in action_refs(document):
            verdict = report_pin(path, f"job '{job}'", ref)
            if verdict == "notice":
                unpinned_first_party += 1
            elif verdict == "error":
                failed = True

    # Composite actions are an indirection layer over the pin gate: a workflow's
    # `uses: ./...` ref is skipped as local code, so the action's own third-party
    # refs would otherwise be scanned by nothing. The directory need not exist.
    if ACTIONS.is_dir():
        for path in sorted(
            list(ACTIONS.glob("**/action.yml")) + list(ACTIONS.glob("**/action.yaml"))
        ):
            try:
                document = load(path)
            except yaml.YAMLError as error:
                print(f"::error file={path}::Not parseable as YAML: {error}")
                failed = True
                continue
            if not isinstance(document, dict):
                print(f"::error file={path}::Action does not parse to a mapping.")
                failed = True
                continue
            for where, ref in composite_refs(document):
                verdict = report_pin(path, where, ref)
                if verdict == "notice":
                    unpinned_first_party += 1
                elif verdict == "error":
                    failed = True

    if failed:
        return 1

    print(
        "Workflow hygiene: no target-context trigger, no write-all token, every third-party "
        f"action pinned ({unpinned_first_party} first-party ref(s) unpinned, not gated)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
