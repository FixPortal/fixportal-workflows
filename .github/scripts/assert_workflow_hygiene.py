#!/usr/bin/env python3
"""Fails when a workflow in .github/workflows breaches the house hygiene bar.

Checked here rather than by a reviewer, because these are properties a glob-tiered
review was never reliably catching:

  * no target-context trigger (`pull_request_target`, `workflow_run`) -- both run in
    the BASE repo's context with its secrets and a write-scoped token, while able to
    reach attacker-controlled head code;
  * no blanket `write-all` token, at workflow or job scope;
  * every third-party action AND container image pinned to an immutable revision.

PARSED, NOT GREPPED. The greps this replaced carried a self-match hazard -- the
pattern for a rule matched the comment explaining the rule, so the guard failed in
every repo it was installed into -- and they were simultaneously too loose (prose
tripped them) and too tight (a quoted value, a list-form trigger, or a digest-pinned
ref read as a violation, or as clean, wrongly).

PyYAML is required and deliberately NOT installed at CI time: this script gates
merges, so fetching an unpinned package from PyPI here would put an
arbitrary-at-install-time dependency in the gating path. It ships in GitHub's ubuntu
images. A runner without it is a runner-image problem and should be loud. Note that
`actions/setup-python` installs a CLEAN interpreter from the tool cache which does
NOT carry PyYAML -- do not add that step to this job.

Exit codes: 0 clean, 1 a hard violation, 2 the checker could not run.

SCOPE, stated so a pass is not mistaken for more than it is: this scans
.github/workflows/*.yml|*.yaml, and follows a local `./` ref into its
action.yml/action.yaml to check the refs inside a composite action. It does not
resolve a reusable workflow in another repository, and pinning is checked by SHAPE
-- see TRUSTED_THIRD_PARTY_ACTIONS below for the stricter mode.
"""

import os
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    # Exit 2, not 1. `sys.exit("message")` prints the message and exits ONE, which this
    # script reserves for a hard workflow violation -- so a runner image missing PyYAML
    # reported as though the workflows themselves were bad, sending whoever read the
    # check into the diff instead of the runner. main() already returns 2 for its other
    # two "could not run" conditions; this is the third.
    print(
        "python3 cannot import yaml. Provide PyYAML in the runner image rather than "
        "installing it at CI time -- this script gates merges.",
        file=sys.stderr,
    )
    sys.exit(2)

WORKFLOWS = Path(".github/workflows")
SHA_LEN = 40
DIGEST_LEN = 64

# THE ONE REVIEWED EXCEPTION TO THE FIRST-PARTY MAJOR-TAG RULE, SCOPED BY FILENAME.
#
# The full-history secret sweep pins `actions/checkout` to a SHA instead of taking the
# v7 tag, and that is a decision rather than drift. It is the one lane whose whole job
# is to read every commit in the repository and send verified candidates to the
# provider that issued them, so the estate fixes the exact reviewed checkout there
# rather than tracking a tag that can move. scaffold-ci ships the asset that way, and
# audit-ci's contract test asserts BOTH halves: that secret-sweep.yml carries the pin,
# and that the private secret gate does not copy it.
#
# This checker has to know the same thing. Without it, correcting the rule-ordering
# defect (L1) turns the estate's own reviewed decision into a hard failure in every
# repository that carries the sweep -- which is exactly what happened: the fix reported
# 19 repositories as non-conformant, and the "obvious" remedy of removing the pins was
# caught by that contract test on the first pull request.
#
# Scoped to the FILENAME rather than an environment list on purpose. An exception the
# caller can widen is an exception that spreads, and the contract this mirrors is
# itself filename-scoped -- the sweep, and nothing else.
SHA_PIN_EXEMPT_WORKFLOWS = frozenset({"secret-sweep.yml", "secret-sweep.yaml"})

# Triggers that run in the base repo's privileged context. Both have legitimate uses;
# none should land without being argued for, so they are refused here rather than
# reviewed by glob.
PRIVILEGED_TRIGGERS = ("pull_request_target", "workflow_run")

# OPTIONAL NO-CHECKOUT EXEMPTION, off unless the environment sets it.
#
# A workflow that never checks out or executes PR/head code is not the attack shape
# PRIVILEGED_TRIGGERS refuses -- pull_request_target is dangerous specifically because it
# combines a write token with attacker-controlled code, and a workflow that only reads the
# API against the base ref (label operations, a status comment) never does that. Setting
# PRIVILEGED_TRIGGER_NO_CHECKOUT to a space- or comma-separated list of workflow FILENAMES
# (matched by name, e.g. "review-tier.yml") exempts those files' PRIVILEGED_TRIGGERS use --
# but the exemption is enforced, not merely granted: any exempted workflow that also uses
# `actions/checkout` fails regardless, because that combination is exactly the dangerous
# shape again.
#
# Deliberately opt-in and file-scoped rather than a blanket disable, so a new workflow
# cannot inherit the exemption by accident, and the CI-guard copy of this script can still
# stay byte-identical to the shipped asset -- the repo-specific exemption list lives in the
# WORKFLOW that sets the environment variable, never hardcoded in this file.
PRIVILEGED_TRIGGER_NO_CHECKOUT = frozenset(
    entry
    for entry in os.environ.get("PRIVILEGED_TRIGGER_NO_CHECKOUT", "").replace(",", " ").split()
    if entry
)

# OPTIONAL STRICTER MODE, off unless the environment sets it.
#
# The pin check validates the SHAPE of a ref, not that the owner is trusted or that
# the revision is immutable in fact -- a 40-hex branch name passes. Setting
# TRUSTED_THIRD_PARTY_ACTIONS to a space- or comma-separated list of `owner/repo`
# entries additionally requires every third-party action to be named there, so a new
# third-party dependency cannot appear without an explicit edit.
#
# Deliberately opt-in. Defaulting it on with a short list would fail any repo using a
# third-party action not in it, which across this estate is most of them; a gate that
# reddens on adoption gets reverted rather than fixed.
#
# Entries are lowercased, because the refs they are matched against are: GitHub
# resolves owner/repository case-insensitively, so an allowlisted action written with
# different capitalisation must still match its own entry.
TRUSTED_THIRD_PARTY_ACTIONS = frozenset(
    entry.lower()
    for entry in os.environ.get("TRUSTED_THIRD_PARTY_ACTIONS", "").replace(",", " ").split()
    if entry
)


def load(path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_local(path):
    """Parse a local YAML file, or None when it is missing, unparseable, or not a
    mapping. Used on the DELEGATION paths, where a broken file is reported by its own
    scan and re-reporting it from every caller would be noise."""
    if path is None or not Path(path).is_file():
        return None
    try:
        document = load(Path(path))
    except yaml.YAMLError:
        return None
    return document if isinstance(document, dict) else None


def ref_owner(ref):
    """The `owner/repo[/subdir]` part of a ref, LOWERCASED.

    GitHub resolves an action's owner and repository case-insensitively, so
    `Actions/checkout@<40-hex>` runs actions/checkout while a literal `==` against
    "actions/checkout" says it does not. That mis-classification reached two places at
    once: the reference was treated as third-party (and its SHA satisfied the generic
    pin check), and the no-checkout enforcement behind PRIVILEGED_TRIGGER_NO_CHECKOUT
    stopped seeing the checkout it exists to refuse. Comparisons are therefore made
    against this normalised value; the original spelling is kept for diagnostics.
    """
    return ref.split("@", 1)[0].lower()


def local_key(ref):
    """A stable identity for a local `./` ref, for the recursion's visited set."""
    return os.path.normcase(os.path.normpath(ref))


def triggers(document):
    """The event names in `on:`, whatever spelling was used.

    YAML 1.1 reads a bare `on` as the boolean True, so the key must be looked up both
    ways -- `document["on"]` alone silently finds nothing in every workflow that
    writes the key unquoted, i.e. all of them. Both keys present at once is a
    duplicate-key document whose resolution depends on the parser; that is refused
    outright rather than guessed at.
    """
    sections = [value for key in ("on", True) if (value := document.get(key)) is not None]
    if len(sections) > 1:
        raise ValueError(
            'both `on:` and a YAML-1.1 boolean `True:` key are present. Which one '
            "GitHub honours depends on the parser, so one of them could carry a "
            "trigger this check never sees. Use exactly one."
        )
    if not sections:
        return []
    section = sections[0]
    if isinstance(section, str):
        return [section]
    if isinstance(section, list):
        return [event for event in section if isinstance(event, str)]
    if isinstance(section, dict):
        return [event for event in section if isinstance(event, str)]
    return []


def permission_blocks(document):
    """(scope, value) for the workflow-level and every job-level `permissions:`."""
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
    """Every ref that causes code to run: `uses:` values and container images.

    A `container:` or `services:` image runs arbitrary code in the runner's context
    exactly as an action does, so images are pin-checked alongside `uses:` refs. A
    reusable-workflow call carries `uses:` on the JOB rather than on a step.
    """
    refs = []
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        return refs
    for name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):
            refs.append((name, job["uses"]))
        steps = job.get("steps")
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict) and isinstance(step.get("uses"), str):
                    refs.append((name, step["uses"]))
        container = job.get("container")
        if isinstance(container, str):
            refs.append((name, container))
        elif isinstance(container, dict) and isinstance(container.get("image"), str):
            refs.append((name, container["image"]))
        services = job.get("services")
        if isinstance(services, dict):
            for service in services.values():
                if isinstance(service, str):
                    # Shorthand: `services: { db: postgres }` names the image
                    # directly, with no mapping and no `image:` key.
                    refs.append((name, service))
                elif isinstance(service, dict) and isinstance(service.get("image"), str):
                    refs.append((name, service["image"]))
    return refs


def is_pinned(ref):
    """True when the ref names an immutable revision.

    Every form the estate uses is accepted. A sed-based scanner previously kept the
    surrounding quotes in the extracted value, so a correctly pinned
    `uses: "actions/checkout@<40-hex>"` failed the hex test and was reported unpinned;
    parsed values carry no quotes.

    THE REVISION IS LOWERCASED BEFORE THE HEX TESTS. Git object names and OCI digests
    are hex, and hex is case-insensitive: `@ABC...` and `@abc...` name the same commit.
    The scheme was already matched case-insensitively while the digest and SHA tests
    below accepted only lowercase, so an uppercase or mixed-case pin -- as immutable as
    any other -- was reported unpinned. A false failure on a required gate, and the
    kind that looks like a real finding. Found by CodeRabbit on
    fixportal-claude-skills#102.
    """
    if ref.startswith("./"):
        return True  # Local: its manifest's own refs are validated separately.
    if "@" not in ref:
        return False
    revision = ref.rsplit("@", 1)[1].lower()
    if ref.lower().startswith("docker://"):
        algorithm, _, digest = revision.partition(":")
        return algorithm == "sha256" and len(digest) == DIGEST_LEN and all(
            char in "0123456789abcdef" for char in digest
        )
    if revision.startswith("sha256:"):
        # A bare container image pins by digest without the docker:// prefix.
        digest = revision.partition(":")[2]
        return len(digest) == DIGEST_LEN and all(char in "0123456789abcdef" for char in digest)
    return len(revision) == SHA_LEN and all(char in "0123456789abcdef" for char in revision)


def is_reusable_workflow_ref(ref):
    """True when a local `./` ref calls a reusable workflow rather than an action.

    GitHub draws this by shape: a reusable-workflow call names a YAML FILE, an action
    names a DIRECTORY containing action.yml. `action_refs` deliberately collects
    job-level `uses:` for pin checking, so the manifest lookup downstream has to tell
    the two apart or it demands action.yml from a reusable workflow that never has one.
    """
    return ref.lower().endswith((".yml", ".yaml"))


def local_manifest(ref):
    """Path to the action manifest for a local `./` ref, or None when not found.

    A local `uses:` names a directory holding `action.yml`/`action.yaml`; the ref is
    repo-root-relative because workflows run with the checkout as working directory.
    """
    for name in ("action.yml", "action.yaml"):
        candidate = Path(ref) / name
        if candidate.is_file():
            return candidate
    return None


def composite_step_refs(document):
    """`uses:` refs inside a composite action's `runs.steps`.

    Only composite actions have shell-style steps; node and docker actions carry no
    `uses:` of their own and contribute nothing here.
    """
    refs = []
    runs = document.get("runs")
    if isinstance(runs, dict) and runs.get("using") == "composite":
        steps = runs.get("steps")
        if isinstance(steps, list):
            for step in steps:
                if isinstance(step, dict) and isinstance(step.get("uses"), str):
                    refs.append(step["uses"])
    return refs


def workflow_checks_out_code(document):
    """True when this workflow fetches head/PR code, directly or through a local
    composite action -- the property PRIVILEGED_TRIGGER_NO_CHECKOUT's exemption
    requires be absent.

    Checks direct `actions/checkout` `uses:` refs at job/step level, and follows every
    LOCAL (`./`) delegation -- composite actions and reusable workflows alike, to any
    depth -- because a workflow that never calls actions/checkout itself but delegates
    to something that does is exactly as dangerous, and the direct check alone missed
    it. See checks_out_code for the two escapes a single level left open.

    KNOWN GAP, stated so a pass is not mistaken for more than it is: a `run:` step
    that fetches code by shelling out (`git clone`, `curl` a tarball, `gh pr checkout`)
    is not detected. That cannot be closed soundly by a regex over arbitrary shell --
    the same reasoning `permission_blocks` above states for the write-all scope gap.
    A workflow relying on that path to defeat the exemption is not caught here; treat
    PRIVILEGED_TRIGGER_NO_CHECKOUT as reviewed-by-argument (the written rationale each
    exempted workflow must carry), not as a fully mechanical guarantee.
    """
    return checks_out_code(document, set())


def checks_out_code(document, visited):
    """workflow_checks_out_code's recursive body, over one workflow document.

    Local delegation is followed to ANY depth, in both of its forms. A single level
    left two escapes open. A composite chain `workflow -> ./action-a -> ./action-b ->
    actions/checkout` stopped at action-a. And a local REUSABLE WORKFLOW was excluded
    outright, even though `./.github/workflows/_x.yml` runs in the CALLER's context
    with the caller's token -- so a checkout there is a checkout here, and scanning
    `_x.yml` on its own never catches the chain because its only trigger is
    `workflow_call`, which is not privileged.

    `visited` is the cycle guard: local composites and reusable workflows may
    legitimately reference each other, and a self-reference would otherwise recurse
    until the stack ran out.
    """
    for _, ref in action_refs(document):
        if ref_owner(ref) == "actions/checkout":
            return True
        if not ref.startswith("./"):
            continue
        key = local_key(ref)
        if key in visited:
            continue
        visited.add(key)
        if is_reusable_workflow_ref(ref):
            inner = load_local(ref)
            if inner is not None and checks_out_code(inner, visited):
                return True
            continue
        inner = load_local(local_manifest(ref))
        if inner is not None and composite_checks_out_code(inner, visited):
            return True
    return False


def composite_checks_out_code(document, visited):
    """The same question asked of a composite action manifest, recursively."""
    for ref in composite_step_refs(document):
        if ref_owner(ref) == "actions/checkout":
            return True
        if not ref.startswith("./") or is_reusable_workflow_ref(ref):
            continue
        key = local_key(ref)
        if key in visited:
            continue
        visited.add(key)
        inner = load_local(local_manifest(ref))
        if inner is not None and composite_checks_out_code(inner, visited):
            return True
    return False


def check_ref(job, ref, origin, unpinned):
    """One pin check, shared by workflow refs and composite-action refs.

    Returns (failed, unpinned), with `unpinned` incremented for a first-party notice.
    """
    owner = ref_owner(ref)
    third_party = not owner.startswith(("actions/", "./", "docker://"))

    # The allowlist names ACTIONS by `owner/repo`, so it must only gate action refs.
    # `action_refs` also yields container and service IMAGES, which reach here as bare
    # names (`postgres@sha256:...`, `mcr.microsoft.com/mssql/server:2022-latest`) and
    # therefore satisfy `third_party` too. Because the allowlist test runs BEFORE
    # is_pinned, a correctly digest-pinned image was rejected for not appearing in an
    # allowlist it could never legitimately be in.
    #
    # Three tells, and the DIGEST is the load-bearing one. A registry host (dot in the
    # first segment) and a port or tag colon both catch `mcr.microsoft.com/...`, but
    # neither catches a Docker Hub org image like `bitnami/postgresql@sha256:...` --
    # no dot, no colon, and `bitnami/postgresql` is exactly action-shaped. Only images
    # pin with an `@sha256:` digest; an action pins to a bare 40-hex commit. So the
    # digest settles the cases the other two miss.
    revision = ref.split("@", 1)[1] if "@" in ref else ""
    action_shaped = (
        not revision.startswith("sha256:")
        and "/" in owner
        and "." not in owner.split("/", 1)[0]
        and ":" not in owner
    )

    # An action may live in a subdirectory (`owner/repo/subdir/action@<sha>`), but the
    # allowlist names REPOSITORIES. Comparing the full `owner` value against it means a
    # subdirectory action from an already-trusted repo never matches its own entry.
    repository = "/".join(owner.split("/")[:2])

    if (
        TRUSTED_THIRD_PARTY_ACTIONS
        and third_party
        and action_shaped
        and repository not in TRUSTED_THIRD_PARTY_ACTIONS
    ):
        print(
            f"::error file={origin}::Third-party action '{ref}' ({job}) is not in "
            "TRUSTED_THIRD_PARTY_ACTIONS. Add it there with a written rationale, or "
            "use an action already trusted by this repository."
        )
        return True, unpinned

    # actions/* is GitHub's own namespace, and the house standard is the INVERSE of
    # the third-party rule: first-party actions take the major tag, and audit-ci
    # grades a SHA-pinned first-party action as drift. "Take the major tag" is
    # enforced here, not assumed -- a branch ref (actions/checkout@main) or a bare
    # action name is just as mutable as an unpinned third-party tag and can change
    # after review.
    #
    # Evaluated BEFORE the generic is_pinned() return, not after. A 40-hex SHA on a
    # first-party action satisfies is_pinned, so the ordering meant such a ref
    # returned clean without the major-tag rule ever running -- the documented policy
    # was unenforceable in exactly the case it is written about, and the conformance
    # count in the summary under-reported by the same references.
    #
    # Digest-pinned refs are excluded: only a container IMAGE pins with `@sha256:`,
    # and an image that happens to sit under an `actions/` name is not an action the
    # major-tag rule speaks about.
    if owner.startswith("actions/") and not revision.startswith("sha256:"):
        if re.fullmatch(r"v\d+(\.\d+)*", revision):
            # Conformant -- a vN release tag (major or dotted minor/patch). Counted
            # only so the summary shows the split.
            return False, unpinned + 1
        # The sweep's reviewed SHA pin. Deliberately NOT counted as tag-conformant --
        # it is an exception, and a summary that folded it into the conformant total
        # would hide the very thing the exception exists to make explicit.
        if Path(origin).name in SHA_PIN_EXEMPT_WORKFLOWS and is_pinned(ref):
            print(
                f"::notice file={origin}::First-party action '{ref}' ({job}) is "
                "SHA-pinned under the reviewed secret-sweep exception."
            )
            return False, unpinned
        print(
            f"::error file={origin}::First-party action '{ref}' ({job}) is not on "
            "a vN release tag (major, or dotted minor/patch). A branch ref or a "
            "bare action name is mutable and can change after review."
        )
        return True, unpinned

    if is_pinned(ref):
        return False, unpinned

    print(
        f"::error file={origin}::Third-party action or image '{ref}' ({job}) is not "
        "pinned to an immutable revision. A mutable tag can change after review."
    )
    return True, unpinned


def check_local_action(job, ref, origin, unpinned, visited):
    """Pin-check one local composite action's own `uses:` refs, and recursively the
    local composites IT calls. Returns (failed, unpinned).

    A local composite is this repository's own reviewed code, but the actions it calls
    are not -- and they are invisible to a scan that stops at .github/workflows.
    Opening only the composites a workflow names DIRECTLY left the same hole one level
    down: `workflow -> ./action-a -> ./action-b -> third-party/action@v1` was reported
    as fully pinned while action-b's mutable third-party ref was never looked at.

    `visited` carries across the whole run, and its guard sits at ENTRY rather than
    around the recursive call. Guarding only the nested call still let a composite
    referenced by two workflows be scanned twice: every pin error inside it was
    printed twice and the first-party conformance total in the summary counted it
    twice. The pass/fail verdict was unaffected; the report was not.

    THE FLIP SIDE, worth knowing when reading the output: only the FIRST workflow to
    reach a given composite prints diagnostics for it. A later workflow that also uses
    it emits nothing, and that silence means "already scanned", not "not scanned". The
    exit code is unaffected either way, because a failure found on the first visit has
    already set the caller's `failed` flag. Raised by Gitar on
    fixportal-agents-skills#131.
    """
    key = local_key(ref)
    if key in visited:
        return False, unpinned
    visited.add(key)

    failed = False
    manifest = local_manifest(ref)
    if manifest is None:
        print(
            f"::error file={origin}::Local action '{ref}' ({job}) has no "
            "action.yml/action.yaml. The ref cannot resolve at run time."
        )
        return True, unpinned
    try:
        inner = load(manifest)
    except yaml.YAMLError as error:
        print(f"::error file={manifest}::Not parseable as YAML: {error}")
        return True, unpinned
    if not isinstance(inner, dict):
        # Reported, not skipped. Returning clean here made a manifest that parses to a
        # string, a list or nothing pass the gate in silence, while the workflow-side
        # loop calls the identical shape an error -- so the two paths disagreed and a
        # malformed action.yml failed at RUN time instead of at review time. Found by
        # CodeRabbit on fixportal-agents-skills#131.
        print(
            f"::error file={manifest}::Local action '{ref}' ({job}) has a manifest whose "
            "top level is not a mapping, so it declares no runs: and cannot resolve at "
            "run time."
        )
        return True, unpinned

    for inner_ref in composite_step_refs(inner):
        bad, unpinned = check_ref(f"{job} -> {ref}", inner_ref, manifest, unpinned)
        failed = failed or bad
        if not inner_ref.startswith("./") or is_reusable_workflow_ref(inner_ref):
            continue
        bad, unpinned = check_local_action(
            f"{job} -> {ref}", inner_ref, manifest, unpinned, visited
        )
        failed = failed or bad
    return failed, unpinned


def main():
    if not WORKFLOWS.is_dir():
        print(f"::error::{WORKFLOWS} does not exist; the guard cannot assert anything.")
        return 2

    failed = False
    first_party_tag = 0
    scanned = 0
    # Shared across every workflow: a composite reached from two of them is checked
    # once, and a reference cycle terminates.
    local_visited = set()

    paths = sorted(
        path
        for pattern in ("*.yml", "*.yaml")
        for path in WORKFLOWS.glob(pattern)
    )
    for path in paths:
        try:
            document = load(path)
        except yaml.YAMLError as error:
            print(f"::error file={path}::Not parseable as YAML: {error}")
            failed = True
            continue
        if not isinstance(document, dict):
            print(f"::error file={path}::Top level is not a mapping; not a workflow.")
            failed = True
            continue

        scanned += 1

        try:
            events = triggers(document)
        except ValueError as error:
            print(f"::error file={path}::{error}")
            failed = True
            events = []

        exempted = path.name in PRIVILEGED_TRIGGER_NO_CHECKOUT
        uses_checkout = workflow_checks_out_code(document)
        for event in events:
            if event in PRIVILEGED_TRIGGERS:
                if exempted and not uses_checkout:
                    print(
                        f"::notice file={path}::Target-context trigger exempted via "
                        "PRIVILEGED_TRIGGER_NO_CHECKOUT -- this workflow never checks out "
                        "head code."
                    )
                    continue
                if exempted and uses_checkout:
                    print(
                        f"::error file={path}::This workflow is named in "
                        "PRIVILEGED_TRIGGER_NO_CHECKOUT but also uses actions/checkout -- "
                        "that combination is exactly the dangerous shape the exemption "
                        "requires absence of. Remove the checkout, or remove the exemption "
                        "and restructure onto plain pull_request."
                    )
                    failed = True
                    continue
                print(
                    f"::error file={path}::This workflow uses a target-context trigger "
                    "(see the refused event list in this script), which runs in the base "
                    "repository's context with its secrets and a write-scoped token while "
                    "able to reach untrusted head code. Restructure so untrusted code runs "
                    "under the plain pull_request trigger, or name this file in "
                    "PRIVILEGED_TRIGGER_NO_CHECKOUT if it genuinely never checks out head "
                    "code, with a written rationale in the workflow itself."
                )
                failed = True

        # A workflow omitting `permissions:` inherits the org/repo default token, which
        # this script cannot see and which may be broader than anything the write-all
        # check would catch. Not a failure: the default is an org setting, not a diff
        # property. Surfaced so the omission is a decision rather than an oversight.
        if "permissions" not in document:
            print(
                f"::notice file={path}::No workflow-level `permissions:` key; the job token "
                "inherits the org/repo default. Set it explicitly, if only to `contents: read`."
            )

        for scope, value in permission_blocks(document):
            # YAML accepts a quoted or bare `write-all` identically; a parsed value
            # carries no quotes either way, which is why this is a comparison and not
            # a pattern.
            if isinstance(value, str) and value.strip() == "write-all":
                print(
                    f"::error file={path}::A write-all token ({scope}) discards least "
                    "privilege. Declare the specific permissions each job needs."
                )
                failed = True

        for job, ref in action_refs(document):
            bad, first_party_tag = check_ref(job, ref, path, first_party_tag)
            failed = failed or bad

            if not ref.startswith("./"):
                continue
            # A local `./` ref is one of two different things, and only one of them has
            # an action manifest. A reusable WORKFLOW call names a FILE
            # (`./.github/workflows/_deploy.yml`); a composite ACTION names a DIRECTORY
            # holding action.yml. Demanding a manifest from the first is a false
            # failure -- and because `Review policy intact` is a required check, it
            # makes every repo using a reusable deploy workflow unmergeable. The
            # extension is the distinction GitHub itself draws, so it is what we test.
            if is_reusable_workflow_ref(ref):
                if not Path(ref).is_file():
                    print(
                        f"::error file={path}::Reusable workflow '{ref}' ({job}) does not "
                        "exist. The ref cannot resolve at run time."
                    )
                    failed = True
                continue
            bad, first_party_tag = check_local_action(
                job, ref, path, first_party_tag, local_visited
            )
            failed = failed or bad

    if failed:
        return 1

    if not scanned:
        print(f"::error::No workflow files found under {WORKFLOWS}; nothing was asserted.")
        return 2

    mode = (
        f", third-party allowlist enforced ({len(TRUSTED_THIRD_PARTY_ACTIONS)} entries)"
        if TRUSTED_THIRD_PARTY_ACTIONS
        else ""
    )
    mode += (
        f", {len(PRIVILEGED_TRIGGER_NO_CHECKOUT)} workflow(s) exempted from the "
        "target-context trigger refusal"
        if PRIVILEGED_TRIGGER_NO_CHECKOUT
        else ""
    )
    print(
        f"Workflow hygiene: {scanned} workflow(s) scanned -- no target-context trigger, "
        f"no write-all token, every third-party action and container image pinned "
        f"({first_party_tag} first-party ref(s) on a vN release tag, conformant){mode}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
