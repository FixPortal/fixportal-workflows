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
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit(
        "python3 cannot import yaml. Provide PyYAML in the runner image rather than "
        "installing it at CI time -- this script gates merges."
    )

WORKFLOWS = Path(".github/workflows")
SHA_LEN = 40
DIGEST_LEN = 64

# Triggers that run in the base repo's privileged context. Both have legitimate uses;
# none should land without being argued for, so they are refused here rather than
# reviewed by glob.
PRIVILEGED_TRIGGERS = ("pull_request_target", "workflow_run")

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
TRUSTED_THIRD_PARTY_ACTIONS = frozenset(
    entry
    for entry in os.environ.get("TRUSTED_THIRD_PARTY_ACTIONS", "").replace(",", " ").split()
    if entry
)


def load(path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


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
    """
    if ref.startswith("./"):
        return True  # Local: its manifest's own refs are validated separately.
    if "@" not in ref:
        return False
    revision = ref.rsplit("@", 1)[1]
    if ref.startswith("docker://"):
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


def check_ref(job, ref, origin, unpinned):
    """One pin check, shared by workflow refs and composite-action refs.

    Returns (failed, unpinned), with `unpinned` incremented for a first-party notice.
    """
    owner = ref.split("@", 1)[0]
    third_party = not ref.startswith(("actions/", "./", "docker://"))

    if TRUSTED_THIRD_PARTY_ACTIONS and third_party and owner not in TRUSTED_THIRD_PARTY_ACTIONS:
        print(
            f"::error file={origin}::Third-party action '{ref}' ({job}) is not in "
            "TRUSTED_THIRD_PARTY_ACTIONS. Add it there with a written rationale, or "
            "use an action already trusted by this repository."
        )
        return True, unpinned

    if is_pinned(ref):
        return False, unpinned

    # actions/* is GitHub's own namespace, and a mutable tag there means trusting
    # GitHub -- which every workflow already does by running on their runners. A
    # third-party mutable tag means trusting that owner forever, with no re-review
    # when they move it. Only the second is gated. Measured 2026-08-19 across 28
    # estate repos: 319 unpinned refs, every one sampled `actions/*` -- a hard gate on
    # all owners would have failed 27 of 28 repos on their next PR.
    if ref.startswith("actions/"):
        print(
            f"::notice file={origin}::'{ref}' ({job}) is not SHA-pinned. First-party "
            "(GitHub) action, so not failed -- pin it when convenient."
        )
        return False, unpinned + 1

    print(
        f"::error file={origin}::Third-party action or image '{ref}' ({job}) is not "
        "pinned to an immutable revision. A mutable tag can change after review."
    )
    return True, unpinned


def main():
    if not WORKFLOWS.is_dir():
        print(f"::error::{WORKFLOWS} does not exist; the guard cannot assert anything.")
        return 2

    failed = False
    unpinned_first_party = 0
    scanned = 0

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

        for event in events:
            if event in PRIVILEGED_TRIGGERS:
                print(
                    f"::error file={path}::This workflow uses a target-context trigger "
                    "(see the refused event list in this script), which runs in the base "
                    "repository's context with its secrets and a write-scoped token while "
                    "able to reach untrusted head code. Restructure so untrusted code runs "
                    "under the plain pull_request trigger, or remove this assertion "
                    "deliberately with a written rationale."
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
            bad, unpinned_first_party = check_ref(job, ref, path, unpinned_first_party)
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
            manifest = local_manifest(ref)
            if manifest is None:
                print(
                    f"::error file={path}::Local action '{ref}' ({job}) has no "
                    "action.yml/action.yaml. The ref cannot resolve at run time."
                )
                failed = True
                continue
            try:
                inner = load(manifest)
            except yaml.YAMLError as error:
                print(f"::error file={manifest}::Not parseable as YAML: {error}")
                failed = True
                continue
            if not isinstance(inner, dict):
                continue
            # A local composite action is this repository's own reviewed code, but the
            # actions IT calls are not -- and they are invisible to a scan that stops
            # at .github/workflows.
            for inner_ref in composite_step_refs(inner):
                bad, unpinned_first_party = check_ref(
                    f"{job} -> {ref}", inner_ref, manifest, unpinned_first_party
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
    print(
        f"Workflow hygiene: {scanned} workflow(s) scanned -- no target-context trigger, "
        f"no write-all token, every third-party action and container image pinned "
        f"({unpinned_first_party} first-party ref(s) unpinned, not gated){mode}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
