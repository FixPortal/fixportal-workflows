# fixportal-workflows documentation

Last checked on 2026-10-27 against `main` at commit `9ee709b` and tags `v1` and
`v1.0.0` (both resolve to commit `3d7f661`).

## What this repository is

A public repository intended to host shared, reusable GitHub Actions workflows
that other repositories call by ref, in the form
`uses: <your-org>/fixportal-workflows/.github/workflows/<file>.yml@<ref>`
(`CONTRIBUTING.md:16-17`).

## Current state

- On `main`, no workflow declares `on: workflow_call`. The only occurrence of the
  string in `.github/workflows/` is a comment at `.github/workflows/ci.yml:57`.
  The four workflow files on `main` are this repository's own automation. See
  [reference.md](reference.md).
- `README.md:13` and `AGENTS.md:10-12` both say no reusable workflow is
  published. The one that existed, `dotnet-coverage.yml`, was removed from `main`
  in commit `28ca3e1` because it used VSTest-only arguments and had no caller
  (`README.md:13-18`).
- The tags `v1` and `v1.0.0` still contain that workflow
  (`git ls-tree -r --name-only v1 .github/workflows` lists only
  `dotnet-coverage.yml`). A caller pinned to `@v1` therefore still resolves it.
  It is documented in [reference.md](reference.md) as a legacy workflow.

New callers should not adopt it; see [usage.md](usage.md).

## Who can call a workflow here

The repository is public, and its description says its workflows are callable by
public and private repositories.

UNVERIFIED: whether a private repository can call a workflow in this public
repository depends on GitHub settings for the calling and called repositories.
Refuted if GitHub's documentation or a test call from a private repository shows
otherwise.

## Support stance

- Maintained on a best-effort basis (`CONTRIBUTING.md:3-4`, `SECURITY.md:16-19`).
- No new features are planned by the owner. This is the owner's stated position
  for this documentation; it is not stated in the other repository files.
- Dependabot configuration is present (`.github/dependabot.yml`) and the repo's
  own CI is in place.
- Only the latest state of `main` is supported; there are no long-term-support
  branches (`SECURITY.md:23-24`).
- Report vulnerabilities privately, as described in `SECURITY.md:5-14`.

## Contents of this directory

- [reference.md](reference.md): the legacy reusable workflow (inputs, permissions,
  jobs) and the internal workflows that must not be called.
- [usage.md](usage.md): a caller example and the ref and pinning rules.

Other repository documents: [README](../README.md),
[CONTRIBUTING](../CONTRIBUTING.md), [SECURITY](../SECURITY.md),
[AGENTS](../AGENTS.md).
