![CI](https://github.com/FixPortal/fixportal-workflows/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/github/license/FixPortal/fixportal-workflows)

# fixportal-workflows

> Shared reusable GitHub Actions workflows for the FixPortal estate, consumed by
> other repositories via `uses:` refs. A change under `.github/workflows/` is a
> **release to every consumer**, not this repo's own CI — treat the workflow
> inputs and defaults as a published contract.

## Quick start

Add a coverage job to a .NET repository by calling the reusable workflow:

```yaml
jobs:
  coverage:
    uses: FixPortal/fixportal-workflows/.github/workflows/dotnet-coverage.yml@main
    with:
      solution: YourSolution.slnx
    secrets: inherit
```

That is the complete minimal call — every other input has a safe default. The
job restores, tests under Microsoft's `dotnet-coverage` engine, renders a
ReportGenerator report, appends a coverage summary to the run, and uploads the
report as an artifact.

A full usage example exercising every input lives in
[`tests/representative-caller.yml`](tests/representative-caller.yml) and is
linted by CI, so it cannot drift from the real contract.

## `dotnet-coverage.yml` contract

Runs `dotnet test` under the `dotnet-coverage` collector (Cobertura output),
generates an HTML/Markdown/Cobertura report, and uploads it as an artifact.

| Input | Required | Default | Description |
|---|---|---|---|
| `solution` | yes | — | Path to the `.slnx`/`.sln` to restore and test |
| `dotnet-version` | no | `10.0.x` | .NET SDK version for `actions/setup-dotnet` |
| `configuration` | no | `Release` | Build configuration passed to `dotnet test` |
| `runs-on` | no | `blacksmith-4vcpu-ubuntu-2404` | Runner label. Callers passing a Blacksmith label must carry their own actionlint allowlist for that label |
| `test-filter` | no | `''` | Optional `dotnet test --filter` expression (e.g. to exclude infra-dependent integration tests) |
| `assembly-filters` | no | `+FixPortal.*;-*.Tests` | ReportGenerator assembly filter — scope the report to the caller's own assemblies |
| `dotnet-coverage-version` | no | `18.9.0` | Pinned `dotnet-coverage` global-tool version; bump deliberately after validating a new release |
| `artifact-name` | no | `coverage-report` | Uploaded artifact name — override when calling the workflow more than once in a single run |

### Private NuGet feed callers

The workflow exports `GITHUB_PACKAGES_TOKEN` (from `secrets.GITHUB_TOKEN`, with
`packages: read`) for the caller's restore. Callers consuming `FixPortal.*`
packages map a private GitHub Packages source in their own `nuget.config` with
`ClearTextPassword=%GITHUB_PACKAGES_TOKEN%`; `secrets: inherit` on the call is
what carries that through.

## Review-policy guard

`.github/workflows/review-policy-guard.yml` asserts on every push and PR that
`.claude/review-policy.json` — the file that decides which AI reviewers a PR
needs — stays tracked and unignored. One `.gitignore` line re-excluding
`.claude/` would silently drop every PR in the repo to the lightest review
tier; the guard fails the run instead. Do not remove it without putting
`.gitignore` back in the policy's `high` list.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Coverage job red on `dotnet restore` for `FixPortal.*` packages | Caller is missing `secrets: inherit`, or its `nuget.config` does not map the private feed to `%GITHUB_PACKAGES_TOKEN%` |
| `upload-artifact` fails on a duplicate name | The workflow was called more than once in one run — set a distinct `artifact-name` per call |
| Report shows third-party or test assemblies | `assembly-filters` left at the FixPortal default — override it for differently-named assemblies |
| Tests fail only under coverage with `InvalidProgramException` | A caller reintroduced coverlet's XPlat collector — this workflow uses Microsoft's `dotnet-coverage` engine precisely because coverlet emits invalid IL on .NET 10 |
| Coverage job's actionlint step flags the caller's workflows | The caller's own `.github/workflows` fails actionlint — the step lints the calling repo's checkout, by design |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: workflows here are a
public interface, so never change an input name or default without a plan for
consumers, validate with actionlint before pushing, and PRs merge via rebase.

## Appendix

- Reusable workflow: `FixPortal/fixportal-workflows/.github/workflows/dotnet-coverage.yml`
- Representative caller (all inputs): `tests/representative-caller.yml`
- Local validation: `actionlint .github/workflows/*.yml tests/*.yml`
- Licence: [Apache-2.0](LICENSE) — see [NOTICE](NOTICE)
