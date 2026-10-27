# Usage

Only one reusable workflow can be called today: the legacy `dotnet-coverage`,
available at tags `v1` and `v1.0.0` and not on `main`. See
[reference.md](reference.md) for its full contract.

## Caller example: dotnet-coverage at `v1`

Uses only inputs listed in the reference. Replace `<your-org>` and the solution
path.

```yaml
name: Coverage
on:
  pull_request:

permissions:
  contents: read
  packages: read

jobs:
  coverage:
    uses: <your-org>/fixportal-workflows/.github/workflows/dotnet-coverage.yml@v1
    with:
      solution: YourSolution.slnx
      runs-on: ubuntu-latest
      assembly-filters: '+YourCompany.*;-*.Tests'
      test-filter: ''
      artifact-name: coverage-report
```

Why these settings:

- `runs-on: ubuntu-latest` overrides a default that is a third-party runner
  label (`v1:.github/workflows/dotnet-coverage.yml:18-21`).
- `assembly-filters` overrides a default aimed at one naming convention
  (`...dotnet-coverage.yml:27-35`).
- The caller grants `contents: read` and `packages: read` because the workflow
  declares those (`...dotnet-coverage.yml:53-55`). UNVERIFIED: that a caller
  must grant at least these. Refuted if the call succeeds with fewer.

UNVERIFIED: that this example runs successfully. It was not executed. Refuted by
a green run.

The workflow is not supported for Microsoft.Testing.Platform projects
(`README.md:13-18`). The README recommends the platform's own
`Microsoft.Testing.Extensions.CodeCoverage` with
`--coverage --coverage-output-format cobertura` instead (`README.md:20-22`).

## Reference form and pinning, as the repository states it

```yaml
uses: <your-org>/fixportal-workflows/.github/workflows/<file>.yml@<ref>
```

(`CONTRIBUTING.md:16-17`, `AGENTS.md:8-10`.) The repository states these rules
and no others:

- Inputs are never renamed or removed, and defaults never changed, without a
  major-ref bump plan communicated to consumers (`CONTRIBUTING.md:22-23`).
- New inputs are optional with a safe default (`CONTRIBUTING.md:24-25`).
- Third-party actions inside workflows are pinned to a full commit SHA
  (`CONTRIBUTING.md:26`).
- A reusable workflow runs in the caller's checkout, runner and secrets scope
  (`AGENTS.md:18-20`). Read its steps before calling it.

Refs observed on 2026-10-27 with `git ls-remote --tags`: `v1` and `v1.0.0`, both
at commit `3d7f6611767f8202ea14087f7d8b77875544cb3b`. The repository does not
state which ref a caller should use or whether `v1` is a moving major tag.
UNVERIFIED: that `v1` will not move. Refuted by a future change to the tag.
A caller wanting an immutable reference can use the full commit SHA instead of a
tag; that is general GitHub behaviour, not a rule stated by this repository.

Do not call the workflows listed as internal in [reference.md](reference.md).
