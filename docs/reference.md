# Workflow reference

Observed on 2026-10-27. Two sources:

- `main` at commit `9ee709b`, directory `.github/workflows/` (four files).
- Tags `v1` and `v1.0.0` (commit `3d7f661`), which contain a single file,
  `.github/workflows/dotnet-coverage.yml`. Cites of the form `v1:<path>:<line>`
  mean `git show v1:<path>`.

## Reusable workflows (`on: workflow_call`)

### `dotnet-coverage` (legacy; present at tag `v1` only, removed from `main`)

Source: `v1:.github/workflows/dotnet-coverage.yml`. Removed from `main` in commit
`28ca3e1` (`README.md:13-18`). Not supported for Microsoft.Testing.Platform
projects; see [usage.md](usage.md).

Purpose: restore a .NET solution, run `dotnet test` under the `dotnet-coverage`
global tool, produce a Cobertura report and an HTML/Markdown report, add a
summary to the job summary, and upload the report as an artifact
(`v1:.github/workflows/dotnet-coverage.yml:97-149`).

Inputs (`v1:.github/workflows/dotnet-coverage.yml:3-51`; all type `string`):

| Name | Required | Default | Line |
|---|---|---|---|
| `solution` | yes | none | 6 |
| `dotnet-version` | no | `10.0.x` | 10 |
| `configuration` | no | `Release` | 14 |
| `runs-on` | no | `blacksmith-4vcpu-ubuntu-2404` | 18 |
| `test-filter` | no | empty string | 22 |
| `assembly-filters` | no | `+FixPortal.*;-*.Tests` | 27 |
| `dotnet-coverage-version` | no | `18.9.0` | 36 |
| `artifact-name` | no | `coverage-report` | 44 |

Notes from the file's own descriptions:

- `solution` is the path to the `.slnx` or `.sln` file (line 7).
- `test-filter` is an optional `dotnet test --filter` expression (line 23).
- `assembly-filters` is the ReportGenerator assembly filter. The default targets
  an assembly naming convention (`FixPortal.*`) and excludes test assemblies;
  override it for differently named assemblies (lines 28-33).
- `artifact-name` should be overridden when the workflow is called more than once
  in one run, because upload-artifact fails on a duplicate name (lines 45-49).
- The default `runs-on` is a third-party runner label. UNVERIFIED: that it
  resolves outside the owner's organisation. Refuted if a run in another
  organisation with the default succeeds. Pass your own `runs-on` (for example
  `ubuntu-latest`).

Secrets: none declared (no `secrets:` block under `workflow_call`, lines 3-51).
The job reads `secrets.GITHUB_TOKEN`, the caller's token, and exposes it as the
environment variable `GITHUB_PACKAGES_TOKEN` for a caller's own `nuget.config`
during restore (line 70, comment at lines 66-69).

Outputs: none declared (no `outputs:` block, lines 3-51). The job uploads an
artifact named by `artifact-name` (line 145 onward).

Permissions: workflow level `contents: read` and `packages: read` (lines 53-55).

Jobs: one job, `coverage` (line 58), running on `${{ inputs.runs-on }}` with
`shell: bash` forced (lines 59-64). Steps:

1. checkout (line 78)
2. `actions/setup-dotnet` (line 82)
3. Cache NuGet packages (line 89)
4. Restore (line 97)
5. Install dotnet-coverage (line 100)
6. Test with coverage (line 109)
7. Generate coverage report, only if a Cobertura file exists (line 123)
8. Add coverage summary (line 136)
9. Upload coverage report, only if a Cobertura file exists (line 145)

UNVERIFIED: runtime behaviour beyond what the YAML states (for example that it
passes under Microsoft.Testing.Platform). The README states it does not
(`README.md:13-16`). Refuted by a successful run on an MTP project.

## Internal workflows on `main` (do NOT call these)

None of the four declares `workflow_call`; they run on this repository's own
events. UNVERIFIED: the exact error GitHub reports if another repository
references one. Refuted if a test call shows it.

### `ci.yml` (name: `CI`)

- Triggers: push to `main` and `v*` tags, pull requests to `main`, manual
  dispatch (`.github/workflows/ci.yml:3-12`).
- Inputs, secrets, outputs: none declared.
- Permissions: workflow `contents: read` (`ci.yml:18-19`); job `gate-coverage`
  `contents: read` (`ci.yml:43-44`); job `ci-gate` `permissions: {}`
  (`ci.yml:85`).
- Jobs: `workflows` ("Reusable workflow contract": actionlint with shellcheck,
  `ci.yml:22-37`); `gate-coverage` ("Gate coverage": runs
  `.github/scripts/assert_gate_coverage.py` and
  `.github/scripts/assert_canonical_assets.py`, `ci.yml:39-68`); `ci-gate`
  ("CI Gate": fails if either job failed or was cancelled, `ci.yml:79-93`).

### `review-policy-guard.yml` (name: `Review policy guard`)

- Triggers: push and pull requests to `main`
  (`review-policy-guard.yml:42-46`).
- Inputs, secrets, outputs: none declared.
- Permissions: `contents: read` (`review-policy-guard.yml:48-49`).
- Jobs: `guard` ("Review policy intact", `:56-61`) with steps at `:69` (policy
  file tracked, unignored and usable), `:117` (policy-controlled paths remain
  HIGH) and `:211` (workflow hygiene: no target-context trigger, no write-all,
  actions pinned). The job display name is load-bearing for branch protection
  (`:57-60`).

### `review-tier.yml` (name: `Review tier`)

- Triggers: `pull_request_target`, types `opened`, `reopened`, `synchronize`,
  `edited`, branch `main` (`review-tier.yml:42-45`).
- Inputs, secrets, outputs: none declared.
- Permissions: `contents: read`, `issues: write`, `pull-requests: write`
  (`review-tier.yml:47-50`).
- Jobs: `tier` ("Apply review tier label", `:58-66`), one step that classifies
  changed paths and sets the `review-high` label (`:70`). The header says the
  policy is read from the PR base ref and that PR code is never checked out
  (`:13-32`).

### `ai-smells.yml` (name: `AI smells`)

- Triggers: `pull_request` (`ai-smells.yml:6-7`).
- Inputs, secrets, outputs: none declared.
- Permissions: workflow `contents: read`; job adds `pull-requests: write`
  (`ai-smells.yml:9-10`, `:23-25`).
- Jobs: `ai-smells`, skipped for fork PRs and for `dependabot[bot]` and
  `renovate[bot]` authors (`:20`). Steps: checkout of the PR head, install
  `semgrep==1.163.0`, run `.github/ai-smells/pr-detect.ps1`, run
  `.github/ai-smells/post-smell-threads.ps1` (`:27-53`). The header says it is
  never a required check (`:3-5`).

## Gap

`CONTRIBUTING.md:61-62` and `AGENTS.md:22-23` ask for a representative caller
under `tests/`. No `tests/` directory exists on `main` at the checked commit.
