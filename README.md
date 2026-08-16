# fixportal-workflows

![CI](https://github.com/FixPortal/fixportal-workflows/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/github/license/FixPortal/fixportal-workflows)

> Shared GitHub Actions workflow home for the FixPortal estate. Anything added
> back under `.github/workflows/` as a reusable workflow is a **release to every
> consumer**, not this repo's own CI — treat its inputs and defaults as a
> published contract.

## Current contents

This repo publishes no reusable workflow at present. `dotnet-coverage.yml` was
removed once the estate moved to Microsoft.Testing.Platform: it wrapped
`dotnet test` with VSTest-only arguments (a positional solution path,
`--blame-hang-timeout`, `--blame-hang-dump-type`, and a VSTest `--filter`
expression), none of which exist under MTP, and it had no caller anywhere in the
org. Recover it from git history if it is ever wanted back.

For a coverage lane under MTP, prefer the platform's own extension —
`Microsoft.Testing.Extensions.CodeCoverage` with
`--coverage --coverage-output-format cobertura`. That is the same Microsoft
engine the removed workflow shelled out to, without the global-tool install or
the wrapper process. Note the reason the engine matters: coverlet's XPlat
collector emits invalid IL on .NET 10 for some methods, so the JIT throws
`InvalidProgramException` and tests fail only under instrumentation.

## Review-policy guard

`.github/workflows/review-policy-guard.yml` asserts on every push and PR that
`.claude/review-policy.json` — the file that decides which AI reviewers a PR
needs — stays tracked and unignored. One `.gitignore` line re-excluding
`.claude/` would silently drop every PR in the repo to the lightest review
tier; the guard fails the run instead. Do not remove it without putting
`.gitignore` back in the policy's `high` list.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: workflows here are a
public interface, so never change an input name or default without a plan for
consumers, validate with actionlint before pushing, and PRs merge via rebase.

## Appendix

- Local validation: `actionlint .github/workflows/*.yml`
- Licence: [Apache-2.0](LICENSE) — see [NOTICE](NOTICE)
