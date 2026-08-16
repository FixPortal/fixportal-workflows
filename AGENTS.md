# AGENTS.md

Repo-specific conventions for agent work. Global rules live in the user-level
config and are not repeated here.

## Reusable workflows are a public interface

This repo exists to host reusable GitHub Actions workflows that other
repositories call by ref
(`uses: FixPortal/fixportal-workflows/.github/workflows/...@<ref>`). None are
published right now — `dotnet-coverage.yml` was removed when the estate moved
to Microsoft.Testing.Platform, which invalidated its VSTest-only `dotnet test`
arguments, and it had no caller. If one is added back:

- Never rename or remove a workflow input, or change a default, without an
  explicit consumer-migration plan. New inputs must be optional with a safe
  default so existing callers keep working unchanged.
- A reusable workflow runs in the **caller's** checkout. Steps added to it
  execute against the caller's repository, runner, and secrets scope — weigh
  that before adding anything.
- Keep third-party actions pinned to a full commit SHA.
- Add a representative caller under `tests/` and lint it in CI, so the
  documented usage cannot drift from the real contract.

## Review-policy guard invariant

`.claude/review-policy.json` must stay tracked and unignored — that file tiers
every PR's reviewers, and losing it silently drops the whole repo to NORMAL.
`.github/workflows/review-policy-guard.yml` asserts the invariant on every push
and PR; never remove the guard without putting `.gitignore` back in the
policy's `high` list.

## No build/test toolchain

This is a docs-class repo with no application code. Validation is:

- `actionlint .github/workflows/*.yml` (what CI runs), and
- `git add --dry-run .claude/review-policy.json` must succeed.
