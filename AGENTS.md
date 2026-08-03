# AGENTS.md

Repo-specific conventions for agent work. Global rules live in the user-level
config and are not repeated here.

## The workflows are a public interface

This repo's product is its reusable GitHub Actions workflows — other
repositories call them by ref
(`uses: FixPortal/fixportal-workflows/.github/workflows/...@<ref>`). A change
under `.github/workflows/` is a **release to every consumer**, not this repo's
own CI:

- Never rename or remove a workflow input, or change a default, without an
  explicit consumer-migration plan. New inputs must be optional with a safe
  default so existing callers keep working unchanged.
- `dotnet-coverage.yml` runs in the **caller's** checkout. Steps added to it
  execute against the caller's repository, runner, and secrets scope — weigh
  that before adding anything.
- Keep third-party actions pinned to a full commit SHA.

## Review-policy guard invariant

`.claude/review-policy.json` must stay tracked and unignored — that file tiers
every PR's reviewers, and losing it silently drops the whole repo to NORMAL.
`.github/workflows/review-policy-guard.yml` asserts the invariant on every push
and PR; never remove the guard without putting `.gitignore` back in the
policy's `high` list.

## No build/test toolchain

This is a docs-class repo with no application code. Validation is:

- `actionlint .github/workflows/*.yml tests/*.yml` (what CI runs), and
- `git add --dry-run .claude/review-policy.json` must succeed.

Keep `tests/representative-caller.yml` in sync with the `dotnet-coverage.yml`
contract — CI lints it, so it is the usage example that cannot drift.
