# Contributing

Thanks for your interest in improving this project. It is maintained on a
best-effort basis; issues and pull requests are welcome.

## Ground rules

- Be civil. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- By contributing, you agree your contributions are licensed under the
  [Apache License 2.0](LICENSE), the same licence as the project.
- Open an issue before a large change so we can agree the approach before you
  invest the time.

## The one rule that matters here

The workflows in this repo are a **public interface**: other repositories call
them by ref (`uses: FixPortal/fixportal-workflows/.github/workflows/...@<ref>`).
A change under `.github/workflows/` is not this repo's CI — it is a release to
every consumer. Treat inputs, outputs, secrets handling, and default behaviour
as a published contract:

- Never rename or remove an input, or change a default, without a major-ref
  bump plan communicated to consumers.
- New inputs must be optional with a safe default, so existing callers keep
  working unchanged.
- Keep third-party actions pinned to a full commit SHA.

## Getting set up

Prerequisites: **git** and a GitHub account. There is no application code and
no build toolchain — the repo's product is its workflows.

```bash
git clone https://github.com/FixPortal/fixportal-workflows.git
cd fixportal-workflows
```

## Before you open a PR

Validate every workflow the same way CI does — with actionlint:

```bash
actionlint .github/workflows/*.yml
```

CI runs exactly this via the `Reusable workflow contract` job, so a locally
clean run means a green check.

## Branches and commits

- Branch from `main` using `feat/<scope>`, `fix/<scope>`, or `chore/<scope>`.
- Write clear, present-tense commit subjects (conventional commits).
- PRs merge via **rebase** — no merge commits, no squash. Keep your branch
  rebased on `main`.

## What makes a good PR

- One focused change per PR.
- The interface-contract rule above honoured, with any consumer-visible change
  called out explicitly in the PR description.
- A reusable workflow added or changed comes with a representative caller under
  `tests/`, so the usage example stays true.
