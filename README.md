# Release/settings skill trial: minimal

This public test repository uses one self-contained GitHub CI workflow for read-only settings monitoring and actual Python Semantic Release through Octo STS. Runtime comparison code is inline in `.github/workflows/ci.yml`; no repository helper scripts are required.

The default release branch is `main`. Releases require the real Settings Audit, and the active branch ruleset grants release bypass only to the verified Octo STS GitHub App. CODEOWNERS names the verified repository owner; independent owner-review enforcement is intentionally outside this sole-owner trial.

## Live release flow proof

This feature commit starts the first semantic-release proof. The expected release will be derived from existing configuration and Conventional Commit history, not forced or manually tagged. A later follow-up commit will verify the next semantic bump and ancestry.

## Follow-up semantic proof

The first actual release was [v0.1.0](https://github.com/ryderstorm/release-settings-trial-minimal-20261008/releases/tag/v0.1.0) at release commit `7f646b9bd96816dba62f8fcc580c7da2df55e0eb`. This fix corrects the trial documentation with its observed first-release evidence. This Conventional Commit is expected to produce `v0.1.1` through the same checked PR and Octo STS pipeline; no version override or manual tag is used.
