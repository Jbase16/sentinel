# Sentinel local security gate

This repository has no GitHub Actions workflows. Pushes and pull requests do
not start an automated security or test pipeline, and GitHub does not enforce
these checks as merge requirements. The operator runs them locally and reviews
their actual results before deciding whether to land a change.

Run `scripts/local-security-check.sh` from any directory. It checks Python under
`core/`, `scripts/`, `tools/`, and `sentinelforge/` for forbidden call patterns,
potential hardcoded secrets, syntax errors, Bandit findings, and Ruff findings.
The script fails when a new finding appears or a required scanner is missing or
cannot run. It requires Python 3, Bandit, and Ruff; the project's `dev` extra
declares the latter two.

The source-pattern baseline and lint baseline are recorded in
`scripts/security-check-baseline.txt` and `scripts/security-lint-baseline.json`.
They retain previously known findings so that new findings block without
silently rewriting unrelated code. The baseline is outstanding review debt,
not a claim that those findings are safe. At this change, the lint baseline
records 24 Bandit and 278 Ruff findings; review any baseline update explicitly.

The only configured pre-commit hook is the schema-drift check in
`.pre-commit-config.yaml`. It does not run the security script or the test suite.
For test commands, see [RUN_WORKFLOWS.md](RUN_WORKFLOWS.md).
