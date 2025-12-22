# GitHub Actions Setup Complete ✅

Your security-first CI pipeline is now fully configured. Here's what you have and how to use it.

---

## What Was Built

### 6 GitHub Actions Workflows

1. **ci.yml** - Enhanced main CI with security gate (blocks shell=True before tests run)
2. **security-scan.yml** - Static analysis: Bandit, Semgrep, forbidden patterns, CVE scanning
3. **sentinel-health.yml** - Behavioral tests: fail-closed, state machines, sandboxing
4. **adversarial-ci.yml** - Sentinel attacks itself (manual trigger or red-team branches)
5. **fast-ci.yml** - Quick feedback for feature branches (unit tests only)
6. **experimental-ci.yml** - Non-blocking checks for experiment branches

### Supporting Files

- `.bandit` - Bandit security scanner configuration
- `.semgrepignore` - Semgrep exclusions
- `.github/workflows/README.md` - Complete workflow documentation
- `.github/RUN_WORKFLOWS.md` - How to trigger workflows
- `.github/SECURITY_CI_OVERVIEW.md` - Architecture overview
- `scripts/local-security-check.sh` - Run security checks locally before pushing

---

## Quick Start

### 1. Test the Setup

Run the local security check to verify everything works:

```bash
./scripts/local-security-check.sh
```

This will check for:
- shell=True (command injection)
- eval()/exec() (code injection)
- os.system() (unsafe subprocess)
- Hardcoded secrets
- Python syntax errors

### 2. Push to Feature Branch

Create a feature branch and push to trigger fast CI:

```bash
git checkout -b feature/test-ci-setup
git add .
git commit -m "Add security-first CI pipeline"
git push origin feature/test-ci-setup
```

This triggers: **fast-ci.yml** (quick security checks + unit tests)

### 3. Create Pull Request

Create a PR to main to trigger full security suite:

```bash
gh pr create --base main --title "Add security-first CI pipeline" --body "Implements security gates, behavioral tests, and adversarial testing"
```

This triggers:
- **ci.yml** (security gate + full tests + lint)
- **security-scan.yml** (Bandit, Semgrep, CVE scanning)
- **sentinel-health.yml** (behavioral verification)

### 4. Run Adversarial Testing

Trigger the adversarial workflow to see Sentinel attack itself:

```bash
gh workflow run adversarial-ci.yml -f attack_intensity=medium
```

Then watch it run:

```bash
gh run watch
```

Download the attack surface map:

```bash
gh run download --name attack-surface-map
cat attack-surface.json | jq
```

---

## What Gets Blocked

The security gate (in ci.yml) will **block merges** if it finds:

❌ `shell=True` in subprocess calls (command injection)
❌ `eval()` or `exec()` (code injection)
❌ `os.system()` (unsafe subprocess)
❌ Bandit HIGH/CRITICAL findings
❌ Ruff lint errors (now blocking, not --exit-zero)
❌ mypy type errors (now blocking)
❌ Test failures
❌ Behavioral test failures (fail-closed, state machine)

---

## Workflow Triggers

| Branch Pattern | Workflow | What Runs |
|----------------|----------|-----------|
| `main`, `develop` | ci.yml, security-scan.yml, sentinel-health.yml | Full security suite |
| `feature/**` | fast-ci.yml | Quick checks (unit tests only) |
| `bugfix/**` | fast-ci.yml | Quick checks |
| `hotfix/**` | fast-ci.yml | Quick checks |
| `experiment/**` | experimental-ci.yml | Non-blocking informational |
| `spike/**` | experimental-ci.yml | Non-blocking informational |
| `poc/**` | experimental-ci.yml | Non-blocking informational |
| `red-team/**` | adversarial-ci.yml | Self-attack suite |
| Manual | adversarial-ci.yml | Self-attack suite |

---

## Recommended GitHub Settings

### Branch Protection Rules (Required)

Set these on the `main` branch:

1. Go to: **Settings > Branches > Add rule**
2. Branch name pattern: `main`
3. Enable:
   - ✅ **Require status checks to pass before merging**
   - ✅ **Require branches to be up to date before merging**
   - Select required status checks:
     - `Security Gate`
     - `Python Tests`
     - `Python Lint (BLOCKING)`
     - `Security Scan Summary`
     - `Sentinel Health Summary`
   - ✅ **Require pull request reviews before merging** (1 approval)
   - ✅ **Dismiss stale pull request approvals when new commits are pushed**
   - ✅ **Require review from Code Owners** (optional)
   - ❌ **Do not allow bypassing the above settings** (even for admins)
4. Save changes

### Notifications (Recommended)

1. Go to: **Settings > Notifications**
2. Enable:
   - ✅ Actions: Failed workflows
   - ✅ Security alerts: Code scanning
   - ✅ Dependabot alerts

---

## Daily Workflow

### During Development

```bash
# 1. Create feature branch
git checkout -b feature/my-feature

# 2. Make changes
# ... edit code ...

# 3. Run local security check
./scripts/local-security-check.sh

# 4. Push to get fast feedback
git push origin feature/my-feature
# → Triggers: fast-ci.yml (30-60 seconds)

# 5. Fix any issues and iterate
# ... fix code ...
git push
```

### Before Merge

```bash
# 1. Create PR to main
gh pr create --base main --title "My feature" --body "Description"
# → Triggers: ci.yml, security-scan.yml, sentinel-health.yml (5-10 minutes)

# 2. Wait for all checks to pass
gh pr checks

# 3. Review artifacts (if needed)
gh run download

# 4. Address any warnings
# Even non-blocking warnings should be reviewed

# 5. Get approval and merge
# Branch protection rules enforce all checks pass
```

### Weekly Security Audit

```bash
# 1. Run adversarial testing
gh workflow run adversarial-ci.yml -f attack_intensity=high

# 2. Wait for completion
gh run watch

# 3. Download artifacts
gh run download --name attack-surface-map
gh run download --name secrets-report

# 4. Review findings
cat attack-surface.json | jq '.command_execution'
cat attack-surface.json | jq '.autonomous_actions'

# 5. Create issues for any problems found
gh issue create --title "Security: Fix shell=True in executor.py" --body "..."
```

---

## Artifacts Generated

All workflows upload artifacts for forensic analysis:

| Artifact | Workflow | Retention | Purpose |
|----------|----------|-----------|---------|
| `bandit-report.json` | security-scan | 30 days | SAST findings |
| `dependency-security-report` | security-scan | 30 days | CVE list |
| `attack-surface-map` | adversarial-ci | 90 days | Attack vector inventory |
| `secrets-report.json` | adversarial-ci | 90 days | Leaked secrets |
| `trivy-results.sarif` | adversarial-ci | 90 days | Container CVEs |
| `coverage.xml` | ci | - | Code coverage |

Download with:
```bash
gh run download --name attack-surface-map
```

---

## Troubleshooting

### "Security Gate" Fails

```bash
# View the error
gh run view --log | grep "BLOCKED"

# Common issues:
# - shell=True → Change to shell=False with list arguments
# - eval() → Use ast.literal_eval() or safe alternatives
# - Hardcoded secrets → Use environment variables
```

### "Python Lint (BLOCKING)" Fails

```bash
# Run locally to see errors
ruff check core/

# Auto-fix what you can
ruff check core/ --fix

# Type check
mypy core/ --ignore-missing-imports
```

### "Sentinel Health Summary" Fails

```bash
# Run specific health check locally
pytest tests/unit/test_arbitration.py -v
python tests/verification/verify_backend.py

# Common issues:
# - State machine broken
# - Event bus not emitting
# - Fail-closed behavior changed
```

### Want to Skip CI (Emergency Only)

```bash
# Add [skip ci] to commit message
git commit -m "Update documentation [skip ci]"

# WARNING: Only use for:
# - Documentation changes
# - README updates
# - Non-code changes

# NEVER skip CI for:
# - Code changes
# - Security-related changes
# - Configuration changes
```

---

## Known Issues & Expected Failures

Some workflows will initially fail because of existing issues in the codebase:

### Expected to FAIL on First Run:

1. **security-scan.yml** - Will find `shell=True` in:
   - `core/engine/executor.py:96`
   - `core/toolkit/installer.py` (multiple locations)

2. **python-lint** - May fail due to ruff/mypy issues that were previously ignored

### What to Do:

**Option 1**: Fix the issues immediately
```bash
# Create a branch
git checkout -b fix/security-issues

# Fix shell=True → shell=False
# Fix other critical issues

# Push and create PR
git push origin fix/security-issues
gh pr create --base main
```

**Option 2**: Temporarily allow specific patterns (not recommended)
```bash
# Add to .bandit config to skip specific files
# Edit .bandit:
[bandit]
exclude_dirs = /core/engine/executor.py,/core/toolkit/installer.py

# But DO NOT do this long-term!
```

**Recommendation**: Fix the issues. The workflows are catching real vulnerabilities.

---

## Next Steps

1. **Push this setup** to a feature branch and test it
2. **Fix any security issues** found by the workflows
3. **Configure branch protection** rules on main
4. **Run adversarial-ci** manually to see what it finds
5. **Review and tune** `.bandit` config as you discover false positives
6. **Set up notifications** for failed workflows
7. **Document security findings** in issues

---

## Documentation

All documentation is in `.github/`:

- **workflows/README.md** - Complete workflow documentation
- **RUN_WORKFLOWS.md** - How to trigger each workflow
- **SECURITY_CI_OVERVIEW.md** - Architecture and philosophy

Read these to understand the full system.

---

## Philosophy

This is **not just CI**. This is **Sentinel's immune system**.

Every workflow answers:
> *"What would be catastrophic if I didn't catch it early?"*

The workflows are designed to be:
- **Adversarial** - They don't give you the benefit of the doubt
- **Fail-closed** - Blocking by default, not --exit-zero
- **Self-auditing** - Sentinel scans itself
- **Forensic** - All artifacts saved for analysis
- **Trust-aware** - Different checks for different branch types

---

## Get Started Now

```bash
# 1. Run local security check
./scripts/local-security-check.sh

# 2. Push to feature branch
git checkout -b feature/test-security-ci
git push origin feature/test-security-ci

# 3. Watch workflows run
gh run watch

# 4. Trigger adversarial testing
gh workflow run adversarial-ci.yml -f attack_intensity=medium

# 5. Review findings
gh run download
```

Good hunting. 🎯
