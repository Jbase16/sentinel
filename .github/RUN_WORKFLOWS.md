# How to Run Sentinel CI Workflows

This guide explains how to trigger different CI workflows for Sentinel.

## Automatic Workflows (Triggered by Git Events)

### Main CI Pipeline
**Workflow**: `ci.yml`
**Triggers automatically on**:
```bash
# Push to main or develop
git push origin main
git push origin develop

# Pull request to main
gh pr create --base main
```

### Security Scan
**Workflow**: `security-scan.yml`
**Triggers automatically on**:
```bash
# Same as main CI: push to main/develop or PR to main
git push origin main
```

### Sentinel Health Check
**Workflow**: `sentinel-health.yml`
**Triggers automatically on**:
```bash
# Same as main CI: push to main/develop or PR to main
git push origin main
```

### Fast CI (Feature Branches)
**Workflow**: `fast-ci.yml`
**Triggers automatically on**:
```bash
# Push to feature branches
git checkout -b feature/my-feature
git push origin feature/my-feature

# Also: bugfix/*, hotfix/*
git checkout -b bugfix/fix-scanner
git push origin bugfix/fix-scanner
```

### Experimental CI
**Workflow**: `experimental-ci.yml`
**Triggers automatically on**:
```bash
# Push to experimental branches
git checkout -b experiment/new-idea
git push origin experiment/new-idea

# Also: spike/*, poc/*
git checkout -b spike/test-approach
git push origin spike/test-approach
```

---

## Manual Workflows (Trigger via GitHub UI or CLI)

### Adversarial Testing
**Workflow**: `adversarial-ci.yml`

#### Via GitHub UI:
1. Go to: https://github.com/YOUR_ORG/sentinelforge/actions
2. Click "Adversarial Testing" in the left sidebar
3. Click "Run workflow" button (top right)
4. Select attack intensity: `low`, `medium`, or `high`
5. Click "Run workflow"

#### Via GitHub CLI:
```bash
# Install GitHub CLI if needed
brew install gh

# Run with low intensity
gh workflow run adversarial-ci.yml -f attack_intensity=low

# Run with medium intensity (default)
gh workflow run adversarial-ci.yml -f attack_intensity=medium

# Run with high intensity (comprehensive)
gh workflow run adversarial-ci.yml -f attack_intensity=high
```

#### Via Red-Team Branch:
```bash
# Create red-team branch (auto-triggers adversarial CI)
git checkout -b red-team/test-attack
git push origin red-team/test-attack
```

---

## Workflow Combinations

### Before Merging to Main (Full Security Audit)
```bash
# 1. Create feature branch
git checkout -b feature/my-feature

# 2. Push to get fast feedback
git push origin feature/my-feature
# → Triggers: fast-ci.yml (quick checks)

# 3. Create PR to main
gh pr create --base main --title "My Feature" --body "Description"
# → Triggers: ci.yml, security-scan.yml, sentinel-health.yml

# 4. (Optional) Run adversarial testing
gh workflow run adversarial-ci.yml -f attack_intensity=high

# 5. Review all workflow results before merging
```

### Red Team Exercise (Full Offensive Testing)
```bash
# 1. Create red-team branch
git checkout -b red-team/$(date +%Y%m%d)-exercise

# 2. Push to auto-trigger adversarial CI
git push origin red-team/$(date +%Y%m%d)-exercise
# → Triggers: adversarial-ci.yml

# 3. Review attack surface map artifact
# Go to: Actions > Adversarial Testing > Latest run > Artifacts

# 4. Download attack-surface-map.json
gh run download --name attack-surface-map

# 5. Analyze findings
cat attack-surface.json | jq '.command_execution'
```

### Security Audit (Manual Trigger All Security Workflows)
```bash
# Trigger security scan manually
gh workflow run security-scan.yml

# Trigger health check manually
gh workflow run sentinel-health.yml

# Trigger adversarial testing
gh workflow run adversarial-ci.yml -f attack_intensity=high

# Check status of all runs
gh run list --limit 10
```

---

## Viewing Results

### Via GitHub UI
1. Go to: https://github.com/YOUR_ORG/sentinelforge/actions
2. Click on a workflow run
3. Click on a specific job to see logs
4. Download artifacts from the Artifacts section

### Via GitHub CLI
```bash
# List recent runs
gh run list --limit 10

# View specific run
gh run view RUN_ID

# Download all artifacts from a run
gh run download RUN_ID

# Watch a running workflow
gh run watch RUN_ID
```

### Via Local Scripts
```bash
# Run security checks locally (before pushing)
./scripts/local-security-check.sh

# Run health checks locally
pytest tests/unit/test_arbitration.py -v
python tests/verification/verify_backend.py
```

---

## Workflow Status Badges

Add these to your README.md to show workflow status:

```markdown
![CI](https://github.com/YOUR_ORG/sentinelforge/workflows/CI/badge.svg)
![Security Scan](https://github.com/YOUR_ORG/sentinelforge/workflows/Security%20Scan/badge.svg)
![Sentinel Health](https://github.com/YOUR_ORG/sentinelforge/workflows/Sentinel%20Health%20Check/badge.svg)
```

---

## Troubleshooting

### Workflow Fails Immediately
```bash
# Check workflow syntax
gh workflow view ci.yml

# View failed run logs
gh run list --workflow=ci.yml --limit 1
gh run view --log-failed
```

### Security Gate Blocks Merge
```bash
# See what was blocked
gh run view --log | grep "BLOCKED"

# Common fixes:
# - Remove shell=True → use shell=False with list args
# - Remove eval() → use ast.literal_eval() or safe alternatives
# - Remove hardcoded secrets → use environment variables
```

### Want to Skip CI (Emergency Only)
```bash
# Add [skip ci] to commit message
git commit -m "Emergency hotfix [skip ci]"

# WARNING: Only use for documentation changes or emergencies
# Security workflows should NEVER be skipped
```

---

## Advanced: Custom Workflow Triggers

### Run Security Scan on Schedule (Nightly)
Add to `security-scan.yml`:
```yaml
on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM daily
```

### Run Adversarial Testing Weekly
Add to `adversarial-ci.yml`:
```yaml
on:
  schedule:
    - cron: '0 3 * * 0'  # 3 AM every Sunday
```

### Trigger from External Event (Webhook)
```yaml
on:
  repository_dispatch:
    types: [security-audit-requested]
```

Then trigger via API:
```bash
curl -X POST \
  -H "Authorization: token YOUR_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/YOUR_ORG/sentinelforge/dispatches \
  -d '{"event_type":"security-audit-requested"}'
```

---

## Quick Reference

| What I Want | Command |
|-------------|---------|
| Run full CI | `git push origin main` |
| Fast feedback | `git push origin feature/my-branch` |
| Adversarial test | `gh workflow run adversarial-ci.yml` |
| View latest run | `gh run list --limit 1` |
| Download artifacts | `gh run download` |
| Check workflow status | `gh run watch` |
| Skip CI (emergency) | `git commit -m "fix [skip ci]"` |

---

## Next Steps

1. Set up branch protection rules to require CI passing before merge
2. Configure GitHub notifications for workflow failures
3. Review artifacts after each adversarial run
4. Tune `.bandit` config as you discover false positives

---

**Remember**: The workflows are your adversarial lab assistant. Let them be hostile. That's the point.
