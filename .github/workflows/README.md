# Sentinel CI/CD Pipeline

This directory contains Sentinel's **security-first CI/CD infrastructure**. Unlike typical CI systems that just check if code runs, Sentinel's pipeline is designed to **act as an adversarial lab assistant** that actively looks for ways the code could be exploited.

## Philosophy

> "Your CI should answer: *What would Sentinel find if it scanned itself?*"

Every workflow is designed to catch catastrophic failures early, treating Sentinel as both the auditor and the audited.

---

## Workflow Overview

### 🛡️ Security-First Workflows (Always-On)

#### 1. **ci.yml** - Main CI Pipeline
**Trigger**: Push/PR to `main` or `develop`
**Purpose**: Primary build and test pipeline with security gates

**Jobs**:
- `security-gate` - Blocks critical security issues (shell=True, hardcoded secrets)
- `python-tests` - Full test suite (unit + integration)
- `python-lint` - Ruff + mypy (BLOCKING, not --exit-zero)
- `swift-build` - macOS UI compilation
- `swift-tests` - UI test suite

**Philosophy**: Security gate runs FIRST. If it fails, nothing else runs. Lint is blocking.

---

#### 2. **security-scan.yml** - Static Security Analysis
**Trigger**: Push/PR to `main`/`develop`, manual dispatch
**Purpose**: Deep security scanning (SAST)

**Jobs**:
- `bandit` - Python security analysis (blocks on HIGH/CRITICAL)
- `semgrep` - Semantic code analysis (security-audit, command-injection, secrets)
- `forbidden-patterns` - Custom pattern detection:
  - shell=True (command injection)
  - os.system(), eval(), exec()
  - Hardcoded secrets
  - Security TODOs
- `dependency-check` - Safety scanner for vulnerable dependencies
- `attack-surface-analysis` - Counts subprocess calls, measures complexity, finds dead code

**Artifacts**:
- `bandit-report.json` (30 days)
- `dependency-security-report` (30 days)

**Philosophy**: If Bandit or forbidden-patterns fail, the build fails. Other checks are warnings.

---

#### 3. **sentinel-health.yml** - Behavioral Verification
**Trigger**: Push/PR to `main`/`develop`, manual dispatch
**Purpose**: Verify Sentinel's core security behaviors work correctly

**Jobs**:
- `agent-contracts` - Verify agents register and emit decisions correctly
- `fail-closed-verification` - Test fail-closed behavior:
  - Arbitration engine vetoes win over approvals
  - State machine blocks invalid transitions
- `scanner-reliability` - Verify scanner output schemas haven't drifted
- `observability-check` - Verify critical paths emit events, check logging
- `configuration-security` - Test secure defaults, API auth
- `sandboxing-verification` - Verify timeout enforcement, subprocess isolation

**Philosophy**: These are **behavioral assertions**. Code can compile and pass tests but still fail to fail-closed. This catches that.

---

### 🎯 Adversarial Workflows (Manual/Red-Team)

#### 4. **adversarial-ci.yml** - Sentinel Attacks Itself
**Trigger**: Manual dispatch (with intensity: low/medium/high), push to `red-team/**`
**Purpose**: Offensive security testing - Sentinel scanning itself

**Jobs**:
- `self-scan` - Run Bandit/Semgrep on own codebase, generate attack surface map
- `fuzzing-simulation` - Fuzz API inputs (injection, path traversal, XSS)
- `exploit-verification` - Test AI-generated code validation (AST analysis)
- `privilege-escalation-test` - Detect setuid, sudo, capability manipulation
- `secrets-leakage-test` - TruffleHog git history scan, API key detection
- `docker-security-scan` - Trivy container scanning, Dockerfile best practices

**Artifacts**:
- `attack-surface-map` (90 days)
- `secrets-report.json`
- `trivy-results.sarif`

**Philosophy**: This workflow is **explicitly hostile**. It tries to break Sentinel. Only run when you want adversarial testing.

---

### ⚡ Trust-Level Workflows (Branch-Based)

#### 5. **fast-ci.yml** - Feature Branch CI
**Trigger**: Push to `feature/**`, `bugfix/**`, `hotfix/**`
**Purpose**: Fast feedback during development

**Jobs**:
- `quick-security-check` - Only critical patterns (shell=True, eval)
- `unit-tests-only` - Skip integration tests for speed
- `lint-fast` - Only errors (E,F), not style

**Philosophy**: Developer experience matters. Give fast feedback on what's broken, skip slow checks.

---

#### 6. **experimental-ci.yml** - Experimental Branch CI
**Trigger**: Push to `experiment/**`, `spike/**`, `poc/**`
**Purpose**: Non-blocking informational checks

**Jobs**:
- `informational-checks` - Syntax check, security scan (non-blocking), quick tests

**Philosophy**: Experiments should be low-friction. All checks are informational, nothing blocks.

---

## Trust Levels

| Branch Pattern | Workflow | Security | Tests | Lint | Blocking? |
|----------------|----------|----------|-------|------|-----------|
| `main` / `develop` | ci.yml + security-scan.yml + sentinel-health.yml | Full SAST | Full suite | Blocking | ✅ YES |
| `feature/**` | fast-ci.yml | Critical only | Unit only | Errors only | ✅ YES |
| `red-team/**` | adversarial-ci.yml | Adversarial | Fuzzing | - | ❌ Manual |
| `experiment/**` | experimental-ci.yml | Informational | Quick | - | ❌ NO |

---

## Security Gates (What Gets Blocked)

### ❌ **BLOCKING** (Build fails immediately)

1. **Command Injection**
   - `shell=True` in subprocess
   - `os.system()`, `eval()`, `exec()`
   - Unescaped `{target}` substitution

2. **Bandit HIGH/CRITICAL**
   - Hardcoded passwords/secrets
   - Unsafe deserialization
   - Unsafe YAML/XML parsing

3. **Forbidden Patterns**
   - `eval(`, `__import__`
   - `subprocess.call.*shell`

### ⚠️ **WARNINGS** (Build continues, manual review required)

1. **Dependency Vulnerabilities** (HIGH severity)
2. **Hardcoded secrets** (regex detection, may be false positives)
3. **Dead code** (vulture)
4. **Network exposure** (0.0.0.0 bindings)
5. **Print statements** without logging

---

## Artifacts & Reports

All workflows upload artifacts for forensic analysis:

| Artifact | Workflow | Retention | Purpose |
|----------|----------|-----------|---------|
| `bandit-report.json` | security-scan | 30 days | SAST findings |
| `dependency-security-report` | security-scan | 30 days | Vulnerable deps |
| `attack-surface-map` | adversarial-ci | 90 days | Attack vector inventory |
| `secrets-report.json` | adversarial-ci | 90 days | TruffleHog findings |
| `trivy-results.sarif` | adversarial-ci | 90 days | Container vulnerabilities |
| `coverage.xml` | ci | - | Code coverage (codecov) |

---

## Workflow Dependencies

```
security-gate (ci.yml)
    ├─> python-tests
    ├─> python-lint
    └─> swift-build

security-scan.yml (parallel)
    ├─> bandit
    ├─> semgrep
    ├─> forbidden-patterns
    ├─> dependency-check
    ├─> attack-surface-analysis
    └─> security-summary

sentinel-health.yml (parallel)
    ├─> agent-contracts
    ├─> fail-closed-verification
    ├─> scanner-reliability
    ├─> observability-check
    ├─> configuration-security
    ├─> sandboxing-verification
    └─> health-summary
```

---

## What's NOT in CI (Yet)

Skip these until Sentinel is ready to ship:

- ❌ Auto-deployments
- ❌ Release automation
- ❌ Docker publishing
- ❌ Marketplace Actions
- ❌ Performance benchmarking
- ❌ Load testing

**Rationale**: Sentinel is still evolving. Don't rush into shipping mode.

---

## Running Workflows Locally

### Security Scan
```bash
# Quick security check
grep -r "shell=True" core/ --include="*.py"

# Full Bandit scan
pip install bandit
bandit -r core/ -ll

# Semgrep
docker run --rm -v "${PWD}:/src" returntocorp/semgrep semgrep --config=p/security-audit /src/core
```

### Sentinel Health Check
```bash
# Verify backend
python tests/verification/verify_backend.py

# Run behavioral tests
pytest tests/unit/test_arbitration.py -v
pytest tests/integration/test_decision_emission.py -v
```

### Adversarial Testing
```bash
# Manual trigger on GitHub:
Actions > Adversarial Testing > Run workflow > Select intensity

# Or push to red-team branch:
git checkout -b red-team/test-attack
git push origin red-team/test-attack
```

---

## Adding New Workflows

### When to add a new workflow

1. **New security boundary** - New execution path, network exposure, data storage
2. **New trust level** - Different branch naming convention needs different rules
3. **New compliance requirement** - SBOM, license scanning, etc.

### When NOT to add a workflow

1. **Nice-to-have metrics** - Unless it catches catastrophic failures
2. **Duplicate checks** - If security-scan.yml already covers it
3. **Premature optimization** - Performance benchmarks before correctness

### Workflow template

```yaml
name: Your Workflow

on:
  # Choose trigger carefully
  push:
    branches: [main]

jobs:
  your-job:
    name: Descriptive Name
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: What would be catastrophic if we didn't catch it?
        run: |
          # Answer that question here
          echo "Checking for [specific failure mode]..."

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: your-artifact
          retention-days: 30
```

---

## Critical Questions Each Workflow Answers

| Workflow | Question |
|----------|----------|
| ci.yml | Does it build and pass tests? |
| security-scan.yml | Did this change increase attack surface? |
| sentinel-health.yml | Did this break Sentinel's defensive mechanisms? |
| adversarial-ci.yml | Would Sentinel catch this if it scanned itself? |
| fast-ci.yml | Is this obviously broken? (fast feedback) |
| experimental-ci.yml | What's the status? (informational) |

---

## North-Star Principle

> **Every GitHub Action you add should answer:**
> *"What failure would be catastrophic if I didn't catch it early?"*

If it doesn't catch one of those, it's probably noise.

---

## Next Steps

1. **Run adversarial-ci manually** to see what Sentinel finds when scanning itself
2. **Review security-scan artifacts** after next PR
3. **Add custom policies** to sentinel-health.yml as you build new behavioral contracts
4. **Tune fail-closed tests** to match your actual security requirements

---

## Links

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Semgrep Rules](https://semgrep.dev/explore)
- [Trivy Scanner](https://trivy.dev/)

---

**Remember**: This isn't just CI. It's Sentinel's **immune system**.
