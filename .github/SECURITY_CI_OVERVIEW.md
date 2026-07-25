# Sentinel Security-First CI Pipeline Overview

## The Mindset Shift

You asked for GitHub Actions that treat CI as an **adversarial lab assistant**, not just a build gate. This is what you now have.

---

## What You Have Now

### 6 Workflows (Branch-Aware, Security-First)

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENTINEL CI ARCHITECTURE                      │
└─────────────────────────────────────────────────────────────────┘

ALWAYS-ON SECURITY (main/develop branches)
├── ci.yml                    Core build + security gate
│   ├── security-gate         ❌ Blocks shell=True, eval(), secrets
│   ├── python-tests          ✅ Full test suite (needs: security-gate)
│   ├── python-lint (BLOCKING)✅ Ruff + mypy (no --exit-zero)
│   └── swift-build           ✅ macOS UI compilation
│
├── security-scan.yml         Static analysis (SAST)
│   ├── bandit                ❌ Blocks HIGH/CRITICAL findings
│   ├── semgrep               ⚠️  Security patterns (SARIF → GitHub)
│   ├── forbidden-patterns    ❌ Blocks shell=True, os.system()
│   ├── dependency-check      ⚠️  CVE scanning with Safety
│   └── attack-surface        📊 Complexity, dead code, subprocess count
│
└── sentinel-health.yml       Behavioral verification
    ├── agent-contracts       ✅ Verify agents register correctly
    ├── fail-closed           ✅ Test veto-wins, state machine
    ├── scanner-reliability   ✅ Schema stability
    ├── observability         ✅ Event emission coverage
    ├── configuration-security✅ Secure defaults
    └── sandboxing            ✅ Timeout enforcement

TRUST-LEVEL WORKFLOWS (branch-based)
├── fast-ci.yml (feature/*, bugfix/*, hotfix/*)
│   └── Quick security + unit tests only (fast feedback)
│
└── experimental-ci.yml (experiment/*, spike/*, poc/*)
    └── Non-blocking informational checks only

ADVERSARIAL WORKFLOWS (manual/red-team)
└── adversarial-ci.yml (manual dispatch or red-team/** branches)
    ├── self-scan             🎯 Sentinel scans itself
    ├── fuzzing-simulation    🎲 Input fuzzing
    ├── exploit-verification  🧪 AI code validation tests
    ├── privilege-escalation  🔓 Setuid/sudo detection
    ├── secrets-leakage       🔑 TruffleHog + API key scan
    └── docker-security       🐳 Trivy + Dockerfile hardening
```

---

## What Each Workflow Catches

| Catastrophic Failure | Workflow | How |
|---------------------|----------|-----|
| Command injection via shell=True | ci.yml (security-gate) | Grep search, blocks build |
| AI-generated malicious code | adversarial-ci.yml | AST validation test |
| Autonomous exploitation without approval | sentinel-health.yml | Fail-closed behavior tests |
| Policy arbitration broken | sentinel-health.yml | Veto-wins verification |
| State machine invalid transitions | sentinel-health.yml | State transition tests |
| Hardcoded secrets | security-scan.yml | Bandit + regex patterns |
| Vulnerable dependencies | security-scan.yml | Safety CVE scanner |
| MITM without validation | security-scan.yml | Attack surface analysis |
| Insecure defaults (auth off) | sentinel-health.yml | Configuration tests |
| Subprocess timeout not enforced | sentinel-health.yml | Sandbox verification |
| Scanner schema drift | sentinel-health.yml | Output schema tests |
| Missing event emissions | sentinel-health.yml | Observability checks |
| Docker running as root | adversarial-ci.yml | Dockerfile security |
| Container vulnerabilities | adversarial-ci.yml | Trivy scan (SARIF) |
| Secrets in git history | adversarial-ci.yml | TruffleHog |
| Input validation bypass | adversarial-ci.yml | Fuzzing tests |

---

## Files Created

```
.github/
├── workflows/
│   ├── ci.yml                  # Enhanced with security gate
│   ├── security-scan.yml       # NEW: SAST pipeline
│   ├── sentinel-health.yml     # NEW: Behavioral tests
│   ├── adversarial-ci.yml      # NEW: Self-attack workflow
│   ├── fast-ci.yml             # NEW: Feature branch CI
│   ├── experimental-ci.yml     # NEW: Experimental branch CI
│   └── README.md               # NEW: Complete documentation
│
├── RUN_WORKFLOWS.md            # NEW: How to trigger workflows
└── SECURITY_CI_OVERVIEW.md     # NEW: This file

.bandit                         # NEW: Bandit security config
.semgrepignore                  # NEW: Semgrep exclusions
```

---

## Security Gates (What Blocks Merges)

### ❌ BLOCKING (Build fails, cannot merge)

1. **Critical Security Patterns**
   - `shell=True` in subprocess
   - `eval()`, `exec()`, `os.system()`
   - Bandit HIGH/CRITICAL findings

2. **Lint Errors** (now blocking, not --exit-zero)
   - Ruff errors
   - mypy type errors

3. **Test Failures**
   - Unit test failures
   - Integration test failures

4. **Behavioral Failures**
   - Fail-closed tests fail
   - Agent contract violations
   - State machine invalid transitions

### ⚠️ WARNINGS (Logged, manual review)

- Dependency vulnerabilities (HIGH)
- Hardcoded secrets (regex, may be false positives)
- Dead code
- 0.0.0.0 network bindings
- Missing event emissions
- Print statements without logging

---

## Artifacts Generated

All workflows upload artifacts for forensic analysis:

| Artifact | Retention | What |
|----------|-----------|------|
| `bandit-report.json` | 30 days | SAST findings |
| `dependency-security-report` | 30 days | CVE list |
| `attack-surface-map` | 90 days | JSON inventory of attack vectors |
| `secrets-report.json` | 90 days | TruffleHog findings |
| `trivy-results.sarif` | 90 days | Container CVEs |
| `coverage.xml` | N/A | Code coverage (codecov) |

Download with:
```bash
gh run download --name attack-surface-map
```

---

## Trust Levels (Branch-Based Separation)

| Branch Pattern | Workflow | Philosophy |
|----------------|----------|------------|
| `main` / `develop` | Full security suite | Production-grade, all gates enabled |
| `feature/**` | Fast CI | Developer experience: quick feedback |
| `red-team/**` | Adversarial CI | Offensive testing: Sentinel attacks itself |
| `experiment/**` | Minimal CI | Low friction: informational only |

**Example**:
```bash
# Fast feedback during development
git checkout -b feature/new-scanner
git push  # → fast-ci.yml (unit tests only)

# Full audit before merge
gh pr create --base main  # → ci.yml + security-scan.yml + sentinel-health.yml

# Red team exercise
git checkout -b red-team/2025-exercise
git push  # → adversarial-ci.yml (full attack suite)
```

---

## How to Use

### Daily Development
```bash
# 1. Create feature branch
git checkout -b feature/my-feature

# 2. Push to get fast feedback
git push origin feature/my-feature
# → Runs: fast-ci.yml (quick checks)

# 3. Create PR to main
gh pr create --base main
# → Runs: ci.yml, security-scan.yml, sentinel-health.yml

# 4. Fix any blocked issues
# If security-gate fails, fix shell=True, eval(), etc.

# 5. Merge when green
```

### Security Audit (Weekly/Monthly)
```bash
# Trigger adversarial testing manually
gh workflow run adversarial-ci.yml -f attack_intensity=high

# Or push to red-team branch
git checkout -b red-team/$(date +%Y%m%d)
git push origin red-team/$(date +%Y%m%d)

# Download attack surface map
gh run download --name attack-surface-map

# Review findings
cat attack-surface.json | jq
```

### Before Major Release
```bash
# 1. Run full security suite
gh workflow run security-scan.yml
gh workflow run sentinel-health.yml
gh workflow run adversarial-ci.yml -f attack_intensity=high

# 2. Check all passed
gh run list --limit 10

# 3. Review all artifacts
gh run download

# 4. Fix any warnings
# Even non-blocking warnings should be reviewed

# 5. Tag release only after all green
git tag -a v1.0.0 -m "Release 1.0.0"
```

---

## Integration with GitHub

### Required: Branch Protection Rules

Set these on `main` branch:

1. Go to: Settings > Branches > Branch protection rules
2. Add rule for `main`:
   - ✅ Require status checks to pass before merging
   - ✅ Require branches to be up to date before merging
   - Select status checks:
     - `Security Gate`
     - `Python Tests`
     - `Python Lint (BLOCKING)`
     - `Security Scan Summary`
     - `Sentinel Health Summary`
   - ✅ Require approvals: 1
   - ✅ Dismiss stale reviews
   - ❌ Do NOT allow bypassing (even admins)

### Optional: Code Scanning (GitHub Advanced Security)

The workflows already upload SARIF files:
- Semgrep → `semgrep.sarif`
- Trivy → `trivy-results.sarif`

These show up in: Security > Code scanning alerts

### Optional: Dependabot

Add `.github/dependabot.yml`:
```yaml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
```

---

## What You Should NOT Do (Yet)

Skip these until Sentinel is production-ready:

- ❌ Auto-deployments
- ❌ Release automation
- ❌ Docker registry publishing
- ❌ Performance benchmarking
- ❌ Load testing
- ❌ Penetration testing against live targets

**Why**: Sentinel is still evolving. Focus on correctness and security first.

---

## Metrics That Matter

After a few weeks of using this, you should track:

1. **Security gate block rate** - How often does it catch shell=True?
2. **False positive rate** - How often are warnings irrelevant?
3. **Time to green** - How long from push to all-green?
4. **Adversarial findings** - What does adversarial-ci find?

Adjust thresholds based on these metrics.

---

## Next-Level Additions (Future)

Once you're comfortable with this setup:

1. **Custom Semgrep rules** for Sentinel-specific patterns
2. **SBOM generation** (Software Bill of Materials)
3. **License compliance** scanning
4. **Performance regression** tests
5. **Fuzzing integration** (AFL, LibFuzzer)
6. **DAST** (Dynamic Application Security Testing)
7. **Container signing** (Cosign)
8. **Attestation** (SLSA provenance)

---

## Philosophy Check

Every workflow answers the question:

> **"What would be catastrophic if I didn't catch it early?"**

If you can't answer that for a workflow, delete it.

---

## The Bottom Line

You now have:

✅ **6 workflows** covering always-on security, behavioral tests, and adversarial testing
✅ **Trust-level separation** (main vs feature vs red-team vs experiment)
✅ **Security gates** that block shell=True, eval(), hardcoded secrets
✅ **Behavioral tests** that verify fail-closed, veto-wins, state machines
✅ **Adversarial testing** where Sentinel attacks itself
✅ **Artifact tracking** with 30-90 day retention for forensics
✅ **Complete documentation** on how to use everything

This is **not just CI**. This is **Sentinel's immune system**.

---

**Next Step**: Push to a feature branch and watch the workflows run. Then trigger adversarial-ci manually to see what Sentinel finds when it scans itself.

```bash
# Try it now
git checkout -b feature/test-ci
git push origin feature/test-ci

# Then:
gh workflow run adversarial-ci.yml -f attack_intensity=medium
```

Good hunting.
