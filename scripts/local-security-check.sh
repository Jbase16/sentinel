#!/bin/bash

# Local Security Check Script
# Run this before pushing to catch issues early
# This replicates what the security-gate workflow does

set -e

echo "🔒 Running local security checks..."
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FAILED=0

# Check 1: shell=True
echo "📍 Checking for shell=True (command injection)..."
if grep -r "shell=True" core/ --include="*.py" > /dev/null 2>&1; then
    echo -e "${RED}❌ BLOCKED: shell=True found${NC}"
    echo "Locations:"
    grep -rn "shell=True" core/ --include="*.py"
    FAILED=1
else
    echo -e "${GREEN}✅ No shell=True found${NC}"
fi
echo ""

# Check 2: eval/exec
echo "📍 Checking for eval()/exec()..."
if grep -r "eval(" core/ --include="*.py" > /dev/null 2>&1; then
    echo -e "${RED}❌ eval() found${NC}"
    grep -rn "eval(" core/ --include="*.py"
    FAILED=1
else
    echo -e "${GREEN}✅ No eval() found${NC}"
fi

if grep -r "exec(" core/ --include="*.py" > /dev/null 2>&1; then
    echo -e "${RED}❌ exec() found${NC}"
    grep -rn "exec(" core/ --include="*.py"
    FAILED=1
else
    echo -e "${GREEN}✅ No exec() found${NC}"
fi
echo ""

# Check 3: os.system
echo "📍 Checking for os.system()..."
if grep -r "os.system(" core/ --include="*.py" > /dev/null 2>&1; then
    echo -e "${RED}❌ os.system() found${NC}"
    grep -rn "os.system(" core/ --include="*.py"
    FAILED=1
else
    echo -e "${GREEN}✅ No os.system() found${NC}"
fi
echo ""

# Check 4: Hardcoded secrets (loose check)
echo "📍 Checking for potential hardcoded secrets..."
if grep -r -E "(password|secret|api_key)\s*=\s*['\"][^'\"]{12,}" core/ --include="*.py" > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  Potential hardcoded secrets found (may be false positives):${NC}"
    grep -rn -E "(password|secret|api_key)\s*=\s*['\"][^'\"]{12,}" core/ --include="*.py"
    # Don't fail, just warn
else
    echo -e "${GREEN}✅ No obvious hardcoded secrets${NC}"
fi
echo ""

# Check 5: Python syntax
echo "📍 Checking Python syntax..."
if python -m py_compile core/**/*.py > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Python syntax valid${NC}"
else
    echo -e "${RED}❌ Python syntax errors found${NC}"
    FAILED=1
fi
echo ""

# Optional: Run Bandit if installed
if command -v bandit &> /dev/null; then
    echo "📍 Running Bandit (if installed)..."
    if bandit -r core/ -ll --quiet; then
        echo -e "${GREEN}✅ Bandit passed${NC}"
    else
        echo -e "${YELLOW}⚠️  Bandit found issues${NC}"
        # Don't fail, just warn
    fi
    echo ""
else
    echo -e "${YELLOW}⚠️  Bandit not installed (pip install bandit to enable)${NC}"
    echo ""
fi

# Optional: Run ruff if installed
if command -v ruff &> /dev/null; then
    echo "📍 Running ruff (if installed)..."
    if ruff check core/ --quiet; then
        echo -e "${GREEN}✅ Ruff passed${NC}"
    else
        echo -e "${YELLOW}⚠️  Ruff found issues${NC}"
        # Don't fail, just warn
    fi
    echo ""
else
    echo -e "${YELLOW}⚠️  Ruff not installed (pip install ruff to enable)${NC}"
    echo ""
fi

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $FAILED -eq 1 ]; then
    echo -e "${RED}❌ SECURITY CHECKS FAILED${NC}"
    echo "Fix the issues above before pushing."
    echo "The CI security gate will block these."
    exit 1
else
    echo -e "${GREEN}✅ ALL CRITICAL CHECKS PASSED${NC}"
    echo "Safe to push (CI security gate should pass)."
    echo ""
    echo "Note: Full CI will also run:"
    echo "  - Semgrep"
    echo "  - Dependency scanning"
    echo "  - Behavioral tests"
    echo "  - Type checking"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
