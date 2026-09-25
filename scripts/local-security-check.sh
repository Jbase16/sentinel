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
BASELINE_FILE="$(dirname "${BASH_SOURCE[0]}")/security-check-baseline.txt"

if [[ ! -r "$BASELINE_FILE" ]]; then
    echo -e "${RED}❌ Security-check baseline is missing or unreadable: $BASELINE_FILE${NC}"
    exit 1
fi

baseline_entries=()
while IFS= read -r entry || [[ -n "$entry" ]]; do
    [[ -z "$entry" || "$entry" == \#* ]] && continue
    baseline_entries+=("$entry")
done < "$BASELINE_FILE"

is_baselined() {
    local candidate="$1" entry
    for entry in "${baseline_entries[@]}"; do
        [[ "$candidate" == "$entry" ]] && return 0
    done
    return 1
}

check_new_matches() {
    local pattern="$1" label="$2" matches status=0 match path content candidate
    local new_matches=()

    matches=$(grep -rn "$pattern" core/ --include="*.py") || status=$?
    if [[ $status -gt 1 ]]; then
        echo -e "${RED}❌ Could not scan core/ for $label${NC}"
        FAILED=1
        return
    fi

    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        path=${match%%:*}
        content=${match#*:}
        content=${content#*:}
        content=$(printf '%s' "$content" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
        candidate="$path"$'\t'"$content"
        if ! is_baselined "$candidate"; then
            new_matches+=("$match")
        fi
    done <<< "$matches"

    if [[ ${#new_matches[@]} -gt 0 ]]; then
        echo -e "${RED}❌ NEW $label violation(s) found${NC}"
        printf '  → %s\n' "${new_matches[@]}"
        FAILED=1
    else
        echo -e "${GREEN}✅ No new $label found${NC}"
    fi
}

# Check 1: shell=True
echo "📍 Checking for shell=True (command injection)..."
check_new_matches "shell=True" "shell=True"
echo ""

# Check 2: eval/exec
echo "📍 Checking for eval()/exec()..."
check_new_matches "eval(" "eval()"
check_new_matches "exec(" "exec()"
echo ""

# Check 3: os.system
echo "📍 Checking for os.system()..."
check_new_matches "os.system(" "os.system()"
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
