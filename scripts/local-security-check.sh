#!/bin/bash

# Local security gate. Run from any directory before committing.
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
FAILED=0
BASELINE_FILE="scripts/security-check-baseline.txt"
LINT_BASELINE="scripts/security-lint-baseline.json"
SCAN_DIRS=(core scripts tools sentinelforge)

if [[ ! -r "$BASELINE_FILE" || ! -r "$LINT_BASELINE" ]]; then
    echo "Security baseline missing or unreadable"
    exit 1
fi

if [[ -x .venv/bin/python ]]; then
    PYTHON_BIN=.venv/bin/python
elif command -v python3 > /dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
else
    echo "Python 3 is required for the local security gate"
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
    local pattern="$1" label="$2" mode="$3" matches status=0 match path content candidate
    local grep_options=() new_matches=()
    [[ "$mode" == extended ]] && grep_options+=(-E)

    matches=$(grep -rn "${grep_options[@]}" --include='*.py' "$pattern" "${SCAN_DIRS[@]}") || status=$?
    if [[ $status -gt 1 ]]; then
        echo "Could not scan Python sources for $label"
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
        echo "NEW $label violation(s):"
        printf '  %s\n' "${new_matches[@]}"
        FAILED=1
    else
        echo "$label: no new matches"
    fi
}

resolve_tool() {
    local name="$1"
    if command -v "$name" > /dev/null 2>&1; then
        command -v "$name"
    elif [[ -x ".venv/bin/$name" ]]; then
        printf '%s\n' ".venv/bin/$name"
    else
        return 1
    fi
}

temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

run_linter() {
    local name="$1" binary="$2" status=0 report="$temp_dir/$1.json"
    shift 2
    "$binary" "$@" > "$report" 2> "$temp_dir/$name.err" || status=$?
    if [[ $status -gt 1 ]]; then
        echo "$name failed to run (exit $status):"
        cat "$temp_dir/$name.err"
        FAILED=1
    elif ! "$PYTHON_BIN" scripts/security_gate_findings.py "$name" "$report" "$LINT_BASELINE"; then
        FAILED=1
    fi
}

echo "Running local security checks across ${SCAN_DIRS[*]}"
check_new_matches 'shell=True' 'shell=True' basic
check_new_matches 'eval(' 'eval()' basic
check_new_matches 'exec(' 'exec()' basic
check_new_matches 'os.system(' 'os.system()' basic
SECRET_PATTERN="(password|secret|api_key)[[:space:]]*=[[:space:]]*['\"][^'\"]{12,}"
check_new_matches "$SECRET_PATTERN" 'potential hardcoded secret' extended

python_files=()
while IFS= read -r -d '' file; do
    python_files+=("$file")
done < <(find "${SCAN_DIRS[@]}" -type f -name '*.py' -print0)
if "$PYTHON_BIN" -m py_compile "${python_files[@]}"; then
    echo "Python syntax: passed (${#python_files[@]} files)"
else
    echo "Python syntax: failed"
    FAILED=1
fi

if bandit_bin="$(resolve_tool bandit)"; then
    run_linter bandit "$bandit_bin" -r "${SCAN_DIRS[@]}" -ll -q -f json
else
    echo "Bandit is required for the local security gate"
    FAILED=1
fi

if ruff_bin="$(resolve_tool ruff)"; then
    run_linter ruff "$ruff_bin" check "${SCAN_DIRS[@]}" --output-format json
else
    echo "Ruff is required for the local security gate"
    FAILED=1
fi

if [[ $FAILED -ne 0 ]]; then
    echo "SECURITY CHECKS FAILED"
    exit 1
fi
echo "SECURITY CHECKS PASSED (existing lint debt remains recorded in the baseline)"
