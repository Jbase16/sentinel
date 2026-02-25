# Scan Failure Root Cause Analysis

## Executive Summary

**Problem:** Sentinel returns 0 findings when scanning intentionally vulnerable targets
**Root Cause:** CAL EvidenceGates law logic error prevents all vulnerability scanning tools from executing
**Fix:** Corrected the gate-checking logic from "list membership" to "all elements present"

---

## Detailed Analysis

### What Happened

When you ran Sentinel against the custom vulnerable target (`http://localhost:3002`), the scan completed with 0 findings. The log showed:

```
[Scan] started: http://localhost:3002 (0 tools)
tool_selection → Selected 2 tools for intent_passive_recon
tool_selection → Selected 2 tools for intent_active_live (rejected 5)
tool_selection → Selected 2 tools for intent_surface_enum (rejected 3)
tool_selection → Selected 0 tools for intent_vuln_scan (rejected 2)  ← CRITICAL
tool_selection → No tools available or all tools blocked
early_termination → All intents exhausted, scan complete
```

**Key Observation:** `intent_vuln_scan` selected 0 tools (rejected 2)

This meant:
1. Tool selection ran ✓
2. Phase transitions happened ✓
3. **Tool execution never occurred** ✗
4. No findings were produced ✗

---

## The Bug

### Location

**File:** `assets/laws/constitution.cal`
**Lines:** 11-16

### Original Code (BROKEN)

```cal
Law EvidenceGates {
    Claim: "Tools require prerequisite evidence"
    When: tool.gates IS NOT EMPTY
    And:  tool.gates NOT IN context.knowledge.tags  # ← BUG
    Then: DENY "Missing Prerequisite: {tool.gates}"
}
```

### Why It Failed

1. **Vulnerability scanning tools** (nuclei, nikto, jaeles, wfuzz) all have:
   ```python
   "gates": ["protocol:http", "protocol:https"]
   ```

2. **Context is correctly seeded** with required tags (strategos.py:238-239):
   ```python
   existing_tags.update({"protocol:http", "protocol:https"})
   self.context.knowledge["tags"] = existing_tags
   ```

3. **The CAL condition fails** because:

   **In CAL:**
   ```cal
   tool.gates NOT IN context.knowledge.tags
   ```

   **Translates to Python:**
   ```python
   tool.gates not in context.knowledge.tags
   # Evaluates to: ("protocol:http", "protocol:https") not in {"protocol:http", "protocol:https"}
   # Result: True (the tuple is not an element of the set)
   ```

   **The Problem:**
   - `tool.gates` becomes a tuple: `("protocol:http", "protocol:https")`
   - `context.knowledge.tags` is a set: `{"protocol:http", "protocol:https"}`
   - The `not in` operator checks if the **entire tuple** is a member of the set
   - This always returns `True` → Law triggers → `DENY` verdict → Tool blocked

### Type Mismatch Details

**From core/cal/parser.py:88:**
```python
# Lists are converted to tuples for hashability
if isinstance(val, list):
    return tuple(val)
```

So `tool.gates = ["protocol:http", "protocol:https"]` becomes `("protocol:http", "protocol:https")`.

The check `tuple not in set` asks: "Is this tuple an element of the set?"
Answer: No → Condition passes → DENY fires → Tool blocked.

---

## The Fix

### Corrected Code

```cal
Law EvidenceGates {
    Claim: "Tools require prerequisite evidence"
    When: tool.gates IS NOT EMPTY
    And:  not all(gate in context.knowledge.tags for gate in tool.gates)
    Then: DENY "Missing Prerequisite: {tool.gates}"
}
```

### How It Works Now

**Python equivalent:**
```python
# Check if all required gates are present in the context tags
not all(gate in context.knowledge.tags for gate in tool.gates)
```

**Example evaluation:**
```python
gates = ("protocol:http", "protocol:https")
tags = {"protocol:http", "protocol:https"}

# New logic
not all(gate in tags for gate in gates)
# → not all([True, True])
# → not True
# → False (condition fails, law doesn't trigger, tool is ALLOWED)
```

---

## Why This Passed Silently

1. **No Logging of Policy Vetoes:** The rejection decision was recorded but the specific policy reason wasn't surfaced clearly in logs

2. **Opaque Veto Messages:** Log showed `"Policy Veto: ArbitrationEngine"` without details about which law triggered

3. **No Tool Execution Logging:** Since tools were blocked during selection, no "Executing tool X" messages appeared

4. **Clean Termination:** Strategos completed all phases cleanly, making it look like a successful scan with no findings

---

## Impact

### What Was Blocked

**All Phase 4 (Vulnerability Scanning) tools:**
- nuclei
- nikto
- jaeles
- wfuzz
- Any other tool with gates

**Result:** Zero vulnerability detection capability

### What Still Ran

**Phase 1 (Passive Recon):**
- subfinder, assetfinder, dnsx, hakrevdns
- These have no gates, so they passed

**Phase 2 (Active Live Check):**
- Some tools like httpx, httprobe
- But tools with protocol gates (whatweb, wafw00f, sslyze, testssl) were also blocked

**Phase 3 (Surface Enumeration):**
- nmap (no gates)
- But directory bruteforcers with gates (feroxbuster, gobuster, dirsearch) were blocked

---

## Additional Issues Found

### 1. Missing Tool Execution Logging

**Location:** `core/engine/runner.py` or wherever tools are executed

**Problem:** No log lines like:
```
[Runner] Executing nuclei against http://localhost:3002
[Runner] nuclei started (PID 12345)
[Runner] nuclei completed with exit code 0
```

**Recommendation:** Add comprehensive tool lifecycle logging:
```python
logger.info(f"[ToolRunner] Starting {tool_name} (intent: {intent})")
logger.info(f"[ToolRunner] Command: {' '.join(cmd)}")
logger.info(f"[ToolRunner] {tool_name} completed in {duration}s with {len(findings)} findings")
```

### 2. Opaque Policy Vetoes

**Location:** `core/scheduler/strategos.py:626`

**Current:**
```python
if judgment.verdict == Verdict.VETO:
    rejected_count += 1
    reason = f"Policy Veto: {judgment.policy_name}"
    reasons.setdefault(reason, []).append(t)
```

**Problem:** Doesn't log **why** the tool was blocked

**Recommendation:**
```python
if judgment.verdict == Verdict.VETO:
    rejected_count += 1
    reason = f"Policy Veto: {judgment.policy_name}"
    reasons.setdefault(reason, []).append(t)
    # ADD THIS:
    logger.warning(
        f"[Strategos] Tool {t} blocked by {judgment.policy_name}: {judgment.reason}"
    )
```

### 3. No Sanity Checks for Target Reachability

**Problem:** Sentinel never verified that `http://localhost:3002` is actually reachable

**Recommendation:** Add pre-scan validation:
```python
async def validate_target(target: str) -> bool:
    """Verify target is reachable before starting scan."""
    try:
        response = await httpx.get(target, timeout=5.0)
        logger.info(f"[Validator] Target {target} is reachable (status: {response.status_code})")
        return True
    except Exception as e:
        logger.error(f"[Validator] Target {target} unreachable: {e}")
        return False
```

### 4. Tool Installation Not Verified

**Location:** Scan startup

**Problem:** No verification that nuclei, nikto, etc. are actually installed

**Recommendation:** Check tool availability before scan:
```python
def verify_tools_installed(required_tools: List[str]) -> Dict[str, bool]:
    """Check which tools are available on system."""
    installed = {}
    for tool in required_tools:
        installed[tool] = shutil.which(tool) is not None

    missing = [t for t, avail in installed.items() if not avail]
    if missing:
        logger.warning(f"[Validator] Missing tools: {', '.join(missing)}")

    return installed
```

---

## How to Verify the Fix

### 1. Check CAL Parse

```bash
# Verify the law parses correctly
python -c "
from core.cal.parser import CALParser
parser = CALParser()
laws = parser.parse_file('assets/laws/constitution.cal')
for law in laws:
    if law.name == 'EvidenceGates':
        print(f'Law: {law.name}')
        print(f'Conditions: {[c.raw_expression for c in law.conditions]}')
        print(f'Action: {law.action.verb} - {law.action.reason_template}')
"
```

**Expected Output:**
```
Law: EvidenceGates
Conditions: ['tool.gates IS NOT EMPTY', 'not all(gate in context.knowledge.tags for gate in tool.gates)']
Action: DENY - Missing Prerequisite: {tool.gates}
```

### 2. Test Gate Logic

```python
# Simulate the corrected logic
gates = ("protocol:http", "protocol:https")
tags = {"protocol:http", "protocol:https"}

# Should be False (law doesn't trigger, tool allowed)
result = not all(gate in tags for gate in gates)
assert result == False, "Gate check should pass"

# Test with missing gate
tags_incomplete = {"protocol:http"}
result = not all(gate in tags_incomplete for gate in gates)
assert result == True, "Gate check should fail when tags missing"
```

### 3. Run Scan Against Target

```bash
# Start your custom lab if needed

# Run Sentinel
curl -X POST "http://127.0.0.1:8765/v1/scans/start" \
     -H "Content-Type: application/json" \
     -d '{"target": "http://localhost:3002", "mode": "comprehensive"}'

# Expected: Should now detect vulnerabilities
```

### 4. Check Logs for Tool Execution

Look for lines like:
```
[Strategos] Dispatching: nuclei (1/3)
[Strategos] ✓ nuclei complete. Findings: 15
[Strategos] Dispatching: nikto (2/3)
[Strategos] ✓ nikto complete. Findings: 8
```

If you still see `Selected 0 tools for intent_vuln_scan`, the fix didn't take effect.

---

## Recommendations

### Immediate (Critical)

1. ✅ **Fix EvidenceGates logic** (DONE)
2. **Add tool execution logging** to runner.py
3. **Log detailed veto reasons** in strategos.py
4. **Add target reachability check** before scan
5. **Verify tool installation** during initialization

### Short-Term (High Priority)

1. **Unit tests for CAL conditions** - Especially gate-checking logic
2. **Integration test:** Scan deliberately vulnerable target, assert findings > 0
3. **Policy veto telemetry:** Emit structured events for blocked tools
4. **Scan validation:** Fail early if no tools can run
5. **Better error messages:** "0 findings" should trigger warning if target was vulnerable

### Medium-Term (Nice to Have)

1. **CAL syntax improvements:** Support native `all()` / `any()` operators
2. **Visual policy debugger:** Show which laws blocked which tools
3. **Dry-run mode:** Show what would run without executing
4. **Gate suggestions:** "Tool X requires gates: Y, Z (you have: A, B)"
5. **Automated CAL testing:** Validate laws on every constitution change

---

## Lessons Learned

### 1. Silent Failures Are Dangerous

**Problem:** Tool blocking was silent—scan "completed successfully" with 0 findings

**Solution:** Explicit warnings when:
- 0 tools selected for an intent
- 0 findings after scanning a target
- All tools blocked by policy

### 2. Type Mismatches in DSLs

**Problem:** CAL list→tuple conversion broke `in` operator semantics

**Solution:**
- Preserve list types when semantics matter
- Document type conversions clearly
- Add type-aware operators (`ALL_IN`, `ANY_IN`)

### 3. Observability Gaps

**Problem:** No logging between "tool selected" and "scan complete"

**Solution:** Log every state transition:
- Tool selection → Tool dispatch → Tool execution → Tool completion → Finding ingestion

### 4. Test Coverage Blindspot

**Problem:** No test caught "vuln scanning always blocked"

**Solution:** Add integration test:
```python
def test_vulnerability_scanning_executes():
    """Ensure vuln scanning tools actually run"""
    results = scan("http://localhost:3002")
    assert results["tools_executed"]["nuclei"] == True
    assert results["findings_count"] > 0
```

---

## Expected Behavior After Fix

### Phase Progression

```
Phase 1: Passive Recon
  ✓ subfinder (found subdomains)
  ✓ dnsx (resolved IPs)

Phase 2: Active Live Check
  ✓ httpx (confirmed 1 live HTTP target)
  ✓ whatweb (identified Tech Stack)
  ✓ wafw00f (WAF check)

Phase 3: Surface Enumeration
  ✓ nmap (found ports 3002, 22, 5000)
  ✓ feroxbuster (discovered endpoints)

Phase 4: Vulnerability Scanning  ← THIS SHOULD NOW RUN
  ✓ nuclei (detected vulnerabilities)
  ✓ nikto (server config issues)

Phase 5: Heavy Artillery
  ✓ masscan (deep port scan)
```

### Expected Findings (Custom Target)

Based on your target structure:
- **Exposed Git Config:** `.git/config` (Status 200)
- **Directory Listing:** `/admin` (403), `/login` (405)
- **Open Ports:** 22 (SSH), 5000 (RTSP), 5432 (Postgres), 5900 (VNC)
- **Missing Headers:** HSTS, CSP
- **SSRF Indicators:** Potentially via `http://localhost:3002` access

---

## File: `/Users/jason/Developer/sentinelforge/assets/laws/constitution.cal`

**Status:** ✅ FIXED (2026-01-09) - **TWO FIXES APPLIED**

### Fix #1: Correct Gate Logic (Initial Fix)
```diff
 Law EvidenceGates {
     Claim: "Tools require prerequisite evidence"
     When: tool.gates IS NOT EMPTY
-    And:  tool.gates NOT IN context.knowledge.tags
+    And:  not all(gate in context.knowledge.tags for gate in tool.gates)
     Then: DENY "Missing Prerequisite: {tool.gates}"
 }
```

**Problem:** Checked if entire tuple was a set member (type mismatch)
**Result:** Tools executed but CAL evaluation failed

### Fix #2: Eval Scope Fix (Final Fix)
```diff
 Law EvidenceGates {
     Claim: "Tools require prerequisite evidence"
     When: tool.gates IS NOT EMPTY
-    And:  not all(gate in context.knowledge.tags for gate in tool.gates)
+    And:  not all([gate in context.knowledge.tags for gate in tool.gates])
     Then: DENY "Missing Prerequisite: {tool.gates}"
 }
```

**Problem:** Generator expressions create their own scope in `eval()`, making `context` undefined
**Solution:** Changed to list comprehension (added square brackets) which evaluates in current scope
**Result:** ✅ CAL evaluation works correctly, no errors

### Verification Test Results
```
Test 1: Tool with all gates satisfied (nuclei)
  Tool gates: ['protocol:http', 'protocol:https']
  Context tags: {'protocol:http', 'protocol:https'}
  ✅ PASS: Law did not trigger (tool ALLOWED)

Test 2: Tool without gates (nmap)
  Tool gates: []
  ✅ PASS: Law did not trigger (tool ALLOWED)

Test 3: Tool with missing gates (testssl)
  Tool gates: ['protocol:https', 'ssl:enabled']
  Context tags: {'protocol:http', 'protocol:https'}
  Missing: ssl:enabled
  ✅ PASS: Law triggered (tool correctly DENIED)
```

**Git Commit:**
```bash
git add assets/laws/constitution.cal
git commit -m "fix(cal): correct EvidenceGates eval scope issue

The law used a generator expression which creates its own scope in eval(),
causing 'context' to be undefined. Changed to list comprehension which
evaluates in the current scope with access to safe_scope variables.

Fixes: #cal-eval-scope-error
Fixes: #0-findings-bug"
```

---

## Contact

If the fix doesn't work or you see other issues, check:
1. Restart Sentinel to reload CAL policies
2. Verify Target lab is running
3. Check logs for "Executing tool" or "Tool blocked" messages
4. Run with debug logging: `export LOG_LEVEL=DEBUG`
