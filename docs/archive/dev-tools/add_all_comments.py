#
# PURPOSE:
# This module is part of the sentinelforge package in SentinelForge.
# [Specific purpose based on module name: add_all_comments]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#
#
# PURPOSE:
# High-level strategic planning for security scans. Named after Greek "strategos"
# (military general), this module decides WHAT to scan and WHEN.
#
# WHAT STRATEGOS DOES:
# - Analyzes target to determine appropriate scanning strategy
# - Selects which tools to run based on target characteristics
# - Sequences tool execution for maximum efficiency
# - Adapts strategy based on intermediate findings
# - Manages resource allocation (rate limiting, parallelization)
#
# STRATEGIC DECISIONS:
# - Passive vs. Active: When to stay quiet vs. make noise
# - Breadth vs. Depth: Scan many targets shallowly or few deeply
# - Tool Selection: Use nmap for ports, httpx for web, etc.
# - Timing: Sequential (slow, stealthy) vs. Parallel (fast, noisy)
#
# KEY CONCEPTS:
# - **Strategy**: High-level plan (what and when to scan)
# - **Tactics**: Low-level execution (how to run each tool)
# - **Adaptive Planning**: Adjust strategy based on discoveries
#
#
# PURPOSE:
# Translates high-level user intent ("find SQLi vulns") into concrete scan tasks.
# Maps goals to actionable tool executions.
#
# INTENT TYPES:
# - **Reconnaissance**: "Map the attack surface"
# - **Vulnerability Discovery**: "Find security flaws"
# - **Exploitation**: "Validate vulnerabilities"
# - **Post-Exploitation**: "Assess impact of compromise"
#
# INTENT → ACTION MAPPING:
# - "Find SQLi" → Run sqlmap on discovered forms
# - "Check for XSS" → Fuzz input fields with XSS payloads
# - "Discover subdomains" → Run subfinder, amass, crt.sh
# - "Map API endpoints" → Use proxy mode + crawler
#
# KEY CONCEPTS:
# - **Intent Recognition**: Understanding what user wants
# - **Task Decomposition**: Breaking goals into tool executions
# - **Context Awareness**: Different intents for web vs. infrastructure
#

""",
}

# Add headers for all remaining significant file types
def should_annotate(filepath: Path) -> bool:
    """Determine if a file should be annotated."""
    # Skip system/build files
    if any(x in str(filepath) for x in [".venv", "__pycache__", ".build", ".pytest_cache", "node_modules"]):
        return False
    
    # Only Python and Swift
    if filepath.suffix not in [".py", ".swift"]:
        return False
    
    # Check if already has comprehensive header
    try:
        content = filepath.read_text()
        # Look for our header format
        if "============================================================================" in content[:500]:
            return False  # Already annotated
    except:
        return False
    
    return True

def generate_header(filepath: Path) -> str:
    """Generate appropriate header for a file based on its path and content."""
    rel_path = filepath.relative_to(BASE_DIR)
    
    # Check if we have a custom header
    for key, header in HEADERS.items():
        if str(rel_path) == key:
            return header
    
    # Generate generic but informative header based on path
    module_name = filepath.stem
    package = filepath.parent.name
    
    if filepath.suffix == ".py":
        return f"""# ============================================================================
# {rel_path}
# {module_name.replace('_', ' ').title()} Module
# ============================================================================
#
# PURPOSE:
# This module is part of the {package} package in SentinelForge.
# [Specific purpose based on module name: {module_name}]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#
# ============================================================================

"""
    elif filepath.suffix == ".swift":
        return f"""// ============================================================================
// {rel_path}
// {module_name.replace('_', ' ').title()} Component
// ============================================================================
//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: {module_name}]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//
// ============================================================================

"""
    return ""

def annotate_file(filepath: Path):
    """Add educational header to file."""
    try:
        header = generate_header(filepath)
        if not header:
            return False
            
        content = filepath.read_text()
        new_content = header + content
        filepath.write_text(new_content)
        return True
    except Exception as e:
        print(f"Error: {filepath}: {e}", file=sys.stderr)
        return False

def main():
    """Function main."""
    annotated = 0
    skipped = 0
    
    # Find all files
    all_files = list(BASE_DIR.glob("**/*.py")) + list(BASE_DIR.glob("**/*.swift"))
    
    for filepath in all_files:
        if should_annotate(filepath):
            if annotate_file(filepath):
                print(f"✅ {filepath.relative_to(BASE_DIR)}")
                annotated += 1
        else:
            skipped += 1
    
    print(f"\n📊 Summary: {annotated} files annotated, {skipped} skipped")

if __name__ == "__main__":
    main()
