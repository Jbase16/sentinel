# ============================================================================
# core/payloads/__init__.py
# Payloads Package - Attack Payload Library
# ============================================================================
#
# PURPOSE:
# Provides a library of attack payloads for testing various vulnerability types.
# Think of this as an arsenal of test cases for penetration testing.
#
# WHAT ARE PAYLOADS:
# Payloads are specific inputs designed to trigger vulnerabilities:
# - **XSS**: <script>alert(document.cookie)</script>
# - **SQLi**: ' OR '1'='1-- 
# - **Command Injection**: ; cat /etc/passwd
# - **Path Traversal**: ../../../../etc/passwd
# - **XXE**: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
#
# PAYLOAD CATEGORIES:
# - **Detection**: Triggers observable behavior (alert box, time delay)
# - **Extraction**: Retrieves sensitive data (database contents, files)
# - **Denial-of-Service**: Causes resource exhaustion or crashes
# - **Code Execution**: Runs arbitrary code on the server
#
# WHY A LIBRARY:
# - Curated collection of proven payloads
# - WAF evasion variants (encoded, obfuscated)
# - Context-specific payloads (different for MySQL vs. PostgreSQL)
# - Continuously updated with new techniques
#
# KEY CONCEPTS:
# - **Payload**: Malicious input designed to exploit a vulnerability
# - **WAF Evasion**: Techniques to bypass web application firewalls
# - **Context**: Payloads must be tailored to where they're used (HTML vs. SQL vs. OS)
#
# ============================================================================
