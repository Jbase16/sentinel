"""
Simple verification script for URL validation logic.
This script tests the validation logic without importing the full module.
"""
import sys
from urllib.parse import urlparse


def validate_target(v: str) -> str:
    """Validate target URL (simplified version of ScanRequest.validate_target)."""
    v = v.strip()
    if not v:
        raise ValueError("Target cannot be empty")
    dangerous_patterns = [";", "&&", "||", "`", "$(", "\n", "\r"]
    for pattern in dangerous_patterns:
        if pattern in v:
            raise ValueError(f"Invalid character in target: {pattern}")
    
    # Validate URL format
    try:
        parsed = urlparse(v)
        if not parsed.scheme:
            raise ValueError("Invalid target URL: missing scheme (e.g., http:// or https://)")
        if not parsed.netloc:
            raise ValueError("Invalid target URL: missing network location")
        if parsed.scheme not in ("http", "https"):
            raise ValueError("Invalid target URL: scheme must be http or https")
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Invalid target URL: {str(e)}")
    
    return v


def test_url_validation():
    """Test URL validation logic."""
    test_cases = [
        # (input, should_pass, description)
        ("http://localhost:3002", True, "Valid HTTP URL"),
        ("https://example.com", True, "Valid HTTPS URL"),
        ("http:/localhost:3002", False, "Malformed URL with single slash (the original issue)"),
        ("localhost:3002", False, "Missing scheme"),
        ("ftp://example.com", False, "Invalid scheme (ftp)"),
        ("file:///etc/passwd", False, "Invalid scheme (file)"),
        ("http://", False, "Missing network location"),
        ("", False, "Empty target"),
        ("   ", False, "Whitespace-only target"),
        ("http://localhost:3002; rm -rf /", False, "Dangerous character (semicolon)"),
        ("http://example.com/path", True, "Valid URL with path"),
        ("http://example.com:8080", True, "Valid URL with port"),
        ("https://api.example.com", True, "Valid URL with subdomain"),
    ]
    
    passed = 0
    failed = 0
    
    print("\n=== URL Validation Test Results ===\n")
    
    for input_url, should_pass, description in test_cases:
        try:
            result = validate_target(input_url)
            if should_pass:
                print(f"✅ PASS: {description}")
                print(f"   Input: '{input_url}'")
                passed += 1
            else:
                print(f"❌ FAIL: {description}")
                print(f"   Input: '{input_url}'")
                print(f"   Expected to fail but passed with: '{result}'")
                failed += 1
        except ValueError as e:
            if not should_pass:
                print(f"✅ PASS: {description}")
                print(f"   Input: '{input_url}'")
                print(f"   Rejected with: {e}")
                passed += 1
            else:
                print(f"❌ FAIL: {description}")
                print(f"   Input: '{input_url}'")
                print(f"   Expected to pass but failed with: {e}")
                failed += 1
        print()
    
    print(f"=== Summary ===")
    print(f"Passed: {passed}/{len(test_cases)}")
    print(f"Failed: {failed}/{len(test_cases)}")
    
    return failed == 0


if __name__ == "__main__":
    success = test_url_validation()
    sys.exit(0 if success else 1)
