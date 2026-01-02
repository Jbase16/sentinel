#
# PURPOSE:
# Static analysis validator for AI-generated code.
# Treats AI like a "Malicious Intern" - nothing it writes is trusted.
#
# WHAT IT SCANS FOR:
# - System destruction commands (rm -rf /)
# - Reverse shells (socket + exec patterns)
# - Crypto mining indicators
# - Dangerous Python patterns (os.system, subprocess.shell=True)
# - Obfuscation indicators (base64 exec, high entropy)
#
# PHILOSOPHY:
# This is NOT a security sandbox. AI can obfuscate malicious code.
# This validation catches:
# - Obvious mistakes
# - Common malware patterns
# - Accidental dangerous output
#
# It does NOT protect against sophisticated malware.
# That's why we NEVER auto-execute and require human review.
#

import re
import ast
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional, Set, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk levels for detected patterns."""
    CRITICAL = "critical"  # Immediate system threat (rm -rf /, reverse shell)
    HIGH = "high"          # Dangerous but may be legitimate (subprocess.shell)
    MEDIUM = "medium"      # Suspicious but common (socket imports)
    LOW = "low"            # Just unusual (base64, exec)
    SAFE = "safe"          # No issues detected


@dataclass
class ValidationResult:
    """Result of code validation."""
    safe: bool
    risk_level: RiskLevel
    violations: List[Dict[str, str]]
    recommendations: List[str]
    
    def to_dict(self) -> Dict:
        return {
            "safe": self.safe,
            "risk_level": self.risk_level.value,
            "violations": self.violations,
            "recommendations": self.recommendations
        }


class ForbiddenPatterns:
    """
    Catalog of forbidden code patterns.
    
    Organized by risk level for graduated response.
    """
    
    # CRITICAL: Immediate rejection, no exceptions
    CRITICAL_PATTERNS = [
        # System destruction
        (r'rm\s+-rf\s+/', "System destruction: rm -rf /"),
        (r'shutil\.rmtree\s*\(\s*[\'\"]/[\'\"]', "System destruction: rmtree of root"),
        (r'os\.system\s*\(\s*[\'"]rm\s+-rf', "System destruction via os.system"),
        
        # Reverse shells
        (r'socket\.socket.*connect.*exec', "Reverse shell pattern"),
        (r'/bin/sh.*-i', "Interactive shell execution"),
        (r'bash\s+-i\s+>&\s+/dev/tcp', "Bash reverse shell"),
        (r'nc\s+-e\s+/bin', "Netcat reverse shell"),
        
        # Crypto mining
        (r'xmrig', "Crypto miner indicator: xmrig"),
        (r'monero', "Crypto miner indicator: monero"),
        (r'stratum\+tcp', "Mining pool connection"),
        
        # Ransomware indicators
        (r'\.encrypt\(.*\.read\(\)', "File encryption pattern"),
        (r'Fernet\(.*\)\.encrypt', "Symmetric encryption of files"),
    ]
    
    # HIGH: Reject by default, may allow with explicit flag
    HIGH_PATTERNS = [
        (r'subprocess\..*shell\s*=\s*True', "Shell injection risk: shell=True"),
        (r'os\.system\s*\(', "Unsafe command execution: os.system"),
        (r'os\.popen\s*\(', "Unsafe command execution: os.popen"),
        (r'eval\s*\(', "Code injection risk: eval()"),
        (r'exec\s*\(', "Code injection risk: exec()"),
        (r'__import__\s*\(', "Dynamic import may bypass security"),
        (r'compile\s*\(.*exec', "Dynamic code compilation"),
    ]
    
    # MEDIUM: Warning, allow with review
    MEDIUM_PATTERNS = [
        (r'import\s+socket', "Network socket usage"),
        (r'import\s+paramiko', "SSH library (may be legitimate)"),
        (r'import\s+ftplib', "FTP library (may be legitimate)"),
        (r'requests\..*verify\s*=\s*False', "SSL verification disabled"),
        (r'urllib.*context\s*=', "Custom SSL context"),
    ]
    
    # LOW: Informational, allow
    LOW_PATTERNS = [
        (r'base64\.b64decode', "Base64 decoding (common in exploits)"),
        (r'pickle\.loads', "Pickle deserialization (may be unsafe)"),
        (r'marshal\.loads', "Marshal deserialization"),
    ]


class CodeValidator:
    """
    Main validator class for AI-generated code.
    
    Usage:
        validator = CodeValidator()
        result = validator.validate(code)
        if not result.safe:
            for v in result.violations:
                print(f"[{v['level']}] {v['reason']}")
    """
    
    def __init__(self, strict_mode: bool = True):
        """
        Initialize validator.
        
        Args:
            strict_mode: If True, HIGH patterns cause rejection.
                        If False, only CRITICAL patterns cause rejection.
        """
        self.strict_mode = strict_mode
        self.max_code_size = 100_000  # 100KB max
        self.max_obfuscation_ratio = 0.3  # 30% special chars = suspicious
    
    def validate(self, code: str) -> ValidationResult:
        """
        Validate code for security issues.
        
        Returns:
            ValidationResult with safety status and details
        """
        violations = []
        recommendations = []
        
        # Basic sanity checks
        if not code or len(code.strip()) < 10:
            return ValidationResult(
                safe=False,
                risk_level=RiskLevel.CRITICAL,
                violations=[{"level": "critical", "reason": "Code too short or empty"}],
                recommendations=["Provide valid code"]
            )
        
        if len(code) > self.max_code_size:
            return ValidationResult(
                safe=False,
                risk_level=RiskLevel.CRITICAL,
                violations=[{"level": "critical", "reason": f"Code too large (>{self.max_code_size} bytes)"}],
                recommendations=["Split into smaller modules"]
            )
        
        # Pattern matching
        violations.extend(self._check_patterns(code, ForbiddenPatterns.CRITICAL_PATTERNS, "critical"))
        violations.extend(self._check_patterns(code, ForbiddenPatterns.HIGH_PATTERNS, "high"))
        violations.extend(self._check_patterns(code, ForbiddenPatterns.MEDIUM_PATTERNS, "medium"))
        violations.extend(self._check_patterns(code, ForbiddenPatterns.LOW_PATTERNS, "low"))
        
        # Obfuscation detection
        obfuscation_result = self._check_obfuscation(code)
        if obfuscation_result:
            violations.append(obfuscation_result)
        
        # AST analysis for deeper inspection
        ast_violations = self._analyze_ast(code)
        violations.extend(ast_violations)
        
        # Determine overall risk
        risk_level = self._calculate_risk_level(violations)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(violations)
        
        # Determine if safe
        safe = True
        if any(v["level"] == "critical" for v in violations):
            safe = False
        elif self.strict_mode and any(v["level"] == "high" for v in violations):
            safe = False
        
        return ValidationResult(
            safe=safe,
            risk_level=risk_level,
            violations=violations,
            recommendations=recommendations
        )
    
    def _check_patterns(
        self,
        code: str,
        patterns: List[Tuple[str, str]],
        level: str
    ) -> List[Dict[str, str]]:
        """Check code against pattern list."""
        violations = []
        for pattern, reason in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                violations.append({
                    "level": level,
                    "pattern": pattern[:50],
                    "reason": reason
                })
        return violations
    
    def _check_obfuscation(self, code: str) -> Optional[Dict[str, str]]:
        """Detect obfuscation via character analysis."""
        # Count hex escapes and unicode escapes
        hex_pattern = r'\\x[0-9a-fA-F]{2}'
        unicode_pattern = r'\\u[0-9a-fA-F]{4}'
        
        hex_count = len(re.findall(hex_pattern, code))
        unicode_count = len(re.findall(unicode_pattern, code))
        
        escape_ratio = (hex_count + unicode_count) / max(len(code), 1)
        
        if escape_ratio > self.max_obfuscation_ratio:
            return {
                "level": "high",
                "reason": f"High obfuscation ratio: {escape_ratio:.1%} escape sequences"
            }
        
        # Check for long single-line strings (often obfuscated payloads)
        for line in code.split('\n'):
            if len(line) > 1000 and not line.strip().startswith('#'):
                return {
                    "level": "medium",
                    "reason": f"Suspiciously long line: {len(line)} characters"
                }
        
        return None
    
    def _analyze_ast(self, code: str) -> List[Dict[str, str]]:
        """Use Python AST for deeper analysis."""
        violations = []
        
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Can't parse - might be intentionally broken
            violations.append({
                "level": "medium",
                "reason": "Syntax error in code - cannot parse for analysis"
            })
            return violations
        
        # Walk AST looking for dangerous patterns
        for node in ast.walk(tree):
            # Check for __builtins__ access
            if isinstance(node, ast.Attribute):
                if node.attr in ('__builtins__', '__globals__', '__code__'):
                    violations.append({
                        "level": "high",
                        "reason": f"Access to dangerous attribute: {node.attr}"
                    })
            
            # Check for suspicious function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ('eval', 'exec', 'compile'):
                        # Already caught by regex, but AST confirms it
                        pass
                    if node.func.id == 'open':
                        # Check for write mode to sensitive paths
                        for arg in node.args:
                            if isinstance(arg, ast.Constant):
                                path = str(arg.value)
                                if any(p in path for p in ['/etc/', '/root/', '/var/']):
                                    violations.append({
                                        "level": "high",
                                        "reason": f"Write to sensitive path: {path}"
                                    })
        
        return violations
    
    def _calculate_risk_level(self, violations: List[Dict]) -> RiskLevel:
        """Calculate overall risk level from violations."""
        levels = [v.get("level", "low") for v in violations]
        
        if "critical" in levels:
            return RiskLevel.CRITICAL
        elif "high" in levels:
            return RiskLevel.HIGH
        elif "medium" in levels:
            return RiskLevel.MEDIUM
        elif "low" in levels:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def _generate_recommendations(self, violations: List[Dict]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        if any("os.system" in str(v) for v in violations):
            recommendations.append("Replace os.system() with subprocess.run() with shell=False")
        
        if any("eval" in str(v) for v in violations):
            recommendations.append("Use ast.literal_eval() instead of eval() for data parsing")
        
        if any("shell=True" in str(v) for v in violations):
            recommendations.append("Use shell=False and pass args as list")
        
        if any("obfuscation" in str(v).lower() for v in violations):
            recommendations.append("De-obfuscate code before review")
        
        if not recommendations:
            recommendations.append("Manual code review recommended before execution")
        
        return recommendations


# Singleton instance
_validator = None

def get_validator(strict_mode: bool = True) -> CodeValidator:
    """Get the singleton validator instance."""
    global _validator
    if _validator is None:
        _validator = CodeValidator(strict_mode)
    return _validator


def validate_code(code: str, strict: bool = True) -> ValidationResult:
    """Convenience function for quick validation."""
    return get_validator(strict).validate(code)
