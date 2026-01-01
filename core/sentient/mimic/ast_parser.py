"""
MIMIC AST Parser - Source Code Structure Analysis

PURPOSE:
Parse JavaScript/WebAssembly/Source Maps using Abstract Syntax Tree (AST) to
reconstruct application structure and identify route definitions, API endpoints,
and hardcoded secrets.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Identify hardcoded secrets in client-side code
- Find hidden/debug endpoints in source
- Audit their own code for leaked credentials
- Test code hygiene during red team exercises

ASSUMPTIONS:
1. JavaScript can be parsed (even if minified/obfuscated)
2. Route definitions follow common patterns
3. Source Maps provide accurate source mappings
4. No code execution is performed (parsing only)

SAFETY CONSTRAINTS:
- SAFE_MODE: If True, refuses to execute any JavaScript code
- Parsing only - no eval() or code execution
- No modification of downloaded assets
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits MIMIC_PARSE_STARTED, MIMIC_ROUTE_FOUND events
- DecisionLedger: Logs parsing decisions and confidence
- KnowledgeGraph: Stores extracted route relationships

DEPENDENCIES (Future):
- esprima-python: JavaScript AST parser
- ast: Built-in Python AST for Python-like analysis
- regex: For pattern-based extraction when AST fails
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

# Safety fuse: prevents unsafe operations
SAFE_MODE: bool = True

logger = logging.getLogger(__name__)


class NodeType(str, Enum):
    """
    Types of AST nodes that can be extracted.

    These represent different kinds of code structures that may
    contain security-relevant information.
    """
    FUNCTION_DECLARATION = "function_declaration"
    ARROW_FUNCTION = "arrow_function"
    VARIABLE_DECLARATION = "variable_declaration"
    OBJECT_EXPRESSION = "object_expression"
    CALL_EXPRESSION = "call_expression"
    STRING_LITERAL = "string_literal"
    TEMPLATE_LITERAL = "template_literal"
    REGEX_LITERAL = "regex_literal"
    COMMENT = "comment"
    IMPORT_STATEMENT = "import_statement"
    EXPORT_STATEMENT = "export_statement"


class SecretType(str, Enum):
    """
    Types of secrets that may be found in source code.

    These are patterns that security professionals look for when
    auditing code for credential leakage.
    """
    API_KEY = "api_key"               # OpenAI, Stripe, etc.
    AWS_KEY = "aws_key"               # AWS access keys
    JWT_SECRET = "jwt_secret"         # JWT signing keys
    DATABASE_URL = "database_url"     # Connection strings
    PRIVATE_KEY = "private_key"       # Crypto keys
    PASSWORD = "password"             # Hardcoded passwords
    TOKEN = "token"                   # Auth tokens
    WEBHOOK_URL = "webhook_url"       # Webhook endpoints
    EMAIL = "email"                   # Email addresses
    IP_ADDRESS = "ip_address"         # IP addresses
    UNKNOWN = "unknown"               # Other sensitive patterns


@dataclass
class ASTNode:
    """
    A node in the Abstract Syntax Tree.

    Attributes:
        node_type: What kind of node this is
        value: The literal value (if applicable)
        children: Child nodes
        line_number: Source line number
        column: Source column position
        source_file: Origin file (if from Source Map)
    """
    node_type: NodeType
    value: Optional[str] = None
    children: List["ASTNode"] = field(default_factory=list)
    line_number: Optional[int] = None
    column: Optional[int] = None
    source_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize node to dict."""
        return {
            "node_type": self.node_type.value,
            "value": self.value,
            "line_number": self.line_number,
            "column": self.column,
            "source_file": self.source_file,
            "child_count": len(self.children),
        }


@dataclass
class RouteDefinition:
    """
    A route definition extracted from source code.

    Attributes:
        path: The route path (e.g., "/api/v1/users")
        method: HTTP method (GET, POST, etc.)
        handler: Name of the handler function
        parameters: List of parameter names
        middleware: List of middleware functions
        line_number: Where this was defined
        source_file: Which file this came from
        is_hidden: Whether this appears to be hidden/debug
    """
    path: str
    method: str = "GET"
    handler: Optional[str] = None
    parameters: List[str] = field(default_factory=list)
    middleware: List[str] = field(default_factory=list)
    line_number: Optional[int] = None
    source_file: Optional[str] = None
    is_hidden: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize route to dict."""
        return {
            "path": self.path,
            "method": self.method,
            "handler": self.handler,
            "parameters": self.parameters,
            "middleware": self.middleware,
            "line_number": self.line_number,
            "source_file": self.source_file,
            "is_hidden": self.is_hidden,
        }

    @property
    def signature(self) -> str:
        """Get unique signature for this route."""
        return f"{self.method}:{self.path}"


@dataclass
class SecretFinding:
    """
    A potential secret found in source code.

    Attributes:
        secret_type: What kind of secret this is
        value: The actual secret value
        context: Surrounding code for verification
        line_number: Where this was found
        source_file: Which file this came from
        confidence: How confident we are (0.0-1.0)
        false_positive_risk: Risk this is a false positive
    """
    secret_type: SecretType
    value: str
    context: str
    line_number: int
    source_file: str
    confidence: float = 0.5
    false_positive_risk: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        """Serialize finding to dict (with redacted value)."""
        return {
            "secret_type": self.secret_type.value,
            "value": self._redact_value(),
            "context": self.context,
            "line_number": self.line_number,
            "source_file": self.source_file,
            "confidence": self.confidence,
            "false_positive_risk": self.false_positive_risk,
        }

    def _redact_value(self) -> str:
        """Redact secret value for logging/storage."""
        if len(self.value) <= 8:
            return "***"
        return self.value[:4] + "***" + self.value[-4:]


@dataclass
class ParseResult:
    """
    Result of parsing a JavaScript/Source Map file.

    Attributes:
        source_file: Original file path/URL
        ast_root: Root of the AST (if successfully parsed)
        routes: All route definitions found
        secrets: All potential secrets found
        imports: All import statements
        exports: All export statements
        parse_errors: Any parsing errors encountered
        parsed_at: When this parsing was performed
    """
    source_file: str
    ast_root: Optional[ASTNode] = None
    routes: List[RouteDefinition] = field(default_factory=list)
    secrets: List[SecretFinding] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)
    parsed_at: datetime = field(default_factory=lambda: datetime.utcnow())

    def to_dict(self) -> Dict[str, Any]:
        """Serialize result to dict."""
        return {
            "source_file": self.source_file,
            "route_count": len(self.routes),
            "secret_count": len(self.secrets),
            "import_count": len(self.imports),
            "export_count": len(self.exports),
            "parse_errors": self.parse_errors,
            "parsed_at": self.parsed_at.isoformat(),
            # Routes and secrets included separately
        }


class ASTParser:
    """
    Parses JavaScript/Source Map files to extract structure.

    This class performs static analysis on frontend code without
    executing it. It identifies:
    - Route definitions
    - API endpoint strings
    - Hardcoded secrets
    - Import/export dependencies

    PARSING STRATEGY:
    1. Try AST parsing with esprima
    2. Fall back to regex-based extraction
    3. Use Source Maps for original source references
    4. Apply heuristics for common frameworks

    EXAMPLE USAGE:
        ```python
        parser = ASTParser()
        asset = DownloadedAsset(...)
        result = await parser.parse_js_file(asset.content)
        print(f"Found {len(result.routes)} routes")
        ```
    """

    # Event names for integration with EventBus
    EVENT_PARSE_STARTED = "mimic_parse_started"
    EVENT_PARSE_COMPLETED = "mimic_parse_completed"
    EVENT_ROUTE_FOUND = "mimic_route_found"
    EVENT_SECRET_FOUND = "mimic_secret_found"

    # Regex patterns for fallback extraction
    ROUTE_PATTERNS = [
        r'["\'](/[/\w-\{\}]+)["\']',  # "/api/users"
        r'path:\s*["\']([^"\']+)["\']',  # path: "/api/users"
        r'router\.(get|post|put|delete)\(["\']([^"\']+)["\']',  # router.get("/path")
    ]

    SECRET_PATTERNS = {
        SecretType.API_KEY: [
            r'(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
            r'sk-[a-zA-Z0-9]{32,}',  # Stripe keys
        ],
        SecretType.AWS_KEY: [
            r'(AWS[_-]?KEY[_-]?ACCESS[_-]?KEY|aws_access_key_id)["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
        ],
        SecretType.JWT_SECRET: [
            r'(JWT[_-]?SECRET|jwt[_-]?secret)["\']?\s*[:=]\s*["\']([^"\']{16,})["\']',
        ],
        SecretType.DATABASE_URL: [
            r'(DATABASE[_-]?URL|db[_-]?url|connectionString)["\']?\s*[:=]\s*["\']((postgres|mysql|mongodb)://[^"\']+)["\']',
        ],
    }

    def __init__(self, safe_mode: bool = SAFE_MODE):
        """
        Initialize ASTParser.

        Args:
            safe_mode: If True, refuses to execute any code
        """
        self._safe_mode = safe_mode
        self._parse_count = 0

    @property
    def safe_mode(self) -> bool:
        """Check if operating in safe mode."""
        return self._safe_mode

    @property
    def parse_count(self) -> int:
        """Get number of parses performed."""
        return self._parse_count

    async def parse_js_file(
        self,
        content: str | bytes,
        source_file: str = "unknown"
    ) -> ParseResult:
        """
        Parse a JavaScript file and extract routes and secrets.

        TODO: Implement AST parsing with esprima.
        TODO: Implement regex-based fallback extraction.
        TODO: Detect common framework patterns (React, Vue, Angular).
        TODO: Parse webpack chunk structure.

        Args:
            content: JavaScript source code
            source_file: File identifier for error reporting

        Returns:
            ParseResult with extracted information

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # Convert bytes to string if needed
        if isinstance(content, bytes):
            try:
                content = content.decode("utf-8")
            except UnicodeDecodeError:
                content = content.decode("latin-1")

        # Update statistics
        self._parse_count += 1

        # Emit event (integration point)
        logger.debug(
            f"[ASTParser] {self.EVENT_PARSE_STARTED}: file={source_file}"
        )

        # Create result skeleton
        ParseResult(source_file=source_file)

        raise NotImplementedError(
            "Wrapper-only: JavaScript parsing implementation deferred. "
            "Future implementation should use esprima or regex fallback."
        )

    def extract_routes(
        self,
        ast_root: ASTNode,
        source_file: str = "unknown"
    ) -> List[RouteDefinition]:
        """
        Extract route definitions from parsed AST.

        TODO: Traverse AST to find route definitions.
        TODO: Detect framework-specific patterns (Express, React Router).
        TODO: Identify parameters in route paths.
        TODO: Flag potentially hidden/debug routes.

        Args:
            ast_root: Root AST node
            source_file: File identifier

        Returns:
            List of RouteDefinition objects

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Route extraction deferred. "
            "Future implementation should traverse AST for route patterns."
        )

    def scan_secrets(
        self,
        content: str,
        source_file: str = "unknown"
    ) -> List[SecretFinding]:
        """
        Scan content for hardcoded secrets.

        TODO: Apply regex patterns for common secret types.
        TODO: Check entropy for potential keys.
        TODO: Validate context to reduce false positives.
        TODO: Calculate confidence scores.

        Args:
            content: Source code to scan
            source_file: File identifier

        Returns:
            List of SecretFinding objects

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        # In safe mode, warn before scanning
        if self._safe_mode:
            logger.warning(
                f"[ASTParser] SAFE_MODE: Secret scanning enabled for {source_file}"
            )

        raise NotImplementedError(
            "Wrapper-only: Secret scanning deferred. "
            "Future implementation should apply regex patterns with validation."
        )

    def parse_source_map(
        self,
        source_map_content: str | bytes,
        source_file: str = "unknown"
    ) -> ParseResult:
        """
        Parse a Source Map file to reconstruct original source structure.

        TODO: Parse Source Map JSON format.
        TODO: Extract source file mappings.
        TODO: Reconstruct original file structure.
        TODO: Map minified names to original names.

        Args:
            source_map_content: Source Map JSON content
            source_file: File identifier

        Returns:
            ParseResult with reconstructed structure

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Source Map parsing deferred. "
            "Future implementation should parse sourcemap JSON format."
        )

    def extract_params_from_code(
        self,
        route_code: str
    ) -> List[str]:
        """
        Extract parameter names from route handler code.

        TODO: Parse function parameters.
        TODO: Extract destructured object params.
        TODO: Identify query parameter references.

        Args:
            route_code: Handler function source code

        Returns:
            List of parameter names

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Parameter extraction deferred. "
            "Future implementation should parse function signatures."
        )

    def replay(self, recorded_parse: Dict[str, Any]) -> ParseResult:
        """
        Replay a previously parsed result for analysis.

        Enables replayability without re-parsing.

        Args:
            recorded_parse: Serialized ParseResult from to_dict()

        Returns:
            Reconstructed ParseResult

        Raises:
            NotImplementedError: This is a wrapper-only implementation
        """
        raise NotImplementedError(
            "Wrapper-only: Parse replay implementation deferred. "
            "Future implementation should deserialize from evidence store."
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for this ASTParser instance.

        Returns:
            Dictionary with parsing statistics
        """
        return {
            "parse_count": self._parse_count,
            "safe_mode": self._safe_mode,
        }


def create_ast_parser(safe_mode: bool = SAFE_MODE) -> ASTParser:
    """
    Factory function to create ASTParser instance.

    This is the recommended way to create ASTParser objects in production code.

    Args:
        safe_mode: Safety mode flag

    Returns:
        Configured ASTParser instance
    """
    return ASTParser(safe_mode=safe_mode)


# ============================================================================
# Module Self-Test (Design Verification)
# ============================================================================

if __name__ == "__main__":
    # Verify enums
    assert NodeType.FUNCTION_DECLARATION.value == "function_declaration"
    assert SecretType.API_KEY.value == "api_key"
    print("✓ Enums work")

    # Verify ASTNode dataclass
    node = ASTNode(
        node_type=NodeType.STRING_LITERAL,
        value="/api/users",
        line_number=42,
    )
    assert node.to_dict()["node_type"] == "string_literal"
    assert node.value == "/api/users"
    print("✓ ASTNode structure works")

    # Verify RouteDefinition dataclass
    route = RouteDefinition(
        path="/admin/debug",
        method="GET",
        is_hidden=True,
    )
    assert route.signature == "GET:/admin/debug"
    assert route.to_dict()["is_hidden"] is True
    print("✓ RouteDefinition structure works")

    # Verify SecretFinding redaction
    secret = SecretFinding(
        secret_type=SecretType.API_KEY,
        value="sk-1234567890abcdef",
        context="const key = 'sk-1234567890abcdef'",
        line_number=10,
        source_file="app.js",
    )
    assert "***" in secret._redact_value()
    assert secret.to_dict()["value"] == "sk-1***cdef"
    print("✓ SecretFinding redaction works")

    # Verify ASTParser creation
    parser = create_ast_parser()
    assert parser.safe_mode is True
    assert parser.parse_count == 0
    print("✓ ASTParser factory works")

    print("\n✅ All ASTParser design invariants verified!")
