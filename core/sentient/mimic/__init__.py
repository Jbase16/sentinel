"""
Project MIMIC - The Source Reconstructor

Grey-box visibility through client-side asset analysis. This module reverse engineers
JavaScript bundles, Source Maps, and frontend code to discover hidden routes and
secrets that aren't documented in public APIs.

THREAT MODEL (Defensive Framing):
This module helps organizations:
- Identify exposed secrets in client-side code
- Find hidden/debug endpoints that shouldn't be public
- Audit their own frontend code for leaked credentials
- Test source map hygiene during red team exercises

SAFETY CONSTRAINTS:
- All downloads are read-only (no modification of target assets)
- Respect robots.txt and rate limits
- No execution of downloaded JavaScript code
- Results are for authorized security assessments only

INTEGRATION POINTS:
- EventBus: Emits MIMIC_DOWNLOAD, MIMIC_PARSE events
- DecisionLedger: Logs asset analysis decisions
- KnowledgeGraph: Stores hidden route relationships
"""

from core.sentient.mimic.downloader import (
    AssetDownloader,
    AssetManifest,
    DownloadedAsset,
    AssetType,
    SAFE_MODE,
    create_asset_downloader,
)
from core.sentient.mimic.ast_parser import (
    ASTParser,
    ASTNode,
    RouteDefinition,
    SecretFinding,
    NodeType,
    SecretType,
    ParseResult,
    SAFE_MODE as AST_SAFE_MODE,
    create_ast_parser,
)
from core.sentient.mimic.route_miner import (
    RouteMiner,
    HiddenRoute,
    RouteReport,
    HiddenRouteReason,
    RiskLevel,
    SAFE_MODE as MINER_SAFE_MODE,
    create_route_miner,
)

# Export SAFE_MODE from downloader as the module-level constant
SAFE_MODE = SAFE_MODE

__all__ = [
    # Downloader
    "AssetDownloader",
    "AssetManifest",
    "DownloadedAsset",
    "AssetType",
    # AST Parser
    "ASTParser",
    "ASTNode",
    "RouteDefinition",
    "SecretFinding",
    "NodeType",
    "SecretType",
    "ParseResult",
    # Route Miner
    "RouteMiner",
    "HiddenRoute",
    "RouteReport",
    "HiddenRouteReason",
    "RiskLevel",
    # Factory Functions
    "create_asset_downloader",
    "create_ast_parser",
    "create_route_miner",
    # Safety
    "SAFE_MODE",
]
