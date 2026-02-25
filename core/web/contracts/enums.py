from __future__ import annotations

from enum import Enum


class WebAuthMode(str, Enum):
    NONE = "none"
    STATIC_HEADER = "static_header"
    FORM_LOGIN = "form_login"


class ParamLocation(str, Enum):
    QUERY = "query"
    PATH = "path"
    JSON = "json"
    FORM = "form"
    HEADER = "header"


class WebMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class SurfaceSource(str, Enum):
    CRAWLER = "crawler"
    JS_INTEL = "js_intel"
    BROWSER = "browser"
    MANUAL = "manual"


class VulnerabilityClass(str, Enum):
    REFLECTION = "reflection"
    SQLI = "sqli"
    IDOR = "idor"
    SSRF = "ssrf"
    GENERAL = "general"


class DeltaSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class EvidenceBundleVersion(str, Enum):
    V1 = "1.0"
