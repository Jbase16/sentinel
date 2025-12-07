from __future__ import annotations

import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

REGISTRY: Dict[str, Callable[[str], None]] = {}


def register(name: str) -> Callable[[Callable[[str], None]], Callable[[str], None]]:
    def decorator(func: Callable[[str], None]) -> Callable[[str], None]:
        REGISTRY[name] = func
        return func

    return decorator


def run_cli() -> None:
    if len(sys.argv) < 3:
        print("[shim] Usage: python -m core.tool_shims <tool> <target>", file=sys.stderr)
        sys.exit(1)
    tool = sys.argv[1]
    target = sys.argv[2]
    handler = REGISTRY.get(tool)
    if not handler:
        print(f"[shim] No handler registered for {tool}", file=sys.stderr)
        sys.exit(1)
    handler(target)


def _clean_host(raw: str) -> str:
    parsed = urlparse(raw if "://" in raw else f"//{raw}", scheme="https")
    host = parsed.hostname or raw
    return host.lower().strip("[]")


def _ensure_url(raw: str) -> str:
    if not raw:
        return raw
    if "://" not in raw:
        return f"https://{raw}"
    return raw


def _safe_request(url: str, method: str = "GET", data: bytes | None = None, headers: Dict[str, str] | None = None, timeout: int = 15, allow_insecure: bool = True) -> Tuple[int | None, str, Dict[str, str]]:
    req = urllib.request.Request(url, method=method)
    hdrs = headers or {}
    hdrs.setdefault("User-Agent", "AraUltra-Shim/1.0")
    for key, value in hdrs.items():
        req.add_header(key, value)

    context = ssl._create_unverified_context() if allow_insecure else None
    try:
        with urllib.request.urlopen(req, data=data, timeout=timeout, context=context) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            out_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, out_headers
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="ignore")
        out_headers = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
        return err.code, body, out_headers
    except Exception as exc:
        print(f"[shim] request error for {url}: {exc}", file=sys.stderr)
        return None, "", {}


def _tls_probe(host: str, port: int = 443) -> Dict[str, str | float | int]:
    info: Dict[str, str | float | int] = {"host": host, "port": port}
    context = ssl.create_default_context()
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                info["handshake_ms"] = (time.perf_counter() - start) * 1000
                info["protocol"] = ssock.version() or "unknown"
                cipher = ssock.cipher() or ("unknown", "", 0)
                info["cipher"] = cipher[0]
                info["cipher_bits"] = cipher[2] or 0
                cert = ssock.getpeercert()
                if cert:
                    info["cert_subject"] = dict(x[0] for x in cert.get("subject", []) if x).get("commonName", "")
                    info["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []) if x).get("commonName", "")
                    info["cert_not_after"] = cert.get("notAfter", "")
    except Exception as exc:
        info["error"] = str(exc)
    return info


def _print_json(data: Dict[str, object], prefix: str) -> None:
    print(f"[{prefix}] {json.dumps(data, default=str)}")


@register("testssl")
def shim_testssl(target: str) -> None:
    host = _clean_host(target)
    info = _tls_probe(host, 443)
    _print_json(info, "testssl-shim")


@register("sslyze")
def shim_sslyze(target: str) -> None:
    host = _clean_host(target)
    info = _tls_probe(host, 443)
    info["analysis"] = "sslyze shim"
    _print_json(info, "sslyze-shim")


@register("assetfinder")
def shim_assetfinder(target: str) -> None:
    domain = _clean_host(target)
    candidates = ["", "www", "api", "dev", "staging", "admin", "beta", "test", "portal", "internal"]
    results: List[Tuple[str, str]] = []
    for prefix in candidates:
        sub = domain if not prefix else f"{prefix}.{domain}"
        try:
            infos = socket.getaddrinfo(sub, None)
        except socket.gaierror:
            continue
        for info in infos:
            addr = info[4][0]
            results.append((sub, addr))
    seen = set()
    for sub, addr in results:
        key = f"{sub}-{addr}"
        if key in seen:
            continue
        seen.add(key)
        print(f"[assetfinder-shim] {sub} -> {addr}")
    if not seen:
        print(f"[assetfinder-shim] No subdomains resolved for {domain}")


@register("hakrawler")
def shim_hakrawler(target: str) -> None:
    url = _ensure_url(target)
    status, body, _ = _safe_request(url)
    if status is None:
        return
    hrefs = re.findall(r'href=[\'"]([^\'"]+)[\'"]', body, flags=re.IGNORECASE)
    uniq = []
    for href in hrefs:
        full = urljoin(url, href)
        if full not in uniq:
            uniq.append(full)
    if not uniq:
        print(f"[hakrawler-shim] No links discovered at {url}")
    for link in uniq[:50]:
        print(f"[hakrawler-shim] {link}")


@register("dnsx")
def shim_dnsx(target: str) -> None:
    host = _clean_host(target)
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        print(f"[dnsx-shim] DNS lookup failed: {exc}")
        return
    seen = set()
    for info in infos:
        addr = info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        fam = "IPv6" if ":" in addr else "IPv4"
        print(f"[dnsx-shim] {host} {fam} -> {addr}")


TAKEOVER_PATTERNS = [
    ("s3", "NoSuchBucket"),
    ("cloudfront", "ERROR: The request could not be satisfied"),
    ("github", "There isn't a GitHub Pages site here."),
    ("heroku", "There's nothing here, yet."),
    ("shopify", "Sorry, this shop is currently unavailable."),
    ("azure", "web app you have attempted to reach is currently stopped"),
    ("fastly", "Fastly error: unknown domain"),
]


@register("subjack")
def shim_subjack(target: str) -> None:
    host = _clean_host(target)
    hits = []
    for scheme in ("https", "http"):
        status, body, _ = _safe_request(f"{scheme}://{host}", allow_insecure=True)
        if status is None:
            continue
        lowered = body.lower()
        for provider, marker in TAKEOVER_PATTERNS:
            if marker.lower() in lowered:
                hits.append((scheme, provider, status))
    if not hits:
        print(f"[subjack-shim] No takeover fingerprints detected for {host}")
    else:
        for scheme, provider, status in hits:
            print(f"[subjack-shim] Potential {provider} takeover indicator via {scheme} (status={status})")


@register("wfuzz")
def shim_wfuzz(target: str) -> None:
    url = _ensure_url(target)
    payloads = [
        "../etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "<script>alert(1)</script>",
        "' OR 1=1 --",
        "file:///etc/passwd",
        "http://localhost",
    ]
    parsed = urlparse(url)
    base_query = parse_qsl(parsed.query, keep_blank_values=True)
    for payload in payloads:
        query = base_query + [("fuzz", payload)]
        new_query = urlencode(query, doseq=True)
        # urlunparse expects (scheme, netloc, path, params, query, fragment)
        fuzzed = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))
        status, body, _ = _safe_request(fuzzed)
        length = len(body)
        print(f"[wfuzz-shim] {fuzzed} -> status={status} len={length}")


@register("pshtt")
def shim_pshtt(target: str) -> None:
    host = _clean_host(target)
    http_status, http_body, http_headers = _safe_request(f"http://{host}", method="HEAD", allow_insecure=True)
    https_status, https_body, https_headers = _safe_request(f"https://{host}", method="HEAD", allow_insecure=True)
    summary = {
        "host": host,
        "http_status": http_status,
        "https_status": https_status,
        "https_enforced": http_status in (301, 302, 307, 308),
        "hsts": "strict-transport-security" in (https_headers or {}),
    }
    _print_json(summary, "pshtt-shim")


@register("eyewitness")
def shim_eyewitness(target: str) -> None:
    url = _ensure_url(target)
    status, body, _ = _safe_request(url)
    if status is None:
        return
    evidence_root = Path.home() / "AraUltra_Evidence" / "eyewitness_shim"
    evidence_root.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", url)
    path = evidence_root / f"{safe_name}_{int(time.time())}.html"
    path.write_text(body, encoding="utf-8")
    print(f"[eyewitness-shim] status={status} saved={path}")


@register("hakrevdns")
def shim_hakrevdns(target: str) -> None:
    host = _clean_host(target)
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        print(f"[hakrevdns-shim] lookup failed for {host}: {exc}")
        return
    ips = {info[4][0] for info in infos}
    for ip in ips:
        try:
            ptr = socket.gethostbyaddr(ip)
            names = [ptr[0]] + ptr[1]
        except socket.herror:
            names = []
        label = ", ".join(names) if names else "No PTR"
    print(f"[hakrevdns-shim] {ip} -> {label}")


@register("httprobe")
def shim_httprobe(target: str) -> None:
    host = _clean_host(target)
    for scheme in ("http", "https"):
        status, _, _ = _safe_request(f"{scheme}://{host}", allow_insecure=True)
        if status is None:
            print(f"[httprobe-shim] {scheme}://{host} unreachable")
        else:
            print(f"[httprobe-shim] {scheme}://{host} -> status {status}")


@register("nikto")
def shim_nikto(target: str) -> None:
    url = _ensure_url(target)
    status, body, headers = _safe_request(url, allow_insecure=True)
    if status is None:
        print(f"[nikto-shim] Target unreachable: {url}")
        return

    checks = []
    hdr_lower = {k.lower(): v for k, v in headers.items()}

    if "x-frame-options" not in hdr_lower:
        checks.append(("Missing X-Frame-Options", "HIGH", "Adds clickjacking exposure."))
    if "content-security-policy" not in hdr_lower:
        checks.append(("Missing Content-Security-Policy", "MEDIUM", "No CSP header present."))
    if "strict-transport-security" not in hdr_lower and url.startswith("https://"):
        checks.append(("Missing HSTS", "MEDIUM", "No Strict-Transport-Security header."))
    if "set-cookie" in hdr_lower and "secure" not in hdr_lower["set-cookie"]:
        checks.append(("Insecure Cookie", "HIGH", hdr_lower["set-cookie"]))
    if "x-powered-by" in hdr_lower:
        checks.append(("Technology Disclosure", "LOW", hdr_lower["x-powered-by"]))
    if status >= 500:
        checks.append(("Server Error Response", "HIGH", f"Status {status}"))

    signature_strings = [
        "phpmyadmin",
        "sql syntax",
        "exception",
        "stack trace",
        "root:",
        "password="
    ]
    snippet = body[:2000].lower()
    for sig in signature_strings:
        if sig in snippet:
            checks.append(("Suspicious Content", "MEDIUM", f"Found marker '{sig}' in body"))

    if not checks:
        print(f"[nikto-shim] No obvious issues detected for {url} (status {status})")
        return

    for title, severity, detail in checks:
        print(f"[nikto-shim] {severity}: {title} — {detail}")
