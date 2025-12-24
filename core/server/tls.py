"""Module tls: inline documentation for /Users/jason/Developer/sentinelforge/core/server/tls.py."""
#
# PURPOSE:
# This module is part of the server package in SentinelForge.
# [Specific purpose based on module name: tls]
#
# KEY RESPONSIBILITIES:
# - [Automatically generated - review and enhance based on actual functionality]
#
# INTEGRATION:
# - Used by: [To be documented]
# - Depends on: [To be documented]
#


import ssl
import socket
import asyncio
import logging
import datetime
from typing import Dict, List, Optional, Any, Tuple

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from curl_cffi import requests as curl_requests

logger = logging.getLogger(__name__)

class TLSAnalyzer:
    """
    Modern TLS analysis using cryptography, httpx, and curl_cffi.
    Replaces legacy nassl/pycurl logic.
    """

    def __init__(self, target: str, port: int = 443):
        """Function __init__."""
        self.target = target
        self.port = port
        self.hostname = target
        # Handle URL inputs gracefully
        if "://" in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            self.hostname = parsed.hostname or target
            self.port = parsed.port or (443 if parsed.scheme == "https" else 80)

    async def analyze(self) -> Dict[str, Any]:
        """Run comprehensive TLS analysis."""
        results = {
            "target": self.hostname,
            "port": self.port,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "versions": {},
            "certificate": {},
            "ciphers": [],
            "fingerprint": {}
        }

        # 1. Get Certificate Chain & Basic Info
        cert_info = await self.get_cert_chain()
        results["certificate"] = cert_info

        # 2. Test TLS Versions
        versions = await self.test_tls_versions()
        results["versions"] = versions

        # 3. Fingerprint (JA3/HTTP2) via curl_cffi
        fp = await self.fingerprint_server_tls()
        results["fingerprint"] = fp

        return results

    async def get_cert_chain(self) -> Dict[str, Any]:
        """Retrieve and parse certificate chain using cryptography."""
        # Error handling block.
        try:
            # Use standard SSL to fetch cert bytes, then parse with cryptography
            # This avoids nassl dependency
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            loop = asyncio.get_running_loop()
            
            def _fetch_cert():
                """Function _fetch_cert."""
                # Context-managed operation.
                with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                        return der_cert
            
            der_cert = await loop.run_in_executor(None, _fetch_cert)
            if not der_cert:
                return {"error": "No certificate retrieved"}

            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            
            # Parse details
            info = {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": cert.serial_number,
                "version": cert.version.name,
                "not_valid_before": cert.not_valid_before_utc.isoformat(),
                "not_valid_after": cert.not_valid_after_utc.isoformat(),
                "signature_algorithm": cert.signature_algorithm_oid._name,
                "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
                "extensions": {}
            }

            # Extract SANs
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                info["extensions"]["subjectAltName"] = san.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            # Check expiration
            now = datetime.datetime.now(datetime.timezone.utc)
            if now > cert.not_valid_after_utc:
                info["status"] = "EXPIRED"
            elif now < cert.not_valid_before_utc:
                info["status"] = "NOT_YET_VALID"
            else:
                info["status"] = "VALID"
                info["days_remaining"] = (cert.not_valid_after_utc - now).days

            return info

        except Exception as e:
            logger.error(f"Cert fetch failed: {e}")
            return {"error": str(e)}

    async def test_tls_versions(self) -> Dict[str, bool]:
        """Test supported TLS versions."""
        results = {}
        # Map of versions to test
        # Note: Python's ssl module support depends on OpenSSL version
        versions = [
            ("TLSv1", ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None),
            ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None),
            ("TLSv1.2", ssl.PROTOCOL_TLSv1_2),
            ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT), # TLS 1.3 is negotiated via TLS_CLIENT/TLS_SERVER usually
        ]

        loop = asyncio.get_running_loop()

        # Loop over items.
        for name, proto in versions:
            if not proto:
                results[name] = "Unsupported by local OpenSSL"
                continue

            def _try_connect():
                """Function _try_connect."""
                # Error handling block.
                try:
                    ctx = ssl.SSLContext(proto)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    if name == "TLSv1.3":
                        # Force TLS 1.3 if possible, though SSLContext(PROTOCOL_TLS_CLIENT) auto-negotiates
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                    
                    with socket.create_connection((self.hostname, self.port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                            return ssock.version()
                except Exception:
                    return None

            negotiated = await loop.run_in_executor(None, _try_connect)
            results[name] = (negotiated is not None)
        
        return results

    async def fingerprint_server_tls(self) -> Dict[str, Any]:
        """
        Use curl_cffi to impersonate a browser and capture TLS fingerprint details.
        """
        # Error handling block.
        try:
            # curl_cffi allows impersonating Chrome/Safari to see how server reacts
            # This is a high-level check
            def _curl_check():
                """Function _curl_check."""
                # Error handling block.
                try:
                    r = curl_requests.get(
                        f"https://{self.hostname}:{self.port}",
                        impersonate="chrome110",
                        timeout=10,
                        verify=True
                    )
                    return {
                        "status": r.status_code,
                        "http_version": r.http_version, # 2 for HTTP/2
                        "headers": dict(r.headers)
                    }
                except Exception as e:
                    return {"error": str(e)}

            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _curl_check)
        except Exception as e:
            return {"error": str(e)}

    async def enumerate_cipher_suites(self) -> List[str]:
        """
        Enumerate supported cipher suites.
        Note: This is limited by local OpenSSL capabilities.
        """
        supported = []
        # Common ciphers to test
        ciphers_to_test = [
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "AES128-GCM-SHA256",
            "AES256-GCM-SHA384",
            "ECDHE-RSA-AES128-SHA256",
            "ECDHE-RSA-AES256-SHA384",
            # Legacy
            "AES128-SHA",
            "AES256-SHA",
            "DES-CBC3-SHA",
        ]

        loop = asyncio.get_running_loop()

        # Loop over items.
        for cipher in ciphers_to_test:
            def _test_cipher():
                """Function _test_cipher."""
                # Error handling block.
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.set_ciphers(cipher)
                    with socket.create_connection((self.hostname, self.port), timeout=2) as sock:
                        with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                            return ssock.cipher()
                except Exception:
                    return None
            
            res = await loop.run_in_executor(None, _test_cipher)
            if res:
                supported.append(res[0])
        
        return supported
