"""
core/ghost/flow.py
The Session & Flow Tracker.
"Ghost observes the user to learn the rules before breaking them."
"""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING, Dict, List
from urllib.parse import urlparse

if TYPE_CHECKING:
    from core.wraith.personas import Persona


class FlowStep:
    """Represents a single HTTP request in a recorded flow.
    
    Attributes:
        id: Unique identifier for this step.
        method: HTTP method (GET, POST, etc.).
        url: The full request URL.
        params: Query parameters or request body parameters.
        headers: HTTP headers sent with the request.
        timestamp: Unix timestamp when the request was made.
        response_status: HTTP response status code.
    """

    def __init__(self, method: str, url: str, params: Dict, headers: Dict):
        """Initialize a flow step with HTTP request details.
        
        Args:
            method: HTTP method.
            url: Request URL.
            params: Request parameters.
            headers: Request headers.
        """
        self.id = str(uuid.uuid4())
        self.method = method
        self.url = url
        self.params = params
        self.headers = headers
        self.timestamp = time.time()
        self.response_status = 0


class UserFlow:
    """Represents a sequence of HTTP requests that form a user flow.
    
    Captures a sequence of actions (e.g., Login -> Search -> AddToCart)
    and automatically extracts authentication tokens from headers.
    
    Attributes:
        name: Human-readable name for this flow.
        steps: List of FlowStep objects in chronological order.
        auth_tokens: Dictionary of extracted authentication tokens.
    """

    def __init__(self, name: str):
        """Initialize a user flow.
        
        Args:
            name: Descriptive name for the flow.
        """
        self.name = name
        self.steps: List[FlowStep] = []
        self.auth_tokens: Dict[str, str] = {}

    def add_step(self, step: FlowStep):
        """Add a step to the flow.
        
        Args:
            step: FlowStep object to append.
        """
        self.steps.append(step)

    def extract_tokens(self, headers: Dict):
        """Extract authentication tokens from headers.
        
        Looks for common auth header names: Authorization, Cookie, X-CSRF-Token.
        Stores found tokens in auth_tokens dictionary.
        
        Args:
            headers: HTTP headers dictionary to scan for tokens.
        """
        for k, v in headers.items():
            if k.lower() in ["authorization", "cookie", "x-csrf-token"]:
                self.auth_tokens[k] = v


class FlowMapper:
    """Singleton recorder and analyzer of HTTP flows.
    
    Records sequences of HTTP requests, extracts authentication tokens,
    and converts recorded flows into Persona objects for use by PersonaManager.
    
    Uses singleton pattern to ensure only one FlowMapper instance exists.
    """

    _instance = None

    @staticmethod
    def instance() -> FlowMapper:
        """Get or create the singleton FlowMapper instance.
        
        Returns:
            The single FlowMapper instance.
        """
        if FlowMapper._instance is None:
            FlowMapper._instance = FlowMapper()
        return FlowMapper._instance

    def __init__(self):
        """Initialize the FlowMapper with an empty active flows dictionary."""
        self.active_flows: Dict[str, UserFlow] = {}

    def start_recording(self, flow_name: str) -> str:
        """Start recording a new flow.
        
        Args:
            flow_name: Descriptive name for the flow being recorded.
            
        Returns:
            Unique flow ID to use when recording requests.
        """
        fid = str(uuid.uuid4())
        self.active_flows[fid] = UserFlow(flow_name)
        return fid

    def record_request(self, flow_id: str, method: str, url: str, params: Dict, headers: Dict):
        """Record a single HTTP request in an active flow.
        
        Automatically extracts authentication tokens from request headers.
        
        Args:
            flow_id: ID returned from start_recording().
            method: HTTP method.
            url: Request URL.
            params: Request parameters.
            headers: Request headers.
        """
        if flow_id in self.active_flows:
            step = FlowStep(method, url, params, headers)
            self.active_flows[flow_id].add_step(step)
            self.active_flows[flow_id].extract_tokens(headers)

    def to_personas(self, base_url: str = "http://localhost:8000") -> List[Persona]:
        """Convert recorded flows into Persona objects.
        
        Iterates through all active flows and creates Persona objects based on
        extracted authentication tokens. Persona types are determined by the
        type of authentication found:
        - Bearer tokens -> PersonaType.USER with bearer_token
        - Cookies -> PersonaType.USER with cookie_jar
        
        The base_url for each persona is extracted from the first step's URL
        (scheme + netloc), falling back to the provided base_url parameter.
        
        Always includes a single ANONYMOUS persona at the end of the list.
        
        Skips flows that have no steps or no extracted authentication tokens.
        
        Args:
            base_url: Default base URL for personas. Defaults to "http://localhost:8000".
            
        Returns:
            List of Persona objects ready for use by PersonaManager.
        """
        from core.wraith.personas import Persona, PersonaType

        personas: List[Persona] = []

        for user_flow in self.active_flows.values():
            # Skip flows with no steps or no auth tokens
            if not user_flow.steps or not user_flow.auth_tokens:
                continue

            # Extract base URL from the first step's URL
            flow_base_url = base_url
            try:
                first_url = user_flow.steps[0].url
                parsed = urlparse(first_url)
                if parsed.scheme and parsed.netloc:
                    flow_base_url = f"{parsed.scheme}://{parsed.netloc}"
            except (ValueError, AttributeError):
                # If parsing fails, use the provided default
                pass

            # Process Bearer token
            if "Authorization" in user_flow.auth_tokens:
                auth_header = user_flow.auth_tokens["Authorization"]
                if auth_header.startswith("Bearer "):
                    token_value = auth_header[7:]  # Remove "Bearer " prefix
                    persona = Persona(
                        name=user_flow.name,
                        persona_type=PersonaType.USER,
                        bearer_token=token_value,
                        base_url=flow_base_url,
                    )
                    personas.append(persona)
                    continue

            # Process Cookie
            if "Cookie" in user_flow.auth_tokens:
                cookie_str = user_flow.auth_tokens["Cookie"]
                cookie_jar = self._parse_cookie_string(cookie_str)
                persona = Persona(
                    name=user_flow.name,
                    persona_type=PersonaType.USER,
                    cookie_jar=cookie_jar,
                    base_url=flow_base_url,
                )
                personas.append(persona)
                continue

        # Always add an ANONYMOUS persona
        personas.append(
            Persona(
                name="Anonymous",
                persona_type=PersonaType.ANONYMOUS,
                base_url=base_url,
            )
        )

        return personas

    @staticmethod
    def _parse_cookie_string(cookie_str: str) -> Dict[str, str]:
        """Parse a cookie string into a dictionary.
        
        Handles standard cookie format: "name1=value1; name2=value2; ..."
        
        Args:
            cookie_str: Cookie header value.
            
        Returns:
            Dictionary mapping cookie names to values.
        """
        cookies = {}
        if not cookie_str:
            return cookies

        parts = cookie_str.split(";")
        for part in parts:
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                cookies[name.strip()] = value.strip()

        return cookies
