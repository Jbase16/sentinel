"""
core/doppelganger/engine.py

Purpose:
    The Session Manager.
    Handles the "Login Dance" to convert Credentials into Sessions.

Magnum Opus Standards:
    - Async: Login IO should not block.
    - Robustness: Handles token extraction from complex JSON bodies.
"""

import logging
import httpx
from typing import Optional, Dict

from .models import Persona, Credential

log = logging.getLogger("doppelganger.engine")

class DoppelgangerEngine:
    """
    Manages Personas and their active sessions.
    """
    
    def __init__(self):
        self.active_personas: Dict[str, Persona] = {}
        
    async def authenticate(self, credential: Credential, target_url: str) -> Optional[Persona]:
        """
        Attempt to log in and create a Persona.
        
        Args:
           credential: The user/pass to use.
           target_url: Base URL of the target (e.g. http://localhost:3000)
           
        Returns:
            Authenticated Persona if successful, None otherwise.
        """
        log.info(f"🎭 Doppelganger: Attempting login for {credential.username} at {target_url}")
        
        # 1. Detect Login Endpoint (For now, hardcoded for Juice Shop)
        # Future: Use Lazarus to find the login route
        login_endpoint = f"{target_url}/rest/user/login"
        
        try:
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    login_endpoint,
                    json={
                        "email": credential.username,
                        "password": credential.password
                    },
                    timeout=5.0
                )
                
                if response.status_code == 200:
                    data = response.json()
                    token = data.get("authentication", {}).get("token")
                    
                    if token:
                        log.info(f"✅ Login Successful! Token: {token[:10]}...")
                        
                        persona = Persona(
                            id=credential.username,
                            credential=credential,
                            session_token=token,
                            cookies=dict(response.cookies)
                        )
                        
                        self.active_personas[persona.id] = persona
                        return persona
                    else:
                        log.warning("Login 200 OK but no token found in response.")
                        
                else:
                    log.warning(f"Login Failed: {response.status_code} - {response.text[:100]}")
                    
        except Exception as e:
            log.error(f"Login Exception: {e}")
            
        return None

    def get_persona(self, persona_id: str) -> Optional[Persona]:
        return self.active_personas.get(persona_id)
