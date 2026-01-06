import socket
import ssl
import logging
from typing import Tuple, Optional
from core.thanatos.models import HereticMutation

logger = logging.getLogger(__name__)

class AnomalyClient:
    """
    Raw socket client for sending 'Heretic' payloads.
    Bypasses standard library safety checks (httpx/requests would block these).
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def send_mutation(self, host: str, port: int, mutation: HereticMutation, use_ssl: bool = False) -> Tuple[str, str]:
        """
        Send a raw mutation to the target and capture the result.
        Returns: (Status, Details)
        """
        try:
            # Create raw socket
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            conn: socket.socket
            if use_ssl:
                conn = context.wrap_socket(sock, server_hostname=host)
            else:
                conn = sock

            conn.connect((host, port))
            conn.sendall(mutation.raw_payload)
            
            # Read response (if any)
            try:
                data = conn.recv(4096)
                response = data.decode(errors="ignore")
                
                # Analyze response for "Surprise"
                if "500 Internal Server Error" in response:
                    return "Crash", f"Server panicked: {response[:50]}..."
                elif not response:
                    return "Drop", "Server closed connection immediately."
                else:
                    return "Handled", f"Server responded normally: {response.splitlines()[0] if response else 'Empty'}"
                    
            except socket.timeout:
                return "Timeout", "Server hung (Possible Resource Exhaustion/Crash)"
            finally:
                conn.close()

        except Exception as e:
            return "ClientError", str(e)
