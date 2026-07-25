# Production Authentication Setup

 SentinelForge enforces strict authentication boundaries in production environments.

 ## 1. Configuration
 Authentication is controlled via the `SecurityConfig` in `core/base/config.py` or environment variables.

 ### Environment Variables
 | Variable | Description | Default |
 |----------|-------------|---------|
 | `SENTINEL_REQUIRE_AUTH` | Enforce API token requirement | `False` (Dev) / `True` (Prod) |
 | `SENTINEL_API_TOKEN` | Static valid token (optional) | Randomly generated on boot |
 | `SENTINEL_ALLOWED_ORIGINS` | Comma-separated allowed CORS/WebSocket origins | `http://localhost:*` |

 ## 2. Token Generation
 If `SENTINEL_API_TOKEN` is not set, the system generates a cryptographically secure token at startup.
 ```bash
 [INFO] API Token generated: <32-byte-urlsafe-string>
 ```

 ## 3. Client Authentication
 Clients must provide the token in one of two ways:

 ### HTTP / REST
 Header: `Authorization: Bearer <token>`

 ### WebSocket
 Query Parameter: `?token=<token>`

 > **Note**: WebSockets blindly reject connections without valid tokens if `SENTINEL_REQUIRE_AUTH=True`.

 ## 4. Production Checklist
 - [ ] Set `SENTINEL_REQUIRE_AUTH=True`
 - [ ] Set `SENTINEL_API_TOKEN` (via Secrets Manager)
 - [ ] Configure `SENTINEL_ALLOWED_ORIGINS` (e.g., `https://dashboard.sentinelforge.com`)
 - [ ] Ensure SSL/TLS termination (HTTPS) at the ingress
