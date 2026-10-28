# Production Authentication Setup

 SentinelForge enforces strict authentication boundaries in production environments.

 ## 1. Configuration
 Authentication is controlled via the `SecurityConfig` in `core/base/config.py` or environment variables.

 ### Environment Variables
 | Variable | Description | Default |
 |----------|-------------|---------|
 | `SENTINEL_REQUIRE_AUTH` | Enforce API token requirement | `True` unless explicitly overridden |
 | `SENTINEL_API_TOKEN` | Static valid token (optional) | Existing token file, or a generated token on first setup |
 | `SENTINEL_ALLOWED_ORIGINS` | Comma-separated allowed CORS/WebSocket origins | `http://127.0.0.1:8765`, `http://localhost:8765` |

 `terminal_require_auth` defaults to `False`; terminal access follows the default-on API authentication requirement unless separately configured.

 ## 2. Token Generation
 If `SENTINEL_API_TOKEN` is not set, the system reuses a valid token from `~/.sentinelforge/api_token` or generates one on first setup.
 ```bash
 [INFO] API Token generated: <32-byte-urlsafe-string>
 ```

 ## 3. Client Authentication
 Clients must provide the token in one of two ways:

 ### HTTP / REST
 Header: `Authorization: Bearer <token>`

 ### WebSocket
 Query Parameter: `?token=<token>`

 > **Note**: WebSockets reject connections without valid tokens while `SENTINEL_REQUIRE_AUTH=True`, which is the default.

 ## 4. Production Checklist
 - [ ] Keep `SENTINEL_REQUIRE_AUTH=True` (the default)
 - [ ] Set `SENTINEL_API_TOKEN` (via Secrets Manager)
 - [ ] Configure `SENTINEL_ALLOWED_ORIGINS` (e.g., `https://dashboard.sentinelforge.com`)
 - [ ] Ensure SSL/TLS termination (HTTPS) at the ingress
