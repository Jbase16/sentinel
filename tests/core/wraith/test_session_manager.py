import pytest

from core.base.config import SentinelConfig, StorageConfig, get_config, set_config
from core.wraith.session_manager import AuthSessionManager


@pytest.fixture(autouse=True)
def _restore_global_config():
    original = get_config()
    yield
    set_config(original)


class _FakePersonaManager:
    def __init__(self, personas):
        self.personas = personas

    async def initialize(self) -> bool:
        # Simulate a successful login flow that yields both a token and a session cookie.
        for p in self.personas:
            if getattr(p, "persona_type", None) and getattr(p.persona_type, "value", "") == "anonymous":
                continue
            p.bearer_token = p.bearer_token or "token123"
            p.cookie_jar = p.cookie_jar or {"sid": "abc"}
        return True

    def get_session(self, _name: str):
        return None

    async def close(self):
        return None


@pytest.mark.anyio
async def test_auth_session_manager_persists_session_material(monkeypatch, tmp_path):
    # Ensure persistence happens inside the test sandbox.
    set_config(SentinelConfig(storage=StorageConfig(base_dir=tmp_path)))

    monkeypatch.setattr("core.wraith.session_manager.PersonaManager", _FakePersonaManager)

    knowledge = {
        "persona_baseline": "Admin",
        "personas": [
            {
                "name": "Admin",
                "persona_type": "admin",
                "persist": True,
                "login_flow": {
                    "endpoint": "/login",
                    "method": "POST",
                    "username_param": "email",
                    "password_param": "password",
                    "username_value": "admin@example.com",
                    "password_value": "REDACTED",
                    "token_extract_path": "data.token",
                },
            }
        ],
    }

    mgr = await AuthSessionManager.from_knowledge(knowledge, base_url="https://example.com")
    assert mgr is not None

    auth = await mgr.get_baseline_auth()
    assert auth is not None
    assert auth.headers.get("Authorization") == "Bearer token123"
    assert auth.cookies.get("sid") == "abc"

    persisted = list((tmp_path / "auth_sessions").rglob("Admin.json"))
    assert len(persisted) == 1

    raw = persisted[0].read_text(encoding="utf-8")
    assert "password_value" not in raw
    assert "token123" in raw

