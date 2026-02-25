import httpx
from core.web.diff.baseline import BaselineBuilder
from core.web.diff.delta import DeltaEngine

b = BaselineBuilder()
d = DeltaEngine()

resp_a = httpx.get("http://localhost:8081/profile?user=123", headers={"X-Test-Principal": "p-owner123"})
base_a = b.build(resp_a.status_code, dict(resp_a.headers), resp_a.content, 10, 20)

resp_b = httpx.get("http://localhost:8081/profile?user=123", headers={"X-Test-Principal": "p-attk123"})
delta = d.diff(base_a, resp_b.status_code, dict(resp_b.headers), resp_b.content, 10, 20)
print(delta)
