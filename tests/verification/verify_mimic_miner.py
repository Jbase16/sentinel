"""
Verification Script for Project MIMIC (Route Mining via core.mimic).

Tests the regex-based mine_routes() function against realistic JS patterns.
"""
from core.mimic.miners.routes import mine_routes


def run_test():
    print("Route Miner Verification (core.mimic)")

    # 1. fetch() detection
    js_fetch = '''
    fetch("/api/users")
    fetch('/api/orders')
    fetch("/admin/secret-panel")
    '''
    routes = mine_routes("verify-asset-1", js_fetch)
    paths = {r.route for r in routes}
    assert "/api/users" in paths, f"Missing /api/users in {paths}"
    assert "/api/orders" in paths, f"Missing /api/orders in {paths}"
    print("  fetch() detection: OK")

    # 2. Hidden route detection
    hidden = {r.route for r in routes if r.hidden}
    assert "/admin/secret-panel" in hidden, f"Missing hidden /admin/secret-panel"
    print("  Hidden route detection: OK")

    # 3. axios detection
    js_axios = 'axios.post("/api/checkout")'
    routes_ax = mine_routes("verify-asset-2", js_axios)
    assert any(r.route == "/api/checkout" and r.method == "POST" for r in routes_ax)
    print("  axios detection: OK")

    # 4. Deduplication
    js_dup = 'fetch("/api/dup")\nfetch("/api/dup")'
    routes_dup = mine_routes("verify-asset-3", js_dup)
    assert sum(1 for r in routes_dup if r.route == "/api/dup") == 1
    print("  Deduplication: OK")

    print("\nMIMIC Route Miner: all checks passed")


if __name__ == "__main__":
    run_test()
