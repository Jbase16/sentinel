"""
Verification Script for Project MIMIC (Route Mining).
Scenario:
1. Feed series of URLs: /users/1, /users/2, /users/55
2. Feed generic URLs: /users/profile, /admin/login
3. Expect Miner to cluster {id} but keep literals distinct.
"""
from core.sentient.mimic.route_miner import RouteMiner

def run_test():
    print("🗺️  Initializing Route Miner...")
    miner = RouteMiner()
    
    # Dataset 1: User IDs
    # Should cluster to /users/{id}
    urls_ids = ["/users/1", "/users/2", "/users/999", "/users/1024"]
    for url in urls_ids:
        ep = miner.ingest("GET", url)
        print(f"   Fed: {url} -> Template: {ep.path_template}")
        assert ep.path_template == "/users/{id}"
    
    print("✅ Parameter Clustering Verified (/users/{id})")
    
    # Dataset 2: UUIDs
    # Should cluster to /files/{id}
    urls_uuids = [
        "/files/550e8400-e29b-41d4-a716-446655440000",
        "/files/123e4567-e89b-12d3-a456-426614174000"
    ]
    for url in urls_uuids:
        ep = miner.ingest("GET", url)
        print(f"   Fed: {url} -> Template: {ep.path_template}")
        assert ep.path_template == "/files/{id}"
        
    print("✅ UUID Clustering Verified (/files/{id})")

    # Dataset 3: Literals mixing with params
    # /users/profile should NOT be /users/{id} (unless 'profile' looks like an ID, which it doesn't)
    ep = miner.ingest("GET", "/users/profile")
    print(f"   Fed: /users/profile -> Template: {ep.path_template}")
    assert ep.path_template == "/users/profile"
    
    # /users/1/details
    ep = miner.ingest("GET", "/users/1/details")
    print(f"   Fed: /users/1/details -> Template: {ep.path_template}")
    assert ep.path_template == "/users/{id}/details"

    print("✅ Mixed Template Verified (/users/{id}/details)")
    print("\n🎉 MIMIC Logic Verified!")

if __name__ == "__main__":
    run_test()
