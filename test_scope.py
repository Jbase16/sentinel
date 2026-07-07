from core.base.scope import ScopeRegistry, ScopeRule, AssetType, ScopeDecision

registry = ScopeRegistry(bounty_mode=True)
registry.add_rule(ScopeRule(asset_type=AssetType.WILDCARD, target="*.tiktok.com", decision=ScopeDecision.ALLOW))

decision = registry.resolve("http://tiktok.com")
print(f"Target: tiktok.com")
print(f"Verdict: {decision.verdict}")
print(f"Reason: {decision.reason_code}")

decision2 = registry.resolve("http://www.tiktok.com")
print(f"Target: www.tiktok.com")
print(f"Verdict: {decision2.verdict}")
print(f"Reason: {decision2.reason_code}")
