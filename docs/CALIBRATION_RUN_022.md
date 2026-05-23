# Calibration Run #22 — Attack Graph chain quality

Continuing the end-to-end UI audit, this run traces the **Attack Graph**
tab (trace → live-test → fix → test → document). The graph's *structure*
was sound — nodes, edges, and the Swift DTO contract all decoded cleanly —
but its **attack chains were semantically inflated**: a benign scan
exported dozens of "attack chains" that were either not chains at all or
ranked harmless recon as high as a real exploit path.

**Verdict:** ✅ Attack Graph is structurally sound; chain enumeration
de-noised (length-1 phantoms dropped, severity-aware ranking added).
A live about.gitlab.com session went from **28 → 20 chains**, all now
genuine multi-node paths, ranked most-dangerous-first. 31 graph tests
passing (+3), 508 reporting+intel+classifier tests still green. Zero
regressions.

---

## The trace (what the tab actually does)

```
NetworkGraphView / NeuralGraphView (SwiftUI)
   → GET /v1/cortex/graph
   → get_current_graph
   → get_graph_dto_for_session  (core/cortex/causal_graph.py)
   → CausalGraphBuilder.export_dto(session_id)
```

`export_dto` returns a `PressureGraphDTO`: `nodes`, `edges`,
`attack_chains`, `pressure_points`, `entry_nodes`, `critical_assets`.
The Swift `PressureGraphDTO` / `PressureNodeDTO` / `PressureEdgeDTO`
decode it. **Live-tested** against the gitlab session: HTTP 200, 26 nodes,
20 edges, 5 pressure points, all 7 required node `data` fields present.
The contract is structurally **sound** — no decode bug here.

## The reported-by-inspection symptom

The same benign session exported **28 "attack chains"** for a scan that
found zero exploitable vulnerabilities — pure recon (subdomains, open
ports behind a CDN, DNS records, a WAF observation). Inspecting them:

- **8 were length-1** — a single finding, e.g. `["waf"]`. A chain of one
  node is not an attack chain.
- **20 were pure-INFO co-location** — `Discovered Subdomain → Open Port`,
  every one scored a flat **1.0**, identical to what a genuine
  multi-stage exploit path would score.

Net effect: the most "dangerous" panel in the app was dominated by noise,
and a real escalation path (if one existed) would be buried among 20
identical-looking benign entries.

## The two root causes (both in `export_dto`)

### 1. `all_simple_paths` emits single-node paths

`get_attack_chains()` collects roots (`in_degree == 0`) and leaves
(`out_degree == 0`), then walks `nx.all_simple_paths(root, leaf)` for every
pair. An **isolated finding** (no edges — a WAF observation, a standalone
DNS record) is simultaneously a root *and* a leaf, so
`all_simple_paths(node, node)` returns `[[node]]`. Those length-1 paths
were emitted verbatim as "chains".

### 2. Severity-blind scoring

Every chain's score defaulted to the sum of its edge `strength` values,
and the inferred recon→service / service→vuln edges all carry the default
strength `1.0`. So a 2-node co-location chain and a 2-node
"info → CRITICAL RCE" chain both scored ~1.0. The ranking carried no
signal about how bad the findings on the path actually were.

## The fix

In `CausalGraphBuilder.export_dto` (`core/cortex/causal_graph.py`):

```python
for idx, chain in enumerate(raw_chains[:100]):
    if not chain or len(chain) < 2:        # (1) drop single-node "chains"
        continue
    chain_ids = [str(n) for n in chain]
    edge_strength = sum(
        float((self.graph.get_edge_data(s, t) or {}).get("strength", 1.0))
        for s, t in zip(chain_ids, chain_ids[1:])
    )
    max_sev = _chain_max_severity(chain_ids)          # worst finding on path
    chain_score = edge_strength * (max_sev / 10.0)    # (2) severity-aware
    ...
attack_chains.sort(key=lambda c: c["score"], reverse=True)  # most dangerous first
```

`_chain_max_severity` maps each node's `severity` through `SEVERITY_SCORES`
(`critical 9.5, high 8.0, medium 5.5, low 3.0, info 1.0`) and takes the
max. The chain is weighted by the **worst finding it traverses**,
normalized to 0–1.

**Score separation this produces:**

| Chain | Edges | Max severity | Score |
|---|---|---|---|
| `Subdomain → Open Port` (INFO) | 1 | info (1.0) | `1 × 0.1` = **0.1** |
| `Subdomain → Open Port → SQL Injection` (CRITICAL) | 2 | critical (9.5) | `2 × 0.95` = **1.9** |

A real escalation path now outranks benign co-location by ~19×, instead of
tying it.

## Why this isn't a reduction in capability

Per the standing directive — never remove or reduce Sentinel's abilities —
nothing is dropped from the graph. **All findings remain as nodes; all
edges remain.** Only the *derived "attack_chains" list* is cleaned: a
single isolated node was never a chain (it's already present as a node),
and the co-location paths are still enumerated — they just sink below real
threats in the ranking instead of masquerading as equals. The graph still
surfaces everything; it now does so with a signal-bearing order.

## Live verification

Re-running `export_dto` for the about.gitlab.com session:

```
Before:  28 attack_chains   (8 length-1, 20 flat-1.0 co-location)
After:   20 attack_chains   (all length ≥ 2, severity-ranked)
         pure-INFO co-location chains  → score 0.1
         (no exploit findings in this benign scan, so all remaining
          chains are correctly low-scored recon — nothing inflated)
DTO still decodes cleanly into the Swift PressureGraphDTO.
```

## Tests

New regression group in `tests/unit/test_phase2_causal_graph.py`, built
through the **real inference engine** (finding `type` + shared `target` →
edges), so it exercises the exact path a live scan takes:

- `test_export_dto_drops_length_one_chains` — asserts the raw walk *does*
  emit a length-1 path (so the test isn't vacuous), then asserts no
  length-1 chain survives into the DTO and the isolated WAF finding never
  appears as a standalone chain.
- `test_export_dto_chains_sorted_most_dangerous_first` — scores are
  non-increasing.
- `test_export_dto_chain_score_is_severity_aware` — a path ending in a
  CRITICAL SQL injection (score 1.9) strictly outranks a pure-INFO
  co-location path (score 0.1); both exact scores pinned.

## Test deltas

| Suite | Before | After |
|---|---|---|
| test_phase2_causal_graph | 14 | 17 (+3 Run #22 chain quality) |
| all graph suites combined | 28 | **31** |
| reporting + intel + classifier | 508 | 508 (unchanged) |

Zero regressions.

## The meta-pattern, again

Same class as Runs #20–21, one layer up: a **producer/consumer contract
that was structurally correct but semantically untested against real
data**. The DTO decoded fine (structure ✓), but no test had ever asserted
that the *chains it carried were meaningful* against a realistic finding
set. The fix pattern held: feed the REAL module a realistic seed, observe
the REAL inflated output, fix it, pin it with a test that goes through the
real inference path.

## Follow-up noted (not a regression)

The edge-builder treats co-location ("these findings share a target") and
true enablement ("this finding makes that one reachable") with the same
default edge — both render as `EXPOSES` / strength 1.0. Run #22 corrects
the *ranking* so co-location sinks, but a deeper improvement is to give
co-location edges a distinct, lower base strength (and label) so the graph
itself distinguishes "near" from "enables". That's an edge-semantics
enhancement, tracked separately — not a bug in the current chain fix.
