# SentinelForge Calibration Lab

A controlled, known-vulnerable environment to verify Sentinel works end-to-end
before pointing it at a real bounty target. **Run this first. Always.**

## What's in here

- `docker-compose.yml` — OWASP Juice Shop, pinned to v17.2.0, bound to
  `127.0.0.1:3000` only.
- `juice-shop-scope.txt` — scope rules that allow only the loopback Juice
  Shop and explicitly deny common public TLDs as a belt-and-braces guard.

## Why Juice Shop

- It's a modern SPA + REST API target — exactly what Sentinel's mutators
  (SQLi/SSRF/IDOR/reflection/persona-diff) are built to find.
- It has a documented [Scoreboard](https://demo.owasp-juice.shop/#/score-board)
  of intended vulnerabilities — you have a *known answer* to grade against.
- It's containerised — start it, run a scan, kill it. No state pollution.
- `core/thanatos/axiom_synthesizer.py` already has Juice Shop endpoint
  heuristics (`/login`, `/search`, `/basket`), so this is the target your
  past self optimized for.

## Quick start

```bash
# 1) Bring up the lab
cd scripts/lab
docker compose up -d

# 2) Wait for healthy (about 30 seconds first time)
docker compose ps

# 3) Verify it's actually live
curl -fsS http://127.0.0.1:3000/ -o /dev/null && echo "Juice Shop up"

# 4) (Now run Sentinel against http://127.0.0.1:3000 with the scope file —
#    see docs/PHASE_1_PLAYBOOK.md for the full flow)

# 5) When done
cd scripts/lab
docker compose down
```

## What "calibration" means in practice

You run Sentinel against the lab. You compare what Sentinel found to what
Juice Shop's Scoreboard says is findable. The gap is your real signal:

- **Sentinel found a known vuln** → that mutator works against this shape.
- **Sentinel missed a known vuln** → either a coverage gap (the mutator
  isn't reaching that endpoint) or a parser gap (it ran but didn't recognise
  the evidence). Use the capsule inspector to figure out which.
- **Sentinel found something the Scoreboard doesn't list** → could be a
  real find, could be a false positive. Manually verify; both outcomes
  teach you something.

## Do NOT do this

- Don't expose the lab on `0.0.0.0`. Juice Shop is trivially exploitable
  and the docker-compose binds loopback intentionally.
- Don't add real bounty target rules to `juice-shop-scope.txt`. Use a
  separate scope file per target.
- Don't skip the lab and jump to a real program "because the lab is too
  easy." A program-level scope misconfiguration can get you banned. The
  lab is where you catch those.
