# Queries and Introspection
CAL should allow querying:
- current claim set
- claim histories
- evidence trees
- audit logs

## 1) Basic claim queries
```cal
let confirmed = query claims where status == CONFIRMED
let high = query claims where confidence >= 0.8
let sqli = query claims PotentialSQLi
```

## 2) Evidence queries
```cal
let e = query evidence for claim c
```

## 3) “Why do we believe this?”
CAL should make it easy to generate explanations:
- from claim history
- from evidence lineage
- optionally from a reasoner agent (`explain(claim)`)

## 4) Proof artifacts
A mature CAL runtime should be able to produce:
- machine-verifiable proof artifacts (hashes + lineage)
- human-readable narratives
- reproducible report bundles
