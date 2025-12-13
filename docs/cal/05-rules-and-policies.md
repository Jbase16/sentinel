# Rules and Policies
Rules are the collaboration layer. They are reactive and declarative.

## 1) Rule anatomy
```cal
rule Name {
  when <condition> {
    <actions>
  }
}
```

## 2) What rules can trigger on
Common triggers:
- an observation was emitted
- a claim was asserted
- confidence crossed a threshold
- a claim entered a status
- a timeout occurred
- conflicting claims exist

## 3) Obligations (`must`) are auditable contracts
When you write:
```cal
Validator::X must validate(c) within 120s
```
You’re saying:
- the system is obligated to attempt validation
- if it cannot (authorization, scope, error, timeout), that failure becomes an audit event

## 4) Timeouts are first-class
```cal
on timeout(120s) {
  c.tags += ["unvalidated"]
  emit warning("Validation timed out")
}
```

## 5) Conflict surfacing
A key CAL stance: don’t silently resolve contradictions.

Pattern:
- detect conflicts
- mark claims contested
- require adjudication or higher-trust validation

## 6) Escalation policies
Common:
- “no CONFIRMED without validation for requires_validation claims”
- “no CRITICAL escalation unless multiple evidence sources corroborate”
- “notify UI/humans on contested high-severity claims”
