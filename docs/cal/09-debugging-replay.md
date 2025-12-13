# Debugging and Replay
A CAL runtime should be debuggable like a language, not a workflow YAML.

## 1) What you debug in CAL
- rule triggers (why a rule fired or didn’t)
- obligations (which `must` actions are pending)
- claim versions (how confidence evolved)
- evidence attachment (what influenced a belief)

## 2) Debug views that matter
- event stream (observation/claim/evidence events)
- rule trace (matched rules + action outcomes)
- claim timeline
- obligation tracker (pending validations/reviews + timeouts)

## 3) Replay
Replay means re-running a mission against:
- the same evidence bundle
- cached LLM responses (by prompt hash)
- simulated tool outputs

Goal: reproduce belief evolution as closely as possible.

## 4) Non-determinism handling
- cache LLM calls (prompt hash → response)
- store random seeds used by fuzzers
- record tool versions
- record scope + config used
