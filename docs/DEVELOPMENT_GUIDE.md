# SentinelForge Developer Guide

## Folder Overview
| Folder | Purpose |
|---------|----------|
| `core/` | Core system logic (AI, Cortex, Engine, Scheduler, etc.) |
| `cli/` | Command-line entrypoint for running SentinelForge |
| `tools/` | Developer scripts and operations helpers |
| `tests/` | Unit, integration, and verification tests |
| `ui/` | Swift user interface |
| `docs/` | Architecture and design documentation |

## Running the System
```bash
python -m sentinelforge.cli.sentinel start

```

## Implementation Slice Communication Standard

Every proposed, starting, or completed implementation slice must be explained in both
of these forms:

1. **Technical explanation** — identify the contracts, execution flow, dependencies,
   safety gates, verification method, and current limitations precisely.
2. **Non-technical explanation** — state what Sentinel can newly do in plain language,
   give one concrete example, and state what it still cannot do safely or automatically.

Both explanations must describe the same scope. The plain-language explanation must not
imply broader automation, vulnerability coverage, safety, or payout certainty than the
technical implementation provides. Each explanation must explicitly state whether the
slice changes target traffic or execution authority.
