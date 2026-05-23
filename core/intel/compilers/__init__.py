"""
Compilers — translate ProgramScope into Sentinel's existing config formats.

Each compiler is a one-way translator:

  - ``scope_compiler``    ProgramScope.scope_rules   → text scope file
  - ``persona_compiler``  ProgramScope.personas      → personas.json
  - ``policy_gate``       ProgramScope.restrictions  → restrictions.json

The compilers MUST emit the exact formats the rest of Sentinel already
consumes (``core.server.routers.scans:265-281`` for scope, ``pysentinel
.py:343`` for personas). Any drift between what intel produces and what
the rest of the engine reads will silently break ingest — verified at
the contract-tests level in ``tests/unit/intel/test_*_compiler.py``.

The output files are conventionally named:

  <program>-scope.txt
  <program>-personas.json
  <program>-restrictions.json

…and live next to each other in the operator's intel cache.

Public surface:
    from core.intel.compilers import (
        compile_scope_file, compile_personas_json, compile_restrictions_json,
    )
"""
from __future__ import annotations

from core.intel.compilers.persona_compiler import compile_personas_json
from core.intel.compilers.policy_gate import compile_restrictions_json
from core.intel.compilers.scope_compiler import compile_scope_file

__all__ = [
    "compile_personas_json",
    "compile_restrictions_json",
    "compile_scope_file",
]
