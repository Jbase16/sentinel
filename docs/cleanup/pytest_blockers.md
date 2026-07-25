# Pytest Blockers

## Duplicate Test Basename Collisions
- `test_execution_policy.py`:
  - `tests/core/wraith/test_execution_policy.py`
  - `tests/unit/core/test_execution_policy.py`
- `test_verifier.py`:
  - `tests/core/wraith/test_verifier.py`
  - `tests/unit/intel/test_verifier.py`

## Safe Remediation Options
- Use `pytest --import-mode=importlib tests/` as a low-risk collection workaround.
- Rename colliding tests only after module/fork decisions, preserving intent in directory names.
- Move package-like duplicate tests under unique packages with `__init__.py` only if that matches the project test layout decision.
- Cleanup cannot safely proceed until full-suite collection is made deterministic.


## Collection Probes Run During Audit
- `python3 -m pytest tests --collect-only -q`: exit 2; 1887 tests collected before interruption; full-suite blocker is an import-file mismatch for `tests/unit/core/test_execution_policy.py` after `tests/core/wraith/test_execution_policy.py` was imported as `test_execution_policy`.
- `python3 -m pytest tests --collect-only --import-mode=importlib -q`: exit 0; 1906 tests collected; this confirms importlib mode avoids basename module collisions for collection.
- Independent default collection passes: `tests/core` 65 tests, `tests/unit` 1632 tests, `tests/integration` 80 tests, `tests/verification` 22 tests, `tests/security` 78 tests, `tests/manual` 1 test.
- Combined collision subtree probe `tests/core/wraith tests/unit/core tests/unit/intel --collect-only -q`: exit 2; reproduced `test_execution_policy.py` collision before reaching the `test_verifier.py` pair.
- Actual test execution was not run; this audit records collection health and blockers only.

## Full-Suite Blocker
Cleanup cannot safely proceed until this is resolved: default pytest import mode treats duplicate basenames as the same top-level module when test files are not packaged uniquely. The two precise collision pairs detected under `tests/` are `test_execution_policy.py` and `test_verifier.py`.
