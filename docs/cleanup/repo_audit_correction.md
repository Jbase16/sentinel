# Whole-Repository Audit Correction

## Status Of Previous Audit
- Unsafe as a whole-repo cleanup plan: it omitted UI, scripts, docs, top-level config, generated artifacts, and non-Python resources.
- Still useful as a `core/` Python reachability map, but cleanup decisions must use `whole_repo_inventory.tsv` and `ui_reachability_summary.md` too.

## Whole-Repo Inventory Counts
- Git-tracked files inventoried: 803
- core-python: 388
- docs: 92
- other-tracked: 21
- python-tests: 193
- root-config-doc: 3
- scripts: 23
- tools: 12
- ui-app-config: 4
- ui-generated-or-build: 1
- ui-metal: 2
- ui-project-config: 3
- ui-resource-or-doc: 1
- ui-swift: 59
- ui-tests: 1

## New Critical Findings
- UI was omitted from the first pass. Cleanup cannot safely proceed from the first report alone.
- `ui/Tests/.build/.lock` is git-tracked despite `.gitignore` ignoring `ui/Tests/.build/`; this is a generated/build artifact candidate requiring explicit removal decision.
- `ui/Tests/Package.swift` appears miswired because it references `../ui` as a Swift package and no `ui/Package.swift` exists.
- Several tracked root-level UI Swift files are duplicates or older forks of live files under `ui/Sources`.
- Large ignored UI build/DerivedData outputs are present locally but ignored; they are not repo cleanup candidates unless local workspace hygiene is in scope.

## New Artifacts
- `whole_repo_inventory.tsv`: every git-tracked repo file with category, LOC, generated/build flag, and git context.
- `ui_inventory.tsv`: tracked UI source/config/resource file map with XcodeGen/Xcode reachability evidence.
- `ui_reachability_summary.md`: human-readable UI cleanup and do-not-touch map.
- `repo_audit_correction.md`: this correction note.
