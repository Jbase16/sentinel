# UI Audit Supplement

## Correction
- The earlier cleanup audit is incomplete for repository-level cleanup because it inventories `core/` Python modules only and omits the macOS UI surface. Treat it as a backend/core supplement, not a whole-repo cleanup plan.
- This supplement maps tracked UI source/config plus generated UI artifacts and should be read before any cleanup decision.

## UI Counts
- Tracked `ui/` files: 71
- Tracked non-generated UI files: 70
- Tracked generated/build UI files: 1
- Ignored UI generated/build files currently present: 3629
- Swift files considered in UI source/test scan: 59
- TEST_HARNESS_REVIEW: 4
- UI_CONFIG_LIVE: 5
- UI_CONFIG_RESOURCE_REVIEW: 2
- UI_DUPLICATE_CLUSTER: 3
- UI_LIVE: 52
- UI_LIVE_RESOURCE: 2
- UI_ORPHAN_REVIEW: 1
- UI_REVIEW: 1

## Build Surface
- `ui/project.yml` defines one macOS application target named `SentinelForge`; its source root is `ui/Sources`, plus `../core` as a non-build folder reference.
- The committed `.xcodeproj` source phase includes Swift/Metal files under `ui/Sources`; `Info.plist` and `SentinelForge.entitlements` are the active app config in `project.yml`.
- Root-level `ui/BackendState.swift`, `ui/ErrorClassifier.swift`, and `ui/RetryBackoff.swift` are exact content duplicates of `ui/Sources/Core/*`; they are tracked but not included by `project.yml` or the Xcode build.
- Root-level `ui/Audit/AuditFeedView.swift` is an older divergent copy; the build points at `ui/Sources/Views/Audit/AuditFeedView.swift`.
- `ui/Info-Release.plist` and `ui/SentinelForge.Release.entitlements` are tracked but not active in `project.yml`; treat as release-config review, not automatic deletion.
- `ui/Tests/Package.swift` references `.package(path: "../ui")`, but no `ui/Package.swift` exists. Static evidence says this SwiftPM test harness is stale or miswired.
- `ui/Tests/.build/.lock` is tracked even though `ui/Tests/.build/` is ignored; this is a generated/build artifact cleanup candidate after confirmation.

## Duplicate / Fork Clusters
- `AuditFeedView.swift`: `ui/Audit/AuditFeedView.swift`, `ui/Sources/Views/Audit/AuditFeedView.swift`
- `BackendState.swift`: `ui/BackendState.swift`, `ui/Sources/Core/BackendState.swift`
- `ErrorClassifier.swift`: `ui/ErrorClassifier.swift`, `ui/Sources/Core/ErrorClassifier.swift`
- `RetryBackoff.swift`: `ui/RetryBackoff.swift`, `ui/Sources/Core/RetryBackoff.swift`

## Exact Content Duplicates
- `ui/BackendState.swift`, `ui/Sources/Core/BackendState.swift`
- `ui/ErrorClassifier.swift`, `ui/Sources/Core/ErrorClassifier.swift`
- `ui/RetryBackoff.swift`, `ui/Sources/Core/RetryBackoff.swift`

## UI Cleanup Candidates By Evidence
- `ui/Tests/Package.swift`: TEST_HARNESS_REVIEW; test_referenced; ui_test_harness; references_missing_ui_package; last=08a3276 2025-12-17.
- `ui/Tests/Sources/TestRunner/CriticalPathTests.swift`: TEST_HARNESS_REVIEW; test_referenced; ui_test_harness; last=19d5fda 2026-01-20.
- `ui/Tests/Sources/TestRunner/main.swift`: TEST_HARNESS_REVIEW; test_referenced; referenced_by=ui/Tests/Package.swift; ui_test_harness; last=19d5fda 2026-01-20.
- `ui/Tests/TESTING_STRATEGY.md`: TEST_HARNESS_REVIEW; ui_test_harness; last=19d5fda 2026-01-20.
- `ui/Info-Release.plist`: UI_CONFIG_RESOURCE_REVIEW; no_project_or_reference_evidence; last=dfb7ddd 2026-02-05.
- `ui/SentinelForge.Release.entitlements`: UI_CONFIG_RESOURCE_REVIEW; no_project_or_reference_evidence; last=dfb7ddd 2026-02-05.
- `ui/BackendState.swift`: UI_DUPLICATE_CLUSTER; identical_duplicate_content; duplicate_basename; last=2bcd112 2026-01-11.
- `ui/ErrorClassifier.swift`: UI_DUPLICATE_CLUSTER; identical_duplicate_content; duplicate_basename; last=0541035 2026-01-11.
- `ui/RetryBackoff.swift`: UI_DUPLICATE_CLUSTER; identical_duplicate_content; duplicate_basename; last=2bcd112 2026-01-11.
- `ui/Audit/AuditFeedView.swift`: UI_ORPHAN_REVIEW; duplicate_basename; last=422226e 2026-01-06.
- `ui/Sources/Resources/terminal/index.html`: UI_REVIEW; included_by_project_yml; last=5a0ffc1 2026-01-01.

## Tracked Generated UI Artifacts
- `ui/Tests/.build/.lock`

## Do Not Touch Without UI Build Validation
- `ui/Info.plist`: UI_CONFIG_LIVE; included_by_project_yml; included_by_xcode_build.
- `ui/SentinelForge.entitlements`: UI_CONFIG_LIVE; included_by_project_yml; included_by_xcode_build.
- `ui/SentinelForge.xcodeproj/project.pbxproj`: UI_CONFIG_LIVE; included_by_project_yml; included_by_xcode_build.
- `ui/SentinelForge.xcodeproj/project.xcworkspace/contents.xcworkspacedata`: UI_CONFIG_LIVE; included_by_project_yml; included_by_xcode_build.
- `ui/Sources/Core/AppReducer.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Models/HelixAppState.swift.
- `ui/Sources/Core/BackendState.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/BackendState.swift,ui/Sources/Services/BackendManager.swift; identical_duplicate_content; duplicate_basename.
- `ui/Sources/Core/ErrorClassifier.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/ErrorClassifier.swift,ui/Sources/Services/EventStreamClient.swift,ui/Sources/Services/SentinelAPIClient.swift,ui/Tests/Sources/TestRunner/CriticalPathTests.swift; identical_duplicate_content; duplicate_basename.
- `ui/Sources/Core/HelixError.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included.
- `ui/Sources/Core/RetryBackoff.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/RetryBackoff.swift,ui/Sources/Services/BackendManager.swift,ui/Sources/Services/EventStreamClient.swift,ui/Sources/Services/SentinelAPIClient.swift,ui/Tests/Sources/TestRunner/CriticalPathTests.swift; identical_duplicate_content; duplicate_basename.
- `ui/Sources/Core/ScanProjection.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Core/AppReducer.swift.
- `ui/Sources/Graph/GraphRenderer.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Core/AppReducer.swift,ui/Sources/Core/ScanProjection.swift,ui/Sources/Graph/NeuralGraphView.swift,ui/Sources/Services/CortexStream.swift,ui/Sources/Services/EventStreamClient.swift,ui/Sources/Views/Graph/GraphModels.swift.
- `ui/Sources/Graph/NeuralGraphView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Graph/NetworkGraphView.swift,ui/Sources/Views/Navigation/TerminalView.swift.
- `ui/Sources/Graph/Pressure/PressureShader.metal`: UI_LIVE_RESOURCE; included_by_project_yml; included_by_xcode_build.
- `ui/Sources/Graph/Shaders.metal`: UI_LIVE_RESOURCE; included_by_project_yml; included_by_xcode_build.
- `ui/Sources/Models/AnyCodable.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Graph/GraphRenderer.swift,ui/Sources/Models/HelixAppState.swift,ui/Sources/Models/SharedModels.swift,ui/Sources/Services/EventStreamClient.swift,ui/Sources/Services/GhostAPIClient.swift,ui/Tests/Sources/TestRunner/CriticalPathTests.swift.
- `ui/Sources/Models/FindingModels.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Models/HelixAppState.swift,ui/Sources/Models/PressureGraphModels.swift,ui/Sources/Models/ToolMetadataModels.swift,ui/Sources/Services/CortexStream.swift,ui/Sources/Services/FoundryAPIClient.swift,ui/Sources/Services/GhostAPIClient.swift.
- `ui/Sources/Models/HelixAppState.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Graph/NeuralGraphView.swift,ui/Sources/SentinelForgeApp.swift,ui/Sources/Services/EventStreamClient.swift,ui/Sources/Services/LLMService.swift,ui/Sources/Services/SentinelAPIClient.swift,ui/Sources/Views/Audit/AuditFeedView.swift.
- `ui/Sources/Models/OperationalStateModels.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Models/HelixAppState.swift,ui/Sources/Views/Components/OperationalAlertBanners.swift,ui/Sources/Views/Scan/ScanControlView.swift.
- `ui/Sources/Models/PressureGraphModels.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Graph/NeuralGraphView.swift,ui/Sources/Models/HelixAppState.swift,ui/Sources/Services/CortexStream.swift,ui/Sources/Services/SentinelAPIClient.swift.
- `ui/Sources/Models/SharedModels.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Core/AppReducer.swift,ui/Sources/Core/ScanProjection.swift,ui/Sources/Models/HelixAppState.swift,ui/Sources/Services/CortexStream.swift,ui/Sources/Services/LLMService.swift,ui/Sources/Views/ChatBubbleView.swift.
- `ui/Sources/Models/ToolMetadataModels.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Models/HelixAppState.swift,ui/Sources/Services/SentinelAPIClient.swift.
- `ui/Sources/SentinelForgeApp.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included.
- `ui/Sources/Services/BackendManager.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/BackendState.swift,ui/ErrorClassifier.swift,ui/RetryBackoff.swift,ui/Sources/Core/BackendState.swift,ui/Sources/Core/ErrorClassifier.swift,ui/Sources/Core/RetryBackoff.swift.
- `ui/Sources/Services/CortexStream.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Graph/GraphRenderer.swift,ui/Sources/Graph/NeuralGraphView.swift,ui/Sources/Models/HelixAppState.swift.
- `ui/Sources/Services/EventStreamClient.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/BackendState.swift,ui/ErrorClassifier.swift,ui/RetryBackoff.swift,ui/Sources/Core/AppReducer.swift,ui/Sources/Core/BackendState.swift,ui/Sources/Core/ErrorClassifier.swift.
- `ui/Sources/Services/FoundryAPIClient.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Models/HelixAppState.swift,ui/Sources/Views/Foundry/FoundryConsoleView.swift.
- `ui/Sources/Services/GenerateModels.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included.
- `ui/Sources/Services/GhostAPIClient.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Services/VerifyAPIClient.swift,ui/Sources/Views/Ghost/GhostConsoleView.swift.
- `ui/Sources/Services/GhostCaptureBrowser.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Ghost/GhostConsoleView.swift.
- `ui/Sources/Services/LLMService.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Models/HelixAppState.swift,ui/Sources/SentinelForgeApp.swift,ui/Sources/Services/SentinelAPIClient.swift.
- `ui/Sources/Services/LedgerStreamClient.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Audit/AuditFeedView.swift.
- `ui/Sources/Services/ModelRouter.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Models/HelixAppState.swift,ui/Sources/Services/LLMService.swift.
- `ui/Sources/Services/PTYClient.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Models/HelixAppState.swift,ui/Sources/Views/Navigation/TerminalView.swift.
- `ui/Sources/Services/SentinelAPIClient.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/BackendState.swift,ui/ErrorClassifier.swift,ui/RetryBackoff.swift,ui/Sources/Core/BackendState.swift,ui/Sources/Core/ErrorClassifier.swift,ui/Sources/Core/RetryBackoff.swift.
- `ui/Sources/Services/VerifyAPIClient.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Verify/VerifyConsoleView.swift.
- `ui/Sources/Views/Audit/AuditFeedView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Audit/AuditFeedView.swift,ui/Sources/Views/MainWindowView.swift; duplicate_basename.
- `ui/Sources/Views/ChatBubbleView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Navigation/ChatView.swift.
- `ui/Sources/Views/Components/IdentityStatusView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Graph/NetworkGraphView.swift.
- `ui/Sources/Views/Components/OperationalAlertBanners.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Dashboard/DashboardView.swift,ui/Sources/Views/Scan/ScanControlView.swift.
- `ui/Sources/Views/Components/StatusComponents.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Dashboard/DashboardView.swift,ui/Sources/Views/MainWindowView.swift,ui/Sources/Views/Navigation/ChatView.swift,ui/Sources/Views/Report/ReportComposerView.swift,ui/Sources/Views/Scan/ScanControlView.swift.
- `ui/Sources/Views/Components/TierBadgeView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Scan/ScanControlView.swift,ui/Sources/Views/ToolsBankView.swift.
- `ui/Sources/Views/Dashboard/DashboardView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/MainWindowView.swift.
- `ui/Sources/Views/Dashboard/DecisionStreamView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Dashboard/DashboardView.swift.
- `ui/Sources/Views/Foundry/FoundryConsoleView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/MainWindowView.swift.
- `ui/Sources/Views/Ghost/GhostConsoleView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Services/GhostAPIClient.swift,ui/Sources/Views/MainWindowView.swift.
- `ui/Sources/Views/Graph/GraphModels.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included.
- `ui/Sources/Views/Graph/NetworkGraphView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/MainWindowView.swift.
- `ui/Sources/Views/MainWindowView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/SentinelForgeApp.swift.
- `ui/Sources/Views/Navigation/ChatView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/MainWindowView.swift.
- `ui/Sources/Views/Navigation/TerminalView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/MainWindowView.swift,ui/Sources/Views/Verify/VerifyConsoleView.swift.
- `ui/Sources/Views/Report/ReportComposerView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included.
- `ui/Sources/Views/Reporting/BountyReportView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Reporting/ReportView.swift.
- `ui/Sources/Views/Reporting/ReportView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/MainWindowView.swift,ui/Sources/Views/Reporting/BountyReportView.swift.
- `ui/Sources/Views/Scan/ActionRequestView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/Scan/ScanControlView.swift.
- `ui/Sources/Views/Scan/ScanControlView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/MainWindowView.swift.
- `ui/Sources/Views/Settings/BackendSettingsView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/MainWindowView.swift.
- `ui/Sources/Views/ToolsBankView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/MainWindowView.swift.
- `ui/Sources/Views/Verify/VerifyConsoleView.swift`: UI_LIVE; included_by_project_yml; included_by_xcode_build; app_reachable_or_build_included; referenced_by=ui/Sources/Views/MainWindowView.swift.
- `ui/project.yml`: UI_CONFIG_LIVE; included_by_project_yml.
