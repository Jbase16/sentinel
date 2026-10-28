# SentinelForge Swift tests

`ui/project.yml` defines `SentinelForgeTests` as an Xcode unit-test target that
imports the app module. The former standalone `TestRunner` SwiftPM manifest was
unresolvable because `ui/` is an XcodeGen application, not a Swift package.

From the repository root, regenerate and run the tests with:

```sh
xcodegen generate --spec ui/project.yml
SENTINEL_DATA_DIR=/tmp/sentinelforge-xctest-state xcodebuild \
  -project ui/SentinelForge.xcodeproj -scheme SentinelForge \
  -configuration Debug -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO test
```

The app is the XCTest host. Tests in `Sources/TestRunner` cover API error parsing,
initial state, event decoding, retry backoff, connection-error classification,
and backend attach decisions without starting a scan. The pure Swift files under
`ui/Tests/GhostBridgeOrigin`, `GhostJavaScript`, and `SecureAppLog` retain their
standalone compile commands in their source headers.
