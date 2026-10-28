# Run Sentinel checks locally

No GitHub Actions workflows are configured in this repository. A push or pull
request does not run these commands automatically. Run and record the relevant
checks before asking for independent verification.

From the repository root:

```sh
scripts/local-security-check.sh
.venv/bin/python -m pytest tests/ -m 'not subprocess_spawn' -q
.venv/bin/python -m pytest tests/ -m subprocess_spawn -q
```

Run the two pytest partitions in separate invocations. The
`subprocess_spawn` tests need a clean process. Tests marked `live_external` are
skipped by default; `SENTINEL_RUN_LIVE=1` is a deliberate opt-in to external
target traffic and is not part of the local gate.

For changes to the macOS app, generate the Xcode project and run its tests:

```sh
xcodegen generate --spec ui/project.yml
SENTINEL_DATA_DIR=/tmp/sentinelforge-xctest-state xcodebuild \
  -project ui/SentinelForge.xcodeproj -scheme SentinelForge \
  -configuration Debug -destination 'platform=macOS' \
  CODE_SIGNING_ALLOWED=NO test
```

The app is the test host, so it may attempt loopback connections when launched.
These commands do not establish native acceptance, live observation, or finding
promotion authority.
