// Pure attach-decision tests. Compile with BackendAttachDecision.swift in the
// temporary SwiftPM proof package; the historical UI test runner is not used.

enum BackendAttachDecisionTests {
    static func run() {
        print("=== Backend Attach Decision Tests ===")
        let probeCount = testProbeClassification()
        let actionCount = testAttachActions()
        let sequenceCount = testDecisionSequences()
        print("PASS: \(probeCount) probe cases, \(actionCount) action cases, \(sequenceCount) decision sequences")
        print("Pure decision proof only; runtime polling, cancellation, and attachment require app verification.")
    }

    private static func testProbeClassification() -> Int {
        let cases: [(name: String, statusCode: Int?, healthStatus: String?, transportFailed: Bool, expected: ExternalCoreProbe)] = [
            // Auth-on with a valid token and auth-off return the same ready observation.
            ("ready response", 200, "ready", false, .ready),
            ("initializing response", 200, "starting", false, .presentNotReady),
            ("unknown health status", 200, "unknown", false, .presentNotReady),
            ("missing health status", 200, nil, false, .presentNotReady),
            ("empty health status", 200, "", false, .presentNotReady),
            ("nonmatching ready status", 200, "READY", false, .presentNotReady),
            // Regression guards: authentication rejection proves presence, never absence.
            ("unauthorized response", 401, nil, false, .presentNotReady),
            ("forbidden response", 403, nil, false, .presentNotReady),
            ("unauthorized overrides ready body", 401, "ready", false, .presentNotReady),
            ("forbidden overrides ready body", 403, "ready", false, .presentNotReady),
            ("no-content response", 204, nil, false, .presentNotReady),
            ("redirect response", 302, "ready", false, .presentNotReady),
            ("not-found response", 404, nil, false, .presentNotReady),
            ("server error overrides ready body", 500, "ready", false, .presentNotReady),
            ("unavailable response", 503, nil, false, .presentNotReady),
            ("transport failure", nil, nil, true, .absent),
            ("transport failure overrides ready fields", 200, "ready", true, .absent),
            ("transport failure overrides auth fields", 401, nil, true, .absent),
            ("missing HTTP response", nil, nil, false, .absent),
            ("missing HTTP response with ready body", nil, "ready", false, .absent),
        ]

        for test in cases {
            let actual = classifyProbe(
                statusCode: test.statusCode,
                healthStatus: test.healthStatus,
                transportFailed: test.transportFailed
            )
            assert(actual == test.expected, "\(test.name): expected \(test.expected), got \(actual)")
        }
        print("  PASS: \(cases.count) probe classifications (including 401/403 regression guards)")
        return cases.count
    }

    private static func testAttachActions() -> Int {
        let cases: [(probe: ExternalCoreProbe, external: Bool, expected: BackendAttachAction)] = [
            (.absent, false, .spawn),
            (.absent, true, .wait),
            (.ready, false, .attach),
            (.ready, true, .attach),
            (.presentNotReady, false, .wait),
            (.presentNotReady, true, .wait),
        ]

        for test in cases {
            let actual = attachAction(for: test.probe, allowExternalBackend: test.external)
            assert(actual == test.expected,
                   "\(test.probe), external=\(test.external): expected \(test.expected), got \(actual)")
        }
        print("  PASS: \(cases.count) attach actions (complete three-outcome/two-mode matrix)")
        return cases.count
    }

    private static func testDecisionSequences() -> Int {
        // These assert decisions for successive observations, not the runtime poll loop.
        let externalProbes: [ExternalCoreProbe] = [.absent, .presentNotReady, .ready]
        let externalActions = externalProbes.map { attachAction(for: $0, allowExternalBackend: true) }
        assert(externalActions == [.wait, .wait, .attach],
               "External mode must wait through absence and initialization, then choose attachment")

        let relaunchProbes = [
            classifyProbe(statusCode: 401, healthStatus: nil, transportFailed: false),
            classifyProbe(statusCode: 200, healthStatus: "starting", transportFailed: false),
            classifyProbe(statusCode: 200, healthStatus: "ready", transportFailed: false),
        ]
        let relaunchActions = relaunchProbes.map { attachAction(for: $0, allowExternalBackend: false) }
        assert(relaunchActions == [.wait, .wait, .attach],
               "Self-managed relaunch must never choose duplicate spawn for a present core")
        print("  PASS: 2 decision sequences (external startup and self-managed relaunch)")
        return 2
    }
}
