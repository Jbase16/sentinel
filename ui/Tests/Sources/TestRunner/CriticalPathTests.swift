import Foundation
import XCTest
@testable import SentinelForge

@MainActor
final class CriticalPathTests: XCTestCase {
    func testInitialState() {
        let state = HelixAppState(llm: LLMService())
        XCTAssertFalse(state.isScanRunning)
        XCTAssertNil(state.apiResults)
        XCTAssertTrue(state.scopeRules.isEmpty)
    }

    func testAPIErrorParsing() throws {
        let url = try XCTUnwrap(URL(string: "http://localhost"))
        let response = try XCTUnwrap(
            HTTPURLResponse(url: url, statusCode: 500, httpVersion: nil, headerFields: nil)
        )
        let toolData = try JSONSerialization.data(withJSONObject: [
            "code": "TOOL_002",
            "details": ["tool": "nmap", "exit_code": 124, "stderr": "timeout"],
        ])
        XCTAssertEqual(
            SentinelAPIClient.parseAPIError(data: toolData, response: response),
            .toolFailed(tool: "nmap", exitCode: 124, stderr: "timeout")
        )

        let timeoutData = try JSONSerialization.data(withJSONObject: [
            "code": "SCAN_003", "details": ["duration": 120],
        ])
        XCTAssertEqual(
            SentinelAPIClient.parseAPIError(data: timeoutData, response: response),
            .scanTimeout(duration: 120)
        )
    }

    func testGraphEventDecodingAndTypes() throws {
        let data = Data("""
        {"id":"event-123","type":"scan_started","timestamp":1234567890.0,
         "wall_time":"2023-01-01T00:00:00Z","sequence":1,
         "payload":{"target":"example.com"},"source":"api","epoch":"epoch-abc"}
        """.utf8)
        let event = try JSONDecoder().decode(GraphEvent.self, from: data)
        XCTAssertEqual(event.id, "event-123")
        XCTAssertEqual(event.sequence, 1)
        XCTAssertEqual(event.epoch, "epoch-abc")
        XCTAssertEqual(event.eventType, .scanStarted)
        XCTAssertEqual(GraphEventType(rawValue: "node_added"), .nodeAdded)
        XCTAssertNil(GraphEventType(rawValue: "unknown_event_xyz"))
    }

    func testBackoffUsesOneIndexedAttempts() {
        XCTAssertEqual(RetryBackoff.delayForAttempt(1), 0)
        XCTAssertEqual(RetryBackoff.delayForAttempt(2), 0.2)
        XCTAssertEqual(RetryBackoff.delayForAttempt(3), 0.5)
        XCTAssertEqual(RetryBackoff.delayForAttempt(4), 1)
        XCTAssertEqual(RetryBackoff.delayForAttempt(5), 5)
    }

    func testConnectionRefusedClassificationRequiresStreamCode() {
        let refused = NSError(
            domain: NSURLErrorDomain,
            code: NSURLErrorCannotConnectToHost,
            userInfo: ["_kCFStreamErrorCodeKey": 61]
        )
        XCTAssertTrue(ErrorClassifier.isConnectionRefused(refused))
        XCTAssertFalse(ErrorClassifier.shouldLogAsError(refused))

        let missingStreamCode = NSError(
            domain: NSURLErrorDomain, code: NSURLErrorCannotConnectToHost
        )
        XCTAssertFalse(ErrorClassifier.isConnectionRefused(missingStreamCode))
        XCTAssertTrue(ErrorClassifier.shouldLogAsError(missingStreamCode))
        XCTAssertFalse(ErrorClassifier.isConnectionRefused(
            NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNREFUSED))
        ))
    }

    func testBackendAttachDecisions() {
        BackendAttachDecisionTests.run()
    }

    func testRetainedPersonaCommandsResolveIdentifier() {
        let arguments: [String: Any] = ["persona": "alice"]
        for command in ["click", "fill", "wait_for", "extract", "screenshot", "get_cookies"] {
            XCTAssertEqual(
                DriverCommandPersona.identifier(for: command, args: arguments),
                "alice",
                command
            )
        }
        XCTAssertNil(DriverCommandPersona.identifier(for: "click", args: [:]))
        XCTAssertNil(DriverCommandPersona.identifier(for: "click", args: ["persona": 42]))
    }
}
