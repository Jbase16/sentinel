# SentinelForge Swift Testing Strategy

## Overview
This document outlines the testing approach for critical paths in the SentinelForge macOS UI.

## Critical Paths Identified

### 1. State Management (HelixAppState)
**File:** `ui/Sources/Models/HelixAppState.swift`

**Critical Behaviors:**
- Initial state correctness
- Scan state transitions (idle → running → complete)
- Finding accumulation and updates
- Event-driven state synchronization

**Test Cases:**
```swift
func testInitialState() {
    let state = HelixAppState()
    XCTAssertFalse(state.isScanRunning)
    XCTAssertTrue(state.findings.isEmpty)
    XCTAssertTrue(state.selectedTarget.isEmpty)
}

func testScanStartTransition() {
    let state = HelixAppState()
    let expectation = XCTestExpectation(description: "State updates on scan start")

    state.$isScanRunning
        .dropFirst() // Skip initial value
        .sink { isRunning in
            XCTAssertTrue(isRunning)
            expectation.fulfill()
        }
        .store(in: &cancellables)

    // Simulate scan start event handling
    // In production, this comes from EventStreamClient
    wait(for: [expectation], timeout: 1.0)
}

func testFindingAccumulation() {
    let state = HelixAppState()

    // Test that findings can be added via API responses
    // In production: state.findings gets updated after API fetch
    // Verify finding count increases
    // Verify finding details are preserved
}
```

**Key Insights:**
- State changes are event-driven (via `EventStreamClient.scanEventPublisher`)
- All state updates happen on `@MainActor`
- Findings are fetched explicitly after scan completion (not streamed)

### 2. API Client (SentinelAPIClient)
**File:** `ui/Sources/Services/SentinelAPIClient.swift`

**Critical Behaviors:**
- Error parsing and classification
- Request/response handling
- Retry logic for connection failures
- Token-based authentication

**Test Cases:**
```swift
func testErrorParsing_ToolFailed() {
    let errorResponse = HTTPURLResponse(url: testURL, statusCode: 500)
    let payload: [String: Any] = [
        "code": "TOOL_002",
        "message": "Tool failed",
        "details": ["tool": "nmap", "exit_code": 124, "stderr": "timeout"]
    ]

    let data = try! JSONSerialization.data(withJSONObject: payload)
    let error = SentinelAPIClient.parseAPIError(data: data, response: errorResponse)

    if case .toolFailed(let tool, let exitCode, let stderr) = error {
        XCTAssertEqual(tool, "nmap")
        XCTAssertEqual(exitCode, 124)
        XCTAssertEqual(stderr, "timeout")
    } else {
        XCTFail("Expected toolFailed error")
    }
}

func testErrorParsing_ScanTimeout() {
    let payload: [String: Any] = [
        "code": "SCAN_003",
        "message": "Scan timed out",
        "details": ["duration": 120]
    ]

    let data = try! JSONSerialization.data(withJSONObject: payload)
    let error = SentinelAPIClient.parseAPIError(data: data, response: errorResponse)

    if case .scanTimeout(let duration) = error {
        XCTAssertEqual(duration, 120)
    } else {
        XCTFail("Expected scanTimeout error")
    }
}

func testPingRetry() async {
    let client = SentinelAPIClient()

    // Test that ping() handles connection refused gracefully
    // Should not throw, should return false
    let alive = await client.ping()
    // Assert based on backend state
}
```

**Key Insights:**
- Structured error types prevent generic "API Error" messages
- Each backend error code maps to a specific Swift enum case
- Connection refused during startup is handled gracefully (no error logs)

### 3. Error Handling (ErrorClassifier)
**File:** `ui/ErrorClassifier.swift`

**Critical Behaviors:**
- Connection refused detection (ECONNREFUSED, NSURLErrorCannotConnectToHost)
- Error logging suppression during startup
- Network error classification

**Test Cases:**
```swift
func testConnectionRefusedDetection() {
    let posixError = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNREFUSED))
    XCTAssertTrue(ErrorClassifier.isConnectionRefused(posixError))

    let urlError = NSError(domain: NSURLErrorDomain, code: NSURLErrorCannotConnectToHost)
    XCTAssertTrue(ErrorClassifier.isConnectionRefused(urlError))

    let otherError = NSError(domain: "CustomDomain", code: 999)
    XCTAssertFalse(ErrorClassifier.isConnectionRefused(otherError))
}

func testErrorLoggingSuppression() {
    let connectionRefused = NSError(domain: NSPOSIXErrorDomain, code: Int(ECONNREFUSED))

    // Should not log connection refused as error (expected during startup)
    XCTAssertFalse(ErrorClassifier.shouldLogAsError(connectionRefused))

    // Should log other errors
    let realError = NSError(domain: "RealFailure", code: 500)
    XCTAssertTrue(ErrorClassifier.shouldLogAsError(realError))
}
```

**Key Insights:**
- Connection refused is expected during backend startup (not logged as error)
- Only real errors are logged, reducing noise in development
- Error classification prevents false alarms

### 4. Event Stream (EventStreamClient)
**File:** `ui/Sources/Services/EventStreamClient.swift`

**Critical Behaviors:**
- SSE connection and reconnection
- Event decoding (JSON → GraphEvent)
- Epoch detection (server restart handling)
- Backoff strategy for retries

**Test Cases:**
```swift
func testGraphEventDecoding() {
    let json = """
    {
        "id": "event-123",
        "type": "scan_started",
        "timestamp": 1234567890.0,
        "wall_time": "2023-01-01T00:00:00Z",
        "sequence": 1,
        "payload": {"target": "example.com"},
        "source": "api",
        "epoch": "epoch-abc"
    }
    """

    let data = json.data(using: .utf8)!
    let event = try! JSONDecoder().decode(GraphEvent.self, from: data)

    XCTAssertEqual(event.id, "event-123")
    XCTAssertEqual(event.type, "scan_started")
    XCTAssertEqual(event.sequence, 1)
    XCTAssertEqual(event.epoch, "epoch-abc")
}

func testEpochChange() {
    let client = EventStreamClient()

    // Simulate receiving events with different epochs
    // Should reset sequence tracking
    // Verify lastSequence resets to 0
    // Verify eventCount resets to 0
}

func testReconnectionBackoff() {
    XCTAssertEqual(RetryBackoff.delayForAttempt(0), 0.0)
    XCTAssertEqual(RetryBackoff.delayForAttempt(1), 0.2)
    XCTAssertEqual(RetryBackoff.delayForAttempt(2), 0.5)
    XCTAssertEqual(RetryBackoff.delayForAttempt(3), 1.0)
    XCTAssertEqual(RetryBackoff.delayForAttempt(4), 5.0)
}
```

**Key Insights:**
- Connection only marked as live after first event receipt (not after HTTP 200)
- Epoch changes trigger sequence reset (handles server restarts)
- Custom backoff: 0s, 0.2s, 0.5s, 1s, 5s (prevents rapid reconnect spam)

## Running Tests

### XCTest Integration (Recommended)
```bash
# From UI directory
swift test
```

### Standalone Test Runner (Current)
```bash
# From Tests directory
swift run TestRunner
```

## Test Coverage Goals

| Component | Current Coverage | Target Coverage |
|-----------|-----------------|----------------|
| HelixAppState | 0% | 80% |
| SentinelAPIClient | ~30% (basic) | 90% |
| EventStreamClient | 0% | 70% |
| ErrorClassifier | 0% | 95% |

## Implementation Priority

1. **High Priority** (Prevents regressions):
   - API error parsing tests (already partially implemented)
   - Error classification tests
   - Event decoding tests

2. **Medium Priority** (Catches integration issues):
   - State transition tests
   - Reconnection logic tests
   - Token refresh tests

3. **Low Priority** (Nice to have):
   - Performance tests
   - UI interaction tests
   - Edge case coverage

## CI/CD Integration

Tests should run automatically on:
- Every commit to `main`
- Every pull request
- Before release builds

### Test Requirements for PR Approval
- All existing tests must pass
- New code must include tests for critical paths
- No reduction in overall test coverage

## Future Enhancements

1. **Mock Backend**: Create a mock HTTP server for deterministic API testing
2. **Snapshot Tests**: Verify UI rendering doesn't regress
3. **Performance Tests**: Ensure event stream can handle high throughput
4. **Integration Tests**: Test full scan lifecycle end-to-end

## References

- Swift Testing Guide: https://developer.apple.com/documentation/xctest
- Combine Testing: https://www.swiftbysundell.com/articles/unit-testing-combine-based-swift-code/
- EventStream Pattern: https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events
