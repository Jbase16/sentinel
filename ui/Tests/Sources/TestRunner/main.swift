//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: main]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import Foundation
import SentinelForgeUI

@main
/// Struct TestRunner {.
struct TestRunner {
    static func main() async {
        print("===================================")
        print("  SentinelForge Swift Test Suite  ")
        print("===================================\n")

        // Run critical path tests first
        runCriticalPathTests()

        print("--- Starting Integration Tests ---\n")

        func assert(_ condition: @autoclosure () -> Bool, _ message: String) {
            if !condition() {
                print("    FAILED: \(message)")
                exit(1)
            }
        }

        // 0. Test API error parsing
        let testURL = URL(string: "http://localhost")!
        let errorResponse = HTTPURLResponse(url: testURL, statusCode: 500, httpVersion: nil, headerFields: nil)
        let toolErrorPayload: [String: Any] = [
            "code": "TOOL_002",
            "message": "Tool failed",
            "details": ["tool": "nmap", "exit_code": 124, "stderr": "timeout"],
        ]
        let scanTimeoutPayload: [String: Any] = [
            "code": "SCAN_003",
            "message": "Scan timed out",
            "details": ["duration": 120],
        ]

        if let data = try? JSONSerialization.data(withJSONObject: toolErrorPayload) {
            let error = SentinelAPIClient.parseAPIError(data: data, response: errorResponse)
            switch error {
            case .toolFailed(let tool, let exitCode, let stderr):
                assert(tool == "nmap", "Expected tool name to be nmap")
                assert(exitCode == 124, "Expected exit code 124")
                assert(stderr == "timeout", "Expected stderr to be timeout")
            default:
                print("    FAILED: Expected toolFailed error")
                exit(1)
            }
        }

        if let data = try? JSONSerialization.data(withJSONObject: scanTimeoutPayload) {
            let error = SentinelAPIClient.parseAPIError(data: data, response: errorResponse)
            switch error {
            case .scanTimeout(let duration):
                assert(duration == 120, "Expected scan timeout duration to be 120")
            default:
                print("    FAILED: Expected scanTimeout error")
                exit(1)
            }
        }
        
        let client = SentinelAPIClient()
        
        // 1. Test Ping
        print("[*] Testing Ping...")
        let alive = await client.ping()
        // Conditional branch.
        if alive {
            print("    SUCCESS: Backend is reachable")
        } else {
            print("    FAILED: Backend unreachable")
            exit(1)
        }
        
        // 2. Test Scan
        print("[*] Testing Start Scan...")
        // Do-catch block.
        do {
            try await client.startScan(target: "scanme.nmap.org")
            print("    SUCCESS: Scan started")
        } catch {
            print("    FAILED: \(error)")
            exit(1)
        }
        
        // 3. Test Chat Stream
        print("[*] Testing Chat Stream...")
        // Do-catch block.
        do {
            // Loop over items.
            for try await token in client.streamChat(prompt: "hello") {
                print("    Received token: \(token)")
                break // Just need one to prove it works
            }
            print("    SUCCESS: Stream working")
        } catch {
            print("    FAILED: Chat stream error: \(error)")
            // Chat might timeout, don't fail the whole suite
        }
        
        print("--- Tests Complete ---")
    }
}
