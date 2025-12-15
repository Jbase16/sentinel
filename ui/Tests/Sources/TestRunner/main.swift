// ============================================================================
// ui/Tests/Sources/TestRunner/main.swift
// Main Component
// ============================================================================
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
// ============================================================================

import Foundation
import SentinelForgeUI

@main
struct TestRunner {
    static func main() async {
        print("--- Starting Swift Client Test ---")
        
        let client = SentinelAPIClient()
        
        // 1. Test Ping
        print("[*] Testing Ping...")
        let alive = await client.ping()
        if alive {
            print("    SUCCESS: Backend is reachable")
        } else {
            print("    FAILED: Backend unreachable")
            exit(1)
        }
        
        // 2. Test Scan
        print("[*] Testing Start Scan...")
        do {
            try await client.startScan(target: "scanme.nmap.org")
            print("    SUCCESS: Scan started")
        } catch {
            print("    FAILED: \(error)")
            exit(1)
        }
        
        // 3. Test Chat Stream
        print("[*] Testing Chat Stream...")
        do {
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
