// Run with:
// xcrun swiftc ui/Sources/Core/GhostCaptureOrigin.swift ui/Tests/GhostBridgeOrigin/main.swift \
//   -o /tmp/ghost-bridge-origin-test && /tmp/ghost-bridge-origin-test
import Foundation

let page = URL(string: "https://target.example.test/path")!
let admits = GhostCaptureOrigin.admitsBridgeFrame

precondition(admits(page, "https", "target.example.test", 443))
precondition(admits(page, "HTTPS", "TARGET.EXAMPLE.TEST.", 0))
precondition(!admits(page, "https", "attacker.example.test", 443))
precondition(!admits(page, "https", "target.example.test", 8443))
precondition(!admits(page, "http", "target.example.test", 80))
precondition(!admits(nil, "https", "target.example.test", 443))
precondition(!admits(page, "about", "", 0))
print("Ghost bridge main and same-origin frames admitted; cross-origin frames rejected")
