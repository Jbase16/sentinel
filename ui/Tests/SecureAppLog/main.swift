// Run with:
// xcrun swiftc ui/Sources/Core/SecureAppLog.swift ui/Tests/SecureAppLog/main.swift \
//   -o /tmp/secure-app-log-test && /tmp/secure-app-log-test
import Foundation

let root = FileManager.default.temporaryDirectory
    .appendingPathComponent("sentinelforge-log-test-\(UUID().uuidString)", isDirectory: true)
defer { try? FileManager.default.removeItem(at: root) }
let directory = root.appendingPathComponent("logs", isDirectory: true)
let log = directory.appendingPathComponent("snd_swift.log")

SecureAppLog.append("first", dataDirectory: root)
let directoryMode = try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as! NSNumber
let fileMode = try FileManager.default.attributesOfItem(atPath: log.path)[.posixPermissions] as! NSNumber
precondition(directoryMode.intValue == 0o700)
precondition(fileMode.intValue == 0o600)

try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: log.path)
SecureAppLog.append("second", dataDirectory: root)
let restrictedMode = try FileManager.default.attributesOfItem(atPath: log.path)[.posixPermissions] as! NSNumber
precondition(restrictedMode.intValue == 0o600)
let content = try String(contentsOf: log, encoding: .utf8)
precondition(content == "first\nsecond\n")

try FileManager.default.removeItem(at: log)
let outside = root.appendingPathComponent("outside.txt")
try "untouched".write(to: outside, atomically: true, encoding: .utf8)
try FileManager.default.createSymbolicLink(at: log, withDestinationURL: outside)
SecureAppLog.append("blocked", dataDirectory: root)
let outsideContent = try String(contentsOf: outside, encoding: .utf8)
precondition(outsideContent == "untouched")
print("Secure app log permissions, append, and symlink refusal passed")
