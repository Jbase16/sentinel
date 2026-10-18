import Darwin
import Foundation

enum SecureAppLog {
    static func append(_ message: String, dataDirectory: URL) {
        let directory = dataDirectory.appendingPathComponent("logs", isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700], ofItemAtPath: directory.path
            )
        } catch {
            return
        }

        let path = directory.appendingPathComponent("snd_swift.log")
        let fd = Darwin.open(path.path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { return }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        guard Darwin.fchmod(fd, 0o600) == 0 else { return }
        try? handle.write(contentsOf: Data((message + "\n").utf8))
    }
}
