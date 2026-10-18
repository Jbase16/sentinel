import Foundation

struct GhostCaptureOrigin: Equatable {
    let scheme: String
    let host: String
    let port: Int

    init?(url: URL) {
        guard let scheme = url.scheme,
              let host = url.host else { return nil }
        let normalizedScheme = scheme.lowercased()
        let defaultPort = normalizedScheme == "https" ? 443 : 80
        self.init(scheme: scheme, host: host, port: url.port ?? defaultPort)
    }

    init?(scheme: String, host: String, port: Int) {
        let normalizedScheme = scheme.lowercased()
        guard ["http", "https"].contains(normalizedScheme) else { return nil }
        var normalizedHost = host.lowercased()
        while normalizedHost.hasSuffix(".") {
            normalizedHost.removeLast()
        }
        guard !normalizedHost.isEmpty else { return nil }
        self.scheme = normalizedScheme
        self.host = normalizedHost
        self.port = port
    }

    static func admitsBridgeFrame(
        pageURL: URL?,
        frameScheme: String,
        frameHost: String,
        framePort: Int
    ) -> Bool {
        guard let pageURL,
              let expected = GhostCaptureOrigin(url: pageURL) else { return false }
        let effectivePort = framePort == 0
            ? (frameScheme.lowercased() == "https" ? 443 : 80)
            : framePort
        guard let frame = GhostCaptureOrigin(
            scheme: frameScheme, host: frameHost, port: effectivePort
        ) else { return false }
        return frame == expected
    }
}
