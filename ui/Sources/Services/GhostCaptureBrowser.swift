//
//  GhostCaptureBrowser.swift
//  SentinelForgeUI — Phase 4-UI
//
//  The "last mile" for Ghost Protocol: getting a browser's traffic to
//  actually traverse the mitmproxy interceptor so it can be recorded.
//
//  Ghost is a PASSIVE proxy — it only sees traffic explicitly routed to
//  127.0.0.1:<port>. Safari and WebKit-based browsers (incl. ChatGPT Atlas)
//  honor only the GLOBAL system proxy, which is invasive and easy to leave
//  dangling. Chromium-family browsers accept a per-instance `--proxy-server`
//  flag plus an isolated `--user-data-dir`, so we can route exactly one
//  throwaway browser window through Ghost without touching the system or the
//  operator's real browsing. This is the same trick Burp/ZAP use for their
//  embedded browsers.
//
//  HTTPS interception requires the mitmproxy CA to be trusted. On macOS,
//  Chromium reads the System keychain, so a single `add-trusted-cert`
//  (behind one admin prompt) makes every HTTPS site capturable.
//

import Foundation

enum GhostCaptureBrowserError: LocalizedError {
    case chromiumNotFound
    case certPathMissing
    case certTrustCancelled
    case certTrustFailed(String)
    case launchFailed(String)

    var errorDescription: String? {
        switch self {
        case .chromiumNotFound:
            return "No Chromium-based browser found (Chrome/Chromium/Brave/Edge). "
                + "Install one to use the isolated capture browser — WebKit browsers "
                + "like Safari/Atlas can't be proxied per-window."
        case .certPathMissing:
            return "mitmproxy CA cert not found. Start the proxy at least once so it "
                + "generates ~/.mitmproxy/mitmproxy-ca-cert.pem."
        case .certTrustCancelled:
            return "HTTPS cert trust was cancelled. HTTPS sites won't be captured until "
                + "the mitmproxy CA is trusted."
        case .certTrustFailed(let m):
            return "Failed to trust the mitmproxy CA cert: \(m)"
        case .launchFailed(let m):
            return "Failed to launch the capture browser: \(m)"
        }
    }
}

/// Stateless helpers for the isolated capture browser. All process calls are
/// blocking (`waitUntilExit`) and MUST be invoked off the main thread — the
/// cert-trust step in particular puts up a modal admin dialog.
enum GhostCaptureBrowser {

    /// Where capture-browser profiles live.
    static var profileBaseURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge")
    }

    /// A FRESH, unique Chromium profile per capture session.
    ///
    /// WHY NOT REUSE ONE PROFILE: that caused the dead-clicks bug. When an
    /// earlier session ran through a broken proxy, Chrome cached the proxy's
    /// HTML error pages *as* the site's JS libraries (jQuery etc.), and that
    /// poison persisted into later, healthy sessions — so `$ is not defined`,
    /// no handlers, a permanent blocking overlay. A fresh dir per launch
    /// guarantees an empty cache AND a brand-new browser instance (so
    /// `--proxy-server` always applies and never inherits a stale port). The
    /// only cost is re-login per session, which you do as part of recording
    /// anyway — and clean per-principal sessions are exactly what you want
    /// for the cross-principal diff.
    static func freshProfileURL() -> URL {
        let stamp = Int(Date().timeIntervalSince1970 * 1000)
        return profileBaseURL.appendingPathComponent("ghost-chrome-\(stamp)")
    }

    /// Remove capture profiles older than `maxAge` so they don't accumulate
    /// on disk (each is a full Chromium profile). Best-effort.
    static func reapOldProfiles(maxAge: TimeInterval = 6 * 3600) {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(
            at: profileBaseURL,
            includingPropertiesForKeys: [.contentModificationDateKey]
        ) else { return }
        let cutoff = Date().addingTimeInterval(-maxAge)
        for url in entries where url.lastPathComponent.hasPrefix("ghost-chrome") {
            let mod = (try? url.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate
            if let mod, mod < cutoff {
                try? fm.removeItem(at: url)
            }
        }
    }

    /// First available Chromium-family browser, in preference order.
    static func chromiumExecutableURL() -> URL? {
        let candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ]
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            return URL(fileURLWithPath: path)
        }
        return nil
    }

    /// Whether the mitmproxy CA cert is already present in the System
    /// keychain. Presence after `add-trusted-cert -r trustRoot` implies it's
    /// trusted as a root, so this doubles as a "do we need the admin prompt?"
    /// check.
    static func isCertTrusted() -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        task.arguments = [
            "find-certificate", "-c", "mitmproxy",
            "/Library/Keychains/System.keychain",
        ]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
        } catch {
            return false
        }
        return task.terminationStatus == 0
    }

    /// Add the mitmproxy CA to the System keychain as a trusted root via a
    /// single native admin prompt (osascript). Idempotent — re-adding an
    /// existing cert is harmless. Throws `.certTrustCancelled` if the user
    /// dismisses the password dialog.
    static func trustCert(certPath: String?) throws {
        guard let certPath, FileManager.default.fileExists(atPath: certPath) else {
            throw GhostCaptureBrowserError.certPathMissing
        }

        // Build the privileged shell command, then wrap it for AppleScript.
        // The cert path is single-quoted for the shell; the whole shell
        // string is escaped for the AppleScript string literal.
        let shellCmd = "security add-trusted-cert -d -r trustRoot "
            + "-k /Library/Keychains/System.keychain '\(certPath)'"
        let escaped = shellCmd
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let appleScript =
            "do shell script \"\(escaped)\" with administrator privileges"

        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        task.arguments = ["-e", appleScript]
        let errPipe = Pipe()
        task.standardOutput = Pipe()
        task.standardError = errPipe

        do {
            try task.run()
            task.waitUntilExit()
        } catch {
            throw GhostCaptureBrowserError.certTrustFailed(error.localizedDescription)
        }

        if task.terminationStatus != 0 {
            let stderr = String(
                data: errPipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            )?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            // osascript returns -128 / "User canceled." when the admin dialog
            // is dismissed — surface that as a distinct, non-alarming error.
            if stderr.contains("User canceled") || stderr.contains("-128") {
                throw GhostCaptureBrowserError.certTrustCancelled
            }
            throw GhostCaptureBrowserError.certTrustFailed(
                stderr.isEmpty ? "exit code \(task.terminationStatus)" : stderr
            )
        }
    }

    /// Launch an isolated Chromium instance whose traffic is routed through
    /// the Ghost proxy. The `--user-data-dir` forces a brand-new instance
    /// (independent of any running Chrome) and quarantines capture state.
    /// `<-loopback>` strips Chromium's implicit localhost bypass so that
    /// loopback targets are captured too. Fire-and-forget: the browser keeps
    /// running after this returns.
    @discardableResult
    static func launchCaptureBrowser(
        proxyPort: Int,
        startURL: String = "about:blank"
    ) throws -> String {
        guard let browser = chromiumExecutableURL() else {
            throw GhostCaptureBrowserError.chromiumNotFound
        }

        // Fresh profile every launch → empty cache + brand-new instance.
        reapOldProfiles()
        let profile = freshProfileURL()
        try? FileManager.default.createDirectory(
            at: profile, withIntermediateDirectories: true
        )

        let task = Process()
        task.executableURL = browser
        task.arguments = [
            "--proxy-server=127.0.0.1:\(proxyPort)",
            "--proxy-bypass-list=<-loopback>",
            "--user-data-dir=\(profile.path)",
            "--no-first-run",
            "--no-default-browser-check",
            "--new-window",
            startURL,
        ]
        do {
            try task.run()
        } catch {
            throw GhostCaptureBrowserError.launchFailed(error.localizedDescription)
        }
        return browser.deletingPathExtension().lastPathComponent
    }
}
