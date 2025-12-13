import AppKit
import Foundation

extension Notification.Name {
    static let backendReady = Notification.Name("backendReady")
}

/// Manages the lifecycle of the Python Backend (Neuro-Symbolic Core).
/// Allows the app to be self-contained during development.
class BackendManager: ObservableObject {
    static let shared = BackendManager()

    @Published var status: String = "Initializing..."
    @Published var isRunning: Bool = false

    private var process: Process?
    private var pipe: Pipe?

    func start() {
        Task {
            if await checkPort8765() {
                await MainActor.run {
                    self.status = "Core Connected (External)"
                    self.isRunning = true
                    NotificationCenter.default.post(name: .backendReady, object: nil)
                }
                return
            }

            await launchIntegratedServer()
        }
    }

    func stop() {
        process?.terminate()
        process = nil
    }

    private func checkPort8765() async -> Bool {
        // Simple TCP check (simulated via URLSession for now)
        let url = URL(string: "http://127.0.0.1:8765/ping")!
        var request = URLRequest(url: url)
        request.timeoutInterval = 1.0
        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            return (response as? HTTPURLResponse)?.statusCode == 200
        } catch {
            return false
        }
    }

    private func launchIntegratedServer() async {
        await MainActor.run { self.status = "Booting Neural Core..." }

        // 1. Locate the Repository Root
        // We assume we are running from DerivedData, so we look for the source root.
        // Helper: In Xcode, we can pass environment variables, but here we'll try to guess.

        let fileManager = FileManager.default
        let home = fileManager.homeDirectoryForCurrentUser
        let possiblePaths = [
            // Standard Dev paths
            home.appendingPathComponent("Developer/sentinelforge"),
            home.appendingPathComponent("Developer/sentinel"),
            // If running from within the repo
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath),
            // Common location for this user
            URL(fileURLWithPath: "/Users/jason/Developer/sentinelforge"),
        ]

        guard let repoPath = possiblePaths.first(where: { fileManager.fileExists(atPath: $0.path) })
        else {
            await MainActor.run { self.status = "Error: Repo not found" }
            return
        }

        print("[BackendManager] Detected Repo at: \(repoPath.path)")

        // 2. Prepare Process
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/python3")

        // We assume the user has dependencies installed locally or in a venv.
        // If venv exists, use it.
        let venvPython = repoPath.appendingPathComponent("venv/bin/python3")
        if fileManager.fileExists(atPath: venvPython.path) {
            p.executableURL = venvPython
        } else {
            // Fallback: Check for homebrew python
            let brewPython = URL(fileURLWithPath: "/opt/homebrew/bin/python3")
            if fileManager.fileExists(atPath: brewPython.path) {
                p.executableURL = brewPython
            }
        }

        p.currentDirectoryURL = repoPath
        p.arguments = ["-m", "uvicorn", "core.api:app", "--host", "127.0.0.1", "--port", "8765"]

        // 3. Capture Output
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe

        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if let str = String(data: data, encoding: .utf8), !str.isEmpty {
                print("[Core] \(str.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
        }

        self.process = p
        self.pipe = pipe

        do {
            try p.run()
            await MainActor.run {
                self.status = "Core Running (PID: \(p.processIdentifier))"
                self.isRunning = true
            }
        } catch {
            await MainActor.run { self.status = "Boot Failed: \(error.localizedDescription)" }
        }
    }
}
