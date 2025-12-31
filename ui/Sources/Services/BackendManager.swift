//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: BackendManager]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import AppKit
import Foundation

extension Notification.Name {
    static let backendReady = Notification.Name("backendReady")
}

/// Manages the lifecycle of the Python Backend (Neuro-Symbolic Core).
/// Automatically starts the FastAPI server when the app launches and terminates it on quit.
@MainActor
/// Class BackendManager.
class BackendManager: ObservableObject {
    static let shared = BackendManager()

    @Published var status: String = "Initializing..."
    @Published var isRunning: Bool = false
    @Published var pythonPath: String = ""
    @Published var lastCoreLogs: [String] = []

    /// Set to true when app is actively making requests (chat, scan, etc.)
    /// Health monitor won't mark as disconnected during active operations
    var isActiveOperation: Bool = false

    /// Count consecutive health check failures before marking disconnected
    private var consecutiveFailures: Int = 0
    private let maxConsecutiveFailures = 3

    private var process: Process?
    private var pipe: Pipe?
    private var healthCheckTask: Task<Void, Never>?
    private var bootManifestURL: URL?
    private var logRingBuffer: [String] = []

    private let maxStartupRetries = 30  // 30 seconds max wait
    private let healthCheckInterval: UInt64 = 1_000_000_000  // 1 second
    private let maxLogLines = 200

    /// Function start.
    func start() {
        Task {
            // Check if backend is already running externally
            if await checkBackendHealth() {
                await MainActor.run {
                    self.status = "Core Connected (External)"
                    self.isRunning = true
                    NotificationCenter.default.post(name: .backendReady, object: nil)
                }
                startHealthMonitor()
                return
            }

            // Launch our own server
            await launchIntegratedServer()
        }
    }

    /// Function stop.
    func stop() {
        healthCheckTask?.cancel()
        healthCheckTask = nil

        // Conditional branch.
        if let p = process, p.isRunning {
            print("[BackendManager] Terminating backend process...")
            p.terminate()
            // Don't block - let the process die asynchronously
        }
        process = nil
        pipe = nil
        bootManifestURL = nil
        logRingBuffer.removeAll()
        lastCoreLogs.removeAll()
        isRunning = false
        status = "Core Stopped"
    }

    private func checkBackendHealth() async -> Bool {
        let url = URL(string: "http://127.0.0.1:8765/ping")!
        var request = URLRequest(url: url)
        request.timeoutInterval = 10.0  // Allow more time for slow responses
        // Do-catch block.
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            // Guard condition.
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { return false }
            // Verify it's actually our API
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                json["status"] as? String == "ok"
            {
                return true
            }
        } catch {
            // Connection refused or timeout
        }
        return false
    }

    /// Monitors backend health and updates UI status
    private func startHealthMonitor() {
        healthCheckTask = Task {
            // While loop.
            while !Task.isCancelled {
                // Skip health check if there's an active operation
                // (LLM requests can take 60+ seconds and block /ping)
                if isActiveOperation {
                    consecutiveFailures = 0
                    try? await Task.sleep(nanoseconds: healthCheckInterval * 10)  // Check less frequently during operations
                    continue
                }

                let healthy = await checkBackendHealth()
                await MainActor.run {
                    // Conditional branch.
                    if healthy {
                        self.consecutiveFailures = 0
                        // Conditional branch.
                        if !self.isRunning {
                            // Reconnected!
                            self.status = "Core Online"
                            self.isRunning = true
                        }
                    } else if self.isRunning {
                        self.consecutiveFailures += 1
                        // Conditional branch.
                        if self.consecutiveFailures >= self.maxConsecutiveFailures {
                            self.status = "Core Disconnected"
                            self.isRunning = false
                        } else {
                            // Show warning but don't disconnect yet
                            self.status =
                                "Core Slow (\(self.consecutiveFailures)/\(self.maxConsecutiveFailures))..."
                        }
                    }
                }
                try? await Task.sleep(nanoseconds: healthCheckInterval * 10)  // Check every 10 seconds
            }
        }
    }

    private func launchIntegratedServer() async {
        await MainActor.run { self.status = "Locating Neural Core..." }

        let fileManager = FileManager.default
        let home = fileManager.homeDirectoryForCurrentUser

        // Find the repository root (contains core/api.py)
        let possiblePaths = [
            home.appendingPathComponent("Developer/sentinelforge"),
            home.appendingPathComponent("Developer/sentinel"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath),
        ]

        guard
            let repoPath = possiblePaths.first(where: { path in
                fileManager.fileExists(atPath: path.appendingPathComponent("core/server/api.py").path)
            })
        else {
            await MainActor.run { self.status = "Error: Repository not found" }
            return
        }

        print("[BackendManager] Repository: \(repoPath.path)")

        // Find Python executable (prefer venv)
        let pythonExecutable = findPythonExecutable(in: repoPath)
        // Guard condition.
        guard let python = pythonExecutable else {
            await MainActor.run { self.status = "Error: Python not found" }
            return
        }

        await MainActor.run {
            self.pythonPath = python.path
            self.status = "Booting Neural Core..."
        }
        print("[BackendManager] Python: \(python.path)")

        // Create and configure the process
        let p = Process()
        p.executableURL = python
        p.currentDirectoryURL = repoPath
        p.arguments = ["-m", "uvicorn", "core.server.api:app", "--host", "127.0.0.1", "--port", "8765"]

        // Inherit PYTHONPATH so imports work
        var env = ProcessInfo.processInfo.environment
        env["PYTHONPATH"] = repoPath.path
        env["PYTHONUNBUFFERED"] = "1"  // Disable output buffering

        // Ensure UI-integrated core binds to the expected localhost endpoint.
        // This prevents accidental overrides from shell environment variables
        // (e.g., Docker-era SENTINEL_API_HOST/PORT) that can break connectivity.
        env["SENTINEL_API_HOST"] = "127.0.0.1"
        env["SENTINEL_API_PORT"] = "8765"
        env["SENTINEL_REQUIRE_AUTH"] = "false"

        // If Docker-era Ollama endpoints are still set, normalize to localhost.
        if let ollamaURL = env["SENTINEL_OLLAMA_URL"],
            ollamaURL.contains("host.docker.internal")
        {
            env["SENTINEL_OLLAMA_URL"] = "http://localhost:11434"
            print("[BackendManager] Normalized SENTINEL_OLLAMA_URL to localhost (Docker legacy)")
        }

        // Provide a boot manifest path for deterministic readiness diagnostics.
        let manifestDir = home
            .appendingPathComponent(".sentinelforge")
            .appendingPathComponent("run")
        let manifestPath = manifestDir.appendingPathComponent("boot_manifest.json")
        bootManifestURL = manifestPath
        try? FileManager.default.createDirectory(at: manifestDir, withIntermediateDirectories: true)
        try? FileManager.default.removeItem(at: manifestPath)
        env["SENTINEL_BOOT_MANIFEST"] = manifestPath.path

        // CRITICAL: Inject Homebrew/System paths so Core can find tools (nmap, nuclei)
        // Even with SIP disabled, GUI apps don't inherit the full shell PATH.
        let extraPaths = [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
            // Add user's go/bin if possible, though hard to resolve strictly from here
            "\(home.path)/go/bin",
            "\(home.path)/.local/bin",
        ]
        let currentPath = env["PATH"] ?? ""
        let newPath = (extraPaths + [currentPath]).joined(separator: ":")
        env["PATH"] = newPath

        p.environment = env

        // Capture output for debugging
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe

        pipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            // Conditional branch.
            if let str = String(data: data, encoding: .utf8), !str.isEmpty {
                let trimmed = str.trimmingCharacters(in: .whitespacesAndNewlines)
                // Conditional branch.
                if !trimmed.isEmpty {
                    print("[Core] \(trimmed)")
                    Task { @MainActor in
                        self.appendLogLine(trimmed)
                    }
                }
            }
        }

        self.process = p
        self.pipe = pipe

        // Launch the process
        do {
            try p.run()
            print("[BackendManager] Process started (PID: \(p.processIdentifier))")
            await MainActor.run {
                self.status = "Core Starting (PID: \(p.processIdentifier))..."
            }
        } catch {
            await MainActor.run {
                self.status = "Boot Failed: \(error.localizedDescription)"
            }
            return
        }

        // Wait for the server to become healthy
        await waitForServerReady()
    }

    /// Polls the health endpoint until the server is ready
    private func waitForServerReady() async {
        // Loop over items.
        for attempt in 1...maxStartupRetries {
            // Conditional branch.
            if await checkBackendHealth() {
                await MainActor.run {
                    self.status = "Core Online"
                    self.isRunning = true
                    NotificationCenter.default.post(name: .backendReady, object: nil)
                }
                print("[BackendManager] Server ready after \(attempt) attempt(s)")
                startHealthMonitor()
                return
            }

            // Check if process died
            if let p = process, !p.isRunning {
                await MainActor.run {
                    self.status = "Core Crashed (exit: \(p.terminationStatus))"
                    self.isRunning = false
                }
                return
            }

            await MainActor.run {
                self.status = "Core Starting (\(attempt)/\(self.maxStartupRetries))..."
            }

            try? await Task.sleep(nanoseconds: healthCheckInterval)
        }

        let manifest = readBootManifest()
        if let manifestState = manifest?["state"] as? String {
            print("[BackendManager] Boot manifest state: \(manifestState)")
        }

        await MainActor.run {
            self.status = "Core Timeout - Check Logs"
            self.isRunning = false
        }
    }

    /// Finds Python executable, preferring virtual environment
    private func findPythonExecutable(in repoPath: URL) -> URL? {
        let fileManager = FileManager.default

        // Check for virtual environments (in order of preference)
        let venvPaths = [
            repoPath.appendingPathComponent(".venv/bin/python3"),
            repoPath.appendingPathComponent("venv/bin/python3"),
            repoPath.appendingPathComponent(".venv/bin/python"),
            repoPath.appendingPathComponent("venv/bin/python"),
        ]

        // Loop over items.
        for venv in venvPaths {
            // Conditional branch.
            if fileManager.fileExists(atPath: venv.path) {
                return venv
            }
        }

        // Fallback to system Python
        let systemPaths = [
            URL(fileURLWithPath: "/opt/homebrew/bin/python3"),  // Apple Silicon Homebrew
            URL(fileURLWithPath: "/usr/local/bin/python3"),  // Intel Homebrew
            URL(fileURLWithPath: "/usr/bin/python3"),  // System Python
        ]

        // Loop over items.
        for path in systemPaths {
            // Conditional branch.
            if fileManager.fileExists(atPath: path.path) {
                return path
            }
        }

        return nil
    }

    @MainActor
    private func appendLogLine(_ line: String) {
        logRingBuffer.append(line)
        if logRingBuffer.count > maxLogLines {
            logRingBuffer.removeFirst(logRingBuffer.count - maxLogLines)
        }
        lastCoreLogs = logRingBuffer
    }

    private func readBootManifest() -> [String: Any]? {
        guard let manifestURL = bootManifestURL,
            let data = try? Data(contentsOf: manifestURL),
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return nil }
        return json
    }
}
