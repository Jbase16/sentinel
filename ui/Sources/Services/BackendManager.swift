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

    /// Set to true when app is actively making requests (chat, scan, etc.)
    /// Health monitor won't mark as disconnected during active operations
    var isActiveOperation: Bool = false

    /// Count consecutive health check failures before marking disconnected
    private var consecutiveFailures: Int = 0
    private let maxConsecutiveFailures = 3

    private var process: Process?
    private var pipe: Pipe?
    private var healthCheckTask: Task<Void, Never>?

    private let healthCheckInterval: UInt64 = 1_000_000_000  // 1 second
    private let maxStartupDuration: TimeInterval = 40  // Hard startup deadline (seconds)
    private let startupRequestTimeout: TimeInterval = 1.5
    private let startupInitialBackoff: TimeInterval = 0.5
    private let startupMaxBackoff: TimeInterval = 5.0
    private let healthCheckURL = URL(string: "http://127.0.0.1:8765/v1/ping")!
    private let startupFailureSignatures = [
        "ModuleNotFoundError: No module named 'uvicorn'"
    ]
    private let startupStateQueue = DispatchQueue(label: "BackendManager.startupState")
    private var startupFailureMessage: String?
    private var startupAbortRequested: Bool = false
    private var isStopping: Bool = false

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
            startupStateQueue.sync {
                self.isStopping = true
            }
            print("[BackendManager] Terminating backend process...")
            p.terminate()
            // Don't block - let the process die asynchronously
        }
        process = nil
        pipe = nil
        isRunning = false
        status = "Core Stopped"
    }

    private func checkBackendHealth(timeoutInterval: TimeInterval = 10.0, url: URL? = nil) async -> Bool {
        let requestURL = url ?? healthCheckURL
        var request = URLRequest(url: requestURL)
        request.timeoutInterval = timeoutInterval  // Allow more time for slow responses
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
        resetStartupState()

        // Create and configure the process
        let p = Process()
        p.executableURL = python
        p.currentDirectoryURL = repoPath
        p.arguments = ["-m", "uvicorn", "core.server.api:app", "--host", "127.0.0.1", "--port", "8765"]

        // Inherit PYTHONPATH so imports work
        var env = ProcessInfo.processInfo.environment
        env["PYTHONPATH"] = repoPath.path
        env["PYTHONUNBUFFERED"] = "1"  // Disable output buffering

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
                    self.detectStartupFailureSignature(in: trimmed)
                }
            }
        }

        p.terminationHandler = { [weak self] process in
            guard let self else { return }
            self.handleProcessTermination(process)
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
        let deadline = Date().addingTimeInterval(maxStartupDuration)
        var attempt = 0
        var backoff = startupInitialBackoff

        while Date() < deadline {
            if shouldAbortStartup() {
                return
            }

            attempt += 1
            let remaining = max(0, deadline.timeIntervalSinceNow)
            let requestTimeout = min(startupRequestTimeout, remaining)

            // Conditional branch.
            if await checkBackendHealth(timeoutInterval: requestTimeout) {
                await MainActor.run {
                    self.status = "Core Online"
                    self.isRunning = true
                    NotificationCenter.default.post(name: .backendReady, object: nil)
                }
                print("[BackendManager] Server ready after \(attempt) attempt(s)")
                startHealthMonitor()
                return
            }

            if shouldAbortStartup() {
                return
            }

            await MainActor.run {
                self.status = "Core Starting (attempt \(attempt))..."
            }

            let sleepDuration = min(backoff, max(0, deadline.timeIntervalSinceNow))
            if sleepDuration > 0 {
                try? await Task.sleep(nanoseconds: UInt64(sleepDuration * 1_000_000_000))
            }
            backoff = min(backoff * 2, startupMaxBackoff)
        }

        await MainActor.run {
            self.status = "Core Timeout (\(Int(maxStartupDuration))s) - Check Logs"
            self.isRunning = false
        }
    }

    private func resetStartupState() {
        startupStateQueue.sync {
            self.startupFailureMessage = nil
            self.startupAbortRequested = false
            self.isStopping = false
        }
    }

    private func shouldAbortStartup() -> Bool {
        startupStateQueue.sync { startupAbortRequested }
    }

    private func detectStartupFailureSignature(in output: String) {
        for signature in startupFailureSignatures where output.contains(signature) {
            recordStartupFailure("Missing dependency: \(signature)")
            return
        }
    }

    private func recordStartupFailure(_ message: String) {
        let shouldUpdate = startupStateQueue.sync { () -> Bool in
            if startupFailureMessage != nil {
                return false
            }
            startupFailureMessage = message
            startupAbortRequested = true
            return true
        }
        guard shouldUpdate else { return }

        Task { @MainActor in
            self.status = "Core Boot Failed: \(message)"
            self.isRunning = false
        }
    }

    private func handleProcessTermination(_ process: Process) {
        let shouldReport = startupStateQueue.sync { () -> Bool in
            if isStopping {
                return false
            }
            startupAbortRequested = true
            return true
        }
        guard shouldReport else { return }

        Task { @MainActor in
            self.status = "Core Crashed (exit: \(process.terminationStatus))"
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
}
