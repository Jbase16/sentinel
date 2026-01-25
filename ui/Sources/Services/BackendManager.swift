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
import Network

enum BackendConfigKeys {
    static let backendRuntime = "backend.runtime"
    static let backendPath = "backend.path"
}

enum BackendRuntimeSelection: String, CaseIterable, Identifiable {
    case auto
    case custom
    case bundled

    var id: String { rawValue }

    var label: String {
        switch self {
        case .auto: return "Auto"
        case .custom: return "Custom Path"
        case .bundled: return "Bundled Runtime"
        }
    }
}

extension Notification.Name {
    static let backendReady = Notification.Name("backendReady")
}

/// Manages the lifecycle of the Python Backend (Neuro-Symbolic Core).
/// Automatically starts the FastAPI server when the app launches and terminates it on quit.
@MainActor
/// Class BackendManager.
class BackendManager: ObservableObject {
    static let shared = BackendManager()

    @Published var backendState: BackendState = .stopped
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

    private let healthCheckInterval: UInt64 = 1_000_000_000  // 1 second
    private let maxLogLines = 200
    private let maxStartupDuration: TimeInterval = 40  // Hard startup deadline (seconds)
    private let startupRequestTimeout: TimeInterval = 1.5
    private let startupInitialBackoff: TimeInterval = 0.5
    private let startupMaxBackoff: TimeInterval = 5.0
    private let bootManifestWaitMax: TimeInterval = 3.0  // Wait for manifest before /health
    private let bootManifestPollInterval: TimeInterval = 0.1
    private let healthCheckURL = URL(string: "http://127.0.0.1:8765/v1/health")!
    private let startupFailureSignatures = [
        "ModuleNotFoundError: No module named 'uvicorn'"
    ]
    private let bundledBackendRelativePath = "Backend"
    private let bundledPythonRelativePath = "PythonRuntime/bin/python3"
    private let minPythonMajor = 3
    private let minPythonMinor = 10
    private let requiredSystemTools = [
        "nmap",
        "httpx",
    ]
    private let requiredPythonModules = [
        "fastapi",
        "uvicorn",
        "httpx",
        "aiosqlite",
        "websockets",
        "sse_starlette",
        "python_multipart",
        "cryptography",
        "requests",
    ]
    private let startupStateQueue = DispatchQueue(label: "BackendManager.startupState")
    private var startupFailureMessage: String?
    private var startupAbortRequested: Bool = false
    private var isStopping: Bool = false

    /// Function start.
    func start() {
        Task {
            // Check if backend is already running externally
            let (reachable, status) = await checkBackendHealth()
            if reachable, status == "ready" {
                await MainActor.run {
                    self.backendState = .ready
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
        bootManifestURL = nil
        logRingBuffer.removeAll()
        lastCoreLogs.removeAll()
        isRunning = false
        backendState = .stopped
        status = "Core Stopped"
    }

    private func checkBackendHealth(timeoutInterval: TimeInterval = 10.0, url: URL? = nil) async
        -> (reachable: Bool, status: String?)
    {
        let requestURL = url ?? healthCheckURL
        if shouldSkipLocalHealthProbe(for: requestURL) {
            return (false, nil)
        }
        var request = URLRequest(url: requestURL)
        request.timeoutInterval = timeoutInterval  // Allow more time for slow responses
        // Do-catch block.
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            // Guard condition.
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { return (false, nil) }
            // Parse the health status
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                let status = json["status"] as? String
            {
                return (true, status)
            }
        } catch {
            // Connection refused or timeout
        }
        return (false, nil)
    }

    private func shouldSkipLocalHealthProbe(for url: URL) -> Bool {
        guard let host = url.host?.lowercased() else { return false }
        let isLoopbackHost = host == "127.0.0.1" || host == "localhost" || host == "::1"
        guard isLoopbackHost else { return false }
        guard let portValue = url.port,
            portValue > 0,
            portValue <= Int(UInt16.max)
        else {
            return false
        }
        return isPortAvailable(UInt16(portValue))
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

                let (reachable, _) = await checkBackendHealth()
                await MainActor.run {
                    // Conditional branch.
                    if reachable {
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

        guard let repoPath = resolveBackendRoot(home: home) else {
            await MainActor.run { self.status = "Error: Backend path not found" }
            return
        }

        print("[BackendManager] Repository: \(repoPath.path)")

        // Find Python executable (prefer venv)
        let pythonExecutable = resolvePythonExecutable(for: repoPath)
        // Guard condition.
        guard let python = pythonExecutable else {
            await MainActor.run { self.status = "Error: Python not found" }
            return
        }

        await MainActor.run {
            self.pythonPath = python.path
            self.status = "Running Preflight..."
        }
        print("[BackendManager] Python: \(python.path)")
        resetStartupState()

        let environmentIssues = await validateEnvironment(python: python, backendRoot: repoPath)
        if !environmentIssues.isEmpty {
            recordStartupFailure("Preflight failed: \(environmentIssues.joined(separator: "; "))")
            return
        }

        if let preflightError = await runPreflightChecks(python: python, backendRoot: repoPath) {
            recordStartupFailure(preflightError)
            return
        }

        await MainActor.run {
            self.status = "Booting Neural Core..."
        }

        // Create and configure the process
        let p = Process()
        p.executableURL = python
        p.currentDirectoryURL = repoPath
        p.arguments = [
            "-m", "uvicorn", "core.server.api:app", "--host", "127.0.0.1", "--port", "8765",
        ]

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
        let manifestDir =
            home
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
                        self.detectStartupFailureSignature(in: trimmed)
                    }

                }
            }
        }

        p.terminationHandler = { [weak self] process in
            guard let self else { return }
            Task { @MainActor in
                self.handleProcessTermination(process)
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
        await waitForServerReady(launchTime: Date())
    }

    /// Polls the health endpoint until the server is ready
    /// - Parameter launchTime: The time the process was started (used to verify token freshness)
    private func waitForServerReady(launchTime: Date) async {
        // Set backend to starting state
        await MainActor.run {
            self.backendState = .starting
        }

        // Avoid spamming /health before the core has written its boot manifest.
        await waitForBootManifest()

        let deadline = Date().addingTimeInterval(maxStartupDuration)
        var attempt = 0

        while Date() < deadline {
            if shouldAbortStartup() {
                return
            }

            attempt += 1
            let remaining = max(0, deadline.timeIntervalSinceNow)
            let requestTimeout = min(startupRequestTimeout, remaining)

            // Check health endpoint and parse readiness status
            let (reachable, status) = await checkBackendHealth(timeoutInterval: requestTimeout)
            if reachable, status == "ready" {
                // TOKEN FRESHNESS CHECK:
                // Ensure the token file has been updated SINCE we launched the process.
                // This prevents race conditions where we connect using an old stale token
                // before the new backend has overwritten it.
                if isTokenFileFresh(since: launchTime) {
                    await MainActor.run {
                        self.backendState = .ready
                        self.status = "Core Online"
                        self.isRunning = true
                        NotificationCenter.default.post(name: .backendReady, object: nil)
                    }
                    print("[BackendManager] Server ready after \(attempt) attempt(s)")
                    startHealthMonitor()
                    return
                } else {
                    print("[BackendManager] Health OK but Token Stale. Waiting for token write...")
                }
            } else if reachable, status == "starting" {
                // Backend is reachable but still initializing - keep waiting
                print(
                    "[BackendManager] Backend reachable but status='starting', continuing to wait..."
                )
            }

            if shouldAbortStartup() {
                return
            }

            await MainActor.run {
                self.status = "Core Starting (attempt \(attempt))..."
            }

            // Custom backoff: 0, 0.2, 0.5, 1.0, 5.0 seconds
            let sleepDuration = min(
                RetryBackoff.delayForAttempt(attempt), max(0, deadline.timeIntervalSinceNow))
            if sleepDuration > 0 {
                try? await Task.sleep(nanoseconds: UInt64(sleepDuration * 1_000_000_000))
            }
        }

        let manifest = readBootManifest()
        if let manifestState = manifest?["state"] as? String {
            print("[BackendManager] Boot manifest state: \(manifestState)")
        }

        await MainActor.run {
            let timeoutError = NSError(
                domain: NSURLErrorDomain,
                code: NSURLErrorTimedOut,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "Backend failed to start within \(Int(maxStartupDuration)) seconds"
                ]
            )
            self.backendState = .failed(timeoutError)
            self.status = "Core Timeout (\(Int(maxStartupDuration))s) - Check Logs"
            self.isRunning = false
        }
    }

    private func waitForBootManifest() async {
        guard bootManifestURL != nil else { return }
        let deadline = Date().addingTimeInterval(bootManifestWaitMax)
        while Date() < deadline {
            if shouldAbortStartup() {
                return
            }
            if readBootManifest() != nil {
                return
            }
            try? await Task.sleep(
                nanoseconds: UInt64(bootManifestPollInterval * 1_000_000_000)
            )
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

    private func resolveBackendRoot(home: URL) -> URL? {
        let fileManager = FileManager.default
        let runtime = resolveRuntimeSelection()

        switch runtime {
        case .custom:
            if let customPath = UserDefaults.standard.string(forKey: BackendConfigKeys.backendPath),
                !customPath.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            {
                let customURL = URL(fileURLWithPath: customPath).standardizedFileURL
                if fileManager.fileExists(
                    atPath: customURL.appendingPathComponent("core/server/api.py").path)
                {
                    return customURL
                }
            }
            return nil
        case .bundled:
            if let bundledURL = Bundle.main.resourceURL?.appendingPathComponent(
                bundledBackendRelativePath),
                fileManager.fileExists(
                    atPath: bundledURL.appendingPathComponent("core/server/api.py").path)
            {
                return bundledURL
            }
            return nil
        case .auto:
            let possiblePaths = [
                home.appendingPathComponent("Developer/sentinelforge"),
                home.appendingPathComponent("Developer/sentinel"),
                URL(fileURLWithPath: FileManager.default.currentDirectoryPath),
            ]

            return possiblePaths.first(where: { path in
                fileManager.fileExists(
                    atPath: path.appendingPathComponent("core/server/api.py").path)
            })
        }
    }

    private func resolvePythonExecutable(for backendRoot: URL) -> URL? {
        let runtime = resolveRuntimeSelection()
        switch runtime {
        case .bundled:
            if let bundledPython = Bundle.main.resourceURL?.appendingPathComponent(
                bundledPythonRelativePath),
                FileManager.default.fileExists(atPath: bundledPython.path)
            {
                return bundledPython
            }
            return findPythonExecutable(in: backendRoot)
        case .custom, .auto:
            return findPythonExecutable(in: backendRoot)
        }
    }

    private func resolveRuntimeSelection() -> BackendRuntimeSelection {
        let rawValue = UserDefaults.standard.string(forKey: BackendConfigKeys.backendRuntime) ?? ""
        return BackendRuntimeSelection(rawValue: rawValue) ?? .auto
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

    private func runPreflightChecks(python: URL, backendRoot: URL) async -> String? {
        let script = """
            import json
            import sys
            import importlib.util

            required = \(requiredPythonModules)
            missing = [name for name in required if importlib.util.find_spec(name) is None]
            payload = {
                "python_version": sys.version.split()[0],
                "missing": missing,
            }
            print(json.dumps(payload))
            """

        let result = runPythonScript(python: python, backendRoot: backendRoot, script: script)
        guard result.exitCode == 0, let output = result.standardOutput,
            let data = output.data(using: .utf8),
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            let detail = result.standardError ?? "Unknown error"
            return "Preflight failed: \(detail)"
        }

        let versionString = json["python_version"] as? String ?? "unknown"
        let versionComponents = versionString.split(separator: ".").compactMap { Int($0) }
        if versionComponents.count >= 2 {
            let major = versionComponents[0]
            let minor = versionComponents[1]
            if major < minPythonMajor || (major == minPythonMajor && minor < minPythonMinor) {
                return
                    "Python \(minPythonMajor).\(minPythonMinor)+ required (found \(versionString))"
            }
        }

        if let missing = json["missing"] as? [String], !missing.isEmpty {
            let missingList = missing.sorted().joined(separator: ", ")
            return "Missing Python packages: \(missingList)"
        }

        return nil
    }

    private func validateEnvironment(python: URL, backendRoot: URL) async -> [String] {
        var errors: [String] = []
        let fileManager = FileManager.default
        let home = fileManager.homeDirectoryForCurrentUser

        if !fileManager.fileExists(atPath: python.path) {
            errors.append("Python runtime missing at \(python.path)")
        }

        if !isPortAvailable(8765) {
            errors.append("Port 8765 already in use")
        }

        let pathValue = buildToolSearchPath(home: home)
        for tool in requiredSystemTools where !isToolInstalled(tool, pathValue: pathValue) {
            errors.append("Required tool missing: \(tool)")
        }

        return errors
    }

    private func buildToolSearchPath(home: URL) -> String {
        let extraPaths = [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
            "/usr/sbin",
            "/sbin",
            "\(home.path)/go/bin",
            "\(home.path)/.local/bin",
        ]
        let currentPath = ProcessInfo.processInfo.environment["PATH"] ?? ""
        return (extraPaths + [currentPath]).joined(separator: ":")
    }

    private func isPortAvailable(_ port: UInt16) -> Bool {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else { return false }
        do {
            let listener = try NWListener(using: .tcp, on: endpointPort)
            listener.cancel()
            return true
        } catch {
            return false
        }
    }

    private func isToolInstalled(_ tool: String, pathValue: String) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        process.arguments = [tool]
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = pathValue
        process.environment = env

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            return false
        }

        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    private func runPythonScript(python: URL, backendRoot: URL, script: String)
        -> (exitCode: Int32, standardOutput: String?, standardError: String?)
    {
        let process = Process()
        process.executableURL = python
        process.currentDirectoryURL = backendRoot
        process.arguments = ["-c", script]
        var env = ProcessInfo.processInfo.environment
        env["PYTHONPATH"] = backendRoot.path
        process.environment = env

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
        } catch {
            return (exitCode: -1, standardOutput: nil, standardError: error.localizedDescription)
        }

        process.waitUntilExit()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        let stdout = String(data: stdoutData, encoding: .utf8)?.trimmingCharacters(
            in: .whitespacesAndNewlines)
        let stderr = String(data: stderrData, encoding: .utf8)?.trimmingCharacters(
            in: .whitespacesAndNewlines)

        return (exitCode: process.terminationStatus, standardOutput: stdout, standardError: stderr)
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

    private func isTokenFileFresh(since launchTime: Date) -> Bool {
        let tokenPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge")
            .appendingPathComponent("api_token")

        guard let attrs = try? FileManager.default.attributesOfItem(atPath: tokenPath.path),
            let modDate = attrs[.modificationDate] as? Date
        else { return false }

        // Allow a small buffer (0.5s) for file system clock skews, but generally
        // the file modification must be AFTER the launch time.
        return modDate >= launchTime.addingTimeInterval(-0.5)
    }
}
