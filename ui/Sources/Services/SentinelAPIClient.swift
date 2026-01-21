//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// Handles all HTTP communication with the Python backend API.
//
// KEY RESPONSIBILITIES:
// - Token-based authentication via ~/.sentinelforge/api_token
// - All REST API calls to the Sentinel backend
// - Server-Sent Events (SSE) streaming for real-time updates
//
// INTEGRATION:
// - Used by: ViewModels, Services
// - Depends on: Python backend (core/server/api.py)
//

import Foundation

/// HTTP client for talking to the local Sentinel Python backend.
/// Automatically reads and applies authentication tokens from ~/.sentinelforge/api_token.
public struct SentinelAPIClient: Sendable {
    public let baseURL: URL
    private let session: URLSession

    /// Path to the token file written by the Python backend.
    /// This solves the "Auth Singularity" - backend generates token, Swift discovers it.
    private static let tokenPath: URL = {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge")
            .appendingPathComponent("api_token")
    }()

    public init(baseURL: URL = URL(string: "http://127.0.0.1:8765")!, session: URLSession? = nil) {
        self.baseURL = baseURL
        if let session = session {
            self.session = session
        } else {
            let config = URLSessionConfiguration.default
            config.requestCachePolicy = .reloadIgnoringLocalCacheData
            config.timeoutIntervalForRequest = 120.0  // Increased for slow local LLMs
            config.timeoutIntervalForResource = 600.0  // Allow very long streams
            self.session = URLSession(configuration: config)
        }
    }

    // MARK: - Authentication

    /// Read the current API token from ~/.sentinelforge/api_token.
    /// Returns nil if the file doesn't exist or can't be read.
    private static func readToken() -> String? {
        try? String(contentsOf: tokenPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func parseAPIError(data: Data, response: URLResponse?) -> APIError {
        if let http = response as? HTTPURLResponse, http.statusCode == 401 {
            return .unauthorized
        }

        guard !data.isEmpty,
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return .badStatus
        }

        let code = json["code"] as? String
        let message = json["message"] as? String ?? "API Error"
        let details = json["details"] as? [String: Any]

        switch code {
        case "TOOL_002", "TOOL_003":
            let tool = details?["tool"] as? String ?? "unknown"
            let exitCode = (details?["exit_code"] as? Int)
                ?? (details?["exit_code"] as? NSNumber)?.intValue
                ?? -1
            let stderr = details?["stderr"] as? String ?? message
            return .toolFailed(tool: tool, exitCode: exitCode, stderr: stderr)
        case "SCAN_003":
            let duration = (details?["duration"] as? TimeInterval)
                ?? (details?["duration"] as? NSNumber)?.doubleValue
                ?? 0
            return .scanTimeout(duration: duration)
        default:
            return .serverError(code: code ?? "UNKNOWN", message: message)
        }
    }

    /// Create an authenticated URLRequest with the Bearer token.
    /// If no token is available, returns a request without auth (for backward compatibility).
    private func authenticatedRequest(url: URL, method: String = "GET") -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        if let token = Self.readToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        return request
    }

    // MARK: - Health Check

    /// Health check - does not require authentication
    public func ping() async -> Bool {
        guard let url = URL(string: "/v1/ping", relativeTo: baseURL) else { return false }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return false
            }
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return (json?["status"] as? String) == "ok"
        } catch {
            // Log error only if it's a real error (not connection refused during startup)
            if ErrorClassifier.shouldLogAsError(error) {
                print("[SentinelAPIClient] ping error: \(error.localizedDescription)")
            }
            return false
        }
    }

    // MARK: - Scan Operations

    /// Kick off a scan for a given target.
    ///
    /// NOTE:
    /// Backend may return 202 (Accepted) OR 200 (OK) with a JSON body:
    ///   {"session_id":"...","status":"started"}
    /// Both are success.
    public func startScan(target: String, modules: [String] = [], mode: String = "standard")
        async throws
    {
        guard let url = URL(string: "/v1/scans/start", relativeTo: baseURL) else { return }
        var request = authenticatedRequest(url: url, method: "POST")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        var body: [String: Any] = ["target": target, "force": true, "mode": mode]
        if !modules.isEmpty {
            body["modules"] = modules
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await session.data(for: request)

        guard let http = response as? HTTPURLResponse else {
            throw Self.parseAPIError(data: data, response: response)
        }

        // ✅ Accept BOTH 200 and 202 as success.
        if http.statusCode == 200 || http.statusCode == 202 {
            return
        }

        // Everything else: log body for debugging.
        let responseBody = String(data: data, encoding: .utf8) ?? "<no body>"
        print("[SentinelAPIClient] startScan rejected")
        print("  status: \(http.statusCode)")
        print("  body: \(responseBody)")
        throw Self.parseAPIError(data: data, response: response)
    }

    /// Request best-effort scan cancellation.
    public func cancelScan() async throws {
        guard let url = URL(string: "/v1/scans/cancel", relativeTo: baseURL) else { return }
        let request = authenticatedRequest(url: url, method: "POST")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw Self.parseAPIError(data: data, response: response)
        }
        // Backend returns 409 when no scan is active; treat as a successful "already stopped".
        if http.statusCode == 202 || http.statusCode == 409 {
            return
        }
        throw Self.parseAPIError(data: data, response: response)
    }

    // MARK: - Status & Results

    /// Pull any buffered log lines from Python since the last call.
    public func fetchLogs() async throws -> [String] {
        guard let url = URL(string: "/v1/logs", relativeTo: baseURL) else { return [] }
        let request = authenticatedRequest(url: url, method: "GET")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }
        let decoded = try JSONDecoder().decode(LogBatch.self, from: data)
        return decoded.lines
    }

    /// Fetch lightweight engine + AI status (model availability, running scan).
    func fetchStatus() async throws -> EngineStatus? {
        guard let url = URL(string: "/v1/status", relativeTo: baseURL) else { return nil }
        let request = authenticatedRequest(url: url, method: "GET")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }
        return try JSONDecoder().decode(EngineStatus.self, from: data)
    }

    /// Fetch dedicated AI status (including Circuit Breaker)
    /// NEW: Trinity of Hardening - Chapter 19
    func fetchAIStatus() async throws -> AIStatusResponse {
        guard let url = URL(string: "/v1/ai/status", relativeTo: baseURL) else {
            throw APIError.badStatus
        }
        let request = authenticatedRequest(url: url, method: "GET")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }
        return try JSONDecoder().decode(AIStatusResponse.self, from: data)
    }

    /// Fetch the latest scan snapshot (findings/issues/killchain/phase_results).
    func fetchResults() async throws -> SentinelResults? {
        let request = authenticatedRequest(url: baseURL.appendingPathComponent("/v1/scans/results"))
        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw Self.parseAPIError(data: data, response: response)
        }

        if httpResponse.statusCode == 204 { return nil }

        guard (200...299).contains(httpResponse.statusCode) else {
            throw Self.parseAPIError(data: data, response: response)
        }

        return try JSONDecoder().decode(SentinelResults.self, from: data)
    }

    /// Fetch the Pressure Graph (Ground Truth).
    func fetchGraph() async throws -> PressureGraphDTO? {
        guard let url = URL(string: "/v1/cortex/graph", relativeTo: baseURL) else { return nil }
        let request = authenticatedRequest(url: url, method: "GET")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw Self.parseAPIError(data: data, response: response)
        }
        if http.statusCode == 204 { return nil }
        guard http.statusCode == 200 else { throw Self.parseAPIError(data: data, response: response) }
        return try JSONDecoder().decode(PressureGraphDTO.self, from: data)
    }

    // MARK: - Tool Management

    /// Install selected tools
    func installTools(_ tools: [String]) async throws -> [InstallResult] {
        struct InstallResponse: Decodable { let results: [InstallResult] }
        guard let url = URL(string: "/v1/tools/install", relativeTo: baseURL) else {
            throw APIError.badStatus
        }
        var request = authenticatedRequest(url: url, method: "POST")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = ["tools": tools]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }
        let decoded = try JSONDecoder().decode(InstallResponse.self, from: data)
        return decoded.results
    }

    /// Uninstall selected tools
    func uninstallTools(_ tools: [String]) async throws -> [InstallResult] {
        struct InstallResponse: Decodable { let results: [InstallResult] }
        guard let url = URL(string: "/v1/tools/uninstall", relativeTo: baseURL) else {
            throw APIError.badStatus
        }
        var request = authenticatedRequest(url: url, method: "POST")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = ["tools": tools]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }
        let decoded = try JSONDecoder().decode(InstallResponse.self, from: data)
        return decoded.results
    }

    // MARK: - Ghost Protocol

    private struct GhostStartResponse: Decodable {
        let status: String
        let port: Int?
    }

    private struct GhostStopResponse: Decodable {
        let status: String
    }

    /// Start the passive interception proxy (Ghost Protocol).
    /// - Returns: The listening port, if provided by the backend.
    public func startGhost(port: Int = 8080) async throws -> Int? {
        guard let base = URL(string: "/v1/ghost/start", relativeTo: baseURL),
            var components = URLComponents(url: base, resolvingAgainstBaseURL: true)
        else { throw APIError.badStatus }

        components.queryItems = [URLQueryItem(name: "port", value: "\(port)")]
        guard let url = components.url else { throw APIError.badStatus }

        let request = authenticatedRequest(url: url, method: "POST")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }

        let decoded = try? JSONDecoder().decode(GhostStartResponse.self, from: data)
        return decoded?.port
    }

    /// Stop the passive interception proxy (Ghost Protocol).
    public func stopGhost() async throws -> Bool {
        guard let url = URL(string: "/v1/ghost/stop", relativeTo: baseURL) else {
            throw APIError.badStatus
        }
        let request = authenticatedRequest(url: url, method: "POST")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }

        if let decoded = try? JSONDecoder().decode(GhostStopResponse.self, from: data) {
            return decoded.status == "stopped" || decoded.status == "not_running"
        }
        return true
    }

    /// Record a user flow for Logic Fuzzing (FlowMapper).
    public func startGhostRecording(flowName: String) async throws -> Bool {
        guard let url = URL(string: "/v1/ghost/record/\(flowName)", relativeTo: baseURL) else {
            return false
        }
        let request = authenticatedRequest(url: url, method: "POST")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw Self.parseAPIError(data: data, response: response)
        }
        return http.statusCode == 200
    }

    // MARK: - Mission Control

    public func startMission(target: String) async throws -> String {
        struct MissionResponse: Decodable {
            let status: String
            let mission_id: String
        }

        guard let base = URL(string: "/v1/mission/start", relativeTo: baseURL),
            var components = URLComponents(url: base, resolvingAgainstBaseURL: true)
        else { throw APIError.badStatus }
        components.queryItems = [URLQueryItem(name: "target", value: target)]
        guard let finalURL = components.url else { throw APIError.badStatus }

        let request = authenticatedRequest(url: finalURL, method: "POST")
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }
        let missionResponse = try JSONDecoder().decode(MissionResponse.self, from: data)
        return missionResponse.mission_id
    }

    // MARK: - Chat & AI
    // TODO: Replace with /v1/chat so the chat call matches the backend API.

    public func chatQuery(question: String) async throws -> String {
        guard let url = URL(string: "/v1/ai/chat", relativeTo: baseURL) else {
            throw APIError.badStatus
        }
        var request = authenticatedRequest(url: url, method: "POST")

        var components = URLComponents(url: url, resolvingAgainstBaseURL: true)!
        components.queryItems = [URLQueryItem(name: "question", value: question)]
        request.url = components.url

        struct ChatResponse: Decodable {
            let response: String
        }

        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }
        let chatResponse = try JSONDecoder().decode(ChatResponse.self, from: data)
        return chatResponse.response
    }

    /// Stream context-aware chat from Python backend (plain text chunks, not SSE)
    public func streamChat(prompt: String) -> AsyncThrowingStream<String, Error> {
        print("[Swift] Attempting to stream chat...")
        return AsyncThrowingStream { continuation in
            let task = Task {
                guard let url = URL(string: "/v1/ai/chat", relativeTo: baseURL) else {
                    continuation.finish(throwing: APIError.badStatus)
                    return
                }
                var request = authenticatedRequest(url: url, method: "POST")
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                let body = ["prompt": prompt]
                do {
                    request.httpBody = try JSONSerialization.data(withJSONObject: body)
                    let (bytes, response) = try await session.bytes(for: request)
                    print("[Swift] Received response headers: \(response)")

                    for try await line in bytes.lines {
                        let chunk = line.trimmingCharacters(in: .newlines)
                        if !chunk.isEmpty {
                            continuation.yield(chunk)
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { @Sendable _ in task.cancel() }
        }
    }

    // MARK: - Forge (Exploit Compilation)

    public func compileExploit(target: String, anomaly: String) async throws -> String {
        guard let url = URL(string: "/v1/forge/compile", relativeTo: baseURL) else {
            throw APIError.badStatus
        }
        var request = authenticatedRequest(url: url, method: "POST")

        var components = URLComponents(url: url, resolvingAgainstBaseURL: true)!
        components.queryItems = [
            URLQueryItem(name: "target", value: target),
            URLQueryItem(name: "anomaly", value: anomaly),
        ]
        request.url = components.url

        struct ForgeResponse: Decodable {
            let status: String
            let script_path: String
        }

        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }
        let forgeResponse = try JSONDecoder().decode(ForgeResponse.self, from: data)
        return forgeResponse.script_path
    }

    // MARK: - Server-Sent Events

    /// Stream server-sent events (logs, findings, etc.)
    /// Automatically reconnects with exponential backoff on failure.
    func streamEvents() -> AsyncThrowingStream<SSEEvent, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                var attempt = 0
                let maxRetries = 5

                while !Task.isCancelled {
                    guard let url = URL(string: "/v1/events/stream", relativeTo: baseURL) else {
                        continuation.finish(throwing: APIError.badStatus)
                        return
                    }

                    let request = authenticatedRequest(url: url, method: "GET")

                    do {
                        let (bytes, _) = try await session.bytes(for: request)
                        // Reset attempt counter on successful connection
                        attempt = 0

                        var currentEvent = ""
                        var currentData = ""

                        for try await line in bytes.lines {
                            if line.hasPrefix("event: ") {
                                currentEvent = String(line.dropFirst(7)).trimmingCharacters(
                                    in: .whitespaces)
                            } else if line.hasPrefix("data: ") {
                                currentData = String(line.dropFirst(6))
                            } else if line.isEmpty {
                                if !currentEvent.isEmpty && !currentData.isEmpty {
                                    continuation.yield(
                                        SSEEvent(type: currentEvent, data: currentData))
                                }
                                currentEvent = ""
                                currentData = ""
                            }
                        }

                        // If stream ends normally (server closed), we might want to reconnect or finish.
                        print("[SSE] Sync stream ended, reconnecting...")
                    } catch {
                        // Log error only if it's a real error (not connection refused during startup)
                        if ErrorClassifier.shouldLogAsError(error) {
                            print("[SSE] Connection lost: \(error). Reconnecting...")
                        }
                    }

                    attempt += 1
                    if attempt > maxRetries {
                        print("[SSE] Max retries reached. Giving up.")
                        continuation.finish(throwing: APIError.badStatus)
                        return
                    }

                    // Custom backoff: 0, 0.2, 0.5, 1.0, 5.0 seconds
                    await RetryBackoff.sleep(for: attempt)
                }

                continuation.finish()
            }
            continuation.onTermination = { @Sendable _ in task.cancel() }
        }
    }

    // MARK: - Action Approval

    /// Approve a pending action
    public func approveAction(id: String) async throws {
        guard let url = URL(string: "/v1/actions/\(id)/approve", relativeTo: baseURL) else {
            return
        }
        let request = authenticatedRequest(url: url, method: "POST")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }
    }

    /// Deny a pending action
    public func denyAction(id: String) async throws {
        guard let url = URL(string: "/v1/actions/\(id)/deny", relativeTo: baseURL) else { return }
        let request = authenticatedRequest(url: url, method: "POST")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw Self.parseAPIError(data: data, response: response)
        }
    }

    // MARK: - Report Generation

    func generateReport(
        target: String,
        scope: String?,
        format: String,
        includeAttackPaths: Bool,
        maxPaths: Int
    ) async throws -> ReportGenerateResponse {
        guard let url = URL(string: "/v1/cortex/reporting/generate", relativeTo: baseURL) else {
            throw APIError.badStatus
        }
        var request = authenticatedRequest(url: url, method: "POST")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        var body: [String: Any] = [
            "target": target,
            "format": format,
            "include_attack_paths": includeAttackPaths,
            "max_paths": maxPaths,
        ]
        if let scope {
            body["scope"] = scope
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw Self.parseAPIError(data: data, response: response)
        }
        return try JSONDecoder().decode(ReportGenerateResponse.self, from: data)
    }

    func fetchPoC(findingId: String) async throws -> PoCResponse {
        guard
            let url = URL(
                string: "/v1/cortex/reporting/poc/\(findingId)", relativeTo: baseURL)
        else {
            throw APIError.badStatus
        }
        let request = authenticatedRequest(url: url, method: "GET")
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw Self.parseAPIError(data: data, response: response)
        }
        return try JSONDecoder().decode(PoCResponse.self, from: data)
    }

    /// Stream report section
    public func streamReportSection(section: String) -> AsyncThrowingStream<String, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                guard
                    let url = URL(
                        string: "/v1/report/generate?section=\(section)", relativeTo: baseURL)
                else {
                    continuation.finish(throwing: APIError.badStatus)
                    return
                }
                let request = authenticatedRequest(url: url, method: "GET")

                do {
                    let (bytes, _) = try await session.bytes(for: request)
                    for try await line in bytes.lines {
                        if line.hasPrefix("data: ") {
                            let jsonStr = String(line.dropFirst(6))
                            if jsonStr == "[DONE]" { break }
                            if let data = jsonStr.data(using: .utf8),
                                let obj = try? JSONDecoder().decode(
                                    [String: String].self, from: data),
                                let token = obj["token"]
                            {
                                continuation.yield(token)
                            }
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { @Sendable _ in task.cancel() }
        }
    }
}
