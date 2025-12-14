import Foundation

/// Tiny HTTP client for talking to the local Sentinel Python bridge.
/// Endpoints live in `core/api.py` and are intentionally simple + JSON-only.
public struct SentinelAPIClient: Sendable {
    public let baseURL: URL
    private let session: URLSession

    public init(baseURL: URL = URL(string: "http://127.0.0.1:8765")!, session: URLSession? = nil) {
        self.baseURL = baseURL
        if let session = session {
            self.session = session
        } else {
            let config = URLSessionConfiguration.default
            config.requestCachePolicy = .reloadIgnoringLocalCacheData
            config.timeoutIntervalForRequest = 120.0 // Increased for slow local LLMs
            config.timeoutIntervalForResource = 600.0 // Allow very long streams
            self.session = URLSession(configuration: config)
        }
    }

    // Health check
    public func ping() async -> Bool {
        guard let url = URL(string: "/ping", relativeTo: baseURL) else { return false }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return false }
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return (json?["status"] as? String) == "ok"
        } catch {
            return false
        }
    }

    // Kick off a scan for a given target.
    public func startScan(target: String, modules: [String] = []) async throws {
        guard let url = URL(string: "/scan", relativeTo: baseURL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Force by default to clean up zombie states
        var body: [String: Any] = ["target": target, "force": true]
        
        if !modules.isEmpty {
            body["modules"] = modules
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 202 else {
            throw APIError.badStatus
        }
    }

    // Pull any buffered log lines from Python since the last call.
    public func fetchLogs() async throws -> [String] {
        guard let url = URL(string: "/logs", relativeTo: baseURL) else { return [] }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw APIError.badStatus
        }
        let decoded = try JSONDecoder().decode(LogBatch.self, from: data)
        return decoded.lines
    }

    // Fetch lightweight engine + AI status (model availability, running scan).
    public func fetchStatus() async throws -> EngineStatus? {
        guard let url = URL(string: "/status", relativeTo: baseURL) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw APIError.badStatus
        }
        return try JSONDecoder().decode(EngineStatus.self, from: data)
    }

    // Fetch the latest scan snapshot (findings/issues/killchain/phase_results).
    public func fetchResults() async throws -> SentinelResults? {
        guard let url = URL(string: "/results", relativeTo: baseURL) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { return nil }
        if http.statusCode == 204 { return nil }
        guard http.statusCode == 200 else { throw APIError.badStatus }
        return try JSONDecoder().decode(SentinelResults.self, from: data)
    }

    // Install selected tools
    public func installTools(_ tools: [String]) async throws -> [InstallResult] {
        struct InstallResponse: Decodable { let results: [InstallResult] }
        guard let url = URL(string: "/tools/install", relativeTo: baseURL) else { throw APIError.badStatus }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = ["tools": tools]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: req)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw APIError.badStatus }
        let decoded = try JSONDecoder().decode(InstallResponse.self, from: data)
        return decoded.results
    }

    // Uninstall selected tools
    public func uninstallTools(_ tools: [String]) async throws -> [InstallResult] {
        struct InstallResponse: Decodable { let results: [InstallResult] }
        guard let url = URL(string: "/tools/uninstall", relativeTo: baseURL) else { throw APIError.badStatus }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = ["tools": tools]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: req)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw APIError.badStatus }
        let decoded = try JSONDecoder().decode(InstallResponse.self, from: data)
        return decoded.results
    }

    // MARK: - God-Tier Endpoints

    public func startMission(target: String) async throws -> String {
        struct MissionResponse: Decodable {
            let status: String
            let mission_id: String
        }
        
        guard let url = URL(string: "/mission/start", relativeTo: baseURL) else { throw APIError.badStatus }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        // Add auth token if we had one (Placeholder)
        // request.setValue("Bearer ...", forHTTPHeaderField: "Authorization")
        
        let pathWithQuery = url.absoluteString + "?target=\(target)"
        request.url = URL(string: pathWithQuery)
        
        let (data, _) = try await session.data(for: request)
        let response = try JSONDecoder().decode(MissionResponse.self, from: data)
        return response.mission_id
    }

    public func chatQuery(question: String) async throws -> String {
        guard let url = URL(string: "/chat/query", relativeTo: baseURL) else { throw APIError.badStatus }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        let pathWithQuery = url.absoluteString + "?question=\(question.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")"
        request.url = URL(string: pathWithQuery)
        
        struct ChatResponse: Decodable {
            let response: String
        }
        
        let (data, _) = try await session.data(for: request)
        let response = try JSONDecoder().decode(ChatResponse.self, from: data)
        return response.response
    }
    
    public func compileExploit(target: String, anomaly: String) async throws -> String {
        guard let url = URL(string: "/forge/compile", relativeTo: baseURL) else { throw APIError.badStatus }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        
        var components = URLComponents(url: url, resolvingAgainstBaseURL: true)!
        components.queryItems = [
            URLQueryItem(name: "target", value: target),
            URLQueryItem(name: "anomaly", value: anomaly)
        ]
        request.url = components.url
        
        struct ForgeResponse: Decodable {
            let status: String
            let script_path: String
        }
        
        let (data, _) = try await session.data(for: request)
        let response = try JSONDecoder().decode(ForgeResponse.self, from: data)
        return response.script_path
    }

    // Request best-effort scan cancellation.
    public func cancelScan() async throws {
        guard let url = URL(string: "/cancel", relativeTo: baseURL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 202 else {
            throw APIError.badStatus
        }
    }

    // Stream context-aware chat from Python backend
    public func streamChat(prompt: String) -> AsyncThrowingStream<String, Error> {
        print("[Swift] Attempting to stream chat...")
        return AsyncThrowingStream { continuation in
            let task = Task {
                guard let url = URL(string: "/chat", relativeTo: baseURL) else {
                    continuation.finish(throwing: APIError.badStatus)
                    return
                }
                var request = URLRequest(url: url)
                request.httpMethod = "POST"
                request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                let body = ["prompt": prompt]
                do {
                    request.httpBody = try JSONSerialization.data(withJSONObject: body)
                    let (bytes, response) = try await session.bytes(for: request)
                    print("[Swift] Received response headers: \(response)")
                    
                    for try await line in bytes.lines {
                        if line.hasPrefix("data: ") {
                            let jsonStr = String(line.dropFirst(6))
                            if jsonStr == "[DONE]" { break }
                            if let data = jsonStr.data(using: .utf8),
                               let obj = try? JSONDecoder().decode([String: String].self, from: data),
                               let token = obj["token"] {
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

    // Stream server-sent events (logs, findings, etc.)
    public func streamEvents() -> AsyncThrowingStream<SSEEvent, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                guard let url = URL(string: "/events", relativeTo: baseURL) else {
                    continuation.finish(throwing: APIError.badStatus)
                    return
                }
                let request = URLRequest(url: url)
                do {
                    let (bytes, _) = try await session.bytes(for: request)
                    var currentEvent = ""
                    var currentData = ""
                    
                    for try await line in bytes.lines {
                        if line.hasPrefix("event: ") {
                            currentEvent = String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces)
                        } else if line.hasPrefix("data: ") {
                            currentData = String(line.dropFirst(6))
                        } else if line.isEmpty {
                            if !currentEvent.isEmpty && !currentData.isEmpty {
                                continuation.yield(SSEEvent(type: currentEvent, data: currentData))
                            }
                            currentEvent = ""
                            currentData = ""
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
    
    // Approve a pending action
    public func approveAction(id: String) async throws {
        guard let url = URL(string: "/actions/\(id)/approve", relativeTo: baseURL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw APIError.badStatus
        }
    }

    // Deny a pending action
    public func denyAction(id: String) async throws {
        guard let url = URL(string: "/actions/\(id)/deny", relativeTo: baseURL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw APIError.badStatus
        }
    }
    // Stream report section
    public func streamReportSection(section: String) -> AsyncThrowingStream<String, Error> {
        AsyncThrowingStream { continuation in
            let task = Task {
                guard let url = URL(string: "/report/generate?section=\(section)", relativeTo: baseURL) else {
                    continuation.finish(throwing: APIError.badStatus)
                    return
                }
                var request = URLRequest(url: url)
                request.httpMethod = "GET"
                
                do {
                    let (bytes, _) = try await session.bytes(for: request)
                    for try await line in bytes.lines {
                        if line.hasPrefix("data: ") {
                            let jsonStr = String(line.dropFirst(6))
                            if jsonStr == "[DONE]" { break }
                            if let data = jsonStr.data(using: .utf8),
                               let obj = try? JSONDecoder().decode([String: String].self, from: data),
                               let token = obj["token"] {
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

public struct InstallResult: Decodable, Identifiable {
    public var id: String { tool }
    public let tool: String
    public let status: String
    public let message: String?
}

public struct SSEEvent {
    public let type: String
    public let data: String
}

// MARK: - Models

public struct LogBatch: Decodable {
    public let lines: [String]
}

public struct EngineStatus: Decodable {
    public let status: String
    public let scanRunning: Bool
    public let latestTarget: String?
    public let ai: AIStatus?
    public let tools: ToolStatus?
    public let scanState: ScanState?
    public let cancelRequested: Bool?

    enum CodingKeys: String, CodingKey {
        case status, ai, tools
        case scanRunning = "scan_running"
        case latestTarget = "latest_target"
        case scanState = "scan_state"
        case cancelRequested = "cancel_requested"
    }
}

public struct ToolStatus: Decodable {
    public let installed: [String]
    public let missing: [String]
    public let countInstalled: Int
    public let countTotal: Int
    
    enum CodingKeys: String, CodingKey {
        case installed, missing
        case countInstalled = "count_installed"
        case countTotal = "count_total"
    }
}

public struct ScanState: Decodable {
    public let target: String?
    public let modules: [String]?
    public let status: String?
    public let startedAt: String?
    public let finishedAt: String?
    public let durationMs: Int?
    public let error: String?

    enum CodingKeys: String, CodingKey {
        case target, modules, status, error
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case durationMs = "duration_ms"
    }
}

public struct AIStatus: Decodable {
    public let provider: String?
    public let model: String?
    public let connected: Bool
    public let fallbackEnabled: Bool
    public let availableModels: [String]?

    enum CodingKeys: String, CodingKey {
        case provider, model, connected
        case fallbackEnabled = "fallback_enabled"
        case availableModels = "available_models"
    }
}

public struct SentinelResults: Decodable {
    public let scan: ScanSummary?
    public let summary: ResultsSummary?
    public let findings: [JSONDict]?
    public let issues: [JSONDict]?
    public let killchain: Killchain?
    public let phaseResults: [String: [JSONDict]]?
    public let evidence: [EvidenceSummary]?
    public let logs: [String]?

    enum CodingKeys: String, CodingKey {
        case scan, summary, findings, issues, killchain, logs, evidence
        case phaseResults = "phase_results"
    }
}

public struct ScanSummary: Decodable {
    public let target: String?
    public let modules: [String]?
    public let status: String?
    public let startedAt: String?
    public let finishedAt: String?
    public let durationMs: Int?
    public let error: String?

    enum CodingKeys: String, CodingKey {
        case target, modules, status, error
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case durationMs = "duration_ms"
    }
}

public struct ResultsSummary: Decodable {
    public let counts: ResultCounts?
    public let ai: AIStatus?
}

public struct ResultCounts: Decodable {
    public let findings: Int
    public let issues: Int
    public let killchainEdges: Int
    public let logs: Int
    public let phaseResults: [String: Int]

    enum CodingKeys: String, CodingKey {
        case findings, issues, logs
        case killchainEdges = "killchain_edges"
        case phaseResults = "phase_results"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        findings = try container.decodeIfPresent(Int.self, forKey: .findings) ?? 0
        issues = try container.decodeIfPresent(Int.self, forKey: .issues) ?? 0
        killchainEdges = try container.decodeIfPresent(Int.self, forKey: .killchainEdges) ?? 0
        logs = try container.decodeIfPresent(Int.self, forKey: .logs) ?? 0
        phaseResults = try container.decodeIfPresent([String: Int].self, forKey: .phaseResults) ?? [:]
    }
}

public struct Killchain: Decodable {
    public let edges: [JSONDict]?
    public let attackPaths: [[String]]?
    public let degradedPaths: [[String]]?
    public let recommendedPhases: [String]?

    enum CodingKeys: String, CodingKey {
        case edges
        case attackPaths = "attack_paths"
        case degradedPaths = "degraded_paths"
        case recommendedPhases = "recommended_phases"
    }
}

public struct EvidenceSummary: Decodable {
    public let id: Int
    public let tool: String?
    public let summary: String?
    public let metadata: JSONDict?
    public let rawPreview: String?
    public let rawBytes: Int?
    public let findingCount: Int?

    enum CodingKeys: String, CodingKey {
        case id, tool, summary, metadata
        case rawPreview = "raw_preview"
        case rawBytes = "raw_bytes"
        case findingCount = "finding_count"
    }
}

// Minimal JSON value wrapper to decode arbitrary dictionaries coming from Python.
public enum JSONValue: Decodable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let b = try? container.decode(Bool.self) {
            self = .bool(b)
        } else if let n = try? container.decode(Double.self) {
            self = .number(n)
        } else if let s = try? container.decode(String.self) {
            self = .string(s)
        } else if let arr = try? container.decode([JSONValue].self) {
            self = .array(arr)
        } else if let obj = try? container.decode([String: JSONValue].self) {
            self = .object(obj)
        } else {
            self = .null
        }
    }
}

public typealias JSONDict = [String: JSONValue]

public extension JSONValue {
    /// Convenience to unwrap a string if present.
    var stringValue: String? {
        switch self {
        case .string(let s): return s
        case .number(let n): return String(n)
        case .bool(let b): return String(b)
        default: return nil
        }
    }
}

public enum APIError: Error {
    case badStatus
}
