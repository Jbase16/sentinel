import Foundation

/// Tiny HTTP client for talking to the local Sentinel Python bridge.
/// Endpoints live in `core/api.py` and are intentionally simple + JSON-only.
struct SentinelAPIClient {
    let baseURL: URL
    private let session: URLSession

    init(baseURL: URL = URL(string: "http://127.0.0.1:8765")!, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    // Health check
    func ping() async -> Bool {
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
    func startScan(target: String, modules: [String] = []) async throws {
        guard let url = URL(string: "/scan", relativeTo: baseURL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        var body: [String: Any] = ["target": target]
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
    func fetchLogs() async throws -> [String] {
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
    func fetchStatus() async throws -> EngineStatus? {
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
    func fetchResults() async throws -> SentinelResults? {
        guard let url = URL(string: "/results", relativeTo: baseURL) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { return nil }
        if http.statusCode == 204 { return nil }
        guard http.statusCode == 200 else { throw APIError.badStatus }
        return try JSONDecoder().decode(SentinelResults.self, from: data)
    }

    // Request best-effort scan cancellation.
    func cancelScan() async throws {
        guard let url = URL(string: "/cancel", relativeTo: baseURL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 202 else {
            throw APIError.badStatus
        }
    }

    // Stream context-aware chat from Python backend
    func streamChat(prompt: String) -> AsyncThrowingStream<String, Error> {
        AsyncThrowingStream { continuation in
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

    // Stream server-sent events (logs, findings, etc.)
    func streamEvents() -> AsyncThrowingStream<SSEEvent, Error> {
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
    func approveAction(id: String) async throws {
        guard let url = URL(string: "/actions/\(id)/approve", relativeTo: baseURL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw APIError.badStatus
        }
    }

    // Deny a pending action
    func denyAction(id: String) async throws {
        guard let url = URL(string: "/actions/\(id)/deny", relativeTo: baseURL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        let (_, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw APIError.badStatus
        }
    }
    // Stream report section
    func streamReportSection(section: String) -> AsyncThrowingStream<String, Error> {
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

struct SSEEvent {
    let type: String
    let data: String
}

// MARK: - Models

struct LogBatch: Decodable {
    let lines: [String]
}

struct EngineStatus: Decodable {
    let status: String
    let scanRunning: Bool
    let latestTarget: String?
    let ai: AIStatus?
    let tools: ToolStatus?
    let scanState: ScanState?
    let cancelRequested: Bool?

    enum CodingKeys: String, CodingKey {
        case status, ai, tools
        case scanRunning = "scan_running"
        case latestTarget = "latest_target"
        case scanState = "scan_state"
        case cancelRequested = "cancel_requested"
    }
}

struct ToolStatus: Decodable {
    let installed: [String]
    let missing: [String]
    let countInstalled: Int
    let countTotal: Int
    
    enum CodingKeys: String, CodingKey {
        case installed, missing
        case countInstalled = "count_installed"
        case countTotal = "count_total"
    }
}

struct ScanState: Decodable {
    let target: String?
    let modules: [String]?
    let status: String?
    let startedAt: String?
    let finishedAt: String?
    let durationMs: Int?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case target, modules, status, error
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case durationMs = "duration_ms"
    }
}

struct AIStatus: Decodable {
    let provider: String?
    let model: String?
    let connected: Bool
    let fallbackEnabled: Bool
    let availableModels: [String]?

    enum CodingKeys: String, CodingKey {
        case provider, model, connected
        case fallbackEnabled = "fallback_enabled"
        case availableModels = "available_models"
    }
}

struct SentinelResults: Decodable {
    let scan: ScanSummary?
    let summary: ResultsSummary?
    let findings: [JSONDict]?
    let issues: [JSONDict]?
    let killchain: Killchain?
    let phaseResults: [String: [JSONDict]]?
    let evidence: [EvidenceSummary]?
    let logs: [String]?

    enum CodingKeys: String, CodingKey {
        case scan, summary, findings, issues, killchain, logs, evidence
        case phaseResults = "phase_results"
    }
}

struct ScanSummary: Decodable {
    let target: String?
    let modules: [String]?
    let status: String?
    let startedAt: String?
    let finishedAt: String?
    let durationMs: Int?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case target, modules, status, error
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case durationMs = "duration_ms"
    }
}

struct ResultsSummary: Decodable {
    let counts: ResultCounts?
    let ai: AIStatus?
}

struct ResultCounts: Decodable {
    let findings: Int
    let issues: Int
    let killchainEdges: Int
    let logs: Int
    let phaseResults: [String: Int]

    enum CodingKeys: String, CodingKey {
        case findings, issues, logs
        case killchainEdges = "killchain_edges"
        case phaseResults = "phase_results"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        findings = try container.decodeIfPresent(Int.self, forKey: .findings) ?? 0
        issues = try container.decodeIfPresent(Int.self, forKey: .issues) ?? 0
        killchainEdges = try container.decodeIfPresent(Int.self, forKey: .killchainEdges) ?? 0
        logs = try container.decodeIfPresent(Int.self, forKey: .logs) ?? 0
        phaseResults = try container.decodeIfPresent([String: Int].self, forKey: .phaseResults) ?? [:]
    }
}

struct Killchain: Decodable {
    let edges: [JSONDict]?
    let attackPaths: [[String]]?
    let degradedPaths: [[String]]?
    let recommendedPhases: [String]?

    enum CodingKeys: String, CodingKey {
        case edges
        case attackPaths = "attack_paths"
        case degradedPaths = "degraded_paths"
        case recommendedPhases = "recommended_phases"
    }
}

struct EvidenceSummary: Decodable {
    let id: Int
    let tool: String?
    let summary: String?
    let metadata: JSONDict?
    let rawPreview: String?
    let rawBytes: Int?
    let findingCount: Int?

    enum CodingKeys: String, CodingKey {
        case id, tool, summary, metadata
        case rawPreview = "raw_preview"
        case rawBytes = "raw_bytes"
        case findingCount = "finding_count"
    }
}

// Minimal JSON value wrapper to decode arbitrary dictionaries coming from Python.
enum JSONValue: Decodable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case object([String: JSONValue])
    case array([JSONValue])
    case null

    init(from decoder: Decoder) throws {
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

typealias JSONDict = [String: JSONValue]

extension JSONValue {
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

enum APIError: Error {
    case badStatus
}
