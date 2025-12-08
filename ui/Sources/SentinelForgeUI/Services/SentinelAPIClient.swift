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
    func startScan(target: String) async throws {
        guard let url = URL(string: "/scan", relativeTo: baseURL) else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body = ["target": target]
        request.httpBody = try JSONEncoder().encode(body)
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
}

// MARK: - Models

struct LogBatch: Decodable {
    let lines: [String]
}

struct SentinelResults: Decodable {
    let target: String
    let findings: [JSONDict]?
    let issues: [JSONDict]?
    let killchain_edges: [JSONDict]?
    let phase_results: [String: [JSONDict]]?
    let logs: [String]?
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
