//
//  VerifyAPIClient.swift
//  SentinelForgeUI — Phase 5-VC4
//
//  Typed async/await client for /v1/verify/*.  Mirrors
//  GhostAPIClient's structure (auth via ~/.sentinelforge/api_token,
//  async/await, one Swift method per backend endpoint, decoded DTOs
//  rather than [String: Any] everywhere).
//

import Foundation

// MARK: - DTOs

public struct VerifySessionSummary: Codable, Identifiable, Equatable {
    public let sessionId: String
    public let findingId: String?
    public let targetUrl: String
    public let allowedOrigins: [String]
    public let personaName: String?
    public let hasPersonaAuth: Bool
    public let transcriptLength: Int
    public let createdAt: Double
    public let lastActivityAt: Double

    public var id: String { sessionId }

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case findingId = "finding_id"
        case targetUrl = "target_url"
        case allowedOrigins = "allowed_origins"
        case personaName = "persona_name"
        case hasPersonaAuth = "has_persona_auth"
        case transcriptLength = "transcript_length"
        case createdAt = "created_at"
        case lastActivityAt = "last_activity_at"
    }
}

public struct VerifyFindingSummary: Codable, Equatable {
    public let type: String?
    public let severity: String?
    public let target: String?
    public let tool: String?
    public let vulnClass: String?
    public let payload: String?
    public let confidence: Double?
    public let probeLabel: String?
    public let persona: String?
    public let message: String?
    public let proofExcerpt: String?

    enum CodingKeys: String, CodingKey {
        case type, severity, target, tool, payload, confidence, message
        case vulnClass = "vuln_class"
        case probeLabel = "probe_label"
        case persona
        case proofExcerpt = "proof_excerpt"
    }
}

public struct VerifyExchange: Codable, Identifiable, Equatable {
    public let id: String
    public let method: String
    public let url: String
    public let headers: [String: String]
    public let requestBody: String
    public let responseStatus: Int
    public let responseHeaders: [String: String]
    public let responseBody: String
    public let responseContentType: String?
    public let responseElapsedMs: Double
    public let timestamp: Double

    enum CodingKeys: String, CodingKey {
        case id, method, url, headers, timestamp
        case requestBody = "request_body"
        case responseStatus = "response_status"
        case responseHeaders = "response_headers"
        case responseBody = "response_body"
        case responseContentType = "response_content_type"
        case responseElapsedMs = "response_elapsed_ms"
    }
}

public struct VerifySession: Codable {
    public let sessionId: String
    public let findingId: String?
    public let targetUrl: String
    public let targetOrigin: String
    public let allowedOrigins: [String]
    public let personaName: String?
    public let hasPersonaAuth: Bool
    public let originalFindingSummary: VerifyFindingSummary?
    public let transcriptLength: Int
    public let transcript: [VerifyExchange]
    public let createdAt: Double
    public let lastActivityAt: Double

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case findingId = "finding_id"
        case targetUrl = "target_url"
        case targetOrigin = "target_origin"
        case allowedOrigins = "allowed_origins"
        case personaName = "persona_name"
        case hasPersonaAuth = "has_persona_auth"
        case originalFindingSummary = "original_finding_summary"
        case transcriptLength = "transcript_length"
        case transcript
        case createdAt = "created_at"
        case lastActivityAt = "last_activity_at"
    }
}

public struct VerifyCreateResult: Codable {
    public let sessionId: String
    public let findingId: String?
    public let targetUrl: String
    public let allowedOrigins: [String]
    public let hasPersonaAuth: Bool

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case findingId = "finding_id"
        case targetUrl = "target_url"
        case allowedOrigins = "allowed_origins"
        case hasPersonaAuth = "has_persona_auth"
    }
}

public struct VerifyScopeResult: Codable {
    public let added: Bool
    public let allowedOrigins: [String]

    enum CodingKeys: String, CodingKey {
        case added
        case allowedOrigins = "allowed_origins"
    }
}

public struct VerifyExchangeResult: Codable {
    public let capturedStep: VerifyExchange
    public let transcriptLengthAfter: Int
    public let durationMs: Double
    public let inScope: Bool

    enum CodingKeys: String, CodingKey {
        case capturedStep = "captured_step"
        case transcriptLengthAfter = "transcript_length_after"
        case durationMs = "duration_ms"
        case inScope = "in_scope"
    }
}

public struct VerifyPromoteEntry: Codable, Identifiable, Equatable {
    public let index: Int
    public let method: String
    public let url: String
    public let prose: String
    public let curl: String
    public let responseStatus: Int
    public let responseExcerpt: String
    public let markdown: String

    public var id: Int { index }

    enum CodingKeys: String, CodingKey {
        case index, method, url, prose, curl, markdown
        case responseStatus = "response_status"
        case responseExcerpt = "response_excerpt"
    }
}

public struct VerifyPromoteResult: Codable {
    public let findingId: String?
    public let targetUrl: String
    public let entryCount: Int
    public let stepsToReproduce: [String]
    public let placeholderLegend: [String: String]
    public let entries: [VerifyPromoteEntry]

    enum CodingKeys: String, CodingKey {
        case findingId = "finding_id"
        case targetUrl = "target_url"
        case entryCount = "entry_count"
        case stepsToReproduce = "steps_to_reproduce"
        case placeholderLegend = "placeholder_legend"
        case entries
    }
}


// MARK: - Errors

public enum VerifyAPIError: Error, LocalizedError {
    case httpError(code: Int, message: String, scopeViolationURL: String? = nil, allowedOrigins: [String]? = nil)
    case decodingFailed(String)
    case networkError(String)

    public var errorDescription: String? {
        switch self {
        case .httpError(let code, let msg, let badURL, _):
            if let url = badURL {
                return "Scope violation: \(url) is not in this session's scope."
            }
            return "HTTP \(code): \(msg)"
        case .decodingFailed(let s): return "Decode error: \(s)"
        case .networkError(let s): return "Network error: \(s)"
        }
    }
}


// MARK: - Client

public final class VerifyAPIClient {
    public static let shared = VerifyAPIClient()

    private let session: URLSession
    private let baseURL: URL

    public init(
        baseURL: URL = URL(string: "http://127.0.0.1:8765")!,
        session: URLSession = .shared
    ) {
        self.baseURL = baseURL
        self.session = session
    }

    private static func readToken() -> String? {
        let tokenPath = FileManager.default
            .homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge")
            .appendingPathComponent("api_token")
        return try? String(contentsOf: tokenPath).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func authed(path: String, method: String = "GET") -> URLRequest {
        let url = URL(string: path, relativeTo: baseURL)!
        var req = URLRequest(url: url)
        req.httpMethod = method
        if let tok = Self.readToken() {
            req.setValue("Bearer \(tok)", forHTTPHeaderField: "Authorization")
        }
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        return req
    }

    private func send<T: Decodable>(_ req: URLRequest, as: T.Type) async throws -> T {
        do {
            let (data, resp) = try await session.data(for: req)
            guard let http = resp as? HTTPURLResponse else {
                throw VerifyAPIError.networkError("non-HTTP response")
            }
            if http.statusCode >= 400 {
                // Try to extract scope violation details from a 403.
                if http.statusCode == 403,
                   let body = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let detail = body["detail"] as? [String: Any],
                   detail["code"] as? String == "out_of_scope" {
                    let rejected = detail["rejected_url"] as? String
                    let allowed = detail["allowed_origins"] as? [String]
                    throw VerifyAPIError.httpError(
                        code: 403, message: "out_of_scope",
                        scopeViolationURL: rejected,
                        allowedOrigins: allowed
                    )
                }
                let msg = String(data: data, encoding: .utf8) ?? ""
                throw VerifyAPIError.httpError(code: http.statusCode, message: msg)
            }
            do {
                return try JSONDecoder().decode(T.self, from: data)
            } catch {
                throw VerifyAPIError.decodingFailed("\(error)")
            }
        } catch let e as VerifyAPIError {
            throw e
        } catch {
            throw VerifyAPIError.networkError("\(error)")
        }
    }

    private func postJSON<T: Decodable>(
        path: String, body: [String: Any], as: T.Type
    ) async throws -> T {
        var req = authed(path: path, method: "POST")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        return try await send(req, as: T.self)
    }

    // MARK: lifecycle

    public func createSession(findingId: String? = nil, targetUrl: String? = nil, note: String? = nil) async throws -> VerifyCreateResult {
        var body: [String: Any] = [:]
        if let f = findingId { body["finding_id"] = f }
        if let t = targetUrl { body["target_url"] = t }
        if let n = note { body["note"] = n }
        return try await postJSON(path: "/v1/verify/sessions", body: body, as: VerifyCreateResult.self)
    }

    public func listSessions() async throws -> [VerifySessionSummary] {
        let req = authed(path: "/v1/verify/sessions", method: "GET")
        return try await send(req, as: [VerifySessionSummary].self)
    }

    public func getSession(_ id: String) async throws -> VerifySession {
        let req = authed(path: "/v1/verify/sessions/\(id)", method: "GET")
        return try await send(req, as: VerifySession.self)
    }

    public func addScope(sessionId: String, urlOrOrigin: String) async throws -> VerifyScopeResult {
        return try await postJSON(
            path: "/v1/verify/sessions/\(sessionId)/scope",
            body: ["url_or_origin": urlOrOrigin],
            as: VerifyScopeResult.self
        )
    }

    // MARK: exchange

    public func sendExchange(
        sessionId: String,
        method: String,
        url: String,
        headers: [String: String] = [:],
        body: String? = nil
    ) async throws -> VerifyExchangeResult {
        var req: [String: Any] = [
            "method": method, "url": url, "headers": headers,
        ]
        if let b = body { req["body"] = b }
        return try await postJSON(
            path: "/v1/verify/sessions/\(sessionId)/exchange",
            body: req,
            as: VerifyExchangeResult.self
        )
    }

    // MARK: promote

    public func promote(
        sessionId: String,
        exchangeIndices: [Int]? = nil,
        sanitize: Bool = true
    ) async throws -> VerifyPromoteResult {
        var body: [String: Any] = ["sanitize": sanitize]
        if let xs = exchangeIndices { body["exchange_indices"] = xs }
        return try await postJSON(
            path: "/v1/verify/sessions/\(sessionId)/promote",
            body: body,
            as: VerifyPromoteResult.self
        )
    }
}
