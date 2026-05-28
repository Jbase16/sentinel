//
//  GhostAPIClient.swift
//  SentinelForgeUI — Phase 4-UI
//
//  Typed Swift client for the Ghost Protocol REST API (POST /v1/ghost/*).
//
//  Mirrors SentinelAPIClient's auth pattern: reads ~/.sentinelforge/api_token
//  and applies Bearer auth to every request. Returns decoded Swift structs
//  for the response payloads so the GhostConsoleView doesn't have to deal
//  with `[String: Any]` everywhere.
//

import Foundation


// MARK: - DTOs

/// Mirror of GhostStatusResponse in core/server/routers/ghost.py.
public struct GhostStatus: Codable, Equatable {
    public let running: Bool
    public let port: Int?
    public let sessionId: String?
    public let activeRecordings: [String]
    public let flowCount: Int
    public let certAvailable: Bool
    public let certPath: String?
    public let findingsSoFar: Int

    enum CodingKeys: String, CodingKey {
        case running, port
        case sessionId = "session_id"
        case activeRecordings = "active_recordings"
        case flowCount = "flow_count"
        case certAvailable = "cert_available"
        case certPath = "cert_path"
        case findingsSoFar = "findings_so_far"
    }
}

public struct GhostStartResult: Codable {
    public let status: String
    public let port: Int?
    public let message: String?
    public let certPath: String?

    enum CodingKeys: String, CodingKey {
        case status, port, message
        case certPath = "cert_path"
    }
}

public struct GhostFlowSummary: Codable, Identifiable, Equatable {
    public let flowId: String
    public let name: String
    public let stepCount: Int
    public let hasAuthTokens: Bool

    public var id: String { flowId }

    enum CodingKeys: String, CodingKey {
        case flowId = "flow_id"
        case name
        case stepCount = "step_count"
        case hasAuthTokens = "has_auth_tokens"
    }
}

public struct GhostMutationProposal: Codable, Identifiable, Equatable {
    public let stepIndex: Int
    public let stepMethod: String
    public let stepUrl: String
    public let mutationLabel: String
    public let rationale: String

    public var id: String { "\(stepIndex)-\(mutationLabel)" }

    enum CodingKeys: String, CodingKey {
        case stepIndex = "step_index"
        case stepMethod = "step_method"
        case stepUrl = "step_url"
        case mutationLabel = "mutation_label"
        case rationale
    }
}

public struct GhostProposeResult: Codable {
    public let flowId: String
    public let flowName: String
    public let stepCount: Int
    public let proposalCount: Int
    public let proposals: [GhostMutationProposal]

    enum CodingKeys: String, CodingKey {
        case flowId = "flow_id"
        case flowName = "flow_name"
        case stepCount = "step_count"
        case proposalCount = "proposal_count"
        case proposals
    }
}

public struct GhostStepDiff: Codable, Identifiable, Equatable {
    public let stepIndex: Int
    public let stepId: String
    public let method: String
    public let url: String
    public let originalStatus: Int
    public let replayStatus: Int
    public let originalSize: Int
    public let replaySize: Int
    public let originalHash: String
    public let replayHash: String
    public let statusChanged: Bool
    public let bodyChanged: Bool
    public let sizeDelta: Int
    public let elapsedDeltaMs: Double
    public let appliedMutations: [String]
    public let diverged: Bool

    public var id: String { stepId + "-\(stepIndex)" }

    enum CodingKeys: String, CodingKey {
        case stepIndex = "step_index"
        case stepId = "step_id"
        case method, url
        case originalStatus = "original_status"
        case replayStatus = "replay_status"
        case originalSize = "original_size"
        case replaySize = "replay_size"
        case originalHash = "original_hash"
        case replayHash = "replay_hash"
        case statusChanged = "status_changed"
        case bodyChanged = "body_changed"
        case sizeDelta = "size_delta"
        case elapsedDeltaMs = "elapsed_delta_ms"
        case appliedMutations = "applied_mutations"
        case diverged
    }
}

public struct GhostReplayResult: Codable {
    public let sourceFlowId: String
    public let sourceFlowName: String
    public let stepDiffs: [GhostStepDiff]
    public let totalElapsedMs: Double
    public let stoppedEarly: Bool
    public let error: String?
    public let divergedStepCount: Int

    enum CodingKeys: String, CodingKey {
        case sourceFlowId = "source_flow_id"
        case sourceFlowName = "source_flow_name"
        case stepDiffs = "step_diffs"
        case totalElapsedMs = "total_elapsed_ms"
        case stoppedEarly = "stopped_early"
        case error
        case divergedStepCount = "diverged_step_count"
    }
}

public struct GhostMutationSpec: Codable {
    public let stepIndex: Int
    public let mutation: String
    public let params: [String: AnyCodable]

    public init(stepIndex: Int, mutation: String, params: [String: AnyCodable] = [:]) {
        self.stepIndex = stepIndex
        self.mutation = mutation
        self.params = params
    }

    enum CodingKeys: String, CodingKey {
        case stepIndex = "step_index"
        case mutation, params
    }
}

/// Minimal AnyCodable for opaque mutation params.
public struct AnyCodable: Codable {
    public let value: Any

    public init(_ value: Any) { self.value = value }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let v = try? c.decode(Bool.self) { self.value = v; return }
        if let v = try? c.decode(Int.self) { self.value = v; return }
        if let v = try? c.decode(Double.self) { self.value = v; return }
        if let v = try? c.decode(String.self) { self.value = v; return }
        self.value = NSNull()
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch value {
        case let v as Bool: try c.encode(v)
        case let v as Int: try c.encode(v)
        case let v as Double: try c.encode(v)
        case let v as String: try c.encode(v)
        default: try c.encodeNil()
        }
    }
}


// MARK: - Errors

public enum GhostAPIError: Error, LocalizedError {
    case noBaseURL
    case httpError(code: Int, message: String)
    case decodingFailed(String)
    case networkError(String)

    public var errorDescription: String? {
        switch self {
        case .noBaseURL: return "API base URL not configured."
        case .httpError(let code, let msg): return "HTTP \(code): \(msg)"
        case .decodingFailed(let s): return "Failed to decode response: \(s)"
        case .networkError(let s): return "Network error: \(s)"
        }
    }
}


// MARK: - Client

/// Async/await client for /v1/ghost/* endpoints.
///
/// One instance per session; thread-safe (URLSession is). Uses the same
/// Bearer-token-from-disk pattern as `SentinelAPIClient`.
public final class GhostAPIClient {
    public static let shared = GhostAPIClient()

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

    private func authedRequest(path: String, method: String = "GET") -> URLRequest {
        let url = URL(string: path, relativeTo: baseURL)!
        var req = URLRequest(url: url)
        req.httpMethod = method
        if let tok = Self.readToken() {
            req.setValue("Bearer \(tok)", forHTTPHeaderField: "Authorization")
        }
        return req
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw GhostAPIError.decodingFailed("\(error)")
        }
    }

    private func send<T: Decodable>(_ req: URLRequest, as: T.Type) async throws -> T {
        do {
            let (data, resp) = try await session.data(for: req)
            guard let http = resp as? HTTPURLResponse else {
                throw GhostAPIError.networkError("non-HTTP response")
            }
            if http.statusCode >= 400 {
                let msg = String(data: data, encoding: .utf8) ?? ""
                throw GhostAPIError.httpError(code: http.statusCode, message: msg)
            }
            return try decode(T.self, from: data)
        } catch let e as GhostAPIError {
            throw e
        } catch {
            throw GhostAPIError.networkError("\(error)")
        }
    }

    // MARK: lifecycle

    public func status() async throws -> GhostStatus {
        let req = authedRequest(path: "/v1/ghost/status", method: "GET")
        return try await send(req, as: GhostStatus.self)
    }

    public func start(port: Int = 0) async throws -> GhostStartResult {
        let req = authedRequest(
            path: "/v1/ghost/start?port=\(port)", method: "POST"
        )
        return try await send(req, as: GhostStartResult.self)
    }

    public func stop() async throws -> GhostStartResult {
        let req = authedRequest(path: "/v1/ghost/stop", method: "POST")
        return try await send(req, as: GhostStartResult.self)
    }

    // MARK: recordings

    public func startRecording(_ flowName: String) async throws {
        let encoded = flowName.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed
        ) ?? flowName
        let req = authedRequest(
            path: "/v1/ghost/record/\(encoded)", method: "POST"
        )
        let (_, resp) = try await session.data(for: req)
        if let http = resp as? HTTPURLResponse, http.statusCode >= 400 {
            throw GhostAPIError.httpError(code: http.statusCode, message: "")
        }
    }

    public func stopRecording(_ flowName: String) async throws {
        let encoded = flowName.addingPercentEncoding(
            withAllowedCharacters: .urlPathAllowed
        ) ?? flowName
        let req = authedRequest(
            path: "/v1/ghost/record/\(encoded)/stop", method: "POST"
        )
        let (_, resp) = try await session.data(for: req)
        if let http = resp as? HTTPURLResponse, http.statusCode >= 400 {
            throw GhostAPIError.httpError(code: http.statusCode, message: "")
        }
    }

    // MARK: flows

    public func listFlows() async throws -> [GhostFlowSummary] {
        let req = authedRequest(path: "/v1/ghost/flows", method: "GET")
        return try await send(req, as: [GhostFlowSummary].self)
    }

    public func proposeFor(flowId: String) async throws -> GhostProposeResult {
        let req = authedRequest(
            path: "/v1/ghost/flows/\(flowId)/propose", method: "GET"
        )
        return try await send(req, as: GhostProposeResult.self)
    }

    public func replayFlow(
        flowId: String,
        mutations: [GhostMutationSpec] = [],
        initialCookies: [String: String] = [:],
        initialHeaders: [String: String] = [:],
        stopOnDivergence: Bool = false
    ) async throws -> GhostReplayResult {
        var req = authedRequest(
            path: "/v1/ghost/flows/\(flowId)/replay", method: "POST"
        )
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body: [String: Any] = [
            "mutations": mutations.map { m -> [String: Any] in
                var d: [String: Any] = [
                    "step_index": m.stepIndex,
                    "mutation": m.mutation,
                ]
                if !m.params.isEmpty {
                    d["params"] = m.params.mapValues { $0.value }
                }
                return d
            },
            "initial_cookies": initialCookies,
            "initial_headers": initialHeaders,
            "stop_on_divergence": stopOnDivergence,
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        return try await send(req, as: GhostReplayResult.self)
    }
}
