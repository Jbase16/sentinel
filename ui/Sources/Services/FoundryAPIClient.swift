//
//  FoundryAPIClient.swift
//  SentinelForgeUI — Phase 7-PF10
//
//  Typed async/await client for /v1/foundry/*. Mirrors Ghost/Verify
//  client structure (Bearer auth from ~/.sentinelforge/api_token, one
//  Swift method per endpoint, decoded DTOs).
//
//  The methods that matter most for the handoff UX:
//    listChallenges()  — poll the pending "Sentinel needs you" walls
//    resolveChallenge() — the 1-click resolution
//

import Foundation

// MARK: - DTOs

public struct FoundryChallenge: Codable, Identifiable, Equatable {
    public let challengeId: String
    public let kind: String
    public let prompt: String
    public let contextUrl: String
    public let recipeId: String
    public let personaId: String
    public let serviceHandle: String
    public let screenshotB64: String?
    public let needsValueFor: String?
    public let createdAt: Double

    public var id: String { challengeId }

    enum CodingKeys: String, CodingKey {
        case challengeId = "challenge_id"
        case kind, prompt
        case contextUrl = "context_url"
        case recipeId = "recipe_id"
        case personaId = "persona_id"
        case serviceHandle = "service_handle"
        case screenshotB64 = "screenshot_b64"
        case needsValueFor = "needs_value_for"
        case createdAt = "created_at"
    }

    /// True if this challenge expects the human to supply a value (an
    /// email link / code), as opposed to a solve-in-place CAPTCHA.
    public var needsValue: Bool { needsValueFor != nil }
}

public struct FoundryAccountRequirement: Codable, Identifiable {
    public let role: String
    public let label: String
    public let tenantGroup: String
    public let setupActions: [String]
    public let rationale: String
    public let fingerprint: String?

    public var id: String { "\(label)-\(role)" }

    enum CodingKeys: String, CodingKey {
        case role, label, rationale, fingerprint
        case tenantGroup = "tenant_group"
        case setupActions = "setup_actions"
    }
}

public struct FoundryAccountPlan: Codable {
    public let targetHandle: String
    public let vulnClasses: [String]
    public let accountCount: Int
    public let tenantCount: Int
    public let accounts: [FoundryAccountRequirement]
    public let relationships: [String]
    public let summary: String

    enum CodingKeys: String, CodingKey {
        case targetHandle = "target_handle"
        case vulnClasses = "vuln_classes"
        case accountCount = "account_count"
        case tenantCount = "tenant_count"
        case accounts, relationships, summary
    }
}

public struct FoundryPersona: Codable, Identifiable {
    public let personaId: String
    public let label: String
    public let email: String
    public let hasPassword: Bool?

    public var id: String { personaId }

    enum CodingKeys: String, CodingKey {
        case personaId = "persona_id"
        case label, email
        case hasPassword = "has_password"
    }
}

public struct FoundryAuthorizationEnvelope: Codable, Identifiable {
    public let envelopeId: String
    public let targetHandle: String
    public let authorizedOrigins: [String]
    public let allowedWorkflows: [String]
    public let context: String

    public var id: String { envelopeId }
    public var isApproved: Bool { context == "approved" }

    enum CodingKeys: String, CodingKey {
        case envelopeId = "envelope_id"
        case targetHandle = "target_handle"
        case authorizedOrigins = "authorized_origins"
        case allowedWorkflows = "allowed_workflows"
        case context
    }
}

public struct BehavioralAuthorizationPlan: Codable {
    public let selectedProposalId: String?

    enum CodingKeys: String, CodingKey {
        case selectedProposalId = "selected_proposal_id"
    }
}

public struct BehavioralAuthorizationExecution: Codable {
    public let legacyVerdict: String

    enum CodingKeys: String, CodingKey {
        case legacyVerdict = "legacy_verdict"
    }
}

public struct BehavioralReadExploration: Codable {
    public let status: String
    public let pairsCompleted: Int
    public let requestsSent: Int
    public let selectedAfterPair: Int

    enum CodingKeys: String, CodingKey {
        case status
        case pairsCompleted = "pairs_completed"
        case requestsSent = "requests_sent"
        case selectedAfterPair = "selected_after_pair"
    }
}

public struct BehavioralAuthorizationResponse: Codable {
    public let status: String
    public let plan: BehavioralAuthorizationPlan
    public let execution: BehavioralAuthorizationExecution?
    public let readExploration: BehavioralReadExploration?

    enum CodingKeys: String, CodingKey {
        case status, plan, execution
        case readExploration = "read_exploration"
    }
}

public struct FoundryRecipeSummary: Codable, Identifiable {
    public let recipeId: String
    public let serviceHandle: String
    public let name: String
    public let stepCount: Int
    public let challengeCount: Int

    public var id: String { recipeId }

    enum CodingKeys: String, CodingKey {
        case recipeId = "recipe_id"
        case serviceHandle = "service_handle"
        case name
        case stepCount = "step_count"
        case challengeCount = "challenge_count"
    }
}

public struct FoundrySignupJob: Codable, Identifiable {
    public let jobId: String
    public let recipeId: String
    public let personaId: String
    public let serviceHandle: String
    public let state: String
    public let error: String?

    public var id: String { jobId }

    enum CodingKeys: String, CodingKey {
        case jobId = "job_id"
        case recipeId = "recipe_id"
        case personaId = "persona_id"
        case serviceHandle = "service_handle"
        case state, error
    }
}


// MARK: - Errors

public enum FoundryAPIError: Error, LocalizedError {
    case httpError(code: Int, message: String)
    case decodingFailed(String)
    case networkError(String)

    public var errorDescription: String? {
        switch self {
        case .httpError(let c, let m): return "HTTP \(c): \(m)"
        case .decodingFailed(let s): return "Decode error: \(s)"
        case .networkError(let s): return "Network error: \(s)"
        }
    }
}


// MARK: - Client

public final class FoundryAPIClient {
    public static let shared = FoundryAPIClient()

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
        let p = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge")
            .appendingPathComponent("api_token")
        return try? String(contentsOf: p).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func authed(_ path: String, method: String = "GET") -> URLRequest {
        var req = URLRequest(url: URL(string: path, relativeTo: baseURL)!)
        req.httpMethod = method
        if let t = Self.readToken() {
            req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization")
        }
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        return req
    }

    private func send<T: Decodable>(_ req: URLRequest, as: T.Type) async throws -> T {
        do {
            let (data, resp) = try await session.data(for: req)
            guard let http = resp as? HTTPURLResponse else {
                throw FoundryAPIError.networkError("non-HTTP response")
            }
            if http.statusCode >= 400 {
                throw FoundryAPIError.httpError(
                    code: http.statusCode,
                    message: String(data: data, encoding: .utf8) ?? "")
            }
            do { return try JSONDecoder().decode(T.self, from: data) }
            catch { throw FoundryAPIError.decodingFailed("\(error)") }
        } catch let e as FoundryAPIError { throw e }
        catch { throw FoundryAPIError.networkError("\(error)") }
    }

    private func postJSON<T: Decodable>(_ path: String, body: [String: Any], as: T.Type) async throws -> T {
        var req = authed(path, method: "POST")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        return try await send(req, as: T.self)
    }

    // MARK: plan

    public func plan(targetHandle: String, vulnClasses: [String]) async throws -> FoundryAccountPlan {
        try await postJSON("/v1/foundry/plan",
            body: ["target_handle": targetHandle, "vuln_classes": vulnClasses],
            as: FoundryAccountPlan.self)
    }

    // MARK: personas / recipes

    public func listPersonas() async throws -> [FoundryPersona] {
        try await send(authed("/v1/foundry/personas"), as: [FoundryPersona].self)
    }

    public func listAuthorizationEnvelopes() async throws -> [FoundryAuthorizationEnvelope] {
        try await send(
            authed("/v1/foundry/envelopes"),
            as: [FoundryAuthorizationEnvelope].self
        )
    }

    public func runBehavioralAuthorization(
        targetOrigin: String,
        envelopeId: String,
        sourcePersonaId: String,
        peerPersonaId: String,
        sourceRecords: [[String: Any]],
        peerRecords: [[String: Any]],
        scriptURLs: [String] = []
    ) async throws -> BehavioralAuthorizationResponse {
        try await postJSON(
            "/v1/foundry/behavioral-authorization",
            body: [
                "target_origin": targetOrigin,
                "envelope_id": envelopeId,
                "source_persona_id": sourcePersonaId,
                "peer_persona_id": peerPersonaId,
                "source_records": sourceRecords,
                "peer_records": peerRecords,
                "script_urls": scriptURLs,
            ],
            as: BehavioralAuthorizationResponse.self
        )
    }

    public func runBehavioralAuthorizationFromURL(
        targetURL: String,
        envelopeId: String,
        sourcePersonaId: String,
        peerPersonaId: String
    ) async throws -> BehavioralAuthorizationResponse {
        var request = authed(
            "/v1/foundry/behavioral-authorization-from-url",
            method: "POST"
        )
        request.timeoutInterval = 900
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(
            withJSONObject: [
                "target_url": targetURL,
                "envelope_id": envelopeId,
                "source_persona_id": sourcePersonaId,
                "peer_persona_id": peerPersonaId,
            ]
        )
        return try await send(request, as: BehavioralAuthorizationResponse.self)
    }

    /// Create a research persona in the vault. The password is stored server-side
    /// (0600) and never echoed back — the returned FoundryPersona carries only
    /// `hasPassword`. This is the missing bootstrap: nothing else could populate
    /// the vault from the UI.
    public func createPersona(
        label: String, email: String, password: String = "",
        firstName: String = "", lastName: String = "", phone: String = ""
    ) async throws -> FoundryPersona {
        try await postJSON("/v1/foundry/personas",
            body: [
                "label": label, "email": email, "password": password,
                "first_name": firstName, "last_name": lastName, "phone": phone,
            ],
            as: FoundryPersona.self)
    }

    public func listRecipes() async throws -> [FoundryRecipeSummary] {
        try await send(authed("/v1/foundry/recipes"), as: [FoundryRecipeSummary].self)
    }

    /// Record a signup recipe in a live Playwright session.
    /// Uses a custom long-lived URLSession since the human has to actually sign up.
    public func deleteRecipe(recipeId: String) async throws {
        var req = authed("/v1/foundry/recipes/\(recipeId)", method: "DELETE")
        let (data, res) = try await URLSession.shared.data(for: req)
        guard let http = res as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            let errStr = String(data: data, encoding: .utf8) ?? "Unknown HTTP error"
            throw NSError(domain: "Foundry", code: (res as? HTTPURLResponse)?.statusCode ?? 500,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to delete recipe: \(errStr)"])
        }
    }

    public func recordRecipe(serviceHandle: String, name: String, origin: String) async throws -> FoundryRecipeSummary {
        var req = authed("/v1/foundry/record", method: "POST")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body: [String: Any] = [
            "service_handle": serviceHandle,
            "name": name,
            "origin": origin
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 900 // 15 mins for manual recording
        config.timeoutIntervalForResource = 900
        let longSession = URLSession(configuration: config)
        
        do {
            let (data, resp) = try await longSession.data(for: req)
            guard let http = resp as? HTTPURLResponse else {
                throw FoundryAPIError.networkError("non-HTTP response")
            }
            if http.statusCode >= 400 {
                throw FoundryAPIError.httpError(
                    code: http.statusCode,
                    message: String(data: data, encoding: .utf8) ?? "")
            }
            return try JSONDecoder().decode(FoundryRecipeSummary.self, from: data)
        } catch let e as FoundryAPIError { throw e }
        catch { throw FoundryAPIError.networkError("\(error)") }
    }

    // MARK: signup

    public func startSignup(recipeId: String, personaId: String) async throws -> FoundrySignupJob {
        try await postJSON("/v1/foundry/signup",
            body: ["recipe_id": recipeId, "persona_id": personaId],
            as: FoundrySignupJob.self)
    }

    public func listSignupJobs() async throws -> [FoundrySignupJob] {
        try await send(authed("/v1/foundry/signup"), as: [FoundrySignupJob].self)
    }

    // MARK: challenges (the handoff)

    public func listChallenges() async throws -> [FoundryChallenge] {
        try await send(authed("/v1/foundry/challenges"), as: [FoundryChallenge].self)
    }

    /// The 1-click resolution. For verification challenges, pass the
    /// human-supplied value (email link / code) as extractedValue.
    @discardableResult
    public func resolveChallenge(
        _ challengeId: String,
        resolved: Bool = true,
        extractedValue: String? = nil
    ) async throws -> Bool {
        var body: [String: Any] = ["resolved": resolved]
        if let v = extractedValue { body["extracted_value"] = v }
        struct R: Codable { let resolved: Bool }
        let r = try await postJSON(
            "/v1/foundry/challenges/\(challengeId)/resolve",
            body: body, as: R.self)
        return r.resolved
    }
}
