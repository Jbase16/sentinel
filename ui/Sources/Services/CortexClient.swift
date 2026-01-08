import Foundation

// MARK: - API DTOs

struct AnalysisCaps: Codable {
    var max_paths: Int = 5
    var timeout_seconds: Double = 5.0
    var approximation_threshold: Int = 500
}

struct TopologyRequest: Codable {
    let graph_data: GraphDataDTO
    let entry_nodes: [String]
    let critical_assets: [String]
    let caps: AnalysisCaps
}

struct PathResult: Codable {
    let path: [String]
    let score: [Double]  // (length, risk, bottleneck)
    let metadata: [String: String]?  // [String: Any] not Codable easily
}

public struct TopologyResponse: Codable {
    public let graph_hash: String
    public let computed_at: Double
    public let centrality: [String: Double]
    public let communities: [String: Int]
    public let critical_paths: [PathResult]?  // Optional if legacy backend
    public let limits_applied: [String: Bool]
}

struct InsightRequest: Codable {
    let graph_hash: String
    let target_nodes: [String]
    let insight_type: String
    let graph_data: GraphDataDTO
}

public struct InsightClaim: Codable, Identifiable {
    public var id: String { claim + String(confidence) }  // Pseudo-ID
    public let claim: String
    public let evidence: [String]
    public let confidence: Double
}

public struct InsightResponse: Codable {
    public let graph_hash: String
    public let insights: [InsightClaim]
}

// Needed for GraphDataDTO to match backend expectation
// We need to mirror what `CortexStream` uses or what `EventStream` emits
// But here we need to Serialize the current graph state from HelixAppState/CortexStream
// Let's assume we pass a structure that matches the backend `metrics` or `node/edge` layout.

struct GraphDataDTO: Codable {
    let nodes: [NodeDTO]
    let edges: [EdgeDTO]
}

struct NodeDTO: Codable {
    let id: String
    let type: String
    let attributes: [String: String]  // simplified
}

struct EdgeDTO: Codable {
    let source: String
    let target: String
    let type: String
    let weight: Double
}

// MARK: - Client

actor CortexClient {
    private let baseURL = URL(string: "http://127.0.0.1:8000/v1/cortex")!

    // We can inject the token, or read it from disk like other clients.
    // For simplicity, let's read it on init or request.

    private func getToken() -> String? {
        let path = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge/api_token")
        return try? String(contentsOf: path).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func fetchTopology(graph: GraphDataDTO, entryNodes: [String], criticalAssets: [String])
        async throws -> TopologyResponse
    {
        let caps = AnalysisCaps()  // Default caps
        let requestPayload = TopologyRequest(
            graph_data: graph,
            entry_nodes: entryNodes,
            critical_assets: criticalAssets,
            caps: caps
        )

        return try await performRequest(endpoint: "analysis/topology", payload: requestPayload)
    }

    func fetchInsights(graph: GraphDataDTO, hash: String, nodes: [String], type: String)
        async throws -> InsightResponse
    {
        let requestPayload = InsightRequest(
            graph_hash: hash,
            target_nodes: nodes,
            insight_type: type,
            graph_data: graph
        )

        return try await performRequest(endpoint: "analysis/insights", payload: requestPayload)
    }

    private func performRequest<T: Codable, R: Codable>(endpoint: String, payload: T) async throws
        -> R
    {
        let url = baseURL.appendingPathComponent(endpoint)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if let token = getToken() {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        request.httpBody = try JSONEncoder().encode(payload)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
            (200...299).contains(httpResponse.statusCode)
        else {
            throw URLError(.badServerResponse)
        }

        return try JSONDecoder().decode(R.self, from: data)
    }
}
