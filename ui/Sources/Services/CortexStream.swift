//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: CortexStream]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

//
//  CortexStream.swift
//  SentinelForgeUI
//
//  Connects to the Neural Core via WebSocket.
//  Feeds the Metal Renderer.
//

import Combine
import Foundation
import simd

/// Class CortexStream.
class CortexStream: ObservableObject {
    private var webSocketTask: URLSessionWebSocketTask?
    private var session: URLSession?
    private var positionCache: [String: SIMD3<Float>] = [:]

    @Published var nodes: [NodeModel] = []
    @Published var edges: [EdgeModel] = []
    @Published var isConnected: Bool = false

    /// Struct NodeModel.
    struct NodeModel: Decodable, Identifiable {
        let id: String
        let type: String
        var x: Float?  // Optional, might be computed on client
        var y: Float?
        var z: Float?  // Added for 3D
        var color: SIMD4<Float>?  // Computable

        // Physics
        var mass: Float?
        var charge: Float?
        var temperature: Float?
        var structural: Bool?
        var description: String?  // Semantic Analysis
        var pressure: Float?  // 0.0-1.0
        var severity: String?  // "HIGH", "CRITICAL", etc.
    }

    /// Struct EdgeModel.
    struct EdgeModel: Decodable, Identifiable {
        let id: String
        let source: String
        let target: String
        let type: String?
    }

    /// Struct GraphData.
    struct GraphData: Decodable {
        let nodes: [NodeModel]
        let edges: [EdgeModel]?

        enum CodingKeys: String, CodingKey {
            case nodes, links, edges, directed, multigraph, graph
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.nodes = (try? container.decode([NodeModel].self, forKey: .nodes)) ?? []

            // Decodes edges if key exists (supports 'edges' or 'links')
            if let edgesDecoded = try? container.decode([EdgeModel].self, forKey: .edges) {
                self.edges = edgesDecoded
            } else if let linksDecoded = try? container.decode([EdgeModel].self, forKey: .links) {
                self.edges = linksDecoded
            } else {
                self.edges = []
            }
        }
    }

    private var targetURL: URL?
    private var retryAttempt = 0
    private let maxRetries = 5

    /// Path to the token file (mirrors SentinelAPIClient)
    private static let tokenPath: URL = {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".sentinelforge")
            .appendingPathComponent("api_token")
    }()

    private static func readToken() -> String? {
        try? String(contentsOf: tokenPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Function connect.
    func connect(url: URL) {
        self.targetURL = url

        let config = URLSessionConfiguration.default
        let session = URLSession(
            configuration: config, delegate: nil, delegateQueue: OperationQueue.main)
        self.session = session

        let token = Self.readToken()
        var finalURL = url
        if let token = token, !token.isEmpty {
            if var components = URLComponents(url: url, resolvingAgainstBaseURL: false) {
                var items = components.queryItems ?? []
                items.append(URLQueryItem(name: "token", value: token))
                components.queryItems = items
                if let withToken = components.url {
                    finalURL = withToken
                }
            }
        }

        var request = URLRequest(url: finalURL)
        if let token = token, !token.isEmpty {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        print("[CortexStream] Connecting to \(url) (Auth: \(Self.readToken() != nil))...")
        webSocketTask = session.webSocketTask(with: request)
        webSocketTask?.resume()
        self.isConnected = true

        receiveMessage()
    }

    /// Function disconnect.
    func disconnect() {
        webSocketTask?.cancel(with: .normalClosure, reason: nil)
        webSocketTask = nil
        isConnected = false
        print("[CortexStream] Disconnected.")
    }

    /// Reset internal state (for Replay)
    func reset() {
        DispatchQueue.main.async {
            self.nodes = []
            self.edges = []
            self.positionCache = [:]
            self.retryAttempt = 0  // Reset interactions
        }
    }

    /// Process a batch of events (optimized for Replay)
    func processBatch(_ events: [GraphEvent]) {
        DispatchQueue.main.async {
            // Temporary buffers
            var newNodes = self.nodes
            var newEdges = self.edges

            for event in events {
                self.applyEvent(event, nodes: &newNodes, edges: &newEdges)
            }

            // Single commit to published properties
            self.nodes = newNodes
            self.edges = newEdges
        }
    }

    /// Process a single event (Live)
    func processEvent(_ event: GraphEvent) {
        DispatchQueue.main.async {
            self.applyEvent(event, nodes: &self.nodes, edges: &self.edges)
        }
    }

    private func applyEvent(_ event: GraphEvent, nodes: inout [NodeModel], edges: inout [EdgeModel])
    {
        switch event.eventType {
        case .nodeAdded, .nodeUpdated:
            guard let id = event.payload["id"]?.stringValue,
                let type = event.payload["type"]?.stringValue
            else { return }

            let data = event.payload["data"]?.dictValue ?? event.payload

            let base = self.positionCache[id] ?? self.stablePosition(for: id)
            self.positionCache[id] = base

            let newNode = NodeModel(
                id: id,
                type: type,
                x: base.x,
                y: base.y,
                z: base.z,
                color: self.colorForType(type, severity: data["severity"] as? Double),
                mass: Float((data["mass"] as? Double) ?? 1.0),
                charge: Float((data["charge"] as? Double) ?? 0.0),
                temperature: Float((data["temperature"] as? Double) ?? 0.0),
                structural: data["structural"] as? Bool,
                description: data["description"] as? String,
                pressure: Float((data["severity"] as? Double ?? 0.0) / 10.0),
                severity: (data["severity"] as? Double ?? 0.0) > 7 ? "HIGH" : "INFO"
            )

            if let idx = nodes.firstIndex(where: { $0.id == id }) {
                nodes[idx] = newNode
            } else {
                nodes.append(newNode)
            }

        case .edgeAdded:
            guard let id = event.payload["id"]?.stringValue,
                let source = event.payload["source"]?.stringValue,
                let target = event.payload["target"]?.stringValue
            else { return }

            let newEdge = EdgeModel(
                id: id,
                source: source,
                target: target,
                type: event.payload["type"]?.stringValue ?? "unknown"
            )
            edges.append(newEdge)

        default:
            break
        }
    }

    private func colorForType(_ type: String, severity: Double?) -> SIMD4<Float> {
        if let sev = severity, sev >= 8.0 { return SIMD4<Float>(1.0, 0.0, 0.0, 1.0) }
        switch type {
        case "service": return SIMD4<Float>(0, 1, 0, 1)
        case "vulnerability": return SIMD4<Float>(1, 0, 0, 0.8)
        case "exposure": return SIMD4<Float>(1, 0.5, 0, 0.8)
        case "trust": return SIMD4<Float>(0, 0.5, 1, 0.8)
        default: return SIMD4<Float>(0.5, 0.5, 0.5, 0.8)
        }
    }

    private func scheduleReconnect() {
        guard retryAttempt < maxRetries else {
            print("[CortexStream] Max retries reached. Giving up.")
            return
        }

        let delay = Double(pow(2.0, Double(retryAttempt)))
        print(
            "[CortexStream] Disconnected. Reconnecting in \(delay)s (Attempt \(retryAttempt+1))...")

        retryAttempt += 1

        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self = self, let url = self.targetURL else { return }
            self.connect(url: url)
        }
    }

    private func receiveMessage() {
        webSocketTask?.receive { [weak self] result in
            // Guard condition.
            guard let self = self else { return }

            // Switch over value.
            switch result {
            case .failure(let error):
                print("WS Error: \(error)")
                DispatchQueue.main.async {
                    self.isConnected = false
                    self.scheduleReconnect()
                }
            case .success(let message):
                // Reset retry count on successful message receipt (implies connection is healthy)
                if self.retryAttempt > 0 {
                    self.retryAttempt = 0
                }

                // Switch over value.
                switch message {
                case .string(let text):
                    self.handleJSON(text)
                case .data(let data):
                    self.handleData(data)
                @unknown default: break
                }
                self.receiveMessage()  // Loop
            }
        }
    }

    private func handleJSON(_ text: String) {
        // Guard condition.
        guard let data = text.data(using: .utf8) else { return }
        handleData(data)
    }

    private func handleData(_ data: Data) {
        // Do-catch block.
        do {
            let update = try JSONDecoder().decode(GraphData.self, from: data)

            // Prune stale cached positions to avoid unbounded growth.
            let ids = Set(update.nodes.map { $0.id })
            positionCache = positionCache.filter { ids.contains($0.key) }

            // Map to 3D Space
            let mappedNodes = update.nodes.map { node -> NodeModel in
                var n = node

                // If backend omits coords, keep a stable pseudo-layout per node id
                // so the graph doesn't jitter each snapshot.
                let base =
                    positionCache[n.id]
                    ?? SIMD3<Float>(
                        Float.random(in: -50...50),
                        Float.random(in: -50...50),
                        Float.random(in: -50...50)
                    )
                let x = n.x ?? base.x
                let y = n.y ?? base.y
                let z = n.z ?? base.z
                positionCache[n.id] = SIMD3<Float>(x, y, z)
                n.x = x
                n.y = y
                n.z = z

                // Color based on type
                // Color based on type (Neural/Ghost Support)
                switch n.type {
                case "target":
                    n.color = SIMD4<Float>(1, 0.2, 0.2, 1)  // Red (Base)
                case "port":
                    n.color = SIMD4<Float>(0, 1, 0, 1)  // Green
                case let t where t.starts(with: "hypothesis"):
                    n.color = SIMD4<Float>(0.6, 0, 1, 1)  // Purple (AI Logic)
                case "endpoint_discovery":
                    n.color = SIMD4<Float>(1, 0.5, 0, 0.8)  // Orange (Ghost Traffic), slightly transparent?
                case let t where t.contains("vuln"):
                    n.color = SIMD4<Float>(1, 0, 0, 1)  // Bright Red (Confirmed)
                default:
                    n.color = SIMD4<Float>(0, 0.5, 1, 1)  // Blue
                }
                return n
            }

            DispatchQueue.main.async {
                self.nodes = mappedNodes
            }
        } catch {
            print("Graph Decode Error: \(error)")
        }
    }
    /// Generate stable 3D coordinates from a string seed (Node ID).
    private func stablePosition(for id: String) -> SIMD3<Float> {
        var hash: UInt64 = 1_469_598_103_934_665_603  // FNV-1a offset basis
        for byte in id.utf8 {
            hash ^= UInt64(byte)
            hash &*= 1_099_511_628_211
        }

        // Use different bit segments for X, Y, Z to decorrelate axes
        let h1 = Float(hash & 0xFFFF) / 65535.0
        let h2 = Float((hash >> 16) & 0xFFFF) / 65535.0
        let h3 = Float((hash >> 32) & 0xFFFF) / 65535.0

        // Map to -50...50 range
        let x = (h1 * 100.0) - 50.0
        let y = (h2 * 100.0) - 50.0
        let z = (h3 * 100.0) - 50.0

        return SIMD3<Float>(x, y, z)
    }

    func updateFromPressureGraph(_ graph: PressureGraphDTO) {
        // Map DTO -> NodeModel
        let mappedNodes = graph.nodes.map { node -> NodeModel in
            let id = node.id

            // Get cached position or generate stable one (Deterministic Layout)
            let base = positionCache[id] ?? stablePosition(for: id)

            // Map Color based on Severity & Type
            var color: SIMD4<Float>
            if node.data.severity >= 8.0 {
                // Critical/High Severity -> Red pulsing (visualized as bright red here)
                color = SIMD4<Float>(1.0, 0.0, 0.0, 1.0)
            } else if node.data.exploitability > 0.8 {
                // Highly Exploitable -> Orange/Red
                color = SIMD4<Float>(1.0, 0.3, 0.0, 1.0)
            } else {
                // Standard Type Coloring
                switch node.type {
                case "service": color = SIMD4<Float>(0, 1, 0, 1)  // Green
                case "vulnerability": color = SIMD4<Float>(1, 0, 0, 0.8)  // Red
                case "exposure": color = SIMD4<Float>(1, 0.5, 0, 0.8)  // Orange
                case "trust": color = SIMD4<Float>(0, 0.5, 1, 0.8)  // Blue
                default: color = SIMD4<Float>(0.5, 0.5, 0.5, 0.8)  // Grey
                }
            }

            // Update Cache
            positionCache[id] = base

            return NodeModel(
                id: id,
                type: node.type,
                x: base.x,
                y: base.y,
                z: base.z,
                color: color,
                mass: Float(node.data.mass ?? 1.0),
                charge: Float(node.data.charge ?? 0.0),
                temperature: Float(node.data.temperature ?? 0.0),
                structural: node.data.structural,
                description: node.data.description,
                pressure: {
                    // Normalize severity (0-10) to pressure (0.0-1.0)
                    // If severity > 10, clamp to 1.0
                    return Float(min(10.0, max(0.0, node.data.severity))) / 10.0
                }(),
                severity: {
                    if node.data.severity >= 9.0 { return "CRITICAL" }
                    if node.data.severity >= 7.0 { return "HIGH" }
                    if node.data.severity >= 4.0 { return "MEDIUM" }
                    if node.data.severity >= 1.0 { return "LOW" }
                    return "INFO"
                }()
            )
        }

        // Map DTO -> EdgeModel
        let mappedEdges = graph.edges.map { edge in
            EdgeModel(
                id: edge.id,
                source: edge.source,
                target: edge.target,
                type: edge.type
            )
        }

        DispatchQueue.main.async {
            self.nodes = mappedNodes
            self.edges = mappedEdges
        }
    }
}
