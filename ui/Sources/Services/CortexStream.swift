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
        var label: String?  // Human-readable name (e.g. "Exposed Git Repository")
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
            guard let id = event.payload["node_id"]?.stringValue ?? event.payload["id"]?.stringValue
            else { return }

            let type =
                event.payload["node_type"]?.stringValue
                ?? event.payload["type"]?.stringValue
                ?? nodes.first(where: { $0.id == id })?.type
                ?? "unknown"

            let data =
                event.payload["changes"]?.dictValue
                ?? event.payload["data"]?.dictValue
                ?? [:]

            let base = self.positionCache[id] ?? self.stablePosition(for: id)
            self.positionCache[id] = base

            let existing = nodes.first(where: { $0.id == id })

            // Break up complex expressions to help compiler type-check
            var resolvedSeverity: Double? = data["severity"] as? Double
            if resolvedSeverity == nil {
                resolvedSeverity = event.payload["severity"]?.doubleValue
            }
            if resolvedSeverity == nil, let p = existing?.pressure {
                resolvedSeverity = Double(p * 10.0)
            }
            let severity = resolvedSeverity ?? 0.0

            let massDouble = (data["mass"] as? Double) ?? Double(existing?.mass ?? 1.0)
            let chargeDouble = (data["charge"] as? Double) ?? Double(existing?.charge ?? 0.0)
            let tempDouble =
                (data["temperature"] as? Double) ?? Double(existing?.temperature ?? 0.0)

            let newNode = NodeModel(
                id: id,
                type: type,
                x: base.x,
                y: base.y,
                z: base.z,
                color: self.colorForType(type, severity: severity),
                mass: Float(massDouble),
                charge: Float(chargeDouble),
                temperature: Float(tempDouble),
                structural: (data["structural"] as? Bool) ?? existing?.structural,
                description: (data["description"] as? String)
                    ?? event.payload["label"]?.stringValue
                    ?? existing?.description,
                pressure: Float(severity / 10.0),
                severity: severity > 7 ? "HIGH" : "INFO"
            )

            if let idx = nodes.firstIndex(where: { $0.id == id }) {
                nodes[idx] = newNode
            } else {
                nodes.append(newNode)
            }

        case .nodeRemoved:
            guard let id = event.payload["node_id"]?.stringValue ?? event.payload["id"]?.stringValue
            else { return }

            nodes.removeAll { $0.id == id }
            edges.removeAll { $0.source == id || $0.target == id }
            positionCache.removeValue(forKey: id)

        case .edgeAdded, .edgeUpdated:
            guard let source = event.payload["source"]?.stringValue,
                let target = event.payload["target"]?.stringValue
            else { return }

            let edgeType =
                event.payload["edge_type"]?.stringValue
                ?? event.payload["type"]?.stringValue
                ?? "unknown"

            let edgeId =
                event.payload["edge_id"]?.stringValue
                ?? event.payload["id"]?.stringValue
                ?? "\(source)->\(target):\(edgeType)"

            let newEdge = EdgeModel(
                id: edgeId,
                source: source,
                target: target,
                type: edgeType
            )

            if let idx = edges.firstIndex(where: { $0.id == edgeId }) {
                edges[idx] = newEdge
            } else {
                edges.append(newEdge)
            }

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

    func updateFromPressureGraph(
        _ graph: PressureGraphDTO,
        includeDecisionLayer: Bool = false,
        hideLowSignalNodes: Bool = false
    ) {
        func categoryForType(_ rawType: String) -> String {
            let t = rawType.lowercased()
            if t == "decision" { return "decision" }
            if t.contains("port") { return "port" }
            if t.contains("service") { return "service" }
            if t.contains("exposure") || t.contains("credential") || t.contains("auth") {
                return "exposure"
            }
            if t.contains("asset") || t.contains("dns") || t.contains("topology") {
                return "asset"
            }
            if t.contains("vuln") || t.contains("rce") || t.contains("sqli") || t.contains("xss")
            {
                return "vulnerability"
            }
            return t
        }

        // Map DTO -> NodeModel
        var mappedNodes = graph.nodes.map { node -> NodeModel in
            let id = node.id

            // Get cached position or generate stable one (Deterministic Layout)
            let base = positionCache[id] ?? stablePosition(for: id)
            let severity = min(10.0, max(0.0, node.data.severity))
            let category = categoryForType(node.type)
            let pressure = Float(severity / 10.0)

            // Map Color based on Severity & Type
            var color: SIMD4<Float>
            if severity >= 9.0 {
                // CRITICAL
                color = SIMD4<Float>(1.0, 0.0, 0.0, 1.0)
            } else if severity >= 7.0 {
                // HIGH
                color = SIMD4<Float>(1.0, 0.45, 0.0, 1.0)
            } else if severity >= 4.0 {
                // MEDIUM
                color = SIMD4<Float>(1.0, 0.8, 0.1, 0.95)
            } else if severity >= 1.0 {
                // LOW
                color = SIMD4<Float>(0.3, 0.75, 1.0, 0.85)
            } else {
                // INFO and non-vulnerability nodes
                switch category {
                case "service", "port": color = SIMD4<Float>(0.4, 1.0, 0.45, 0.95)
                case "asset": color = SIMD4<Float>(0.3, 0.8, 1.0, 0.9)
                case "exposure": color = SIMD4<Float>(1.0, 0.6, 0.2, 0.9)
                case "decision": color = SIMD4<Float>(0.7, 0.4, 1.0, 0.9)
                default: color = SIMD4<Float>(0.55, 0.55, 0.6, 0.8)
                }
            }

            // Exploitability bias: strong exploitability nudges toward warmer colors.
            if node.data.exploitability >= 0.85 && severity < 7.0 {
                color = SIMD4<Float>(max(color.x, 0.95), max(color.y, 0.35), color.z * 0.8, color.w)
            }

            // Update Cache
            positionCache[id] = base

            return NodeModel(
                id: id,
                type: category,
                x: base.x,
                y: base.y,
                z: base.z,
                color: color,
                mass: Float(node.data.mass ?? 1.0),
                charge: Float(node.data.charge ?? 0.0),
                temperature: Float(node.data.temperature ?? 0.0),
                structural: node.data.structural,
                label: node.label,
                description: node.data.description,
                pressure: pressure,
                severity: {
                    if severity >= 9.0 { return "CRITICAL" }
                    if severity >= 7.0 { return "HIGH" }
                    if severity >= 4.0 { return "MEDIUM" }
                    if severity >= 1.0 { return "LOW" }
                    return "INFO"
                }()
            )
        }

        // Map DTO -> EdgeModel
        var mappedEdges = graph.edges.map { edge in
            EdgeModel(
                id: edge.id,
                source: edge.source,
                target: edge.target,
                type: edge.data?.renderType ?? edge.type
            )
        }

        // Optional noise filter: hide low-signal nodes while preserving anchors.
        //
        // Design goal: keep the graph legible by default without collapsing it into
        // a meaningless "top-N" list. We do this by keeping:
        // - Anchors: entry + critical assets
        // - Structural nodes
        // - High-signal nodes (confirmed/probable, high severity, execution/access capability)
        // - One-hop neighborhood of the high-signal core (context)
        if hideLowSignalNodes {
            let pinnedIDs = Set((graph.criticalAssets ?? []) + (graph.entryNodes ?? []))

            let highConfirmIDs: Set<String> = Set(
                graph.nodes.compactMap { node in
                    let level = (node.data.confirmationLevel ?? "").lowercased()
                    return (level == "confirmed" || level == "probable") ? node.id : nil
                }
            )

            let highCapabilityIDs: Set<String> = Set(
                graph.nodes.compactMap { node in
                    guard let caps = node.data.capabilityTypes, !caps.isEmpty else { return nil }
                    let lower = caps.map { $0.lowercased() }
                    return (lower.contains("execution") || lower.contains("access")) ? node.id : nil
                }
            )

            let highSeverityIDs: Set<String> = Set(
                graph.nodes.compactMap { node in
                    return node.data.severity >= 7.0 ? node.id : nil  // HIGH+
                }
            )

            var coreIDs: Set<String> = pinnedIDs
            coreIDs.formUnion(highConfirmIDs)
            coreIDs.formUnion(highCapabilityIDs)
            coreIDs.formUnion(highSeverityIDs)
            for node in mappedNodes where node.structural == true {
                coreIDs.insert(node.id)
            }

            // Keep the core plus its immediate neighborhood so connections remain visible.
            var keepIDs: Set<String> = coreIDs
            for edge in mappedEdges {
                if coreIDs.contains(edge.source) || coreIDs.contains(edge.target) {
                    keepIDs.insert(edge.source)
                    keepIDs.insert(edge.target)
                }
            }

            // Guard: never filter down to an unusable graph. If we're about to drop
            // too much, keep the top nodes by pressure plus anchors.
            let minKeep = min(30, mappedNodes.count)
            if keepIDs.count < minKeep {
                let ranked = mappedNodes.sorted { lhs, rhs in
                    let lp = lhs.pressure ?? 0.0
                    let rp = rhs.pressure ?? 0.0
                    if lp != rp { return lp > rp }
                    let ls = lhs.structural ?? false
                    let rs = rhs.structural ?? false
                    if ls != rs { return ls }
                    return lhs.id < rhs.id
                }
                let top = ranked.prefix(min(40, ranked.count)).map { $0.id }
                keepIDs.formUnion(top)
            }

            mappedNodes = mappedNodes.filter { keepIDs.contains($0.id) }
            mappedEdges = mappedEdges.filter { keepIDs.contains($0.source) && keepIDs.contains($0.target) }
        }

        var finalNodes = mappedNodes

        // Defensive rendering cap: keep the graph interactive when backend snapshots
        // contain a large amount of low-signal nodes.
        let maxRenderableNodes: Int = {
            // As graphs grow, rendering hundreds of nodes degrades both legibility and
            // interactivity. Use an adaptive cap: keep more detail for small graphs,
            // but tighten as density increases.
            let n = mappedNodes.count
            if n <= 260 { return 260 }
            if n <= 600 { return 220 }
            if n <= 1_200 { return 180 }
            return 150
        }()

        if mappedNodes.count > maxRenderableNodes {
            let nodeById = Dictionary(uniqueKeysWithValues: mappedNodes.map { ($0.id, $0) })

            var degreeByNode: [String: Int] = [:]
            for edge in mappedEdges {
                degreeByNode[edge.source, default: 0] += 1
                degreeByNode[edge.target, default: 0] += 1
            }

            // Pin only a SMALL set of meaningful anchors. Pinning an entire
            // `entry_nodes` array (often huge in sparse graphs) defeats the cap.
            let criticalIDs = graph.criticalAssets ?? []
            let entryIDs = graph.entryNodes ?? []

            let maxPinnedTotal = 30
            let maxPinnedEntryNodes = 18

            let rankedEntryIDs = entryIDs.sorted { lhs, rhs in
                let lhsPressure = nodeById[lhs]?.pressure ?? 0.0
                let rhsPressure = nodeById[rhs]?.pressure ?? 0.0
                if lhsPressure != rhsPressure { return lhsPressure > rhsPressure }

                let lhsDegree = degreeByNode[lhs, default: 0]
                let rhsDegree = degreeByNode[rhs, default: 0]
                if lhsDegree != rhsDegree { return lhsDegree > rhsDegree }

                return lhs < rhs
            }

            var pinnedIDs = Set<String>()
            for id in criticalIDs { pinnedIDs.insert(id) }

            var addedEntry = 0
            for id in rankedEntryIDs {
                if addedEntry >= maxPinnedEntryNodes { break }
                if pinnedIDs.count >= maxPinnedTotal { break }
                if nodeById[id] == nil { continue }
                pinnedIDs.insert(id)
                addedEntry += 1
            }

            let ranked = mappedNodes.sorted { lhs, rhs in
                let lhsPinned = pinnedIDs.contains(lhs.id)
                let rhsPinned = pinnedIDs.contains(rhs.id)
                if lhsPinned != rhsPinned { return lhsPinned }

                let lhsPressure = lhs.pressure ?? 0.0
                let rhsPressure = rhs.pressure ?? 0.0
                if lhsPressure != rhsPressure { return lhsPressure > rhsPressure }

                let lhsStructural = lhs.structural ?? false
                let rhsStructural = rhs.structural ?? false
                if lhsStructural != rhsStructural { return lhsStructural }

                let lhsDegree = degreeByNode[lhs.id, default: 0]
                let rhsDegree = degreeByNode[rhs.id, default: 0]
                if lhsDegree != rhsDegree { return lhsDegree > rhsDegree }

                return lhs.id < rhs.id
            }

            var keepIDs = Set(ranked.prefix(maxRenderableNodes).map { $0.id })
            keepIDs.formUnion(pinnedIDs)

            finalNodes = mappedNodes.filter { keepIDs.contains($0.id) }
            mappedEdges = mappedEdges.filter { keepIDs.contains($0.source) && keepIDs.contains($0.target) }
        }
        if includeDecisionLayer, let decisionLayer = graph.decisionLayer {
            // Decision layer can be large; cap to keep the renderer usable.
            // Backend order is newest-first; we preserve that.
            let maxTotalNodesWithDecisions = 320
            let remainingSlots = max(0, maxTotalNodesWithDecisions - finalNodes.count)
            let maxDecisionNodes = min(80, remainingSlots)
            let selectedDecisionNodes = decisionLayer.nodes.prefix(maxDecisionNodes)

            let decisionNodes: [NodeModel] = selectedDecisionNodes.map { node in
                let id = node.id
                let base = positionCache[id] ?? stablePosition(for: id)
                positionCache[id] = base
                let confidence = Float(node.confidence ?? 0.6)
                return NodeModel(
                    id: id,
                    type: "decision",
                    x: base.x,
                    y: base.y,
                    z: base.z,
                    color: SIMD4<Float>(0.7, 0.4, 1.0, 0.9),
                    mass: 6.0,
                    charge: 20.0,
                    temperature: 0.0,
                    structural: false,
                    label: node.chosen ?? node.type,
                    description: node.reason,
                    pressure: max(0.1, min(1.0, confidence)),
                    severity: "INFO"
                )
            }
            finalNodes.append(contentsOf: decisionNodes)

            let allowedDecisionIDs = Set(decisionNodes.map { $0.id })
            let allowedNodeIDs = Set(finalNodes.map { $0.id })
            let decisionEdges: [EdgeModel] = decisionLayer.edges
                .filter { allowedNodeIDs.contains($0.source) && allowedNodeIDs.contains($0.target) }
                .map { edge in
                    EdgeModel(
                        id: edge.id,
                        source: edge.source,
                        target: edge.target,
                        type: edge.type
                    )
                }

            // Avoid adding a large decision-only subgraph that isn't connected to the
            // visible node set (e.g. when the base graph is heavily capped).
            let connectedDecisionEdges = decisionEdges.filter {
                allowedDecisionIDs.contains($0.source) || allowedDecisionIDs.contains($0.target)
            }
            mappedEdges.append(contentsOf: connectedDecisionEdges)
        }

        DispatchQueue.main.async {
            self.nodes = finalNodes
            self.edges = mappedEdges
        }
    }
}
