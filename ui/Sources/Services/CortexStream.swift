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

import Foundation

/// Class CortexStream.
class CortexStream: ObservableObject {
    private var webSocketTask: URLSessionWebSocketTask?
    private var session: URLSession?
    private var positionCache: [String: SIMD3<Float>] = [:]

    @Published var nodes: [NodeModel] = []
    @Published var isConnected: Bool = false

    /// Struct NodeModel.
    struct NodeModel: Decodable, Identifiable {
        let id: String
        let type: String
        var x: Float?  // Optional, might be computed on client
        var y: Float?
        var z: Float?  // Added for 3D
        var color: SIMD4<Float>?  // Computable
    }

    /// Struct GraphData.
    struct GraphData: Decodable {
        let nodes: [NodeModel]
        // networkx format uses 'links', some formats use 'edges'
        // Use AnyCodable-like approach to handle both

        /// Enum CodingKeys.
        enum CodingKeys: String, CodingKey {
            case nodes, links, edges, directed, multigraph, graph
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            // Nodes might be empty array
            self.nodes = (try? container.decode([NodeModel].self, forKey: .nodes)) ?? []
        }
    }

    /// Function connect.
    func connect(url: URL) {
        let config = URLSessionConfiguration.default
        let session = URLSession(
            configuration: config, delegate: nil, delegateQueue: OperationQueue.main)
        self.session = session

        webSocketTask = session.webSocketTask(with: url)
        webSocketTask?.resume()
        self.isConnected = true

        receiveMessage()
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
                }
            case .success(let message):
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
                let base = positionCache[n.id] ?? SIMD3<Float>(
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
}
