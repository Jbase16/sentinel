//
//  CortexStream.swift
//  SentinelForgeUI
//
//  Connects to the Neural Core via WebSocket.
//  Feeds the Metal Renderer.
//

import Foundation

class CortexStream: ObservableObject {
    private var webSocketTask: URLSessionWebSocketTask?
    private var session: URLSession?

    @Published var nodes: [NodeModel] = []
    @Published var isConnected: Bool = false

    struct NodeModel: Decodable, Identifiable {
        let id: String
        let type: String
        var x: Float?  // Optional, might be computed on client
        var y: Float?
        var z: Float?  // Added for 3D
        var color: SIMD4<Float>?  // Computable
    }

    struct GraphData: Decodable {
        let nodes: [NodeModel]
        // networkx format uses 'links', some formats use 'edges'
        // Use AnyCodable-like approach to handle both

        enum CodingKeys: String, CodingKey {
            case nodes, links, edges, directed, multigraph, graph
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            // Nodes might be empty array
            self.nodes = (try? container.decode([NodeModel].self, forKey: .nodes)) ?? []
        }
    }

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
            guard let self = self else { return }

            switch result {
            case .failure(let error):
                print("WS Error: \(error)")
                DispatchQueue.main.async {
                    self.isConnected = false
                }
            case .success(let message):
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
        guard let data = text.data(using: .utf8) else { return }
        handleData(data)
    }

    private func handleData(_ data: Data) {
        do {
            let update = try JSONDecoder().decode(GraphData.self, from: data)

            // Map to 3D Space
            let mappedNodes = update.nodes.map { node -> NodeModel in
                var n = node
                // If backend sends 2D or no coords, project to 3D sphere/cloud
                if n.x == nil { n.x = Float.random(in: -50...50) }
                if n.y == nil { n.y = Float.random(in: -50...50) }
                if n.z == nil { n.z = Float.random(in: -50...50) }

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
