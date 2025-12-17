//
// PURPOSE:
// This Swift component is part of the SentinelForge macOS UI.
// [Specific purpose based on component name: GraphModels]
//
// KEY RESPONSIBILITIES:
// - [Automatically generated - review and enhance based on actual functionality]
//
// INTEGRATION:
// - Used by: [To be documented]
// - Depends on: [To be documented]
//

import Foundation
import SwiftUI
import Combine

// MARK: - Graph Data Models

/// Struct GraphNode.
struct GraphNode: Identifiable, Equatable, Hashable {
    let id: UUID
    let label: String
    let type: NodeType
    var position: CGPoint
    var velocity: CGPoint = .zero
    var radius: CGFloat = 20.0
    
    // Hashable conformance for SwiftUI loop
    /// Function hash.
    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }

    /// Enum NodeType.
    enum NodeType: String {
        case target
        case domain
        case ip
        case port
        case vulnerability
        case finding
        
        var color: Color {
            switch self {
            case .target: return .blue
            case .domain: return .purple
            case .ip: return .orange
            case .port: return .gray
            case .vulnerability: return .red
            case .finding: return .green
            }
        }
        
        var icon: String {
            switch self {
            case .target: return "target"
            case .domain: return "network"
            case .ip: return "pc"
            case .port: return "cable.connector"
            case .vulnerability: return "exclamationmark.shield.fill"
            case .finding: return "magnifyingglass"
            }
        }
    }
}

/// Struct GraphLink.
struct GraphLink: Identifiable, Equatable {
    let id: UUID = UUID()
    let sourceID: UUID
    let targetID: UUID
}

// MARK: - Physics Engine

/// Class ForceSimulator.
class ForceSimulator: ObservableObject {
    @Published var nodes: [GraphNode] = []
    @Published var links: [GraphLink] = []
    
    private var timer: Timer?
    private let center = CGPoint(x: 400, y: 300) // Default center, updates on resize
    
    // Physics constants
    private let repulsionForce: CGFloat = 800.0
    private let springLength: CGFloat = 80.0
    private let springForce: CGFloat = 0.05
    private let damping: CGFloat = 0.90
    private let centerForce: CGFloat = 0.005

    init() {
        startSimulation()
    }
    
    /// Function updateData.
    func updateData(findings: [JSONDict]?, issues: [JSONDict]?, target: String?) {
        // Differential update to avoid resetting positions of existing nodes
        var newNodes = self.nodes
        var newLinks = self.links
        
        // 1. Ensure Root Target Node
        let rootLabel = target?.isEmpty == false ? target! : "Target"
        let rootID: UUID
        
        if let idx = newNodes.firstIndex(where: { $0.type == .target }) {
            newNodes[idx] = GraphNode(id: newNodes[idx].id, label: rootLabel, type: .target, position: newNodes[idx].position, velocity: newNodes[idx].velocity, radius: 30)
            rootID = newNodes[idx].id
        } else {
            rootID = UUID()
            newNodes.append(GraphNode(id: rootID, label: rootLabel, type: .target, position: center, radius: 30))
        }
        
        // Helper to find or create node
        /// Function getOrCreateNode.
        func getOrCreateNode(label: String, type: GraphNode.NodeType, parentID: UUID) -> UUID {
            if let existing = newNodes.first(where: { $0.label == label }) {
                // Ensure link exists
                if !newLinks.contains(where: { $0.sourceID == parentID && $0.targetID == existing.id }) {
                    newLinks.append(GraphLink(sourceID: parentID, targetID: existing.id))
                }
                return existing.id
            }
            
            // Spawn near parent
            let parentPos = newNodes.first(where: { $0.id == parentID })?.position ?? center
            let randomOffset = CGPoint(x: CGFloat.random(in: -50...50), y: CGFloat.random(in: -50...50))
            let pos = CGPoint(x: parentPos.x + randomOffset.x, y: parentPos.y + randomOffset.y)
            
            let newNode = GraphNode(id: UUID(), label: label, type: type, position: pos)
            newNodes.append(newNode)
            newLinks.append(GraphLink(sourceID: parentID, targetID: newNode.id))
            return newNode.id
        }

        // 2. Map Findings
        if let findings = findings {
            for finding in findings {
                guard let type = finding["type"]?.stringValue,
                      let severity = finding["severity"]?.stringValue else { continue }
                
                let asset = finding["asset"]?.stringValue ?? finding["target"]?.stringValue ?? "Unknown"
                
                // Link Asset to Root
                let assetID = getOrCreateNode(label: asset, type: .domain, parentID: rootID)
                
                // Determine node type based on finding
                var nodeType: GraphNode.NodeType = .finding
                if severity == "HIGH" || severity == "CRITICAL" {
                    nodeType = .vulnerability
                } else if type.lowercased().contains("port") {
                    nodeType = .port
                }
                
                // Link Finding to Asset
                _ = getOrCreateNode(label: type, type: nodeType, parentID: assetID)
            }
        }
        
        self.nodes = newNodes
        self.links = newLinks
    }
    
    /// Function startSimulation.
    func startSimulation() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1.0/60.0, repeats: true) { [weak self] _ in
            self?.tick()
        }
    }
    
    /// Function stopSimulation.
    func stopSimulation() {
        timer?.invalidate()
    }
    
    private func tick() {
        for i in 0..<nodes.count {
            var force = CGPoint.zero
            
            // 1. Repulsion (Coulomb's Law-ish)
            for j in 0..<nodes.count {
                if i == j { continue }
                let dx = nodes[i].position.x - nodes[j].position.x
                let dy = nodes[i].position.y - nodes[j].position.y
                let distSq = dx*dx + dy*dy
                let dist = sqrt(distSq)
                
                if dist > 0 {
                    let f = repulsionForce / distSq
                    force.x += (dx / dist) * f
                    force.y += (dy / dist) * f
                }
            }
            
            // 2. Attraction (Springs)
            // Naive O(N^2) search for links for simplicity in this demo, optimize later
            for link in links {
                var otherIdx: Int? = nil
                if link.sourceID == nodes[i].id {
                    otherIdx = nodes.firstIndex(where: { $0.id == link.targetID })
                } else if link.targetID == nodes[i].id {
                    otherIdx = nodes.firstIndex(where: { $0.id == link.sourceID })
                }
                
                if let idx = otherIdx {
                    let other = nodes[idx]
                    let dx = nodes[i].position.x - other.position.x
                    let dy = nodes[i].position.y - other.position.y
                    let dist = sqrt(dx*dx + dy*dy)
                    
                    let displacement = dist - springLength
                    let f = displacement * springForce
                    
                    if dist > 0 {
                        force.x -= (dx / dist) * f
                        force.y -= (dy / dist) * f
                    }
                }
            }
            
            // 3. Center Gravity
            let cx = nodes[i].position.x - center.x
            let cy = nodes[i].position.y - center.y
            force.x -= cx * centerForce
            force.y -= cy * centerForce
            
            // Apply Velocity
            nodes[i].velocity.x = (nodes[i].velocity.x + force.x) * damping
            nodes[i].velocity.y = (nodes[i].velocity.y + force.y) * damping
            
            // Apply Position
            nodes[i].position.x += nodes[i].velocity.x
            nodes[i].position.y += nodes[i].velocity.y
        }
    }
}
