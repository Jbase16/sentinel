//
//  PressureGraphModels.swift
//  SentinelForgeUI
//
//  DTOs for the Pressure Graph (Ground Truth) API.
//

import Foundation

public struct PressureGraphDTO: Decodable, Sendable {
    public let sessionId: String
    public let nodes: [PressureNodeDTO]
    public let edges: [PressureEdgeDTO]
    public let count: GraphCountDTO
    public let entryNodes: [String]?
    public let criticalAssets: [String]?
    public let attackChains: [AttackChainDTO]?
    public let pressurePoints: [PressurePointDTO]?
    public let graphMetrics: GraphMetricsDTO?

    enum CodingKeys: String, CodingKey {
        case sessionId = "session_id"
        case nodes, edges, count
        case entryNodes = "entry_nodes"
        case criticalAssets = "critical_assets"
        case attackChains = "attack_chains"
        case pressurePoints = "pressure_points"
        case graphMetrics = "graph_metrics"
    }
}

public struct GraphMetricsDTO: Decodable, Sendable {
    public let attackChainsCount: Int?
    public let pressurePointsCount: Int?
    public let entryNodesCount: Int?
    public let leafNodesCount: Int?

    enum CodingKeys: String, CodingKey {
        case attackChainsCount = "attack_chains_count"
        case pressurePointsCount = "pressure_points_count"
        case entryNodesCount = "entry_nodes_count"
        case leafNodesCount = "leaf_nodes_count"
    }
}

public struct AttackChainDTO: Decodable, Sendable, Identifiable {
    public let id: String
    public let nodeIds: [String]
    public let labels: [String]?
    public let entryNode: String?
    public let leafNode: String?
    public let length: Int?
    public let score: Double?

    enum CodingKeys: String, CodingKey {
        case id
        case nodeIds = "node_ids"
        case labels
        case entryNode = "entry_node"
        case leafNode = "leaf_node"
        case length
        case score
    }
}

public struct PressurePointDTO: Decodable, Sendable, Identifiable {
    public var id: String { findingId }
    public let findingId: String
    public let findingTitle: String?
    public let severity: String?
    public let outDegree: Int?
    public let attackPathsBlocked: Int?
    public let downstreamCount: Int?
    public let centralityScore: Double?
    public let enablementScore: Double?
    public let recommendation: String?

    enum CodingKeys: String, CodingKey {
        case findingId = "finding_id"
        case findingTitle = "finding_title"
        case severity
        case outDegree = "out_degree"
        case attackPathsBlocked = "attack_paths_blocked"
        case downstreamCount = "downstream_count"
        case centralityScore = "centrality_score"
        case enablementScore = "enablement_score"
        case recommendation
    }
}

public struct GraphCountDTO: Decodable, Sendable {
    public let nodes: Int
    public let edges: Int
}

public struct PressureNodeDTO: Decodable, Identifiable, Sendable {
    public let id: String
    public let type: String
    public let label: String?
    public let data: PressureNodeDataDTO

    enum CodingKeys: String, CodingKey {
        case id, type, label, data
    }
}

public struct PressureNodeDataDTO: Decodable, Sendable {
    public let severity: Double
    public let exposure: Double
    public let exploitability: Double
    public let privilegeGain: Double
    public let assetValue: Double
    public let pressureSource: String
    public let revision: Int

    // Physics Properties
    public let mass: Double?
    public let charge: Double?
    public let temperature: Double?
    public let structural: Bool?
    public let description: String?
    public let rawSeverity: String?
    public let findingType: String?
    public let target: String?
    public let confirmationLevel: String?
    public let capabilityTypes: [String]?
    public let baseScore: Double?
    public let centralityScore: Double?
    public let enablementScore: Double?
    public let outDegree: Int?
    public let inDegree: Int?
    public let downstreamCount: Int?
    public let attackPathsBlocked: Int?
    public let attackChainMembership: Int?
    public let isEntryNode: Bool?
    public let isLeafNode: Bool?
    public let fixImpactEstimate: Int?

    enum CodingKeys: String, CodingKey {
        case severity, exposure, exploitability
        case privilegeGain = "privilege_gain"
        case assetValue = "asset_value"
        case pressureSource = "pressure_source"
        case revision
        case mass, charge, temperature, structural
        case description
        case rawSeverity = "raw_severity"
        case findingType = "finding_type"
        case target
        case confirmationLevel = "confirmation_level"
        case capabilityTypes = "capability_types"
        case baseScore = "base_score"
        case centralityScore = "centrality_score"
        case enablementScore = "enablement_score"
        case outDegree = "out_degree"
        case inDegree = "in_degree"
        case downstreamCount = "downstream_count"
        case attackPathsBlocked = "attack_paths_blocked"
        case attackChainMembership = "attack_chain_membership"
        case isEntryNode = "is_entry_node"
        case isLeafNode = "is_leaf_node"
        case fixImpactEstimate = "fix_impact_estimate"
    }
}

public struct PressureEdgeDTO: Decodable, Identifiable, Sendable {
    public let id: String
    public let source: String
    public let target: String
    public let type: String
    public let weight: Double
    public let data: PressureEdgeDataDTO?

    enum CodingKeys: String, CodingKey {
        case id, source, target, type, weight, data
    }
}

public struct PressureEdgeDataDTO: Decodable, Sendable {
    public let confidence: Double
    public let createdAt: Double
    public let relationshipRaw: String?
    public let renderType: String?
    public let enablementClass: String?
    public let effortReplaced: Double?

    enum CodingKeys: String, CodingKey {
        case confidence
        case createdAt = "created_at"
        case relationshipRaw = "relationship_raw"
        case renderType = "render_type"
        case enablementClass = "enablement_class"
        case effortReplaced = "effort_replaced"
    }
}
